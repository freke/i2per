-module(i2p_ntcp2_acceptor).

-moduledoc """
The only process that accepts an inbound NTCP2 connection, one per listener.

`m:i2p_ntcp2_listener` owns the listening socket and answers for it;
everything below the `accept` — admitting the connection under
`m:i2p_ntcp2_sup`'s limit, starting `m:i2p_ntcp2_conn` in the responder role and
handing the socket over — is this process's whole job. It blocks in
`f:gen_tcp:accept/1` and loops, so an inbound connection is taken as soon as the
kernel has completed it.

## Why accepting needs a process of its own

A listening socket does not notify. `{active, true}` on it delivers nothing: no
`{tcp, ListenSock, Sock}`, and no message of any kind when a connection arrives.
That is not an option this module failed to set, it is how the driver works — the
inet driver only arms `FD_ACCEPT` on a listening socket while a `gen_tcp:accept`
call is outstanding (`inet_drv.c`, `INET_REQ_ACCEPT`, which is the sole place
`sock_select(..., FD_ACCEPT, 1)` appears). Verified on this tree at OTP 28 with
`{active, true}`, `{active, once}` and `{active, false}`: all three accept
identically, and none of them produces a message.

So a process that accepts must either block in `gen_tcp:accept` and answer
nothing while it does, or come back out of it on a timer to look at its mailbox.
`m:i2p_ntcp2_listener` used to do the second, with a one-second timeout, and so
accepted exactly one inbound connection per second no matter how many were
waiting: a peer-set rebuild after a restart converged one peer per second. One
accept per connection, in a process that has nothing else to do, is the fix; the
listener's control messages then have a process that is not blocked to answer
them.

## The handover, and the window it must not have

The accepted socket belongs to this process, because the caller of
`gen_tcp:accept` is who owns what it returns. It is handed to the connection
process with `f:gen_tcp:controlling_process/2` after the connection exists, and
`i2p_ntcp2_conn` acknowledges the supervisor *before* it starts its handshake, so
the new owner is already reading the peer's first message when the socket arrives.

Nothing can be misrouted in between, and that rests on one option rather than on
the loop being quick. An accepted socket **inherits its listen socket's active
mode** — measured, not assumed: the same accept over a `{active, true}` listener
yields an accepted socket that delivers `{tcp, Sock, Data}` to this process, and
over a `{active, false}` listener one that does not. So the listen socket is
`{active, false}` and the accepted socket is set `{active, false}` again here, at
the one place that owns it. A socket that cannot deliver cannot deliver to the
wrong owner, whatever the peer sends in that window — and the responder's peer has
sent its first message and is waiting for the second, so the bytes in question are
the handshake's, not the data phase's.

## Lifetime

The listener owns the listening socket, so the listener's death is what stops
accepting: the socket closes, the blocked `f:gen_tcp:accept/1` answers
`{error, closed}`, and this process exits `normal`. The other direction is the
listener's to hold — it monitors this process and ends with it, so an acceptor
that crashed cannot leave behind a live `m:i2p_ntcp2_listener` pid that has
quietly stopped accepting, with every caller of
`f:i2p_ntcp2_listener:port/1` still reporting a port nothing is listening on.
""".

-export([start_link/3]).

-export([init/3]).

-doc false.
-spec start_link(gen_tcp:socket(), i2p_ntcp2_conn:local_keys(), pid()) ->
    {ok, pid()} | {error, term()}.
start_link(ListenSock, LocalKeys, Owner) ->
    proc_lib:start_link(?MODULE, init, [ListenSock, LocalKeys, Owner]).

-doc false.
-dialyzer({no_underspecs, init/3}).
-spec init(gen_tcp:socket(), i2p_ntcp2_conn:local_keys(), pid()) -> no_return().
init(ListenSock, LocalKeys, Owner) ->
    %% Acknowledged before the first `accept`, so the caller's `listen/3` does not
    %% return until the door is armed. A connection that lands in between the
    %% socket being bound and the acceptor being armed would sit in the kernel's
    %% backlog and be taken microseconds later, so this is not a correctness
    %% requirement — it is the difference between "the listener is up" meaning the
    %% accept path is running and meaning only that a socket exists.
    proc_lib:init_ack({ok, self()}),
    accept_loop(ListenSock, LocalKeys, Owner).

accept_loop(ListenSock, LocalKeys, Owner) ->
    case gen_tcp:accept(ListenSock) of
        {ok, Sock} ->
            start_connection(Sock, LocalKeys, Owner),
            accept_loop(ListenSock, LocalKeys, Owner);
        {error, closed} ->
            %% The listener closed the socket on its way out. This is the ordinary
            %% end of this loop and the reason `f:i2p_ntcp2_listener:stop/1` can
            %% answer before this process has finished exiting.
            exit(normal);
        {error, Reason} ->
            %% A resource limit or an error this loop has no way to work around
            %% (`emfile` on a busy node is the one worth naming). It stops
            %% accepting, and the listener ends with it, so the supervisor sees a
            %% listener that is not accepting rather than a router that looks
            %% healthy and refuses connections. The reason is in the exit because
            %% the shape this replaced — a `case_clause` on the same value — said
            %% nothing about which value it was.
            exit({accept_failed, Reason})
    end.

start_connection(Sock, LocalKeys, Owner) ->
    %% Set again, deliberately, though it is already the value: the accepted
    %% socket inherits the listen socket's active mode, and this is the only
    %% process that owns the socket between here and the handover. Setting it
    %% here makes the handover's safety a property of this function rather than
    %% of an option the listener happens to pass. See the module doc.
    ok = inet:setopts(Sock, [{nodelay, true}, {keepalive, true}, {active, false}]),
    Args = #{role => bob, sock => Sock, local => LocalKeys, owner => Owner},
    case i2p_ntcp2_sup:start_connection(i2p_ntcp2_sup:conn_child(Args)) of
        {ok, Conn} ->
            ok = gen_tcp:controlling_process(Sock, Conn);
        {ok, Conn, _Extra} ->
            ok = gen_tcp:controlling_process(Sock, Conn);
        {error, _Reason} ->
            %% The connection limit, or a supervisor that would not start it. The
            %% peer is already connected at the TCP level and there is nothing to
            %% tell it, so closing is the whole of the answer — the same outcome
            %% the listener's own loop produced for this case.
            %%
            %% No frame and no bus event for it, and that is a decision rather than
            %% an omission. A frame here would be a fifth module emitting frames,
            %% which `i2p_log_tests` exists to object to; an event has nowhere to
            %% key: the handshake has not run, so there is no RouterInfo and no
            %% peer hash to count against. What the peer sees — a completed TCP
            %% connection closed at once — is what it saw before this loop moved.
            ok = gen_tcp:close(Sock)
    end.
