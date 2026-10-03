-module(i2p_ntcp2_listener).

-moduledoc """
The NTCP2 listener: owns a listening socket, and answers for it.

One `temporary` child of `m:i2p_ntcp2_sup`, started on demand for a specific
local port. Accepted connections are handed to a fresh Bob connection process
under the same supervisor, so a connection's death — even by `kill` — leaves the
listener and every sibling connection alive. Closing the listener stops future
accepts but does not touch established connections.

## Two processes, because a listening socket does not notify

`f:i2p_ntcp2_listener:listen/3` returns two processes, and the split is the whole
design. This one owns the listening socket and answers the three questions that
can be asked of a listener — its port, its address, and whether it should stop.
`m:i2p_tcp_acceptor` is the only process that accepts, and it blocks in
`f:gen_tcp:accept/1` while it does so.

The reason is that a listening socket delivers no message when a connection
arrives, whatever its active mode — `m:i2p_tcp_acceptor` has the measurement
and the driver detail. So a process that accepts must either block in `accept`
and answer nothing while it does, or return from it on a timer to look at its
mailbox. This loop used to do the second, with a **one-second** timeout, and so
it accepted at most one inbound connection per second: six simultaneous
connections took 6.06 seconds to drain, read from the kernel's accept queue, and
the rate was exactly the timeout rather than anything about load. That is the rate
a router's peer set grows at, and the rate it rebuilds one after a restart, so it
was worth a process.

Which means the three control messages are now answered by a process that is not
blocked, which is what the timeout used to be for. The loop below has no timeout
clause at all: there is nothing left to poll for, so each message is answered when
it arrives. The bound that matters moved to the other end — see
`f:i2p_ntcp2_listener:stop/1`.

`f:start_bob/3` is what an accepted socket becomes. It lives here rather
than in `m:i2p_tcp_acceptor` because the child spec and the responder's
announcement are this transport's, and the acceptor's job is to own the socket
until they exist.

## Usage

```erlang
{ok, Listener} = i2p_ntcp2_listener:listen(Port, Local, self()),
Port = i2p_ntcp2_listener:port(Listener),
ok = i2p_ntcp2_listener:stop(Listener).
```
""".

-export([listen/3, port/1, address/1, stop/1, start_link/3, init/3]).

%% How long a caller of `f:port/1`, `f:address/1` or `f:stop/1` waits for its
%% answer. These are exported functions whose caller has no other way to find out
%% whether the listener is there, so an unbounded receive is a caller that never
%% comes back — the same class of wait `m:i2p_ntcp2_conn:stop/1` bounds, found in
%% the same module family. Generous by orders of magnitude against what it is
%% actually measuring: the listener does nothing but answer, so this is a
%% guarantee about a hung process, not a synchronisation.
-define(CONTROL_TIMEOUT_MS, 1000).

-doc """
Start a listener on `Port` (0 for an ephemeral port) using the node's
`t:i2p_ntcp2_conn:local_keys()`. Accepted connections deliver decrypted frames
to `Owner` as `{ntcp2_frame, ConnPid, Payload}`.
Output: `{ok, Pid}`.
""".
-spec listen(0..65535, i2p_ntcp2_conn:local_keys(), pid()) -> {ok, pid()}.
listen(Port, LocalKeys, Owner) ->
    supervisor:start_child(i2p_ntcp2_sup, i2p_ntcp2_sup:listener_child(Port, LocalKeys, Owner)).

-doc "The bound local port of the listener (useful with port 0).".
-spec port(pid()) -> inet:port_number().
port(Listener) ->
    case control(Listener, port) of
        {ok, Port} ->
            Port;
        no_answer ->
            error({listener_unanswered, Listener, port})
    end.

-doc """
Return the local address on which the listener is bound.

Input: a listener pid. Output: the bound IP address, useful for verifying that
an operator did not widen the listener unintentionally.
""".
-spec address(pid()) -> inet:ip_address().
address(Listener) ->
    case control(Listener, address) of
        {ok, Address} ->
            Address;
        no_answer ->
            error({listener_unanswered, Listener, address})
    end.

-doc """
Stop accepting new connections; established connections are unaffected.

Returns `ok` once the listener has acknowledged, whether or not it was alive to
be asked. If it does not answer within `?CONTROL_TIMEOUT_MS` it is killed: it
owns the listening socket, so a listener left running is a port that keeps
accepting after this function has reported that it stopped, and a listener that
cannot answer a stop request cannot be reasoned about as anything else. The same
trade `f:i2p_ntcp2_conn:stop/1` makes, and for the same reason — an exported
function's wait is bounded rather than open.
""".
-spec stop(pid()) -> ok.
stop(Listener) ->
    case control(Listener, stop) of
        {ok, stopped} ->
            ok;
        no_answer ->
            _ = catch exit(Listener, kill),
            ok
    end.

%% Ask the listener one question and wait, bounded, for the answer.
%%
%% Output `{ok, Answer}` with whatever the listener sent back, or `no_answer` if
%% the bound passed with neither an answer nor a `'DOWN'`. The monitor is what
%% makes a listener that is already dead a fast answer rather than a full second
%% of waiting for a reply that was never coming; `[flush]` is what keeps a
%% listener that answered and then died from leaking a `'DOWN'` into the caller.
%%
%% Each caller decides what a missing answer means, because the three mean
%% different things: an unknown port is a bug worth raising over, and a stop that
%% went unanswered is a listener to kill.
control(Listener, Question) ->
    Ref = make_ref(),
    MRef = erlang:monitor(process, Listener),
    Listener ! {Question, self(), Ref},
    receive
        {Question, Ref, Answer} ->
            erlang:demonitor(MRef, [flush]),
            {ok, Answer};
        {'DOWN', MRef, process, Listener, _Reason} ->
            no_answer
    after ?CONTROL_TIMEOUT_MS ->
        erlang:demonitor(MRef, [flush]),
        no_answer
    end.

-doc false.
-spec start_link(0..65535, i2p_ntcp2_conn:local_keys(), pid()) -> {ok, pid()} | {error, term()}.
start_link(Port, LocalKeys, Owner) ->
    proc_lib:start_link(?MODULE, init, [Port, LocalKeys, Owner]).

init(Port, LocalKeys, Owner) ->
    ListenIP = i2p_config:listen_ip(),
    {ok, ListenSock} = gen_tcp:listen(
        Port,
        [
            binary,
            {packet, raw},
            %% Passive, and load-bearing rather than conventional: an accepted
            %% socket inherits its listen socket's active mode, so this is what
            %% makes every socket `m:i2p_tcp_acceptor` accepts one that cannot
            %% deliver a frame to the wrong owner during the handover. The module
            %% doc there has the measurement, and sets it again on the accepted
            %% socket so the invariant does not rest on this option alone.
            {active, false},
            {reuseaddr, true},
            {nodelay, true},
            {ip, ListenIP}
        ]
    ),
    {ok, BoundPort} = inet:port(ListenSock),
    %% Armed before this process acknowledges, so `f:listen/3` does not return
    %% until something is accepting on the socket. The acceptor is monitored, not
    %% merely relied upon: if it dies, this process ends with it, because a live
    %% listener pid that has stopped accepting is worse than a dead one — every
    %% caller of `f:port/1` would keep reporting a port nothing listens on. A
    %% monitor rather than a link because the link is a platform detail
    %% (`f:proc_lib:start_link/3` unlinks after the ack on some releases and does
    %% not on others), and this must not depend on which one this is.
    {ok, Acceptor} = i2p_tcp_acceptor:start_link(
        ListenSock, fun(Sock) -> start_bob(Sock, LocalKeys, Owner) end
    ),
    MRef = erlang:monitor(process, Acceptor),
    proc_lib:init_ack({ok, self()}),
    control_loop(ListenSock, BoundPort, ListenIP, Acceptor, MRef).

%% No timeout clause, and the absence is the fix. There is nothing to poll for any
%% more — the accept moved to a process whose whole job is to block in it — so a
%% message here is answered as soon as it is read rather than at the end of a
%% wait that existed to make room for one connection per tick.
control_loop(ListenSock, BoundPort, ListenIP, Acceptor, MRef) ->
    receive
        {port, From, Ref} ->
            From ! {port, Ref, BoundPort},
            control_loop(ListenSock, BoundPort, ListenIP, Acceptor, MRef);
        {address, From, Ref} ->
            From ! {address, Ref, ListenIP},
            control_loop(ListenSock, BoundPort, ListenIP, Acceptor, MRef);
        {stop, From, Ref} ->
            %% Answered before exiting, and exiting closes the listening socket
            %% because this process owns it — which is what ends the acceptor's
            %% blocked `f:gen_tcp:accept/1` with `{error, closed}`. Established
            %% connections are children of the same supervisor and are not touched
            %% by any of this.
            From ! {stop, Ref, stopped},
            exit(normal);
        {'DOWN', MRef, process, Acceptor, Reason} ->
            %% The socket is not accepting and nothing here can make it accept, so
            %% this process stops claiming that it is. The one way to get here
            %% while the listener is alive is an acceptor that crashed; the
            %% supervisor then restarts the boot listener, which is the recovery
            %% that a crash report asks for anyway.
            exit({acceptor_gone, Reason})
    end.

%% Start the responder for one accepted socket and hand the socket over.
%%
%% Called by `m:i2p_tcp_acceptor` in the acceptor process, which is the socket's
%% owner at this point and therefore the only process that can transfer it. The
%% `controlling_process/2` has to come before anything the new owner does, which
%% is why the socket arrives in the child spec rather than in a message the child
%% might read too early: `i2p_ntcp2_conn:init/1` acknowledges its supervisor
%% before the handshake starts, so the owner of the socket is already reading the
%% peer's first message by the time the bytes arrive.
start_bob(Sock, LocalKeys, Owner) ->
    Args = #{role => bob, sock => Sock, local => LocalKeys, owner => Owner},
    case i2p_ntcp2_sup:start_connection(i2p_ntcp2_sup:conn_child(Args)) of
        {ok, Conn} ->
            ok = gen_tcp:controlling_process(Sock, Conn);
        {ok, Conn, _Extra} ->
            ok = gen_tcp:controlling_process(Sock, Conn);
        {error, _Reason} ->
            %% The connection limit, or a supervisor that would not start it. The
            %% peer is already connected at the TCP level and there is nothing to
            %% tell it, so closing is the whole of the answer.
            %%
            %% No frame and no bus event for it, and that is a decision rather than
            %% an omission. A frame here would be a fifth module emitting frames,
            %% which `i2p_log_tests` exists to object to; an event has nowhere to
            %% key: the handshake has not run, so there is no RouterInfo and no
            %% peer hash to count against. What the peer sees — a completed TCP
            %% connection closed at once — is what it saw before this loop moved.
            ok = gen_tcp:close(Sock)
    end.
