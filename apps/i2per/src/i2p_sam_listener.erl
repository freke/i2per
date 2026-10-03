-module(i2p_sam_listener).

-moduledoc """
SAM v3 TCP listener: owns a listening socket, and answers for it.

One `temporary` child of `m:i2p_sam_sup`, started on demand for a specific
local port. Accepted sockets are handed to a fresh `m:i2p_sam_session` under
the same supervisor, so a session's death — even by `kill` — leaves the listener
and every sibling session alive. Closing the listener stops future accepts but
does not touch established sessions.

## Two processes, because a listening socket does not notify

`f:listen/1` returns two processes, and the split is the whole design. This one
owns the listening socket and answers the three questions that can be asked of a
listener — its port, its address, and whether it should stop.
`m:i2p_tcp_acceptor` is the only process that accepts, and it blocks in
`f:gen_tcp:accept/1` while it does so.

The reason is that a listening socket delivers no message when a connection
arrives, whatever its active mode — `m:i2p_tcp_acceptor` has the measurement and
the driver detail. So a process that accepts must either block in `accept` and
answer nothing while it does, or return from it on a timer to look at its
mailbox. This loop used to do the second, with a **one-second** timeout, and so
it accepted at most one inbound session per second no matter how many were
waiting: six simultaneous connections took 6.06 seconds to drain, read from the
kernel's accept queue rather than from load.

**That rate is the one a client feels.** SAM is how an application reaches the
router, an application opens a connection per session, and a client that
reconnects — or opens a second session while the first is still being set up —
waited a second for each. `m:i2p_sam_sup` starts this as a **boot listener**, so
it is on the default path of every router with SAM on rather than behind an
option.

Which means the three control messages are now answered by a process that is not
blocked, which is what the timeout used to be for. The loop below has no timeout
clause at all: there is nothing left to poll for, so each message is answered when
it arrives. The bound that matters moved to the other end — see `f:stop/1`.

`f:start_session/2` is what an accepted socket becomes. It lives here rather than
in `m:i2p_tcp_acceptor` because the child spec and the `{socket_ready, Sock}` the
new owner owes are SAM's, and the acceptor's job is to own the socket until they
exist.

## Usage

```erlang
{ok, Listener} = i2p_sam_listener:listen(#{port => 7656}),
Port = i2p_sam_listener:port(Listener),
ok = i2p_sam_listener:stop(Listener).
```
""".

-export([listen/1, port/1, address/1, stop/1, start_link/1, init/1]).

-doc """
Start a SAM listener on the given port.

Input: `Opts` — a map with keys `port` (default 7656) and `local`
(`t:i2p_peer:local_keys/0`, required).
Output: `{ok, Pid}`.
""".
-spec listen(map()) -> {ok, pid()}.
listen(#{local := _Local} = Opts) ->
    supervisor:start_child(i2p_sam_sup, i2p_sam_sup:listener_child(Opts)).

-doc "The bound local port of the listener.".
-spec port(pid()) -> inet:port_number().
port(Listener) ->
    Ref = make_ref(),
    Listener ! {port, self(), Ref},
    receive
        {port, Ref, P} -> P
    end.

-doc """
Return the local address on which the listener is bound.

Input: a listener pid. Output: the bound IP address.
""".
-spec address(pid()) -> inet:ip_address().
address(Listener) ->
    Ref = make_ref(),
    Listener ! {address, self(), Ref},
    receive
        {address, Ref, Address} -> Address
    end.

-doc "Stop accepting new connections; existing sessions are unaffected.".
-spec stop(pid()) -> ok.
stop(Listener) ->
    Ref = make_ref(),
    Listener ! {stop, self(), Ref},
    receive
        {stopped, Ref} -> ok
    end.

-doc false.
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    proc_lib:start_link(?MODULE, init, [Opts]).

-doc false.
-dialyzer({no_underspecs, init/1}).
-spec init(map()) -> no_return().
init(#{port := Port, local := Local}) ->
    ListenIP = i2p_config:listen_ip(),
    {ok, ListenSock} = gen_tcp:listen(
        Port,
        [
            binary,
            {packet, raw},
            %% Passive, and load-bearing rather than conventional: an accepted
            %% socket inherits its listen socket's active mode, so this is what
            %% makes every socket `m:i2p_tcp_acceptor` accepts one that cannot
            %% deliver a line to the wrong owner during the handover. The module
            %% doc there has the measurement, and sets the option again on the
            %% accepted socket so the invariant does not rest on this one alone.
            {active, false},
            {reuseaddr, true},
            {nodelay, true},
            {ip, ListenIP}
        ]
    ),
    {ok, BoundPort} = inet:port(ListenSock),
    %% Armed before this process acknowledges, so `f:listen/1` does not return
    %% until something is accepting on the socket. The acceptor is monitored, not
    %% merely relied upon: if it dies, this process ends with it, because a live
    %% listener pid that has stopped accepting is worse than a dead one — every
    %% caller of `f:port/1` would keep reporting a port nothing listens on.
    {ok, Acceptor} = i2p_tcp_acceptor:start_link(
        ListenSock, fun(Sock) -> start_session(Sock, Local) end
    ),
    MRef = erlang:monitor(process, Acceptor),
    proc_lib:init_ack({ok, self()}),
    control_loop(BoundPort, ListenIP, MRef, Acceptor).

%% No timeout clause, and the absence is the fix. There is nothing to poll for any
%% more — the accept moved to a process whose whole job is to block in it — so a
%% message here is answered as soon as it is read rather than at the end of a wait
%% that existed to make room for one connection per tick.
control_loop(BoundPort, ListenIP, MRef, Acceptor) ->
    receive
        {port, From, Ref} ->
            From ! {port, Ref, BoundPort},
            control_loop(BoundPort, ListenIP, MRef, Acceptor);
        {address, From, Ref} ->
            From ! {address, Ref, ListenIP},
            control_loop(BoundPort, ListenIP, MRef, Acceptor);
        {stop, From, Ref} ->
            %% Answered before exiting, and exiting closes the listening socket
            %% because this process owns it — which is what ends the acceptor's
            %% blocked `f:gen_tcp:accept/1` with `{error, closed}`. Established
            %% sessions are children of the same supervisor and are not touched by
            %% any of this.
            %%
            %% `{stopped, Ref}`, and **not** the `{stop, Ref, stopped}` that
            %% `m:i2p_ntcp2_listener` uses for the same question. The two listeners
            %% multiplex their control messages differently -- NTCP2 funnels all
            %% three through one `f:control/2` and so tags the reply with the
            %% question, while this module has a function per question and each
            %% matches its own shape -- and the two shapes are not interchangeable.
            From ! {stopped, Ref},
            exit(normal);
        {'DOWN', MRef, process, Acceptor, Reason} ->
            %% The socket is not accepting and nothing here can make it accept, so
            %% this process stops claiming that it is. The one way to get here
            %% while the listener is alive is an acceptor that crashed — an `emfile`
            %% on a busy node, which `m:i2p_tcp_acceptor` reports as
            %% `{accept_failed, _}` — and the supervisor then restarts the boot
            %% listener, which is the recovery a crash report asks for anyway.
            exit({acceptor_gone, Reason})
    end.

%%% %%%%% %%% What an accepted socket becomes %%%%% %%%

%% Start the session for one accepted socket, then hand the socket over.
%%
%% Called by `m:i2p_tcp_acceptor` in the acceptor process, which is the socket's
%% owner at this point and therefore the only process that can transfer it.
start_session(Sock, Local) ->
    Args = #{sock => Sock, local => Local},
    case i2p_sam_sup:start_session(i2p_sam_sup:session_child(Args)) of
        {ok, SessionPid} ->
            handover(Sock, SessionPid);
        {ok, SessionPid, _Extra} ->
            handover(Sock, SessionPid);
        {error, _Reason} ->
            %% The session limit, or a supervisor that would not start it. The
            %% client is already connected at the TCP level and there is nothing to
            %% tell it, so closing is the whole of the answer.
            %%
            %% **This is the resource the accept path can now be hit hardest on**,
            %% since accept is no longer rate-limited: a flood of inbound
            %% connections becomes a flood of session children until
            %% `max_sam_sessions` says no. That cap is the only thing bounding it,
            %% which is why it is enforced in `m:i2p_admission` rather than
            %% checked here — see #41D5PFF, where the same cap turned out never to
            %% have held.
            ok = gen_tcp:close(Sock)
    end.

%% **The handover, and the invariant it rests on.**
%%
%% The socket is `{active, false}` — set by `m:i2p_tcp_acceptor` on the accepted
%% socket, and again the value it inherited from this module's listen socket. So
%% between the `accept` and this transfer the peer can send as much as it likes and
%% not one byte is delivered anywhere, because a socket that cannot deliver cannot
%% deliver to the wrong owner.
%%
%% The transfer has to happen before the session reads, and it cannot happen from
%% inside the session: `m:i2p_sam_session:init/1` does not touch the socket, because
%% a process that does not own a socket cannot set options on it and would fail
%% before the handover had run. That is why the socket travels in the child spec
%% and the go-ahead arrives as a message, in this order:
%%
%%   1. `controlling_process/2` — the session is now the owner and the only process
%%      that can read or activate the socket;
%%   2. `{socket_ready, Sock}` — the session's own handler sets `{active, once}`,
%%      which is the first moment the peer can deliver a byte.
%%
%% A session that dies between the two closes the socket on its way out, and the
%% message is sent to a dead pid. Both are ordinary and neither leaves a socket
%% reading for anyone.
handover(Sock, SessionPid) ->
    ok = gen_tcp:controlling_process(Sock, SessionPid),
    SessionPid ! {socket_ready, Sock},
    ok.
