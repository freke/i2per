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

## What `f:stop/1` promises, and what it takes to keep that promise

`f:stop/1` returns `ok` when **the accept path can no longer produce a
connection**, which is a stronger statement than "this listener has been asked to
stop" and a stronger one than "the listening socket is closed". All three are
different, and the distinction is the whole of the shutdown contract between these
two processes:

- **asked to stop** — a reply sent before the process does anything else. What
  this module used to send. A send does not wait for the sender to go on to exit,
  so the answer arrived while the socket was still open.
- **socket closed** — true the instant this process owns the last reference and
  lets go of it. It ends a *blocked* `f:gen_tcp:accept/1`, and it is not enough:
  an acceptor that has already returned a socket is inside `f:start_bob/3`, a
  `f:supervisor:start_child/2` that a socket close does not reach.
- **accept path finished** — the acceptor is gone, so there is nothing left that
  can call `f:start_bob/3`. This is what `f:stop/1` waits for, and it is
  reachable because the acceptor is already monitored.

So the answer is sent after the close and after the acceptor's `'DOWN'`, in that
order, and each step is commented where it is written — `f:shutdown/5` is the
whole of it. A caller that has been told the listener stopped cannot then be
handed a new connection, which is what the previous ordering allowed: a
connection already sitting in the kernel's accept queue could still be taken, and
`f:start_bob/3` could still run — after `f:stop/1` reported that nothing further
would happen.

**What that costs here, and not only on SAM.** `m:i2p_sam_listener`'s equivalent
handed out a session, which can then hit `max_sam_sessions`. `f:start_bob/3`
starts a responder that **dials out to a peer**, so the post-answer work on this
path is not a session appearing: it is an outbound connection attempt to a remote
router, started after the local listener reported it had stopped. #9Q6Q43Q built
the mechanism on the SAM side and `m:i2p_tcp_acceptor` already understands the
announcement it needs; this is the same three steps applied to the other caller.

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

%% How long a caller of `f:port/1` or `f:address/1` waits for its answer. These
%% are exported functions whose caller has no other way to find out whether the
%% listener is there, so an unbounded receive is a caller that never comes back —
%% the same class of wait `m:i2p_ntcp2_conn:stop/1` bounds, found in the same
%% module family. Generous by orders of magnitude against what it is actually
%% measuring: the listener does nothing but answer, so this is a guarantee about a
%% hung process, not a synchronisation.
%%
%% `f:stop/1` does **not** use this figure: it asks for a stronger answer, so it
%% waits out the listener's own bound as well — see `?STOP_TIMEOUT_MS`.
-define(CONTROL_TIMEOUT_MS, 1000).

%% How long the listener waits for its acceptor to reach the end of its accept
%% loop once the listening socket is closed. The acceptor is blocked in
%% `f:gen_tcp:accept/1` while it waits for a connection, so closing the socket is
%% what ends it -- with one exception this bound is about, and it is the reason
%% the bound is here at all: the acceptor can be *inside* `f:start_bob/3`, which
%% is a `f:supervisor:start_child/2` that starts a responder, and the socket close
%% does not reach that. Generous by orders of magnitude against what it measures,
%% because it is measuring a wedged process rather than a synchronisation.
-define(ACCEPTOR_EXIT_TIMEOUT_MS, 500).

%% How long `f:stop/1` waits for the listener's answer. **Larger than
%% `?ACCEPTOR_EXIT_TIMEOUT_MS` on purpose**: the listener's own bound decides the
%% ordinary case and answers before it, and a caller bound at the same figure
%% would sometimes fire first and report a stop that was about to succeed. This
%% one is the outer guarantee -- the *listener* is not answering at all, which is a
%% different condition and is reported as one.
-define(STOP_TIMEOUT_MS, 2000).

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

Returns `ok` once the accept path **cannot produce another connection**, which is
a stronger statement than "the listening socket has been closed" and is what this
function waits for. See the shutdown section of the module doc.

**One failure is raised, and it is the condition that matters:**
`{accept_path_did_not_stop, Listener}` — the listener answered, and its answer was
that it could not confirm. Its acceptor would not finish, so a connection the
acceptor had already taken can still become a responder. `m:i2p_sam_listener` raises
the same shape for the same reason: #YJ0DSAT asks whether the two listeners should
answer the same question the same way, and they now do.

**The other way of not answering is reported rather than raised**, and the
asymmetry is the point. A listener that says *nothing at all* within
`?STOP_TIMEOUT_MS` is not answering at all, so there is no claim of it to
contradict — and killing it restores the invariant rather than leaving it broken,
because it owns the listening socket: a live listener that has stopped answering is
a port that keeps accepting after this function reported that it stopped, and a
listener that cannot answer a stop request cannot be reasoned about as anything
else. The same trade `f:i2p_ntcp2_conn:stop/1` makes, and for the same reason — an
exported function's wait is bounded rather than open.

A listener that is **already dead** answers `ok`, immediately, by monitor rather
than by waiting: the listening socket is owned by that process, so its death
closed the socket and its acceptor's `f:gen_tcp:accept/1` could accept nothing
more. This is also why the listener always answers — a reply that can go missing
cannot be told apart from a listener that was never there.
""".
-spec stop(pid()) -> ok.
stop(Listener) ->
    Ref = make_ref(),
    MRef = erlang:monitor(process, Listener),
    Listener ! {stop, self(), Ref},
    receive
        {stopped, Ref} ->
            erlang:demonitor(MRef, [flush]),
            ok;
        {stop_failed, Ref} ->
            erlang:demonitor(MRef, [flush]),
            erlang:error({accept_path_did_not_stop, Listener});
        {'DOWN', MRef, process, Listener, _Reason} ->
            %% The socket died with the listener, which is the whole of what a
            %% close is. Not a timeout, so not an error: nothing can be accepted.
            ok
    after ?STOP_TIMEOUT_MS ->
        erlang:demonitor(MRef, [flush]),
        _ = catch exit(Listener, kill),
        ok
    end.

%% Ask the listener one of the two questions it answers from a value it already
%% holds, and wait, bounded, for the answer.
%%
%% Output `{ok, Answer}` with whatever the listener sent back, or `no_answer` if
%% the bound passed with neither an answer nor a `'DOWN'`. The monitor is what
%% makes a listener that is already dead a fast answer rather than a full second
%% of waiting for a reply that was never coming; `[flush]` is what keeps a
%% listener that answered and then died from leaking a `'DOWN'` into the caller.
%%
%% `f:stop/1` does not come through here: it needs a second answer, and a question
%% this generic cannot tell apart from an answer to a question it is not asking.
%% See `f:shutdown/5`.
%%
%% Both callers of what is left raise over a missing answer, because an unknown
%% port is a bug worth raising over rather than a value to invent.
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
            %% See `f:shutdown/5` for why the answer is not sent from here.
            shutdown(ListenSock, Acceptor, MRef, From, Ref);
        {'DOWN', MRef, process, Acceptor, Reason} ->
            %% The socket is not accepting and nothing here can make it accept, so
            %% this process stops claiming that it is. The one way to get here
            %% while the listener is alive is an acceptor that crashed; the
            %% supervisor then restarts the boot listener, which is the recovery
            %% that a crash report asks for anyway.
            exit({acceptor_gone, Reason})
    end.

%% %%%%%%% %%% Stopping, and what the answer means %%%%%%% %%%

%% **The close comes first, and the answer comes last, and the acceptor is waited
%% for in between.** Those are three separate facts and the order is the whole
%% guarantee, so it is worth saying what each one is for.
%%
%% 1. **`f:gen_tcp:close/1` before the answer.** The listening socket is owned by
%%    this process, so it would close when this process exits — but that is
%%    *after* a message sent from here has already been delivered, and a send does
%%    not wait for the sender to go on to exit. Answering first and exiting
%%    second is how a caller learns the listener stopped while a connection is
%%    still sitting in the kernel's accept queue, about to be taken by an acceptor
%%    that is about to call `f:start_bob/3`.
%%
%% 2. **Waiting for the acceptor at all.** Closing the socket ends a *blocked*
%%    `f:gen_tcp:accept/1` — that is what `{error, closed}` means. It does not
%%    reach an acceptor that has already returned a socket and is inside
%%    `f:start_bob/3`, which is a `f:supervisor:start_child/2` that **dials out to
%%    a peer**. Until that returns, one more outbound connection attempt can still
%%    appear, so answering before it does is the same lie one step further in. The
%%    acceptor is already monitored, so waiting for its `'DOWN'` needs no new
%%    mechanism: `m:i2p_tcp_acceptor` exits `normal` on the announced close whether
%%    it was blocked or mid-handler, and a crash is a `'DOWN'` too, so this receive
%%    cannot miss its exit.
%%
%% 3. **The bounded wait, and the answer on both sides of it.** An exported
%%    function's wait is bounded rather than open, and this one is new with the
%%    guarantee above: an unbounded version would be a hang this change
%%    *introduces* rather than one it fixed, because before it `f:stop/1` returned
%%    the moment it was asked.
%%
%%    **Both bounds answer, and that is not belt-and-braces — it is what makes
%%    the answers mean anything.** This function's own bound sends
%%    `{stop_failed, Ref}`, and `f:stop/1` reports that as
%%    `{accept_path_did_not_stop, _}`. If it gave up silently instead, the caller's
%%    monitor would see *this process* exit with no reply and would have to decide
%%    whether a listener that never answered is a listener that was already gone —
%%    and `ok` is the wrong answer to that question, because the socket closed on
%%    the way out while the acceptor it was waiting for did not. A reply that can go
%%    missing cannot be told apart from a listener that was never there, so the
%%    reply is unconditional and the caller's monitor branch is left meaning
%%    exactly one thing.
%%
%%    `{stopped, Ref}` and *not* the `{stop, Ref, stopped}` this module used to
%%    send. The question tag was there because all three control messages shared
%%    one `f:control/2`; `f:stop/1` now keeps its own receive, because a two-outcome
%%    protocol does not fit a helper that matches its answer by question, and
%%    dropping the tag is what makes this byte for byte the shape
%%    `m:i2p_sam_listener` already answers the same question with. #YJ0DSAT asks
%%    whether they should be unified; this is the answer for this half of it.
%%
%% Established connections are children of the same supervisor and are not touched
%% by any of this.
-spec shutdown(gen_tcp:socket(), pid(), reference(), pid(), reference()) -> no_return().
shutdown(ListenSock, Acceptor, MRef, From, Ref) ->
    %% Announced *before* the close, and that is the point of the order rather
    %% than an incidental detail: closing the socket under the acceptor's
    %% outstanding `f:gen_tcp:accept/1` makes the driver answer `{error, einval}`
    %% rather than `{error, closed}`. The announcement is what lets
    %% `m:i2p_tcp_acceptor` recognise this as the ordinary end instead of exiting
    %% `{accept_failed, einval}` — a crash report on every listener shutdown, and
    %% this listener's `{acceptor_gone, _}` exit on top of it.
    Acceptor ! {stopping, self()},
    ok = gen_tcp:close(ListenSock),
    receive
        {'DOWN', MRef, process, _Acceptor, _Reason} ->
            From ! {stopped, Ref}
    after ?ACCEPTOR_EXIT_TIMEOUT_MS ->
        From ! {stop_failed, Ref}
    end,
    exit(normal).

%%% %%%%% %%% What an accepted socket becomes %%%%% %%%

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
