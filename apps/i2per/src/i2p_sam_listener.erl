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
it arrives.

**So the bounds moved to the callers, which is where they belong.** A wait that a
process cannot reach is not a bound: before #YJ0DSAT the only bounded waits in this
listener were *inside* the loop that answered the questions, and the two questions a
caller asks most often -- what port are you on, where are you bound -- had a
`receive` with no timeout clause at all. Each exported function now bounds its own
wait, and `?CONTROL_TIMEOUT_MS` and `?STOP_TIMEOUT_MS` are the two figures. Neither
is a synchronisation: the control loop does nothing but answer, so both are
guarantees about a hung process and both are generous by orders of magnitude for
that reason. `f:stop/1` waits out the listener's own bound as well, because it asks
for a stronger answer -- see the shutdown section below.

## The two listeners answer the same question the same way

`m:i2p_ntcp2_listener` is the other caller of `m:i2p_tcp_acceptor`, and it owns a
listening socket and answers for it in exactly the terms set out here. #YJ0DSAT
asked whether the two should agree, and they do -- on all three functions and on
both sides of each bound:

- **a listener that answers** sends `{stopped, Ref}` or `{stop_failed, Ref}`, with
  no question tag, and the caller turns the second into
  `{accept_path_did_not_stop, Listener}`. #AAYXPQK is where this was settled;
- **a listener that cannot answer a control question** raises
  `{listener_unanswered, Listener, port}` or `{listener_unanswered, Listener,
  address}` -- an unknown port is a fact worth raising over rather than a value to
  invent;
- **a listener that cannot answer `f:stop/1` at all** is killed, and `ok` is
  returned, because a kill restores the invariant this function exists to protect:
  the listener owns the listening socket, so nothing accepts afterwards.

That last one is the only place the answer is reached by acting rather than by
asking, and both modules say so rather than leaving the pair to look like one
convention followed without thought.

## What `f:stop/1` promises, and what it takes to keep that promise

`f:stop/1` returns `ok` when **the accept path can no longer produce a session**,
which is a stronger statement than "this listener has been asked to stop" and a
stronger one than "the listening socket is closed". All three are different, and
the distinction is the whole of the shutdown contract between these two processes:

- **asked to stop** — a reply sent before the process does anything else. What
  this module used to send. A send does not wait for the sender to go on to exit,
  so the answer arrived while the socket was still open.
- **socket closed** — true the instant this process owns the last reference and
  lets go of it. It ends a *blocked* `f:gen_tcp:accept/1`, and it is not enough:
  an acceptor that has already returned a socket is inside `f:start_session/2`,
  a `f:supervisor:start_child/2` that a socket close does not reach.
- **accept path finished** — the acceptor is gone, so there is nothing left that
  can call `f:start_session/2`. This is what `f:stop/1` waits for, and it is
  reachable because the acceptor is already monitored.

So the answer is sent after the close and after the acceptor's `'DOWN'`, in that
order, and each step is commented where it is written — `f:shutdown/5` is the whole
of it. A caller that has been told the listener stopped cannot then be handed a
new SAM session, which is what the previous ordering allowed: a connection
already sitting in the kernel's accept queue could still be taken,
`f:start_session/2` could still run, and `max_sam_sessions` could still be hit —
after `f:stop/1` reported that nothing further would happen.

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

%% How long a caller of `f:port/1` or `f:address/1` waits for its answer. These are
%% exported functions whose caller has no other way to find out whether the listener
%% is there, so an unbounded receive is a caller that never comes back -- and the
%% listener being unreachable is ordinary, because a supervisor restart of the boot
%% listener is. Generous by orders of magnitude against what it is actually
%% measuring: the control loop does nothing but answer, so this is a guarantee about
%% a hung process, not a synchronisation.
%%
%% `f:stop/1` does **not** use this figure: it asks for a stronger answer, so it
%% waits out the listener's own bound as well -- see `?STOP_TIMEOUT_MS`.
-define(CONTROL_TIMEOUT_MS, 1000).

%% How long the listener waits for its acceptor to reach the end of its accept
%% loop once the listening socket is closed. The acceptor is blocked in
%% `f:gen_tcp:accept/1` while it waits for a connection, so closing the socket is
%% what ends it -- with one exception this bound is about, and it is the reason
%% the bound is here at all: the acceptor can be *inside* `f:start_session/2`,
%% which is a `f:supervisor:start_child/2`, and the socket close does not reach
%% that. Generous by orders of magnitude against what it measures, because it is
%% measuring a wedged process rather than a synchronisation.
-define(ACCEPTOR_EXIT_TIMEOUT_MS, 500).

%% How long `f:stop/1` waits for the listener's answer. **Larger than
%% `?ACCEPTOR_EXIT_TIMEOUT_MS` on purpose**: the listener's own bound decides the
%% ordinary case and answers before it, and a caller bound at the same figure
%% would sometimes fire first and report a stop that was about to succeed. This
%% one is the outer guarantee -- the *listener* is not answering at all, which is a
%% different condition and is treated as one by killing it rather than reporting it.
%% See the `after` clause in `f:stop/1`.
-define(STOP_TIMEOUT_MS, 2000).

-doc """
Start a SAM listener on the given port.

Input: `Opts` — a map with keys `port` (default 7656) and `local`
(`t:i2p_peer:local_keys/0`, required).
Output: `{ok, Pid}`.
""".
-spec listen(map()) -> {ok, pid()}.
listen(#{local := _Local} = Opts) ->
    supervisor:start_child(i2p_sam_sup, i2p_sam_sup:listener_child(Opts)).

-doc """
The bound local port of the listener.

Raises `{listener_unanswered, Listener, port}` if the listener cannot answer within
`?CONTROL_TIMEOUT_MS`, or is already gone. See the module doc on the two listeners
answering the same question the same way.
""".
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

Input: a listener pid. Output: the bound IP address.

Raises `{listener_unanswered, Listener, address}` on the same terms as `f:port/1`.
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
Stop accepting new connections; existing sessions are unaffected.

Returns `ok` once the accept path **cannot produce another session**, which is a
stronger statement than "the listening socket has been closed" and is what this
function waits for. See the shutdown section of the module doc.

**One failure is raised, and it is the condition that matters:**
`{accept_path_did_not_stop, Listener}` — the listener answered, and its answer was
that it could not confirm. Its acceptor would not finish, so it is still possible
for a queued connection to become a session.
`m:i2p_ntcp2_listener:stop/1` raises the same shape for the same reason.

**The other way of not answering is reported rather than raised, and that is the
asymmetry worth naming.** A listener that says *nothing at all* within
`?STOP_TIMEOUT_MS` is not answering at all, so there is no claim of it to contradict
— and killing it restores the invariant rather than leaving it broken, because it
owns the listening socket. Raising there would report a fault and leave the fault in
place: the port would go on accepting after this function had told its caller that
nothing further would happen, and the caller would have no way to make that true
except by killing the listener itself. So a silent listener is killed and `ok` is
returned. `m:i2p_ntcp2_listener:stop/1` makes the same trade for the same reason, and
for the same reason this is the only answer on either side that is reached by acting
rather than by asking.

That kill is a *sufficient* stop rather than merely a plausible one, and it is worth
being exact about why, because the socket close alone is not the whole of it: the
listener's death closes the listening socket, which ends a blocked
`f:gen_tcp:accept/1`; and the acceptor is **linked** to the listener, so it does not
merely find its accept failing — it is killed outright, which also covers the one
case a socket close cannot reach, an acceptor already inside `f:start_session/2`.

`ok` is also the right answer for a listener that is **already dead**, immediately,
by monitor rather than by waiting, and for the reason the kill gives: the listening
socket died with it and its acceptor was killed with it. This is also why the
listener always answers — a reply that can go missing cannot be told apart from a
listener that was never there.
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
        %% The listener is alive and has said nothing for longer than its own
        %% shutdown bound plus this one, so it is not going to. `catch` because it
        %% may have died in the same instant the bound expired -- which is the same
        %% condition reached two ways, and one answer for both is the point.
        erlang:demonitor(MRef, [flush]),
        _ = catch exit(Listener, kill),
        ok
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
    control_loop(BoundPort, ListenIP, ListenSock, MRef, Acceptor).

%% No timeout clause, and the absence is the fix. There is nothing to poll for any
%% more — the accept moved to a process whose whole job is to block in it — so a
%% message here is answered as soon as it is read rather than at the end of a wait
%% that existed to make room for one connection per tick.
control_loop(BoundPort, ListenIP, ListenSock, MRef, Acceptor) ->
    receive
        {port, From, Ref} ->
            From ! {port, Ref, BoundPort},
            control_loop(BoundPort, ListenIP, ListenSock, MRef, Acceptor);
        {address, From, Ref} ->
            From ! {address, Ref, ListenIP},
            control_loop(BoundPort, ListenIP, ListenSock, MRef, Acceptor);
        {stop, From, Ref} ->
            %% See `f:shutdown/5` for why the answer is not sent from here.
            shutdown(ListenSock, Acceptor, MRef, From, Ref);
        {'DOWN', MRef, process, Acceptor, Reason} ->
            %% The socket is not accepting and nothing here can make it accept, so
            %% this process stops claiming that it is. The one way to get here
            %% while the listener is alive is an acceptor that crashed — an `emfile`
            %% on a busy node, which `m:i2p_tcp_acceptor` reports as
            %% `{accept_failed, _}` — and the supervisor then restarts the boot
            %% listener, which is the recovery a crash report asks for anyway.
            exit({acceptor_gone, Reason})
    end.

%% %%%%%%% %%% Asking, and not answering %%%%%%% %%%

%% Ask the listener one of the two questions it answers from a value it already
%% holds, and wait, bounded, for the answer.
%%
%% Placed next to the loop it questions rather than next to its two callers,
%% because the pairing is the point: every clause in the receive above has exactly
%% one counterpart here, and reading them together is how a question tag, an answer
%% tag or a bound going missing becomes visible.
%%
%% Output `{ok, Answer}` with whatever the listener sent back, or `no_answer` if the
%% bound passed with neither an answer nor a `'DOWN'`. The monitor is what makes a
%% listener that is already dead a fast answer rather than a full second of waiting
%% for a reply that was never coming; `[flush]` is what keeps a listener that
%% answered and then died from leaking a `'DOWN'` into the caller.
%%
%% `f:stop/1` does not come through here: it needs a second answer, and a question
%% this generic cannot tell apart from an answer to a question it is not asking.
%% See `f:shutdown/5`.
%%
%% Both callers of what is left raise over a missing answer, because an unknown port
%% is a bug worth raising over rather than a value to invent.
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
%%    still sitting in the kernel's accept queue, about to be taken.
%%
%% 2. **Waiting for the acceptor at all.** Closing the socket ends a *blocked*
%%    `f:gen_tcp:accept/1` — that is what `{error, closed}` means. It does not
%%    reach an acceptor that has already returned a socket and is inside
%%    `f:start_session/2`, which is a `f:supervisor:start_child/2`. Until that
%%    returns, one more session can still appear, so answering before it does is
%%    the same lie one step further in. The acceptor is already monitored, so
%%    waiting for its `'DOWN'` needs no new mechanism: `m:i2p_tcp_acceptor` exits
%%    `normal` on `{error, closed}` whether it was blocked or mid-handler, and a
%%    crash is a `'DOWN'` too, so this receive cannot miss its exit.
%%
%% 3. **The bounded wait, and the answer on both sides of it.** Per #YJ0DSAT, an
%%    exported function's wait is bounded rather than open. This one is new with
%%    the guarantee above, and an unbounded version would be a hang this change
%%    *introduces* rather than one it fixed: before it, `f:stop/1` returned the
%%    moment it was asked.
%%
%%    **Both bounds answer, and that is not belt-and-braces — it is what makes
%%    the answers mean anything.** This loop's own bound sends `{stop_failed,
%%    Ref}`, and `f:stop/1` reports that as
%%    `{accept_path_did_not_stop, _}`. If this loop gave up silently instead, the
%%    caller's monitor would see *this process* exit with no reply and would have
%%    to decide whether a listener that never answered is a listener that was
%%    already gone — and `ok` is the wrong answer to that question, because the
%%    socket closed on the way out while the acceptor it was waiting for did not.
%%    A reply that can go missing cannot be told apart from a listener that was
%%    never there, so the reply is unconditional and the caller's monitor branch
%%    is left meaning exactly one thing.
%%
%%    `{stopped, Ref}` and *not* the `{stop, Ref, stopped}` that
%%    `m:i2p_ntcp2_listener` used to send for the same question. The question tag
%%    was there because all three control messages shared one `f:control/2`; that
%%    listener now keeps its own receive too, so the two answer the same question
%%    with the same shape. #YJ0DSAT asked whether they should be unified, and
%%    #AAYXPQK is where the outcome protocol was: one shape, two tags, no question
%%    tag. The *timeout* answers were the other half of that question, and they
%%    came together with `f:control/2` below -- both listeners now kill a silent
%%    listener and answer `ok`, which is the module doc's third bullet.
%%
%% Established sessions are children of the same supervisor and are not touched by
%% any of this.
-spec shutdown(gen_tcp:socket(), pid(), reference(), pid(), reference()) -> no_return().
shutdown(ListenSock, Acceptor, MRef, From, Ref) ->
    %% Announced *before* the close, and that is the point of the order rather
    %% than an incidental detail: closing the socket under the acceptor's
    %% outstanding `f:gen_tcp:accept/1` makes the driver answer `{error, einval}`
    %% rather than `{error, closed}`. The announcement is what lets
    %% `m:i2p_tcp_acceptor` recognise this as the ordinary end instead of
    %% exiting `{accept_failed, einval}` -- a crash report on every listener
    %% shutdown, which is what the first version of this fix did.
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
