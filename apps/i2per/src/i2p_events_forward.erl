-module(i2p_events_forward).

-moduledoc """
Generic event-bus forwarder for remote subscribers.

`m:i2p_events` handlers run on the MANAGER's node, so a subscriber on another
Erlang node cannot install its own handler module there without shipping code.
This module ships WITH the router and solves it generically: it forwards every
bus event as `{event, Event}` messages to any pid.

## Usage

Subscribers do not call this module, or `gen_event`, at all: they call
`m:i2p_events:subscribe/1`, which attaches this forwarder on their behalf. It
stays exported because that entry point names it, and because it is the only way
to reach a collector on another node without shipping code to the router.

```erlang
%% from any connected node:
ok = erpc:call(RouterNode, i2p_events, subscribe, [self()], 5000).
receive {event, E} -> ... end
```

## A forwarder whose collector has died takes itself off

**Sending to a dead pid is not an error**, so nothing here used to raise when a
collector died: `f:handle_event/2` returned `{ok, State}` and the bus went on
calling a pid that would never read another event. `gen_event` removes a handler
in exactly three cases -- `delete_handler`, a stop, and the handler raising -- and
none of them fired, so **one forwarder accumulated per subscriber restart and
never came off** (#DN82Z7J). Every event was then dispatched to all of them, so
the cost was on the bus and not merely in memory: measured 8,951 us for 20,000
announcements with one dead forwarder attached, linear in the dead count.

The manager now watches the collector and this handler removes itself.

**The `'DOWN'` really does arrive here, and that is not obvious.** A monitor
created inside `f:init/1` is owned by the *manager*, so its `'DOWN'` lands in the
manager's mailbox -- where \`gen_event:fetch_msg/6\`'s **catch-all** receive
(\`gen_event.erl:1619\`) picks it up and \`gen_event:handle_msg/3\` hands to **every**
handler's `handle_info/2` (\`gen_event.erl:1690-1692\`). So the message is not
dropped and does not accumulate in a mailbox: it is routed to this handler, which
matches it against the monitor it owns and ignores every other handler's.

**Returning \`remove_handler\` is \`gen_event\`'s own documented self-removal**
(\`server_update/4\`, \`gen_event.erl:1932\`), and it is the *silent* path: the removal
passes \`normal\` as its reason, which \`report_error/5\` drops
(\`report_error(_Handler, normal, _, _, _) -> ok\`). Nothing is logged for a
subscriber that stops existing, which is what makes this the right shape -- an
ordinary end of life, not a crash.

**Measured, on this build at OTP 28.5 / ERTS 16.4.0.6**, against a real manager:

| what died | before | after |
|---|---|---|
| a local collector | handler stays attached | gone; bus still answers \`notify\` |
| five attach-and-die cycles | 6 handlers left | **0** |
| a remote collector's process | handler stays attached | gone |
| **the whole far node, stopped** | handler stays attached | gone; \`notify\` still \`ok\` |

The last row is the deployment that leaks in production: `m:i2per_status_state`
runs on its own node and never unsubscribes.

**This runs inside the manager, which is the whole point.** Every other way of
reaping -- \`gen_event:delete_handler/3\` from a watcher process, or from the
subsampler -- is an rpc with no timeout (\`gen_event.erl:1576\`), so it stops working
precisely when the bus is wedged, which is when the pile-up matters. Removing the
handler from here needs no rpc and cannot be blocked by one.
""".

-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2, terminate/2, code_change/3]).

-export_type([state/0]).

-doc """
The forwarder's state: the collector it carries to, and the monitor on it.
""".
-type state() :: {pid(), reference()}.

-doc """
Attach the forwarder, and start watching the collector.

Input: `[CollectorPid]`. Output: `{ok, {CollectorPid, MRef}}`; every later bus
event is sent to `CollectorPid`, and the handler takes itself off when that pid
is gone.

**The monitor is created here rather than by the caller because the caller is
not the process that has to be told.** `f:init/1` runs *inside* the manager, so
the monitor it creates is owned by the manager, and \`'DOWN'\` therefore arrives
where \`f:handle_info/2\` can be handed it -- see the module note.

**Monitoring an already-dead pid is not a special case to guard.** The monitor is
installed, the \`'DOWN'\` is delivered at once, and the handler removes itself on
the next message the manager handles. A subscription to a collector that died
between the call and the attach is therefore a subscription that exists for
microseconds, which is the correct answer; the alternative would be to refuse it
at \`add_handler\` time and have to decide what a refusal means.
""".
-spec init([pid(), ...]) -> {ok, state()}.
init([Pid]) when is_pid(Pid) ->
    {ok, {Pid, erlang:monitor(process, Pid)}}.

-doc """
Carry one bus event to the collector.

Input: the event and a `t:state/0`. Output: `{ok, State}`, unchanged -- the
monitor is the same one, so it survives being carried here.
""".
-spec handle_event(term(), state()) -> {ok, state()}.
handle_event(Event, State = {Pid, _MRef}) ->
    Pid ! {event, Event},
    {ok, State}.

handle_call(_Query, State) ->
    {ok, ok, State}.

-doc """
Take the handler off the bus when the collector it carries to is gone.

Input: a message the manager could not account for, and a `t:state/0`. Output:
\`remove_handler\` for our own collector's \`'DOWN'\`, which is `gen_event`'s
self-removal, and `{ok, State}` for everything else.

**Every unrecognised message reaches here**, including the \`'DOWN'\` of every
*other* forwarder's collector, because \`gen_event\` hands the same message to every
handler. Matching on both the monitor and the pid is what keeps one forwarder from
tearing itself off on another's death.
""".
-spec handle_info(term(), state()) -> remove_handler | {ok, state()}.
handle_info({'DOWN', MRef, process, Pid, _Reason}, {Pid, MRef}) ->
    remove_handler;
handle_info(_Info, State) ->
    {ok, State}.

-doc """
The handler is going away, for whatever reason.

Input: \`gen_event\`'s argument and the `t:state/0`. Output: \`ok\`, always.

**The monitor is not demonitored here.** It is owned by the manager, which is
where it is already gone: \`terminate/2\` only runs while the manager is alive to
run it, and a monitor dies with the process that owns it. There is nothing here
to release.

**Nothing is recorded from here either**, deliberately. The bus's subscriber
registry is written where the handler is added and removed, and this is a third
removal path; \`m:i2p_events\`'s subsampler takes that half, because it owns the
table and a core forwarder reaching back into the bus's bookkeeping for it is
the coupling that module argues against.
""".
-spec terminate(term(), state()) -> ok.
terminate(_Arg, {_Pid, MRef}) ->
    erlang:demonitor(MRef, [flush]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
