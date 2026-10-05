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
""".

-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2, terminate/2, code_change/3]).

-doc """
Attach the forwarder.

Input: `[CollectorPid]`. Output: `{ok, CollectorPid}`; every later bus event
is sent to `CollectorPid`.
""".
-spec init([pid(), ...]) -> {ok, pid()}.
init([Pid]) when is_pid(Pid) ->
    {ok, Pid}.

handle_event(Event, Pid) ->
    Pid ! {event, Event},
    {ok, Pid}.

handle_call(_Query, State) ->
    {ok, ok, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Arg, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
