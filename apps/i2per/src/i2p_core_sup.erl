-module(i2p_core_sup).

-moduledoc """
Per-domain supervisor for the core infrastructure group.

Holds the counter home, event bus, runtime configuration service, peer
reputation store and SSU2 reachability decision. `one_for_one`: a crash in
one of these restarts only that process.
""".

-behaviour(supervisor).

-export([start_link/0, start_link/1, init/1]).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

-spec start_link([supervisor:child_spec()]) -> {ok, pid()} | {error, term()}.
start_link(Children) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, Children).

init(Children) ->
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, Children}}.
