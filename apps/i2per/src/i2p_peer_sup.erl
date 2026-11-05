-module(i2p_peer_sup).

-moduledoc """
Per-domain supervisor for the peer group.

`rest_for_one`: peer reputation -> peer manager -> lookup service.
""".

-behaviour(supervisor).

-export([start_link/0, start_link/1, init/1]).

start_link() -> start_link([]).
start_link(Children) -> supervisor:start_link({local, ?MODULE}, ?MODULE, Children).

init(Children) ->
    {ok, {#{strategy => rest_for_one, intensity => 10, period => 10}, Children}}.
