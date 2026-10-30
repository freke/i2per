-module(i2p_transport_sup).

-moduledoc """
Per-domain supervisor for the transport group.

`one_for_one`: NTCP2 and SSU2 supervisors.
""".

-behaviour(supervisor).

-export([start_link/0, start_link/1, init/1]).

start_link() -> start_link([]).
start_link(Children) -> supervisor:start_link({local, ?MODULE}, ?MODULE, Children).

init(Children) ->
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, Children}}.
