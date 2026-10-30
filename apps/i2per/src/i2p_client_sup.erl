-module(i2p_client_sup).

-moduledoc """
Per-domain supervisor for the client-facing group.

`one_for_one`: SAM supervisor, addressbook, subscriptions, addressbook publish.
""".

-behaviour(supervisor).

-export([start_link/0, start_link/1, init/1]).

start_link() -> start_link([]).
start_link(Children) -> supervisor:start_link({local, ?MODULE}, ?MODULE, Children).

init(Children) ->
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, Children}}.
