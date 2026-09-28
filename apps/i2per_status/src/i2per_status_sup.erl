-module(i2per_status_sup).

-moduledoc """
Supervisor of the `i2per_status` web service.

Owns the snapshot server (`m:i2per_status_state`) and the HTTP listener
(`m:i2per_status_listener`), in that order: the listener accepts requests that
immediately ask the snapshot server for data, so it starts second and is not
serving before there is anything to serve.

Both are real children. The listener used to be started from `f:init/1` with
`ok = start_listener()` before any child spec was returned, which linked it to
this supervisor without registering it as a child — so a listener that died
stayed dead while the supervisor reported healthy. Application stop still takes
the HTTP endpoint down with the tree, which was the only thing that arrangement
bought.
""".

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-doc "Start the supervisor. Called only by `m:i2per_status_app`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% A single child crashing takes down the service, so the intensity window is
%% tight: a listener that cannot bind, or a snapshot server that cannot reach its
%% router, should surface as a failed start rather than as a restart loop that
%% looks healthy from outside.
init([]) ->
    {ok,
        {#{strategy => one_for_one, intensity => 5, period => 10}, [
            #{
                id => i2per_status_state,
                start => {i2per_status_state, start_link, []},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2per_status_state]
            },
            #{
                id => i2per_status_listener,
                start => {i2per_status_listener, start_link, []},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2per_status_listener]
            }
        ]}}.
