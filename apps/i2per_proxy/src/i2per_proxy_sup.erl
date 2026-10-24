-module(i2per_proxy_sup).

-moduledoc """
Supervisor of the `i2per_proxy` service.

Owns one listener per protocol (HTTP and SOCKS). A listener that cannot bind
surfaces as a failed start rather than a restart loop.
""".

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-doc "Start the supervisor. Called only by `m:i2per_proxy_app`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok,
        {#{strategy => one_for_one, intensity => 5, period => 10}, [
            #{
                id => i2per_proxy_http_listener,
                start => {i2per_proxy_listener, start_link, [#{protocol => http}]},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2per_proxy_listener]
            },
            #{
                id => i2per_proxy_socks_listener,
                start => {i2per_proxy_listener, start_link, [#{protocol => socks}]},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2per_proxy_listener]
            }
        ]}}.
