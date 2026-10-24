-module(i2per_tun_sup).

-moduledoc """
Supervisor of the `i2per_tun` fd spike: one child, the TUN device owner.

The intensity window is tight for the same reason `i2per_status`'s is: an
owner that cannot open its device should surface as a failed start, not as a
restart loop that looks healthy from outside.
""".

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-doc "Start the supervisor. Called only by `m:i2per_tun_app`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok,
        {#{strategy => one_for_one, intensity => 5, period => 10}, [
            #{
                id => i2per_tun_dev,
                start => {i2per_tun_dev, start_link, []},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2per_tun_dev]
            },
            #{
                id => i2per_tun_listener,
                start => {i2per_tun_listener, start_link, []},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2per_tun_listener]
            }
        ]}}.
