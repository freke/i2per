-module(i2per_tun_datapath_SUITE).

-moduledoc """
Privileged end-to-end TUN datapath case (epiq 091VYQC, item 2).

Skipped by default: opening `/dev/net/tun` needs CAP_NET_ADMIN. Enable with
`I2PER_TUN_PRIVILEGED=1` in the environment. Outside the smoke tier.
""".

-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([device_opens_and_drains/1]).

all() ->
    [device_opens_and_drains].

init_per_suite(Config) ->
    case os:getenv("I2PER_TUN_PRIVILEGED") of
        "1" ->
            Config;
        _ ->
            {skip, "set I2PER_TUN_PRIVILEGED=1 (needs CAP_NET_ADMIN)"}
    end.

end_per_suite(_Config) ->
    ok.

device_opens_and_drains(_Config) ->
    process_flag(trap_exit, true),
    case i2per_tun_dev:start_link() of
        {ok, Pid} ->
            true = is_pid(Pid),
            ok = gen_server:stop(Pid);
        {error, _Reason} ->
            receive {'EXIT', _, _} -> ok after 0 -> ok end,
            ct:fail("TUN device could not be opened")
    end,
    process_flag(trap_exit, false),
    ok.