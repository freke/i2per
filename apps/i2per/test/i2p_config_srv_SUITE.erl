%% Server-driven configuration tests. Each case boots the `i2per` application,
%% drives `i2p_config_srv:get/get_all/set`, checks hot versus restart-required
%% keys, and verifies strict rejection of unknown or malformed values. The
%% event collector is installed and removed with the case.

-module(i2p_config_srv_SUITE).

-export([all/0, suite/0, init_per_testcase/2, end_per_testcase/2]).

-export([
    get_returns_env_value/1,
    get_unknown_key_error/1,
    get_all_covers_known_set_keys/1,
    hot_set_applies_and_announces/1,
    restart_required_set_not_applied/1,
    rate_limit_keys_set_hot/1,
    rate_limit_bad_values_rejected/1,
    invalid_value_rejected/1,
    sam_port_is_known_restart_required/1,
    unknown_key_rejected/1,
    non_integer_key_rejected/1
]).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        get_returns_env_value,
        get_unknown_key_error,
        get_all_covers_known_set_keys,
        hot_set_applies_and_announces,
        restart_required_set_not_applied,
        rate_limit_keys_set_hot,
        rate_limit_bad_values_rejected,
        invalid_value_rejected,
        sam_port_is_known_restart_required,
        unknown_key_rejected,
        non_integer_key_rejected
    ].

init_per_testcase(_Case, Config) ->
    {ok, _} = application:ensure_all_started(i2per),
    ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
    Config.

end_per_testcase(_Case, _Config) ->
    gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
    %% Do not leak the app (and its i2p_netdb_srv/peer owners) to later suites.
    _ = application:stop(i2per),
    ok.

get_returns_env_value(_Config) ->
    application:set_env(i2per, transit_max_tunnels, 77),
    {ok, 77} = i2p_config_srv:get(transit_max_tunnels),
    application:unset_env(i2per, transit_max_tunnels).

get_unknown_key_error(_Config) ->
    error = i2p_config_srv:get(no_such_key).

get_all_covers_known_set_keys(_Config) ->
    Old = application:get_env(i2per, transit_max_tunnels),
    application:set_env(i2per, transit_max_tunnels, 33),
    try
        All = i2p_config_srv:get_all(),
        33 = maps:get(transit_max_tunnels, All)
    after
        restore(transit_max_tunnels, Old)
    end.

hot_set_applies_and_announces(_Config) ->
    Old = application:get_env(i2per, transit_max_tunnels),
    try
        ok = i2p_config_srv:set(transit_max_tunnels, 4242),
        {ok, 4242} = i2p_config_srv:get(transit_max_tunnels),
        {config_changed, transit_max_tunnels, 4242} = collect_config_changed()
    after
        restore(transit_max_tunnels, Old)
    end.

restart_required_set_not_applied(_Config) ->
    Old = application:get_env(i2per, host),
    try
        {ok, pending_restart} = i2p_config_srv:set(host, <<"10.1.2.3">>),
        Old = application:get_env(i2per, host),
        {config_changed, host, <<"10.1.2.3">>} = collect_config_changed()
    after
        restore(host, Old)
    end.

rate_limit_keys_set_hot(_Config) ->
    Olds = [
        {K, application:get_env(i2per, K)}
     || K <- [transit_bandwidth_kbps, tunnel_build_rate]
    ],
    try
        ok = i2p_config_srv:set(transit_bandwidth_kbps, 512),
        {ok, 512} = i2p_config_srv:get(transit_bandwidth_kbps),
        {config_changed, transit_bandwidth_kbps, 512} = collect_config_changed(),
        ok = i2p_config_srv:set(tunnel_build_rate, 2),
        {ok, 2} = i2p_config_srv:get(tunnel_build_rate),
        {config_changed, tunnel_build_rate, 2} = collect_config_changed()
    after
        lists:foreach(fun restore_env/1, Olds)
    end.

rate_limit_bad_values_rejected(_Config) ->
    Old = application:get_env(i2per, transit_bandwidth_kbps),
    try
        %% 0 is the documented off switch (see `i2p_config_srv:valid_values_test/0`),
        %% so the rejected forms are negative rates and non-integers.
        {error, {bad_value, transit_bandwidth_kbps, _}} =
            i2p_config_srv:set(transit_bandwidth_kbps, -1),
        {error, {bad_value, tunnel_build_rate, _}} = i2p_config_srv:set(tunnel_build_rate, -1),
        {error, {bad_value, transit_bandwidth_kbps, _}} =
            i2p_config_srv:set(transit_bandwidth_kbps, <<"fast">>),
        Old = application:get_env(i2per, transit_bandwidth_kbps)
    after
        restore(transit_bandwidth_kbps, Old)
    end.

invalid_value_rejected(_Config) ->
    Old = application:get_env(i2per, port),
    try
        {error, {bad_value, port, _}} = i2p_config_srv:set(port, 70000),
        Old = application:get_env(i2per, port)
    after
        restore(port, Old)
    end.

sam_port_is_known_restart_required(_Config) ->
    Old = application:get_env(i2per, sam_port),
    try
        {ok, pending_restart} = i2p_config_srv:set(sam_port, 7657),
        Old = application:get_env(i2per, sam_port),
        {config_changed, sam_port, 7657} = collect_config_changed()
    after
        restore(sam_port, Old)
    end.

unknown_key_rejected(_Config) ->
    {error, {unknown_key, _}} = i2p_config_srv:set(bogus_knob, 1).

non_integer_key_rejected(_Config) ->
    {error, {unknown_key, _}} = i2p_config_srv:set("host", x).

%% The event travels over the i2p_events gen_event bus (installed in
%% init_per_testcase), so it fans out asynchronously; drain non-matching
%% messages (incl. boot-time EXITs) and wait on the deadline.
collect_config_changed() ->
    i2p_ct_helpers:wait_msg(
        fun(Ev) ->
            case Ev of
                {config_changed, _, _} -> {true, Ev};
                _ -> false
            end
        end,
        5000
    ).

restore(_Key, undefined) ->
    application:unset_env(i2per, _Key);
restore(Key, {ok, V}) ->
    application:set_env(i2per, Key, V).

restore_env({_Key, undefined}) ->
    application:unset_env(i2per, _Key);
restore_env({Key, {ok, V}}) ->
    application:set_env(i2per, Key, V).
