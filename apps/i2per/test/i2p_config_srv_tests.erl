-module(i2p_config_srv_tests).

-moduledoc """
Direct-callback unit tests for `m:i2p_config_srv`: every `validate_value`
branch (hot + restart-required + rejections), the pure `f:get/1` /
`f:get_all/0` readers, and the gen_server boilerplate callbacks. The service
is invoked as a plain module (`handle_call`/`handle_cast`/`handle_info` with
crafted state) so no live router is needed; `i2p_events:notify/1` is a safe
no-op when the bus is absent.
""".

-include_lib("eunit/include/eunit.hrl").

init_test() ->
    ?assertEqual({ok, #{}}, i2p_config_srv:init([])).

generic_call_test() ->
    ?assertEqual(
        {reply, {error, not_implemented}, #{}},
        i2p_config_srv:handle_call({some, request}, from(), #{})
    ).

cast_test() ->
    ?assertEqual({noreply, #{}}, i2p_config_srv:handle_cast(any, #{})).

info_test() ->
    ?assertEqual({noreply, #{}}, i2p_config_srv:handle_info(any, #{})).

terminate_test() ->
    ?assertEqual(ok, i2p_config_srv:terminate(shutdown, #{})).

code_change_test() ->
    ?assertEqual({ok, #{}}, i2p_config_srv:code_change(0, #{}, [])).

get_get_all_test() ->
    ok = application:set_env(i2per, port, 12345),
    ok = application:set_env(i2per, host, <<"i2p.example">>),
    try
        ?assertEqual({ok, 12345}, i2p_config_srv:get(port)),
        ?assertEqual({ok, <<"i2p.example">>}, i2p_config_srv:get(host)),
        ?assertEqual(12345, maps:get(port, i2p_config_srv:get_all())),
        ?assertEqual(<<"i2p.example">>, maps:get(host, i2p_config_srv:get_all())),
        ?assertEqual(error, i2p_config_srv:get(never_set))
    after
        application:unset_env(i2per, port),
        application:unset_env(i2per, host)
    end.

set_hot_key_applies_test() ->
    ?assertEqual(
        {reply, ok, #{}},
        i2p_config_srv:handle_call({set, transit_max_tunnels, 16}, from(), #{})
    ),
    ?assertEqual({ok, 16}, application:get_env(i2per, transit_max_tunnels)),
    ok = application:unset_env(i2per, transit_max_tunnels).

set_restart_key_pending_test() ->
    ok = application:unset_env(i2per, port),
    ?assertEqual(
        {reply, {ok, pending_restart}, #{}},
        i2p_config_srv:handle_call({set, port, 4444}, from(), #{})
    ),
    %% Restart-required keys are validated but never applied at runtime.
    ?assertEqual(undefined, application:get_env(i2per, port)).

unknown_and_non_atom_key_test() ->
    ?assertEqual(
        {reply, {error, {unknown_key, bogus}}, #{}},
        i2p_config_srv:handle_call({set, bogus, 1}, from(), #{})
    ),
    ?assertEqual(
        {reply, {error, {unknown_key, <<"k">>}}, #{}},
        i2p_config_srv:handle_call({set, <<"k">>, 1}, from(), #{})
    ).

valid_values_test() ->
    %% Hot keys are applied and acknowledged ok; restart-required keys are
    %% acknowledged as pending. Both run through validate.
    Cases = [
        {transit_max_tunnels, 4, ok},
        {transit_bandwidth_kbps, 100, ok},
        {tunnel_build_rate, 2, ok},
        {floodfill, true, ok},
        {floodfill, false, ok},
        {ntcp2_published, true, {ok, pending_restart}},
        {ntcp2_published, false, {ok, pending_restart}},
        {live_network, true, {ok, pending_restart}},
        {live_network, false, {ok, pending_restart}},
        {listen_host, <<"127.0.0.1">>, {ok, pending_restart}},
        {max_ntcp2_connections, 64, {ok, pending_restart}},
        {max_sam_sessions, 32, {ok, pending_restart}},
        {max_ssu2_sessions, 16, {ok, pending_restart}},
        {max_stream_connections, 128, {ok, pending_restart}},
        {ntcp2_keepalive_interval_ms, 60000, {ok, pending_restart}},
        {net_id, 0, ok},
        {net_id, 9, ok},
        {tunnel_pool, #{outbound => 2, inbound => 1}, ok},
        {tunnel_pool, #{outbound => 2, inbound => 1, exploratory => 3}, ok},
        {tunnel_pool, #{outbound => 2, inbound => 1, exploratory => 3, exploratory_hops => 3}, ok},
        {host, <<"i2p.example">>, {ok, pending_restart}},
        {port, 8080, {ok, pending_restart}},
        {sam_port, 7656, {ok, pending_restart}},
        {data_dir, "./i2per", {ok, pending_restart}},
        {data_dir, <<"/tmp/i2per">>, {ok, pending_restart}},
        {reseed, #{enabled => true}, {ok, pending_restart}},
        {addressbook, #{subscriptions => [<<"http://a.i2p">>]}, {ok, pending_restart}},
        {server_tunnels, [<<"eepsite1">>, <<"eepsite2">>], {ok, pending_restart}}
    ],
    lists:foreach(
        fun({Key, Value, Expected}) ->
            Reply = i2p_config_srv:handle_call({set, Key, Value}, from(), #{}),
            ?assertEqual({reply, Expected, #{}}, Reply)
        end,
        Cases
    ),
    ?assertEqual({ok, 4}, application:get_env(i2per, transit_max_tunnels)),
    ok = restore_env(all_keys()).

%% Every key this module's cases set, unset at the end.
%%
%% **This was `application:unset_env/2` on one key, and it leaked four.** The
%% cases above set `transit_bandwidth_kbps`, `tunnel_build_rate`, `floodfill` and
%% `net_id` as a side effect of being valid; only `transit_max_tunnels` was
%% cleaned up. Nothing failed, because the leak is invisible to every test that
%% does not read the whole environment -- until `i2p_config_tests` does:
%% `i2p_config:in_force/0` reports *every* `loggable_config_keys/0` key that is
%% set, so a key another module left behind shows up in a boot line this module
%% is asserting the contents of.
%%
%% It surfaced the moment the unit tier ran as an explicit module list, which
%% orders cases differently from a whole-tree discovery run. The fix belongs here
%% rather than in the test that noticed: this module is the one that set the
%% keys, so it is the one that owns putting them back.
all_keys() ->
    [
        transit_max_tunnels,
        transit_bandwidth_kbps,
        tunnel_build_rate,
        floodfill,
        ntcp2_published,
        live_network,
        listen_host,
        max_ntcp2_connections,
        max_sam_sessions,
        max_ssu2_sessions,
        max_stream_connections,
        ntcp2_keepalive_interval_ms,
        net_id,
        tunnel_pool,
        host,
        port,
        sam_port,
        data_dir,
        reseed,
        addressbook,
        server_tunnels
    ].

restore_env(Keys) ->
    lists:foreach(fun(Key) -> application:unset_env(i2per, Key) end, Keys).

invalid_values_test() ->
    Cases = [
        {transit_max_tunnels, 0},
        {transit_max_tunnels, -3},
        {transit_bandwidth_kbps, 0},
        {transit_bandwidth_kbps, -1},
        {tunnel_build_rate, 0},
        {floodfill, sometimes},
        {ntcp2_published, sometimes},
        {live_network, sometimes},
        {listen_host, 123},
        {max_ntcp2_connections, 0},
        {max_sam_sessions, -1},
        {max_ssu2_sessions, 0},
        {max_stream_connections, 0},
        {max_stream_connections, -1},
        {ntcp2_keepalive_interval_ms, 0},
        {net_id, -1},
        {tunnel_pool, #{}},
        {tunnel_pool, #{outbound => 0, inbound => 1}},
        {tunnel_pool, #{outbound => 1}},
        {tunnel_pool, #{outbound => 1, inbound => 0}},
        {tunnel_pool, #{outbound => 1, inbound => 1, exploratory => 0}},
        {tunnel_pool, #{outbound => 1, inbound => 1, exploratory => 1, exploratory_hops => 0}},
        {tunnel_pool, #{outbound => 1, inbound => 1, exploratory => 1, exploratory_hops => 4}},
        {host, 123},
        {host, "list-not-binary"},
        {port, 0},
        {port, 65536},
        {port, "8080"},
        {sam_port, 0},
        {sam_port, 65536},
        {data_dir, 123},
        {reseed, #{}},
        {reseed, #{enabled => sometimes}},
        {addressbook, #{}},
        {addressbook, #{subscriptions => nope}},
        {server_tunnels, []}
    ],
    lists:foreach(
        fun({Key, Value}) ->
            Reply = i2p_config_srv:handle_call({set, Key, Value}, from(), #{}),
            ?assertEqual(
                {reply, {error, {bad_value, Key, Value}}, #{}},
                Reply
            )
        end,
        Cases
    ),
    ?assertEqual(undefined, application:get_env(i2per, transit_max_tunnels)).

%% %% %%% Internal %%% %%

from() ->
    {self(), make_ref()}.
