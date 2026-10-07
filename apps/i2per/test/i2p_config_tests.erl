-module(i2p_config_tests).

-moduledoc """
Tests for `m:i2p_config`: ini parsing, strict whitelist validation, value
coercion and the gap-fill application-env semantics of the loader.
""".

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%% Parser %%%%% %%%

parse_sections_comments_test() ->
    Text =
        <<
            "# leading comment\n"
            "data_dir = /var/lib/i2per   ; trailing comment\n"
            "\n"
            "; another comment style\n"
            "[Tunnel_Pool]\n"
            "outbound = 3\n"
            "inbound = 3\n"
        >>,
    {ok, Raw} = i2p_config:parse(Text),
    ?assertEqual(#{<<"data_dir">> => "/var/lib/i2per"}, maps:get(top, Raw)),
    ?assertEqual(
        #{<<"outbound">> => "3", <<"inbound">> => "3"}, maps:get(<<"tunnel_pool">>, Raw)
    ).

crlf_tolerated_test() ->
    {ok, Raw} = i2p_config:parse(<<"port = 9150\r\nnet_id = 2\r\n">>),
    ?assertEqual("9150", maps:get(<<"port">>, maps:get(top, Raw))).

duplicate_key_rejected_test() ->
    ?assertEqual(
        {error, {line, 2, {duplicate_key, <<"port">>}}},
        i2p_config:parse(<<"port = 1\nport = 2\n">>)
    ).

malformed_line_rejected_test() ->
    ?assertEqual({error, {line, 1, malformed}}, i2p_config:parse(<<"garbage line\n">>)).

empty_section_header_malformed_test() ->
    ?assertEqual({error, {line, 1, malformed}}, i2p_config:parse(<<"[]\n">>)).

unterminated_section_header_test() ->
    ?assertEqual({error, {line, 1, malformed}}, i2p_config:parse(<<"[nope\n">>)).

hash_inside_value_preserved_test() ->
    %% Without preceding whitespace a '#' is part of the value.
    {ok, Raw} = i2p_config:parse(<<"data_dir = /a#b\n">>),
    ?assertEqual("/a#b", maps:get(<<"data_dir">>, maps:get(top, Raw))).

%% %%%%% %%% Validation %%%%% %%%

scalars_coerced_test() ->
    {ok, Raw} =
        i2p_config:parse(
            <<
                "data_dir = /d\nhost = 10.0.0.1\nport = 9150\nnet_id = 2\n"
                "transit_max_tunnels = 500\nfloodfill = TRUE\nsam_port = 7656\n"
            >>
        ),
    {ok, Pairs} = i2p_config:validate(Raw),
    ?assert(lists:member({data_dir, "/d"}, Pairs)),
    ?assert(lists:member({host, <<"10.0.0.1">>}, Pairs)),
    ?assert(lists:member({port, 9150}, Pairs)),
    ?assert(lists:member({net_id, 2}, Pairs)),
    ?assert(lists:member({transit_max_tunnels, 500}, Pairs)),
    ?assert(lists:member({floodfill, true}, Pairs)),
    ?assert(lists:member({sam_port, 7656}, Pairs)).

ntcp2_published_coerced_test() ->
    {ok, Raw} = i2p_config:parse(<<"ntcp2_published = false\n">>),
    {ok, Pairs} = i2p_config:validate(Raw),
    ?assert(lists:member({ntcp2_published, false}, Pairs)).

live_network_and_listen_host_coerced_test() ->
    {ok, Raw} = i2p_config:parse(<<"live_network = true\nlisten_host = 127.0.0.1\n">>),
    {ok, Pairs} = i2p_config:validate(Raw),
    ?assert(lists:member({live_network, true}, Pairs)),
    ?assert(lists:member({listen_host, <<"127.0.0.1">>}, Pairs)).

live_network_bad_value_rejected_test() ->
    {ok, Raw} = i2p_config:parse(<<"live_network = sometimes\n">>),
    ?assertEqual(
        {error, {bad_value, live_network, "sometimes"}},
        i2p_config:validate(Raw)
    ).

listen_ip_defaults_to_loopback_test() ->
    application:unset_env(i2per, listen_host),
    ?assertEqual({127, 0, 0, 1}, i2p_config:listen_ip()).

listen_ip_uses_configured_literal_test() ->
    application:set_env(i2per, listen_host, <<"192.0.2.10">>),
    try
        ?assertEqual({192, 0, 2, 10}, i2p_config:listen_ip())
    after
        application:unset_env(i2per, listen_host)
    end.

ntcp2_published_bad_value_rejected_test() ->
    {ok, Raw} = i2p_config:parse(<<"ntcp2_published = sometimes\n">>),
    ?assertEqual(
        {error, {bad_value, ntcp2_published, "sometimes"}},
        i2p_config:validate(Raw)
    ).

unknown_key_rejected_test() ->
    {ok, Raw} = i2p_config:parse(<<"bogus_knob = 1\n">>),
    ?assertEqual({error, {unknown_key, <<"bogus_knob">>}}, i2p_config:validate(Raw)).

unknown_section_rejected_test() ->
    {ok, Raw} = i2p_config:parse(<<"[mystery]\nx = 1\n">>),
    ?assertEqual({error, {unknown_section, <<"mystery">>}}, i2p_config:validate(Raw)).

bad_int_rejected_test() ->
    {ok, Raw} = i2p_config:parse(<<"port = ninety\n">>),
    ?assertEqual({error, {bad_value, port, "ninety"}}, i2p_config:validate(Raw)).

trailing_junk_int_rejected_test() ->
    {ok, Raw} = i2p_config:parse(<<"port = 9150x\n">>),
    ?assertMatch({error, {bad_value, port, _}}, i2p_config:validate(Raw)).

rate_limit_scalars_coerced_test() ->
    {ok, Raw} =
        i2p_config:parse(
            <<
                "transit_bandwidth_kbps = 256\n"
                "tunnel_build_rate = 5\n"
                "max_ntcp2_connections = 64\n"
                "max_sam_sessions = 32\n"
                "max_ssu2_sessions = 16\n"
                "max_stream_connections = 128\n"
                "ntcp2_keepalive_interval_ms = 60000\n"
            >>
        ),
    {ok, Pairs} = i2p_config:validate(Raw),
    ?assert(lists:member({transit_bandwidth_kbps, 256}, Pairs)),
    ?assert(lists:member({tunnel_build_rate, 5}, Pairs)),
    ?assert(lists:member({max_ntcp2_connections, 64}, Pairs)),
    ?assert(lists:member({max_sam_sessions, 32}, Pairs)),
    ?assert(lists:member({max_ssu2_sessions, 16}, Pairs)),
    ?assert(lists:member({max_stream_connections, 128}, Pairs)),
    ?assert(lists:member({ntcp2_keepalive_interval_ms, 60000}, Pairs)).

rate_limit_non_positive_rejected_test() ->
    {ok, Raw} =
        i2p_config:parse(
            <<
                "transit_bandwidth_kbps = 0\n"
                "tunnel_build_rate = -2\n"
                "max_ntcp2_connections = 0\n"
                "max_sam_sessions = -1\n"
                "max_ssu2_sessions = 0\n"
                "max_stream_connections = 0\n"
            >>
        ),
    ?assertMatch({error, {bad_value, _, _}}, i2p_config:validate(Raw)).

sam_port_bad_value_rejected_test() ->
    {ok, Raw} = i2p_config:parse(<<"sam_port = huge\n">>),
    ?assertMatch({error, {bad_value, sam_port, _}}, i2p_config:validate(Raw)).

tunnel_pool_complete_pair_test() ->
    {ok, Raw} = i2p_config:parse(<<"[tunnel_pool]\noutbound = 2\ninbound = 3\n">>),
    {ok, Pairs} = i2p_config:validate(Raw),
    ?assert(lists:member({tunnel_pool, #{outbound => 2, inbound => 3}}, Pairs)).

tunnel_pool_half_pair_rejected_test() ->
    {ok, Raw} = i2p_config:parse(<<"[tunnel_pool]\noutbound = 2\n">>),
    ?assertEqual({error, {missing_key, tunnel_pool}}, i2p_config:validate(Raw)).

reseed_pairs_folded_into_map_test() ->
    {ok, Raw} =
        i2p_config:parse(
            <<
                "[reseed]\nenabled = true\nmin_routers = 50\n"
                "hosts = https://a/x.su3, https://b/y.su3\n"
            >>
        ),
    {ok, Pairs} = i2p_config:validate(Raw),
    ?assert(
        lists:member(
            {reseed, #{
                enabled => true,
                min_routers => 50,
                hosts => ["https://a/x.su3", "https://b/y.su3"]
            }},
            Pairs
        )
    ).

trust_extra_is_app_env_only_test() ->
    {ok, Raw} = i2p_config:parse(<<"[reseed]\ntrust_extra = x\n">>),
    ?assertEqual({error, {app_env_only, trust_extra}}, i2p_config:validate(Raw)).

addressbook_section_is_app_env_only_test() ->
    ?assertEqual(
        {error, {app_env_only, addressbook}},
        i2p_config:validate(#{<<"addressbook">> => #{}})
    ).

%% %%%%% %%% Loader integration %%%%% %%%

%% Temp files live in a directory this module creates, under the system temp
%% dir. The path used to be hardcoded to `/tmp/opencode/...`, which exists on a
%% developer's machine and not on a CI runner: `file:write_file/2` raised
%% `enoent` there and took eight cases with it.
%%
%% **The path was the smaller half of the defect.** Three of these cases call
%% `application:set_env/3` *before* their `try`, so when the write raised, the
%% `after` that unsets those keys never ran. A leaked `net_id` then broke the
%% two `in_force_*` cases, which have nothing to do with the loader and report
%% an exact key set. Ten red marks, one missing directory.
tmp_dir() ->
    Dir = filename:join("/tmp", "i2per_config_tests"),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

tmp_conf(Lines) ->
    Path = filename:join(
        tmp_dir(),
        "conf_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    ok = file:write_file(Path, Lines),
    Path.

loader_applies_envs_test() ->
    application:unset_env(i2per, net_id),
    Path = tmp_conf(<<"net_id = 7\n">>),
    try
        ?assertEqual(ok, i2p_config:load(Path)),
        ?assertEqual({ok, 7}, application:get_env(i2per, net_id))
    after
        application:unset_env(i2per, net_id),
        file:delete(Path)
    end.

preset_env_wins_over_file_test() ->
    Path = tmp_conf(<<"net_id = 7\n">>),
    %% **Inside the `try`, deliberately.** Setting this key outside it meant a
    %% failure in `tmp_conf/1` skipped the `after` below, leaked `net_id` into the
    %% application env for the rest of the run, and broke the two `in_force_*`
    %% cases with an unrelated key-set mismatch. The `after` is only a cleanup
    %% guarantee for code that runs after it is installed.
    try
        application:set_env(i2per, net_id, 42),
        ?assertEqual(ok, i2p_config:load(Path)),
        ?assertEqual({ok, 42}, application:get_env(i2per, net_id))
    after
        application:unset_env(i2per, net_id),
        file:delete(Path)
    end.

bad_file_aborts_load_test() ->
    Path = tmp_conf(<<"wat is this\n">>),
    try
        ?assertEqual({error, {line, 1, malformed}}, i2p_config:load(Path))
    after
        file:delete(Path)
    end.

pre_section_typo_aborts_boot_config_test() ->
    Path = tmp_conf(<<"prot = typo\n[eepsite]\ntype = server\nport = 8081\n">>),
    try
        application:set_env(i2per, config_file, missing_conf_path()),
        application:set_env(i2per, tunnels_conf_file, Path),
        ?assertEqual(
            {error, {unknown_key, <<"prot">>}},
            i2p_config:load_default()
        )
    after
        application:unset_env(i2per, config_file),
        application:unset_env(i2per, tunnels_conf_file),
        file:delete(Path)
    end.

addressbook_file_section_aborts_loader_test() ->
    Path = tmp_conf(<<"[addressbook]\nsubscriptions = http://host/hosts.txt\n">>),
    try
        ?assertEqual(
            {error, {app_env_only, addressbook}},
            i2p_config:load(Path)
        )
    after
        file:delete(Path)
    end.

load_default_missing_file_ok_test() ->
    %% A configured-but-absent file is not an error (defaults apply).
    application:set_env(i2per, config_file, missing_conf_path()),
    try
        ?assertEqual(ok, i2p_config:load_default())
    after
        application:unset_env(i2per, config_file)
    end.

missing_conf_path() ->
    filename:join(
        tmp_dir(),
        "absent_" ++ integer_to_list(erlang:unique_integer([positive])) ++ ".conf"
    ).

load_default_explicit_path_test() ->
    Path = tmp_conf(<<"transit_max_tunnels = 1234\n">>),
    try
        application:set_env(i2per, config_file, Path),
        application:unset_env(i2per, transit_max_tunnels),
        ?assertEqual(ok, i2p_config:load_default()),
        ?assertEqual({ok, 1234}, application:get_env(i2per, transit_max_tunnels))
    after
        application:unset_env(i2per, config_file),
        application:unset_env(i2per, transit_max_tunnels),
        file:delete(Path)
    end.

%% %%%%% %%% tunnels.conf %%%%% %%%

tunnels_parsed_in_order_test() ->
    Text =
        <<
            "[eepsite]\ntype = server\nport = 8081\n\n"
            "[irc]\ntype = SERVER\nhost = 192.168.1.10\nport = 6668\n"
        >>,
    {ok, Decls} = i2p_config:parse_tunnels(Text),
    ?assertEqual(
        [
            #{name => <<"eepsite">>, host => <<"127.0.0.1">>, port => 8081},
            #{name => <<"irc">>, host => <<"192.168.1.10">>, port => 6668}
        ],
        Decls
    ).

decls_match_child_spec_shape_test() ->
    %% File-parsed declarations are the same maps the app env takes.
    {ok, [Decl]} = i2p_config:parse_tunnels(<<"[x]\ntype = server\nport = 1\n">>),
    #{id := i2p_server_tunnel_x, start := {i2p_server_tunnel, start_link, [Decl]}} =
        i2p_server_tunnel:child_spec(Decl).

client_type_rejected_test() ->
    ?assertEqual(
        {error, {tunnel_error, <<"c">>, unsupported_type}},
        i2p_config:parse_tunnels(<<"[c]\ntype = client\nport = 1\n">>)
    ).

missing_port_rejected_test() ->
    ?assertEqual(
        {error, {tunnel_error, <<"s">>, missing_port}},
        i2p_config:parse_tunnels(<<"[s]\ntype = server\n">>)
    ).

bad_port_range_rejected_test() ->
    {error, {tunnel_error, _, _}} =
        i2p_config:parse_tunnels(<<"[s]\ntype = server\nport = 70000\n">>).

unknown_tunnel_key_rejected_test() ->
    ?assertMatch(
        {error, {tunnel_error, <<"s">>, {unknown_key, <<"keys">>}}},
        i2p_config:parse_tunnels(<<"[s]\ntype = server\nport = 5\nkeys = k.dat\n">>)
    ).

empty_tunnel_section_rejected_test() ->
    ?assertEqual(
        {error, {tunnel_error, <<"s">>, empty_section}},
        i2p_config:parse_tunnels(<<"[s]\n">>)
    ).

duplicate_sections_rejected_everywhere_test() ->
    ?assertEqual(
        {error, {line, 3, {duplicate_section, <<"a">>}}},
        i2p_config:parse(<<"[a]\nx = 1\n[a]\ny = 2\n">>)
    ).

tunnels_conf_loaded_into_env_test() ->
    Path = tmp_conf(<<"[eepsite]\ntype = server\nport = 8081\n">>),
    application:set_env(i2per, tunnels_conf_file, Path),
    application:unset_env(i2per, server_tunnels_file),
    try
        ?assertEqual(ok, i2p_config:load_default()),
        {ok, [#{name := <<"eepsite">>, port := 8081}]} =
            application:get_env(i2per, server_tunnels_file)
    after
        application:unset_env(i2per, tunnels_conf_file),
        application:unset_env(i2per, server_tunnels_file),
        file:delete(Path)
    end.

bad_tunnels_conf_aborts_boot_config_test() ->
    Path = tmp_conf(<<"[eepsite]\ntype = client\nport = 8081\n">>),
    application:set_env(i2per, tunnels_conf_file, Path),
    %% Point the router conf at an absent file so only the tunnels step runs.
    application:set_env(i2per, config_file, missing_conf_path()),
    try
        ?assertMatch({error, _}, i2p_config:load_default())
    after
        application:unset_env(i2per, config_file),
        application:unset_env(i2per, tunnels_conf_file)
    end.

%% --------------------------------------------------------------------------
%% `f:in_force/0` -- what the boot's configuration line is built from.
%% --------------------------------------------------------------------------

%% Sorted, so two boots of one configuration produce byte-identical lines. A test
%% comparing two boots would be comparing orderings otherwise, and a change to the
%% allowlist's order would show up as a diff in a log nobody reads on purpose.
in_force_is_sorted_test() ->
    Restored = save_env([data_dir, host, log_level, allow_private_host]),
    try
        application:set_env(i2per, data_dir, "/tmp/d"),
        application:set_env(i2per, host, <<"127.0.0.1">>),
        application:set_env(i2per, log_level, info),
        application:set_env(i2per, allow_private_host, true),
        InForce = i2p_config:in_force(),
        ?assertEqual(
            [allow_private_host, data_dir, host, log_level],
            [Key || {Key, _} <- InForce]
        )
    after
        restore_env(Restored)
    end.

%% A key that is allowed but unset is absent, and one that is set but not allowed is
%% absent. The two omissions are different decisions, so they are checked apart:
%% "unset" must not print `undefined`, and "not on the list" must not print at all
%% even when it holds something.
in_force_omits_unset_and_unlisted_keys_test() ->
    Restored = save_env([data_dir, log_level, i2p_peer]),
    try
        application:set_env(i2per, log_level, info),
        application:set_env(i2per, i2p_peer, #{local => #{static_priv => <<"secret">>}, seeds => []}),
        InForce = i2p_config:in_force(),
        Keys = [Key || {Key, _} <- InForce],
        ?assert(lists:member(log_level, Keys)),
        ?assertNot(lists:member(data_dir, Keys)),
        ?assertNot(lists:member(i2p_peer, Keys)),
        ?assertEqual(
            nomatch, string:find(lists:flatten(io_lib:format("~p", [InForce])), "secret")
        )
    after
        restore_env(Restored)
    end.

%% The values are reported exactly as stored. A renderer that prettified them could
%% disagree with what the router is using, and the whole value of the line is that it
%% does not -- so a binary stays a binary here.
in_force_reports_values_as_stored_test() ->
    Restored = save_env([data_dir, host]),
    try
        application:set_env(i2per, host, <<"198.51.100.7">>),
        application:set_env(i2per, data_dir, <<"/var/lib/i2per">>),
        ?assertEqual(
            [{data_dir, <<"/var/lib/i2per">>}, {host, <<"198.51.100.7">>}],
            i2p_config:in_force()
        )
    after
        restore_env(Restored)
    end.

save_env(Keys) ->
    [{Key, application:get_env(i2per, Key)} || Key <- Keys].

restore_env(Saved) ->
    lists:foreach(
        fun
            ({Key, {ok, Value}}) -> application:set_env(i2per, Key, Value);
            ({Key, undefined}) -> application:unset_env(i2per, Key)
        end,
        Saved
    ).
