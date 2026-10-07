%% Identity persistence tests. The identity file round-trips through
%% disk (generate → load → build_local) and a corrupted file is rejected.

-module(i2p_identity_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TEMP_DIR, "/tmp/i2p_identity_test").

identity_roundtrip_test_() ->
    {setup,
        fun() ->
            file:del_dir_r(?TEMP_DIR),
            file:make_dir(?TEMP_DIR)
        end,
        fun(_) -> file:del_dir_r(?TEMP_DIR) end, [
            fun generates_and_loads/0,
            fun load_reuses_existing/0,
            fun corrupted_file_rejected/0,
            fun build_local_reconstructs_keys/0,
            fun build_local_nonpublished/0,
            fun rebuild_router_info_resigns/0
        ]}.

generates_and_loads() ->
    ?assertMatch(
        {ok, #{
            static_priv := _,
            static_pub := _,
            sign_pub := _,
            sign_seed := _,
            iv := _
        }},
        i2p_identity:ensure_identity(?TEMP_DIR)
    ),
    %% Second call loads the same file.
    {ok, Id1} = i2p_identity:ensure_identity(?TEMP_DIR),
    {ok, Id2} = i2p_identity:ensure_identity(?TEMP_DIR),
    ?assertEqual(Id1, Id2).

load_reuses_existing() ->
    %% Write a known file, load it back.
    {ok, Id1} = i2p_identity:ensure_identity(?TEMP_DIR),
    {ok, Id2} = i2p_identity:ensure_identity(?TEMP_DIR),
    ?assertEqual(maps:get(static_pub, Id1), maps:get(static_pub, Id2)),
    ?assertEqual(maps:get(sign_pub, Id1), maps:get(sign_pub, Id2)),
    ?assertEqual(maps:get(iv, Id1), maps:get(iv, Id2)).

corrupted_file_rejected() ->
    %% A corrupted file is silently replaced by a fresh identity.
    {ok, Original} = i2p_identity:ensure_identity(?TEMP_DIR),
    Path = filename:join(?TEMP_DIR, "identity.bin"),
    file:write_file(Path, <<0, 1, 2, 3>>),
    ?assertMatch({ok, #{static_pub := _}}, i2p_identity:ensure_identity(?TEMP_DIR)),
    {ok, AfterCorruption} = i2p_identity:ensure_identity(?TEMP_DIR),
    %% The new identity must differ from the original.
    ?assertNotEqual(maps:get(static_pub, Original), maps:get(static_pub, AfterCorruption)).

build_local_reconstructs_keys() ->
    {ok, Id} = i2p_identity:ensure_identity(?TEMP_DIR),
    Seed = maps:get(sign_seed, Id),
    Local = i2p_identity:build_local(Id, <<"127.0.0.1">>, 9150, Seed),
    ?assertMatch(
        #{
            static_priv := _,
            static_pub := _,
            hash := _,
            iv := _,
            ri := _
        },
        Local
    ),
    ?assertEqual(maps:get(static_pub, Id), maps:get(static_pub, Local)),
    %% The built RouterInfo must carry a spec-valid router-level caps string.
    ?assert(
        i2p_router_info:validate_caps(
            maps:get(<<"caps">>, i2p_router_info:options(maps:get(ri, Local)))
        )
    ).

build_local_nonpublished() ->
    application:set_env(i2per, ntcp2_published, false),
    application:set_env(i2per, allow_private_host, true),
    try
        {ok, Id} = i2p_identity:ensure_identity(?TEMP_DIR),
        Local = i2p_identity:build_local(
            Id, <<"127.0.0.1">>, 9150, maps:get(sign_seed, Id)
        ),
        ?assertEqual(9150, maps:get(port, Local)),
        ?assertEqual(
            {error, no_reachable_ntcp2},
            i2p_router_info:ntcp2_connector(maps:get(ri, Local))
        ),
        Options = i2p_router_info:options(maps:get(ri, Local)),
        ?assertEqual(<<"UL">>, maps:get(<<"caps">>, Options)),
        [Address] = i2p_router_info:addresses(maps:get(ri, Local)),
        ?assertEqual(false, maps:is_key(<<"host">>, maps:get(options, Address)))
    after
        application:unset_env(i2per, ntcp2_published),
        application:unset_env(i2per, allow_private_host)
    end.

%% Re-signing on the refresh cycle: rebuild_router_info mints a fresh
%% RouterInfo with a new publish timestamp but the same identity/hash, and the
%% result still parses (signature verifies). This is what keeps the router from
%% aging out of peer netDbs. The publish timestamp is injected explicitly so
%% the test never depends on a wall-clock tick (no sleep).
rebuild_router_info_resigns() ->
    {ok, Id} = i2p_identity:ensure_identity(?TEMP_DIR),
    Seed = maps:get(sign_seed, Id),
    T0 = 1_700_000_000_000,
    Local0 = i2p_identity:build_local(Id, <<"192.0.2.10">>, 9150, Seed, T0),
    Hash0 = maps:get(hash, Local0),
    RIBin0 = i2p_router_info:to_binary(maps:get(ri, Local0)),
    ?assertEqual(T0, i2p_router_info:published(maps:get(ri, Local0))),
    Local1 = i2p_identity:rebuild_router_info(Local0, T0 + 1000),
    RIBin1 = i2p_router_info:to_binary(maps:get(ri, Local1)),
    ?assertNotEqual(RIBin0, RIBin1),
    ?assertEqual(Hash0, maps:get(hash, Local1)),
    ?assertEqual(T0 + 1000, i2p_router_info:published(maps:get(ri, Local1))),
    %% Same identity/addresses/options; only the timestamp + signature change.
    ?assertEqual(
        i2p_router_info:identity(maps:get(ri, Local0)),
        i2p_router_info:identity(maps:get(ri, Local1))
    ),
    ?assertEqual(
        i2p_router_info:addresses(maps:get(ri, Local0)),
        i2p_router_info:addresses(maps:get(ri, Local1))
    ),
    ?assertEqual(
        i2p_router_info:options(maps:get(ri, Local0)),
        i2p_router_info:options(maps:get(ri, Local1))
    ),
    %% The fresh RouterInfo still parses under the strict validator.
    ?assertMatch({ok, _}, i2p_router_info:parse(RIBin1)).

%% --------------------------------------------------------------------------
%% The UDP transport setting
%% --------------------------------------------------------------------------
%%
%% The setting is one enum read through two questions, and the whole ticket turns
%% on the questions being separate. So these assert the pair per value, not the
%% setting alone: a case that asserted `ssu2_setting()` three times would pass
%% against an implementation where both accessors answered from the same bit.
%%
%% `with_ssu2/2` restores the environment whole rather than unsetting one key,
%% for the reason `i2p_log_tests:f:with_env/2` says: a key left behind here
%% reconfigures whichever suite boots next.

%% Every value, and both answers, in one table so the two columns cannot drift
%% apart in a future edit -- the table *is* the contract the boot and the dial
%% path each depend on.
setting_answers_both_transport_questions_test() ->
    [
        ?_assertEqual(
            {S, Available, Preferred},
            with_ssu2(
                [{ssu2, S}],
                fun() ->
                    {
                        i2p_identity:ssu2_setting(),
                        i2p_identity:ssu2_available(),
                        i2p_identity:ssu2_preferred()
                    }
                end
            )
        )
     || {S, Available, Preferred} <- [
            {no_udp, false, false},
            {enable_udp, true, false},
            {prefer_udp, true, true}
        ]
    ].

%% `enable_udp` is the value the boolean could not express, so it is pinned from
%% both sides in one case: served and not preferred. Either half alone would be
%% satisfied by `prefer_udp`.
%%
%% The setting is also read by the boot (`m:i2per_sup`) and by the dial
%% (`f:i2p_peer:ssu2_connect/3`), which want exactly these two answers and ask for
%% them by these two names.
enable_udp_serves_without_preferring_test() ->
    with_ssu2(
        [{ssu2, enable_udp}],
        fun() ->
            ?assertEqual(enable_udp, i2p_identity:ssu2_setting()),
            ?assertEqual(true, i2p_identity:ssu2_available()),
            ?assertEqual(false, i2p_identity:ssu2_preferred())
        end
    ).

%% An unset key is `no_udp`, not an error and not `undefined`. A router booted
%% with nothing configured must still answer the question, because the answer is
%% what decides whether the SSU2 supervisor comes up at all.
unset_is_no_udp_test() ->
    with_ssu2(
        [],
        fun() ->
            %% Start from a *known-unset* key rather than from whatever this VM
            %% happens to hold, and prove it: a case asserting the unset default
            %% in an environment where the key is set is asserting nothing.
            ok = application:unset_env(i2per, ssu2),
            ok = application:unset_env(i2per, ssu2_enabled),
            ?assertEqual(undefined, application:get_env(i2per, ssu2)),
            ?assertEqual(no_udp, i2p_identity:ssu2_setting()),
            ?assertEqual(false, i2p_identity:ssu2_available()),
            ?assertEqual(false, i2p_identity:ssu2_preferred())
        end
    ).

%% The deprecated boolean, at the meaning it had. `true` is `prefer_udp` and not
%% `enable_udp`: it gated the published address *and* the outbound preference
%% together, so reading it as the weaker value would change which transport a
%% live router dials -- the one thing this mapping exists to prevent. Pinned from
%% both sides for the same reason as `enable_udp` above.
legacy_true_still_means_prefer_udp_test() ->
    with_ssu2(
        [{ssu2_enabled, true}],
        fun() ->
            ?assertEqual(prefer_udp, i2p_identity:ssu2_setting()),
            ?assertEqual(true, i2p_identity:ssu2_available()),
            ?assertEqual(true, i2p_identity:ssu2_preferred())
        end
    ).

legacy_false_still_means_no_udp_test() ->
    with_ssu2(
        [{ssu2_enabled, false}],
        fun() ->
            ?assertEqual(no_udp, i2p_identity:ssu2_setting()),
            ?assertEqual(false, i2p_identity:ssu2_available())
        end
    ).

%% A value that is not one of the three raises rather than falling back. The
%% mutant this kills is a `_ -> no_udp` catch-all: it passes every case above and
%% silently gives an operator who asked for `prefer_udp` a router that publishes
%% no SSU2 address and declines every UDP dial, with nothing in the log about it.
%%
%% Asserted through both accessors, because a validator reached only from
%% `ssu2_setting/0` would leave `ssu2_available/0` reading the key itself.
unknown_setting_is_refused_test() ->
    with_ssu2(
        [{ssu2, "prefer"}],
        fun() ->
            ?assertError({unknown_ssu2_setting, "prefer"}, i2p_identity:ssu2_setting()),
            ?assertError({unknown_ssu2_setting, "prefer"}, i2p_identity:ssu2_available()),
            ?assertError({unknown_ssu2_setting, "prefer"}, i2p_identity:ssu2_preferred())
        end
    ).

%% Both keys set: the enum wins, because it is the one an operator is being asked
%% to edit. The direction matters and is asserted, not merely that *a* value
%% came back -- a fallback to the legacy boolean here would mean an operator who
%% migrated the key and left the old line behind silently kept the old behaviour.
enum_wins_over_the_deprecated_key_test() ->
    with_ssu2(
        [{ssu2, prefer_udp}, {ssu2_enabled, false}],
        fun() ->
            ?assertEqual(prefer_udp, i2p_identity:ssu2_setting()),
            ?assertEqual(true, i2p_identity:ssu2_preferred())
        end
    ).

%% Run `Body` with `Env` set on the `i2per` application, then put the environment
%% back the way it was found.
%%
%% Restore is **unset-everything-then-put-back**, not a diff, for the reason
%% `i2p_log_tests:f:restore_env/2` gives: a diff cannot unset a key the snapshot
%% does not mention, and that is exactly the key that leaks. These cases set
%% `ssu2`, which the suites that boot a router read, so a leaked one reconfigures
%% whichever suite runs next -- which is how a unit test in this module once broke
%% seven cases in a different suite.
with_ssu2(Env, Body) ->
    Saved = application:get_all_env(i2per),
    try
        lists:foreach(fun({K, V}) -> application:set_env(i2per, K, V) end, Env),
        Body()
    after
        lists:foreach(
            fun({K, _}) -> application:unset_env(i2per, K) end,
            application:get_all_env(i2per)
        ),
        lists:foreach(fun({K, V}) -> application:set_env(i2per, K, V) end, Saved),
        ok
    end.
