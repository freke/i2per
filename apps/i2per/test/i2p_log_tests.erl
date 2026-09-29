-module(i2p_log_tests).

-moduledoc """
Tests for `m:i2p_log`: the level vocabulary, the level in force, and the one place
in the tree that can change it.

These cases change the running node's log level, so each one puts back what it
found. That is not tidiness — a level left at `debug` by one case makes every later
case in the run log verbosely, and a level left at `emergency` silences a real
failure. `with_level/1` is the single place that restores, so there is one rule
rather than one per case.
""".

-include_lib("eunit/include/eunit.hrl").

%%% %%%%% The vocabulary %%%%% %%%

%% All eight, and in the order an operator reads them. The order is the contract:
%% `notice` has to be findable by position, not by counting, when someone is
%% deciding what to set at 3am.
the_eight_levels_are_accepted_test() ->
    ?assertEqual(
        [emergency, alert, critical, error, warning, notice, info, debug], i2p_log:levels()
    ),
    lists:foreach(
        fun(Level) -> ?assert(i2p_log:is_level(Level)) end, i2p_log:levels()
    ),
    %% Exactly eight. A ninth would be a level the map does not have, and a missing
    %% one would be a level an operator expects to be able to choose.
    ?assertEqual(8, length(i2p_log:levels())).

%% Anything that is not one of the eight is refused, including near-misses. A level
%% name that was silently coerced to the default would turn a debugging session off
%% at exactly the moment someone turned it on, which is the worst possible time for
%% a typo to go unnoticed.
unrecognised_levels_are_refused_not_coerced_test() ->
    lists:foreach(
        fun(Term) -> ?assertNot(i2p_log:is_level(Term)) end,
        [louder, notice_, "notice", 'NOTICE', 5, undefined, {notice}, [notice]]
    ),
    ?assertEqual({error, {invalid_level, louder}}, i2p_log:set_level(louder)),
    ?assertEqual({error, {invalid_level, "notice"}}, i2p_log:set_level("notice")).

%% The vocabulary has one copy. `m:i2p_config`'s whitelist and `m:i2p_config_srv`'s
%% validator both consult `f:levels/0` rather than listing levels, and this is what
%% makes that safe: every level the module owns is one `logger` will actually take.
%% Checked against `logger` rather than against a restated list, so an OTP that
%% stopped accepting one of them would fail here rather than at a 3am boot.
every_level_the_module_owns_is_one_logger_accepts_test() ->
    with_level(
        fun() ->
            lists:foreach(
                fun(Level) ->
                    ok = i2p_log:set_level(Level),
                    ?assertEqual(Level, applied_level())
                end,
                i2p_log:levels()
            )
        end
    ).

%%% %%%%% The level in force %%%%% %%%

%% `notice`, per the map, and the level a stock install ends up at whether or not
%% anything was configured.
%%
%% Asserted as a *change*, deliberately. The first version of this case cleared the
%% key, called `f:apply_configured/0` and asserted the level was `notice` -- which
%% passed with the function turned into `ok`, because `notice` is also what the node
%% was already running at. An assertion that cannot fail is worse than no assertion:
%% it reads as coverage. So the level is put somewhere else first, and the case
%% fails unless the call is what moved it.
the_default_is_notice_and_boot_applies_it_test() ->
    ?assertEqual(notice, i2p_log:default_level()),
    with_level(
        fun() ->
            ok = logger:update_primary_config(#{level => error}),
            application:unset_env(i2per, log_level),
            ?assertEqual(error, applied_level()),
            ?assertEqual(notice, i2p_log:level()),
            ok = i2p_log:apply_configured(),
            ?assertEqual(notice, applied_level())
        end
    ).

%% A configured level is applied at boot too, not only the default. Same reasoning:
%% asserted as a move from a known-different level, so it cannot pass by accident.
a_configured_level_is_applied_at_boot_test() ->
    with_level(
        fun() ->
            ok = logger:update_primary_config(#{level => error}),
            application:set_env(i2per, log_level, info),
            ok = i2p_log:apply_configured(),
            ?assertEqual(info, applied_level())
        end
    ).

%% Setting the level applies it *and* remembers it, so a later boot reaches the same
%% answer without anything else having to remember it. A setter that only applied
%% would leave the router reporting one level and running at another.
setting_the_level_applies_it_and_remembers_it_test() ->
    with_level(
        fun() ->
            ok = i2p_log:set_level(debug),
            ?assertEqual(debug, i2p_log:level()),
            ?assertEqual(debug, applied_level()),
            %% ... and the remembered value is what a re-boot applies.
            ok = i2p_log:apply_configured(),
            ?assertEqual(debug, applied_level())
        end
    ).

%% A refused level changes nothing at all. Not the applied level, not the
%% remembered one: a config that says `log_level = louder` must not leave the
%% router at a verbosity nobody chose.
a_refused_level_changes_nothing_test() ->
    with_level(
        fun() ->
            ok = i2p_log:set_level(warning),
            ?assertEqual({error, {invalid_level, louder}}, i2p_log:set_level(louder)),
            ?assertEqual(warning, i2p_log:level()),
            ?assertEqual(warning, applied_level())
        end
    ).

%%% %%%%% The key is hot, and it is the only way in %%%%% %%%

%% The reason this module exists. `f:application:set_env/3` alone would record the
%% new level without applying it, and the router would appear to have accepted a
%% verbosity change it had not made — which is the failure an operator hits at 3am,
%% because the symptom is "I turned it up and nothing happened" with no error
%% anywhere.
setting_the_key_through_the_config_service_applies_it_test() ->
    with_config_srv(
        fun() ->
            ok = i2p_config_srv:set(log_level, debug),
            ?assertEqual(debug, i2p_log:level()),
            ?assertEqual(debug, applied_level()),
            ?assertEqual({ok, debug}, i2p_config_srv:get(log_level))
        end
    ).

%% The key announces like every other runtime key, so a subscriber sees the level
%% change on the bus rather than having to poll for it.
setting_the_key_announces_it_test() ->
    with_config_srv(
        fun() ->
            Events = i2p_ct_helpers:events_from(
                fun() -> ok = i2p_config_srv:set(log_level, info) end
            ),
            ?assert(lists:member({config_changed, log_level, info}, Events))
        end
    ).

%% Refused through the service, with the same vocabulary the module owns. A level
%% list written into the service as well as the module would be a level the ini
%% accepts and the service refuses, and neither is discoverable without running both.
the_service_refuses_a_level_the_module_does_not_own_test() ->
    with_config_srv(
        fun() ->
            ?assertEqual(
                {error, {bad_value, log_level, louder}}, i2p_config_srv:set(log_level, louder)
            ),
            %% And a string is not a level, even though the ini file accepts one.
            ?assertEqual(
                {error, {bad_value, log_level, "notice"}}, i2p_config_srv:set(log_level, "notice")
            )
        end
    ).

%% The key is usable from the ini file as well as from the service, and the file
%% gets there through the same vocabulary. The loader is fail-closed, so without this
%% clause a `log_level` line in `i2per.conf` would abort the boot rather than set
%% the level.
the_key_is_usable_from_an_ini_file_test() ->
    ?assertEqual(
        {ok, [{log_level, debug}]},
        i2p_config:validate(#{
            top => #{<<"log_level">> => <<"debug">>}
        })
    ),
    ?assertEqual(
        {ok, [{log_level, notice}]},
        i2p_config:validate(#{
            top => #{<<"log_level">> => <<"NOTICE">>}
        })
    ),
    %% Case-insensitive, like every other key in the file.
    ?assertEqual(
        {ok, [{log_level, alert}]},
        i2p_config:validate(#{
            top => #{<<"log_level">> => <<"Alert">>}
        })
    ),
    ?assertEqual(
        {error, {bad_value, <<"log_level">>, <<"louder">>}},
        i2p_config:validate(#{
            top => #{<<"log_level">> => <<"louder">>}
        })
    ).

%% A file naming something that is not a level must not grow the atom table on the
%% way to being rejected: configuration files are operator input, and
%% `binary_to_atom/3` on unvalidated input is how a running node ends up unable to
%% load its own saved state.
a_rejected_ini_level_does_not_create_an_atom_test() ->
    Before = erlang:system_info(atom_count),
    lists:foreach(
        fun(Name) ->
            ?assertMatch(
                {error, {bad_value, <<"log_level">>, _}},
                i2p_config:validate(#{
                    top => #{<<"log_level">> => Name}
                })
            )
        end,
        [<<"louder">>, <<"verboser">>, <<"log_level_typo">>]
    ),
    ?assertEqual(Before, erlang:system_info(atom_count)).

%%% %%%%% Internal %%%%% %%%%%

%% The level `logger` is actually running at, read back rather than assumed. Asking
%% `f:i2p_log:level/0` would be circular: it reports intent, and the point of these
%% tests is that intent became reality.
applied_level() ->
    maps:get(level, logger:get_primary_config()).

%% Run `Fun` and put the level back exactly as it was, whatever happens.
with_level(Fun) ->
    Before = applied_level(),
    Configured = application:get_env(i2per, log_level),
    try
        Fun()
    after
        _ = application:unset_env(i2per, log_level),
        ok = logger:update_primary_config(#{level => Before}),
        case Configured of
            {ok, Value} -> application:set_env(i2per, log_level, Value);
            undefined -> ok
        end
    end.

%% As `with_level/1`, for a case that wants the key absent.

%% `f:set/2` is a `gen_server:call`, so the service has to be running. Started only
%% if it is not already, and stopped only if this function was what started it, so
%% no case leaves the config service down for the rest of the run.
with_config_srv(Fun) ->
    Owned = start_config_srv(),
    try
        with_level(Fun)
    after
        stop_config_srv(Owned)
    end.

start_config_srv() ->
    case whereis(i2p_config_srv) of
        undefined ->
            {ok, Pid} = i2p_config_srv:start_link(),
            unlink(Pid),
            Pid;
        _Existing ->
            none
    end.

stop_config_srv(none) -> ok;
stop_config_srv(Pid) -> gen_server:stop(Pid).
