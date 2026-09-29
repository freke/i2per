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

%%% %%%%% The checklist %%%%% %%%

%% The map is the discipline, so the first thing to check is that it really is a
%% declaration: every row names an OTP level and an instrument, and
%% `f:fact_names/0` is its sorted keys rather than a second list to keep in step.
the_checklist_declares_a_level_and_an_instrument_for_every_fact_test() ->
    Checklist = i2p_log:checklist(),
    ?assertEqual(lists:sort(maps:keys(Checklist)), i2p_log:fact_names()),
    lists:foreach(
        fun(Fact) ->
            Entry = maps:get(Fact, Checklist),
            case Entry of
                #{instrument := log, level := Level} ->
                    ?assert(lists:member(Level, i2p_log:levels()));
                #{instrument := log} ->
                    erlang:error({log_row_without_a_level, Fact, Entry});
                #{instrument := bus, level := _} ->
                    erlang:error({bus_row_carrying_a_level, Fact, Entry});
                #{instrument := bus} ->
                    ok;
                Other ->
                    erlang:error({unreadable_checklist_row, Fact, Other})
            end
        end,
        i2p_log:fact_names()
    ),
    %% The three boot gaps are the rows ADR 0002 marks as gaps, and they are the ones
    %% nothing else in the tree can answer. A row silently dropped from here is a whole
    %% symptom with no instrument at all, so they are named explicitly rather than
    %% inferred from the length of the list.
    lists:foreach(
        fun(Fact) ->
            ?assertEqual(
                #{level => notice, instrument => log}, maps:get(Fact, Checklist)
            )
        end,
        [config_in_force, started_as, online]
    ).

%% A bus-carried fact cannot be written to the log, which is ADR 0002's one-instrument
%% rule enforced rather than described: the six bus rows exist so that a fact a counter
%% reads cannot also become a log line, and `f:emit/3` is where that is a fact rather
%% than a hope.
a_bus_carried_fact_cannot_be_written_to_the_log_test() ->
    Bus = [F || {F, #{instrument := bus}} <- maps:to_list(i2p_log:checklist())],
    ?assertEqual(6, length(Bus)),
    lists:foreach(
        fun(Fact) -> ?assertError({fact_on_the_bus, Fact}, i2p_log:emit(Fact, "x ~p", [1])) end,
        Bus
    ).

%% A fact that is not declared cannot be recorded through the module. Without this
%% the checklist would be a list nobody is obliged to write to, which is the thing
%% ADR 0002 says the module exists to prevent: the checklist needs an address, and
%% an address nothing is required to use is just a comment.
an_undeclared_fact_cannot_be_recorded_test() ->
    ?assertError(
        {undeclared_fact, an_invented_fact}, i2p_log:emit(an_invented_fact, "hello ~p", [1])
    ),
    %% Nor by spelling something close to a declared name.
    ?assertError(
        {undeclared_fact, config_in_force_}, i2p_log:emit(config_in_force_, "~s", ["x"])
    ).

%% A declared fact is recorded at the level the checklist gives it, not at one the
%% caller chose. The claim is about what the caller *cannot* do, so the assertion is
%% about the event `logger` actually produced.
%%
%% Both wrong directions are caught by one assertion, and neither by a timer. With
%% the primary level set to the declared one, a marker logged at that same level is
%% the barrier: the handler processes its mailbox in order, so once the marker has
%% arrived, every event that was going to arrive has arrived.
%%
%% - recorded at the declared level: exactly one event, at that level;
%% - recorded *quieter* (say `debug` where `notice` is declared): filtered out by
%%   the primary level, so nothing at all arrives before the marker;
%% - recorded *louder*: an event arrives, at the wrong level.
%%
%% The first version of this case waited for the event instead, with a five-second
%% hang guard. When the level was wrong the event was correctly *absent*, so the case
%% sat on its guard until eunit's own timeout cancelled the whole run -- the mutation
%% was caught, as a green-and-cancelled report naming none of the cases involved.
%% Absence has to be established by a barrier or not at all.
a_declared_fact_is_recorded_at_its_declared_level_test() ->
    with_level(
        fun() ->
            {ok, Id} = i2p_log_tests_collector:start(self()),
            try
                lists:foreach(
                    fun(Fact) ->
                        #{level := Level, instrument := log} =
                            maps:get(Fact, i2p_log:checklist()),
                        ok = logger:update_primary_config(#{level => Level}),
                        Marker = lists:flatten(
                            io_lib:format("level probe barrier ~p", [make_ref()])
                        ),
                        i2p_log:emit(Fact, "level probe ~p", [Fact]),
                        logger:log(Level, "~s", [Marker]),
                        ?assertEqual(
                            [Level],
                            [
                                maps:get(level, Event)
                             || Event <- events_until(Marker)
                            ]
                        )
                    end,
                    log_carried_facts()
                )
            after
                i2p_log_tests_collector:stop({ok, Id})
            end
        end
    ).

%% Both branches of the online line.
%%
%% Every boot takes the `bus=up` / `read_api=answering` path, and
%% `boot_announces_config_posture_and_online/1` in the boot suite covers that one.
%% This covers the other two -- the ones that exist for the situation an operator
%% actually needs them in, and that would otherwise be reached for the first time
%% during an incident:
%%
%% - `bus=down`: the event bus is not registered. Unreachable from
%%   `m:i2per_app:start/2`, which reports only after the supervisor started, so a
%%   case here is the only way to reach it.
%% - `read_api=silent`: `m:i2p_status_data:view/0` fails, which in a booted router is
%%   exactly the "the status page shows nothing" symptom the line exists to name.
%%
%% The `catch` in `f:read_api_state/0` is what makes the second one reachable, so this
%% is also the case that says the boot does not die for being unable to report that
%% it is broken.
both_branches_of_the_online_line_test() ->
    %% Both branches need the tree *down*: the bus unregistered, and the read API
    %% calling into processes that are not there. EUnit runs the modules in one VM
    %% and several of them start the application, so a case that merely assumes the
    %% tree is down passes alone and fails in a full run -- which is the definition
    %% of an order-dependent test, and is what the first version of this case was.
    %% Stopping it is safe rather than rude: the modules run sequentially and every
    %% one that wants the tree starts it.
    _ = application:stop(i2per),
    ?assertEqual(undefined, whereis(i2p_events)),
    Lines = i2p_ct_helpers:log_lines_from(fun() -> ok = i2per_app:report_online() end),
    Rendered = lists:flatten(lists:join(" ", Lines)),
    ct_pal(Rendered),
    ?assertNotEqual(nomatch, string:find(Rendered, "bus=down")),
    ?assertNotEqual(nomatch, string:find(Rendered, "read_api=silent(")),
    %% The reason, not just the verdict: an operator who sees "silent" needs to know
    %% whether the read API is absent, crashing, or answering the wrong shape.
    ?assertNotEqual(nomatch, string:find(Rendered, "noproc")),
    %% Still one line. A caught exception rendered whole would wrap.
    ?assertEqual(1, length(Lines)).

%%% %%%%% What may be logged about the configuration %%%%% %%%

%% Every key the boot line may name is a key the router can actually be given.
%%
%% Checked by putting each one in the environment and reading back
%% `f:i2p_config_srv:get_all/0`, which walks that module's own key list: a key not
%% on it is simply absent from the answer. So a typo on the allowlist fails here,
%% rather than shipping as a configuration line that quietly omits a key somebody
%% expected to see -- and it fails with the typo named, which is the useful half.
%%
%% Two allowlisted keys have no validator in front of them at all, and are
%% recognised here for that reason rather than silently excused. See
%% `f:env_only_config_keys/0`.
every_loggable_config_key_is_a_key_the_router_can_be_given_test() ->
    Keys = i2p_log:loggable_config_keys(),
    with_env(
        Keys,
        fun() ->
            Known = maps:keys(i2p_config_srv:get_all()) ++ env_only_config_keys(),
            lists:foreach(fun(Key) -> ?assert(lists:member(Key, Known)) end, Keys)
        end
    ).

%% The allowlist has no duplicates and is sorted. A duplicate would print a key
%% twice; unsorted would make two boots of the same configuration read
%% differently, which is the thing the line exists to prevent.
the_loggable_allowlist_is_sorted_and_free_of_duplicates_test() ->
    Keys = i2p_log:loggable_config_keys(),
    ?assertEqual(lists:sort(Keys), Keys),
    ?assertEqual(lists:usort(Keys), Keys).

%% No secret reaches the log, and this is the test that says so.
%%
%% Three real pieces of key material are set -- the distribution cookie (which
%% lives in `kernel`, not `i2per`), the identity's static private key and its
%% signing seed (which arrive in `i2per` under `i2p_peer`) -- the configuration
%% line is rendered, and none of the three may appear in it.
%%
%% The last three assertions are what stop this passing for the wrong reason: a
%% renderer that emitted nothing at all would also contain no secrets, and would
%% also have removed the answer the operator needed. So the line must contain the
%% allowlisted keys, binary ones included.
no_key_material_reaches_a_config_line_test() ->
    Priv = crypto:strong_rand_bytes(32),
    Seed = crypto:strong_rand_bytes(32),
    Cookie = "a-distribution-cookie-nobody-should-see",
    Local = #{
        static_priv => Priv, sign_seed => Seed, static_pub => <<>>, intro_key => <<>>
    },
    Rendered =
        with_env(
            %% `host` is here so the line contains a *binary* value as well as a
            %% string one. Asserting that a binary prints would otherwise be an
            %% assertion about a key this case never set.
            [data_dir, host, log_level, {kernel, cookie}],
            fun() ->
                application:set_env(i2per, i2p_peer, #{local => Local, seeds => []}),
                captured_config_line()
            end
        ),
    ?assertEqual(nomatch, string:find(Rendered, binary_to_list(Priv))),
    ?assertEqual(nomatch, string:find(Rendered, binary_to_list(Seed))),
    ?assertEqual(nomatch, string:find(Rendered, Cookie)),
    %% Non-vacuous in both directions: the allowlisted keys are printed, including
    %% a binary one, so the renderer produced a real line -- and the key carrying
    %% the key material is not named at all, which is the whole mechanism.
    ?assertNotEqual(nomatch, string:find(Rendered, "data_dir=")),
    ?assertNotEqual(nomatch, string:find(Rendered, "log_level=")),
    ?assertNotEqual(nomatch, string:find(Rendered, "host=")),
    ?assertEqual(nomatch, string:find(Rendered, "i2p_peer=")).

%% A key that is allowed but unset is absent rather than reported as `undefined`,
%% and a key that is not allowed is absent even when set. Between them, the set of
%% keys a line can name is the allowlist intersected with the environment, and both
%% halves of that are checked.
only_allowed_keys_that_are_set_appear_in_the_line_test() ->
    Rendered =
        with_env(
            [log_level],
            fun() ->
                application:set_env(i2per, not_allowed_at_all, <<"should not appear">>),
                captured_config_line()
            end
        ),
    ?assertNotEqual(nomatch, string:find(Rendered, "log_level=info")),
    ?assertEqual(nomatch, string:find(Rendered, "not_allowed_at_all")).

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

%% The rendered configuration line, joined from whatever the collector saw.
captured_config_line() ->
    lists:flatten(lists:join(" ", i2p_ct_helpers:log_lines_from(fun render_config_line/0))).

%% The configuration line, exactly as `m:i2per_app` writes it.
render_config_line() ->
    i2p_log:emit(
        config_in_force, "i2per config in force: ~s", [lists:join(" ", config_pairs())]
    ).

config_pairs() ->
    [io_lib:format("~p=~p", [Key, Value]) || {Key, Value} <- i2p_config:in_force()].

log_carried_facts() ->
    [Fact || {Fact, #{instrument := log}} <- maps:to_list(i2p_log:checklist())].

%% Configuration the router reads straight from the application environment with
%% nothing in front of it: not on `m:i2p_config_srv`'s key list, and not in the ini
%% whitelist either, so there is no validator anywhere in the tree.
%%
%% `seeds` is a third, and is deliberately absent -- it is far too large to print,
%% which is why the boot reports a seed *count* on a different line. These two are
%% on the allowlist because both change what the router publishes: whether it
%% advertises a private address, and whether it binds an SSU2 listener at all. An
%% operator reading the configuration line needs both.
%%
%% Named here so that a fourth one is a decision rather than an omission, which is
%% the whole point of the case that reads this.
-spec env_only_config_keys() -> [atom()].
env_only_config_keys() ->
    [allow_private_host, ssu2_enabled].

%% EUnit has no `ct:pal/2`.
ct_pal(Rendered) ->
    io:format(user, "~nonline line (tree down): ~ts~n", [Rendered]).

%% Every log event captured before `Marker`, oldest first.
%%
%% The marker is logged at whatever level the case set, so it arrives exactly when
%% that level stops filtering -- which is the condition the case is setting up. The
%% guard is a hang guard for a handler that stopped forwarding, not the assertion:
%% arriving at all is what establishes the ordering.
events_until(Marker) ->
    receive
        {log_line, Event} ->
            case i2p_ct_helpers:render_log_event(Event) of
                Marker -> [];
                _ -> [Event | events_until(Marker)]
            end
    after 2000 ->
        erlang:error({log_marker_never_arrived, Marker})
    end.

%% Run `Fun` with `Keys` set in the application environment and every one of them
%% put back afterwards. Keys are atoms, or `{App, Key}` pairs for the ones that do
%% not live under `i2per`; values come from `f:probe_value/1`, which differs per key
%% so a line naming the wrong one is visible rather than plausible.
%%
%% Returns whatever `Fun` returns, so a case that wants a rendered line and a case
%% that wants an assertion about the environment can both use it.
-spec with_env([atom() | {atom(), atom()}], fun(() -> Result)) -> Result when
    Result :: term().
with_env(Keys, Fun) ->
    Set = [{resolve(Key), probe_value(Key)} || Key <- Keys],
    Saved = [{App, Key, application:get_env(App, Key)} || {App, Key} <- Set],
    I2per = application:get_all_env(i2per),
    try
        lists:foreach(
            fun({{App, Key}, Value}) -> application:set_env(App, Key, Value) end,
            Set
        ),
        Fun()
    after
        %% `i2per` is restored whole rather than key by key. A case may set a key
        %% directly instead of through this function's list -- the secret case does,
        %% because it needs particular key material -- and the whole tree reads that
        %% environment. Unsetting everything and putting the snapshot back is the only
        %% restore that cannot leave a key behind, and leaving `i2p_peer` set is how a
        %% unit test in this module silently reconfigured a boot suite: seven cases
        %% failed in a different suite, which is the least useful failure report there
        %% is.
        restore_env(i2per, I2per),
        lists:foreach(
            fun
                ({App, Key, {ok, Value}}) -> application:set_env(App, Key, Value);
                ({App, Key, undefined}) -> application:unset_env(App, Key)
            end,
            Saved
        )
    end.

%% Unset everything, then put the snapshot back. Deliberately not diffing the two:
%% a diff cannot unset a key the snapshot does not mention, and that is precisely the
%% key that leaked.
-spec restore_env(atom(), [{atom(), term()}]) -> ok.
restore_env(App, Snapshot) ->
    lists:foreach(
        fun({Key, _}) -> application:unset_env(App, Key) end, application:get_all_env(App)
    ),
    lists:foreach(fun({Key, Value}) -> application:set_env(App, Key, Value) end, Snapshot).

resolve({App, Key}) -> {App, Key};
resolve(Key) -> {i2per, Key}.

probe_value(log_level) -> info;
probe_value(data_dir) -> "/tmp/i2p-log-probe";
probe_value(host) -> <<"198.51.100.7">>;
probe_value(port) -> 49152;
probe_value(_Key) -> <<"i2p-log-probe">>.
