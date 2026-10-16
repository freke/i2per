%% Reachability-verdict tests for `m:i2p_ssu2_reachability`.
%%
%% Ported from the EUnit module of the same subject: every case here (re)boots
%% the whole router under a configured `allow_private_host` value, which is
%% Common Test territory, not EUnit. The decision under test is asynchronous
%% after a peertest event, so every assertion polls to a deadline and a timeout
%% is a failure, not a pass.

-module(i2p_ssu2_reachability_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, suite/0]).
-export([
    boot_firewalled_when_private_host/1,
    peertest_results_reachability/1,
    one_firewalled_demotion_demotes_immediately/1,
    measured_reachability_drives_the_caps/1,
    test_in_flight_moves_the_rung_to_testing/1
]).

-define(APP, i2per).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        boot_firewalled_when_private_host,
        peertest_results_reachability,
        one_firewalled_demotion_demotes_immediately,
        measured_reachability_drives_the_caps,
        test_in_flight_moves_the_rung_to_testing
    ].

%% A loopback/private-host boot is firewalled by construction: it cannot accept
%% inbound SSU2, so the decision is immediate, on both families, with the
%% aggregate `{reachability, ssu2, firewalled}` event. The measured detail is
%% the honest answer for a profile pinned that way: no test ran, so the rung
%% reads `unknown` with reason `own_config`.
boot_firewalled_when_private_host(_Config) ->
    start_app(true),
    try
        ?assertEqual(firewalled, i2p_ssu2_reachability:status()),
        ?assertEqual(firewalled, i2p_ssu2_reachability:status(ipv4)),
        ?assertEqual(firewalled, i2p_ssu2_reachability:status(ipv6)),
        ?assertEqual(
            #{
                ipv4 => #{rung => unknown, reason => own_config},
                ipv6 => #{rung => unknown, reason => own_config}
            },
            i2p_ssu2_reachability:detail()
        )
    after
        stop_app()
    end.

%% A non-private boot starts undecided and only resolves on peer-test results.
%% One `reachable` conclusion moves the family's rung but not the coarse
%% verdict — the hysteresis promotes at `peertest_promote_after` consecutive
%% conclusions, because one lucky test promoting us is the expensive mistake.
peertest_results_reachability(_Config) ->
    start_app(false),
    try
        ?assertEqual(unknown, i2p_ssu2_reachability:status()),
        ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
        try
            i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
            ?assertEqual(reachable, wait_status({detail_rung, ipv4}, reachable)),
            %% One conclusion does not promote the coarse verdict.
            ?assertEqual(unknown, i2p_ssu2_reachability:status()),

            %% Two more consecutive conclusions and the coarse promotes.
            i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
            i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
            ?assertEqual(reachable, wait_status(status, reachable)),

            %% An `unknown` conclusion (nothing arrived, the introducer
            %% rejected) is no evidence about our reachability: it moves
            %% neither the coarse nor the count.
            i2p_events:notify({peertest_result, ipv6, {unknown, no_charlie_report}}),
            ?assertEqual(unknown, i2p_ssu2_reachability:status(ipv6)),
            ?assertEqual(reachable, i2p_ssu2_reachability:status())
        after
            gen_event:delete_handler(i2p_events, i2p_events_tests_collector, [])
        end
    after
        stop_app()
    end.

%% The asymmetry: one `introducer_only` conclusion (the stateful-firewall case
%% — the Charlie confirmed, the punch never landed) demotes the coarse verdict
%% immediately, and it also resets the consecutive count, so a promotion
%% streak in progress cannot carry a later demotion with it.
one_firewalled_demotion_demotes_immediately(_Config) ->
    start_app(false),
    try
        ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
        try
            i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
            i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
            %% Two of three: not yet promoted.
            ?assertEqual(unknown, wait_status(status, unknown)),

            i2p_events:notify({peertest_result, ipv4, {introducer_only, punch_not_delivered}}),
            ?assertEqual(firewalled, wait_status(status, firewalled)),
            ?assertEqual(introducer_only, wait_status({detail_rung, ipv4}, introducer_only)),
            ?assertEqual(
                #{rung => introducer_only, reason => punch_not_delivered},
                wait_detail(ipv4)
            ),

            %% A following `reachable` conclusion is one of three again, not
            %% the third of the streak the demotion reset.
            i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
            ?assertEqual(firewalled, wait_status(status, firewalled)),
            i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
            ?assertEqual(firewalled, wait_status(status, firewalled)),
            i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
            ?assertEqual(reachable, wait_status(status, reachable))
        after
            gen_event:delete_handler(i2p_events, i2p_events_tests_collector, [])
        end
    after
        stop_app()
    end.

%% The verdict's effects: a demotion writes `firewalled` to app env
%% `measured_reachability`, which is what `f:i2p_identity:local_caps/0` reads,
%% so the published caps can never claim reachable while the measured verdict
%% says otherwise. A promotion writes `reachable` back. With no identity the
%% boot runs no peer manager, so the swap itself is a skip — the caps are the
%% half that follows here.
measured_reachability_drives_the_caps(_Config) ->
    start_app(false),
    try
        %% Absent before any measurement: the operator's configured
        %% reachability is the answer, and no test has contradicted it.
        ?assertEqual(undefined, application:get_env(?APP, measured_reachability)),

        i2p_events:notify({peertest_result, ipv4, {introducer_only, punch_not_delivered}}),
        ?assertEqual(firewalled, wait_status(status, firewalled)),
        ?assertEqual(firewalled, wait_env(measured_reachability, firewalled)),

        i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
        i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
        i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
        ?assertEqual(reachable, wait_status(status, reachable)),
        ?assertEqual(reachable, wait_env(measured_reachability, reachable))
    after
        stop_app()
    end.

%% A test in flight moves the family's rung to `testing` until its conclusion,
%% which is the difference between "we don't know yet" and "we know and the
%% answer is unknown". The coarse verdict is untouched: a test in flight is
%% not a verdict about anything.
test_in_flight_moves_the_rung_to_testing(_Config) ->
    start_app(false),
    try
        ?assertEqual(unknown, wait_detail_rung(ipv4)),
        ok = i2p_ssu2_reachability:test_started(ipv4),
        ?assertEqual(testing, wait_status({detail_rung, ipv4}, testing)),
        i2p_events:notify({peertest_result, ipv4, {reachable, undefined}}),
        ?assertEqual(reachable, wait_status({detail_rung, ipv4}, reachable))
    after
        stop_app()
    end.

%% ----------------------------------------------------------------------
%% Fixture

start_app(AllowPrivateHost) ->
    catch application:stop(?APP),
    ok = application:set_env(?APP, allow_private_host, AllowPrivateHost),
    {ok, _} = application:ensure_all_started(?APP),
    ?assert(is_pid(whereis(i2p_ssu2_reachability))),
    ok.

stop_app() ->
    _ = application:stop(?APP),
    _ = application:unset_env(?APP, allow_private_host),
    _ = application:unset_env(?APP, measured_reachability),
    ok.

%% Poll `Query` until it equals `Expected`, or fail after 2 s. The decision is
%% applied asynchronously after the peertest event, so assertions on it must
%% wait.
wait_status(Query, Expected) ->
    Deadline = erlang:monotonic_time(millisecond) + 2000,
    wait_status(Query, Expected, Deadline).

wait_status(Query, Expected, Deadline) ->
    Current =
        case Query of
            status -> i2p_ssu2_reachability:status();
            {status, Family} -> i2p_ssu2_reachability:status(Family);
            {detail_rung, Family} -> wait_detail_rung(Family)
        end,
    case {Current, erlang:monotonic_time(millisecond) > Deadline} of
        {Expected, _} ->
            Expected;
        {_, true} ->
            erlang:error({status_timeout, Query, Expected, Current});
        _ ->
            timer:sleep(20),
            wait_status(Query, Expected, Deadline)
    end.

wait_detail_rung(Family) ->
    case maps:find(Family, i2p_ssu2_reachability:detail()) of
        {ok, #{rung := Rung}} -> Rung;
        error -> erlang:error({no_detail, Family})
    end.

wait_detail(Family) ->
    case maps:find(Family, i2p_ssu2_reachability:detail()) of
        {ok, Detail} -> Detail;
        error -> erlang:error({no_detail, Family})
    end.

wait_env(Key, Expected) ->
    Deadline = erlang:monotonic_time(millisecond) + 2000,
    wait_env(Key, Expected, Deadline).

wait_env(Key, Expected, Deadline) ->
    Current = application:get_env(?APP, Key),
    Value =
        case Current of
            {ok, V} -> V;
            undefined -> undefined
        end,
    case {Value, erlang:monotonic_time(millisecond) > Deadline} of
        {Expected, _} ->
            Expected;
        {_, true} ->
            erlang:error({env_timeout, Key, Expected, Current});
        _ ->
            timer:sleep(20),
            wait_env(Key, Expected, Deadline)
    end.
