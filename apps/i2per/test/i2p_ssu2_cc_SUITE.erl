%% CT-level coverage for the supervisor-driven congestion-state claims that used
%% to live in `m:i2p_ssu2_cc_tests`. That module is the unit layer: it may not
%% start a real `*_sup:start_link/0`, so the aggregation cases that need a
%% running supervisor moved here. The pure arithmetic (RTT estimator, drain
%% maths) stays in the eunit module.

-module(i2p_ssu2_cc_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-export([all/0, suite/0, init_per_testcase/2, end_per_testcase/2]).
-export([
    rtt_summary_is_zero_without_a_supervisor/1,
    rtt_summary_averages_rtt_across_live_sessions/1,
    rtt_summary_skips_uninitialised_rtts_in_the_average/1,
    rtt_summary_counts_only_established_windows/1,
    rtt_summary_prunes_rows_whose_session_is_gone/1,
    remove_metrics_releases_the_row/1
]).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        rtt_summary_is_zero_without_a_supervisor,
        rtt_summary_averages_rtt_across_live_sessions,
        rtt_summary_skips_uninitialised_rtts_in_the_average,
        rtt_summary_counts_only_established_windows,
        rtt_summary_prunes_rows_whose_session_is_gone,
        remove_metrics_releases_the_row
    ].

init_per_testcase(_Case, Config) ->
    %% Make sure no supervisor leaks in from an earlier case or another suite.
    stop_sup(),
    ets_wipe(),
    Config.

end_per_testcase(_Case, _Config) ->
    stop_sup(),
    ets_wipe(),
    ok.

%% ---------------------------------------------------------------------------
%% Cases
%% ---------------------------------------------------------------------------

rtt_summary_is_zero_without_a_supervisor(_Config) ->
    ?assertEqual(undefined, whereis(i2p_ssu2_sup)),
    ?assertEqual(#{sessions => 0, rtt_ms => 0, cwnd => 0}, i2p_ssu2_sup:rtt_summary()).

rtt_summary_averages_rtt_across_live_sessions(_Config) ->
    {ok, _Sup} = i2p_ssu2_sup:start_link(),
    ets_wipe(),
    Session = live_session(),
    ok = i2p_ssu2_sup:update_metrics(self(), 100, true, 1000, established),
    ok = i2p_ssu2_sup:update_metrics(Session, 200, true, 2000, established),
    ?assertMatch(#{rtt_ms := 150, cwnd := 3000}, i2p_ssu2_sup:rtt_summary()),
    Session ! stop,
    ok.

rtt_summary_skips_uninitialised_rtts_in_the_average(_Config) ->
    {ok, _Sup} = i2p_ssu2_sup:start_link(),
    ets_wipe(),
    Session = live_session(),
    ok = i2p_ssu2_sup:update_metrics(self(), 100, true, 1000, established),
    ok = i2p_ssu2_sup:update_metrics(Session, 0, false, 5000, established),
    ?assertMatch(#{rtt_ms := 100, cwnd := 6000}, i2p_ssu2_sup:rtt_summary()),
    Session ! stop,
    ok.

rtt_summary_counts_only_established_windows(_Config) ->
    {ok, _Sup} = i2p_ssu2_sup:start_link(),
    ets_wipe(),
    Session = live_session(),
    ok = i2p_ssu2_sup:update_metrics(Session, 100, true, 9999, handshake),
    ?assertMatch(#{rtt_ms := 100, cwnd := 0}, i2p_ssu2_sup:rtt_summary()),
    Session ! stop,
    ok.

rtt_summary_prunes_rows_whose_session_is_gone(_Config) ->
    {ok, _Sup} = i2p_ssu2_sup:start_link(),
    ets_wipe(),
    Gone = dead_session(),
    ok = i2p_ssu2_sup:update_metrics(Gone, 999, true, 999, established),
    ?assertMatch(#{rtt_ms := 0, cwnd := 0}, i2p_ssu2_sup:rtt_summary()),
    ?assertEqual([], ets:lookup(i2p_ssu2_metrics, Gone)),
    ok.

remove_metrics_releases_the_row(_Config) ->
    {ok, _Sup} = i2p_ssu2_sup:start_link(),
    ets_wipe(),
    Session = live_session(),
    ok = i2p_ssu2_sup:update_metrics(Session, 100, true, 1000, established),
    ?assertEqual(1, length(ets:lookup(i2p_ssu2_metrics, Session))),
    ok = i2p_ssu2_sup:remove_metrics(Session),
    ?assertEqual([], ets:lookup(i2p_ssu2_metrics, Session)),
    Session ! stop,
    ok.

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

stop_sup() ->
    case whereis(i2p_ssu2_sup) of
        undefined ->
            ok;
        Pid ->
            Ref = monitor(process, Pid),
            unlink(Pid),
            exit(Pid, shutdown),
            receive
                {'DOWN', Ref, process, Pid, _} -> ok
            after 5000 ->
                ct:fail("supervisor did not stop")
            end
    end.

ets_wipe() ->
    case ets:whereis(i2p_ssu2_metrics) of
        undefined ->
            ok;
        _ ->
            ets:delete_all_objects(i2p_ssu2_metrics),
            ok
    end.

live_session() ->
    spawn(fun() ->
        receive
            stop -> ok
        end
    end).

dead_session() ->
    Pid = spawn(fun() -> ok end),
    Ref = monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _} -> Pid
    end.
