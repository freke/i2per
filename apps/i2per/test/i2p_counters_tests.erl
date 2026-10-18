-module(i2p_counters_tests).

-moduledoc """
Unit tests for the counter home.

The properties that matter here are not arithmetic. They are that a counter
costs an atomic add rather than a message, that the numbers are still readable
when the owning process cannot answer, and that nothing in the module wakes up
on a timer.
""".

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%% The registry %%%%% %%%

%% Uniqueness, checked as uniqueness. An earlier version of this case asserted
%% `lists:usort(Names) =:= Names`, which is a *sortedness* check wearing a
%% uniqueness check's clothes: it passed on a one-element registry and failed the
%% moment a second counter arrived, because the registry is grouped by transport
%% and direction rather than alphabetically. A test that only holds while the
%% list has one element is not a test.
counters_are_unique_test() ->
    Owner = ensure_counters(),
    try
        Names = i2p_counters:counters(),
        ?assertEqual(length(Names), length(lists:usort(Names))),
        ?assert(length(Names) > 0)
    after
        case Owner of
            started -> stop_counters();
            existing -> ok
        end
    end.

%% %%%%% %%% Volatility %%%%% %%%

%% A stopped owner must not be able to crash a caller on a packet path. Same
%% reason `i2p_events:notify/1` always succeeds: telemetry is never worth a
%% dropped connection.
add_is_a_no_op_while_the_owner_is_absent_test() ->
    Owner = ensure_counters_absent(),
    try
        ?assertEqual(undefined, whereis(i2p_counters)),
        ?assertEqual(ok, i2p_counters:add(events_notified, 1)),
        ?assertEqual(#{}, i2p_counters:snapshot())
    after
        restore_counters(Owner)
    end.

%% %%%%% %%% Gauges %%%%% %%%

%% A gauge write is a no-op while the owner is absent, for the reason
%% `f:add/2` is: telemetry must not be able to crash a working connection, and the
%% suites that start part of the tree rely on it.
set_gauge_is_a_no_op_while_the_owner_is_absent_test() ->
    Owner = ensure_counters_absent(),
    try
        ?assertEqual(undefined, whereis(i2p_counters)),
        ?assertEqual(ok, i2p_counters:set_gauge(bus_backlog, 999)),
        ?assertEqual(#{}, i2p_counters:gauges())
    after
        restore_counters(Owner)
    end.

%% %%%%% %%% Internal helpers %%%%% %%%

ensure_counters() ->
    case whereis(i2p_counters) of
        undefined ->
            {ok, Pid} = i2p_counters:start_link(),
            true = unlink(Pid),
            started;
        _ ->
            existing
    end.

stop_counters() ->
    case whereis(i2p_counters) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

ensure_counters_absent() ->
    case whereis(i2p_counters) of
        undefined ->
            absent;
        Pid ->
            gen_server:stop(Pid),
            present
    end.

restore_counters(absent) ->
    ok;
restore_counters(present) ->
    {ok, Pid} = i2p_counters:start_link(),
    true = unlink(Pid),
    ok.
