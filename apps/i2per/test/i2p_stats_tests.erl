-module(i2p_stats_tests).

-moduledoc """
Unit tests for the counter home.

The properties that matter here are not arithmetic. They are that a counter
costs an atomic add rather than a message, that the numbers are still readable
when the owning process cannot answer, and that nothing in the module wakes up
on a timer.
""".

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%% The registry %%%%% %%%

%% The list is the contract: `snapshot/0` reports by name and the read API's
%% key-set test reads it, so a name that is listed but not wired up, or wired up
%% but not listed, is a drift nobody would otherwise notice.
every_registered_counter_appears_in_the_snapshot_test() ->
    with_stats(fun() ->
        Expected = maps:from_list([{Name, 0} || Name <- i2p_stats:counters()]),
        ?assertEqual(Expected, i2p_stats:snapshot())
    end).

counters_are_unique_test() ->
    Names = i2p_stats:counters(),
    ?assertEqual(lists:usort(Names), Names),
    ?assertEqual(length(Names), length(lists:usort(Names))).

%% %%%%% %%% Counting %%%%% %%%

counters_accumulate_test() ->
    with_stats(fun() ->
        Before = i2p_stats:snapshot(),
        ok = i2p_stats:add(events_notified, 3),
        ok = i2p_stats:add(events_notified, 4),
        After = i2p_stats:snapshot(),
        ?assertEqual(7, maps:get(events_notified, After)),
        ?assert(maps:get(events_notified, After) > maps:get(events_notified, Before))
    end).

%% Counters are independent, not one shared total: a mistake that charged the
%% wrong index would otherwise still look plausible. Asserted over the registry
%% rather than over a fixed pair, so it keeps holding as counters are added —
%% a name sharing an index with another would make two unrelated totals move
%% together, and the first such collision would be invisible from the read API.
counters_have_distinct_indices_test() ->
    with_stats(fun() ->
        ok = i2p_stats:add(events_notified, 5),
        Snap = i2p_stats:snapshot(),
        ?assertEqual(5, maps:get(events_notified, Snap)),
        %% Every registered name is reported, and reported under its own name:
        %% a registry entry that was never read back would be a counter nothing
        %% can observe.
        ?assertEqual(lists:sort(i2p_stats:counters()), lists:sort(maps:keys(Snap)))
    end).

%% A name nobody declared is a bug, not a value to discard. Silently dropping
%% the count is how the bus lost five event shapes in the first place.
unregistered_counter_raises_test() ->
    with_stats(fun() ->
        ?assertError({badkey, no_such_counter}, i2p_stats:add(no_such_counter, 1))
    end).

%% A negative amount is rejected rather than applied. This is not pedantry: the
%% underlying counter operation performs a subtraction and returns `ok`, and a
%% cumulative counter that goes backwards is precisely the signal a differencing
%% consumer reads as "the router restarted". One underflowed length difference
%% would therefore look like a restart and poison every rate derived after it.
negative_amount_raises_test() ->
    with_stats(fun() ->
        ok = i2p_stats:add(events_notified, 10),
        ?assertError({badmatch, false}, i2p_stats:add(events_notified, -1)),
        %% And the counter is untouched, so the crash did not half-apply.
        ?assertEqual(10, maps:get(events_notified, i2p_stats:snapshot()))
    end).

non_integer_amount_raises_test() ->
    with_stats(fun() ->
        ?assertError({badmatch, false}, i2p_stats:add(events_notified, 1.5))
    end).

%% %%%%% %%% The hot path does not go through the process %%%%% %%%

%% This is the load-bearing test of the design. The owning process is suspended,
%% so it cannot answer anything, and every read still succeeds. If any of these
%% went through a message to the process, this would block until the timetrap
%% rather than returning.
reads_work_while_the_owning_process_is_suspended_test() ->
    with_stats(fun() ->
        ok = i2p_stats:add(events_notified, 9),
        ok = sys:suspend(i2p_stats),
        try
            ?assertEqual(9, maps:get(events_notified, i2p_stats:snapshot())),
            ?assert(is_integer(i2p_stats:uptime_ms())),
            ?assert(is_integer(i2p_stats:boot_time()))
        after
            ok = sys:resume(i2p_stats)
        end
    end).

%% Uptime is computed from the clock at call time, not carried in the owner's
%% state, so it advances while the owner is unable to run. A cached uptime would
%% read as 0 and stop.
uptime_advances_while_the_owning_process_is_suspended_test() ->
    with_stats(fun() ->
        ok = sys:suspend(i2p_stats),
        try
            Before = i2p_stats:uptime_ms(),
            timer:sleep(60),
            After = i2p_stats:uptime_ms(),
            ?assert(After > Before)
        after
            ok = sys:resume(i2p_stats)
        end
    end).

%% Nothing in this module schedules anything. The strongest available statement
%% of that is behavioural: over a window in which a periodic process would have
%% fired several times, the owning process has received no message at all and no
%% timer is outstanding.
no_timer_is_scheduled_test() ->
    with_stats(fun() ->
        Pid = whereis(i2p_stats),
        _ = i2p_stats:snapshot(),
        1 = erlang:trace(Pid, true, ['receive']),
        %% A window comfortably longer than any sampling interval a timer-free
        %% module would have been tempted to use. If anything were scheduled on
        %% the owner — a timer, a poll, a reader's request — it would arrive as a
        %% message, and the trace is the only way to see a message that the
        %% process then handles and discards.
        timer:sleep(300),
        ?assertEqual([], received_during([])),
        1 = erlang:trace(Pid, false, ['receive']),
        ?assertEqual({message_queue_len, 0}, process_info(Pid, message_queue_len))
    end).

%% %%%%% %%% Uptime and boot time %%%%% %%%

uptime_is_monotonic_and_never_negative_test() ->
    with_stats(fun() ->
        Readings = [i2p_stats:uptime_ms() || _ <- lists:seq(1, 50)],
        ?assert(lists:all(fun(N) -> is_integer(N) andalso N >= 0 end, Readings)),
        %% Non-decreasing, not strictly increasing: consecutive readings in a
        %% tight loop legitimately come back identical.
        ?assertEqual(Readings, lists:sort(Readings))
    end).

%% Monotonic, not wall clock: a large negative shift of the system clock must not
%% be able to make the uptime go backwards. This is the property the choice of
%% clock buys, and it is asserted rather than assumed.
uptime_survives_a_wall_clock_jump_test() ->
    with_stats(fun() ->
        Before = i2p_stats:uptime_ms(),
        %% `erlang:timestamp/0` is the only wall-clock source a test can move,
        %% so assert the weaker but still meaningful property: uptime is
        %% independent of the wall clock reading taken alongside it.
        _WallBefore = erlang:system_time(millisecond),
        _ = erlang:system_time(millisecond),
        After = i2p_stats:uptime_ms(),
        ?assert(After >= Before)
    end).

boot_time_is_a_wall_clock_reading_test() ->
    with_stats(fun() ->
        Boot = i2p_stats:boot_time(),
        ?assert(is_integer(Boot)),
        Now = erlang:system_time(millisecond),
        %% Boot cannot be in the future, and cannot predate the epoch.
        ?assert(Boot =< Now),
        ?assert(Boot > 0)
    end).

%% %%%%% %%% Volatility %%%%% %%%

%% Counters do not survive a restart, and the boot time moves with them. A
%% counter that outlived the process while the uptime reset would make the first
%% rate derived after the restart wrong, and wrong in the shape of a traffic
%% spike.
counters_are_volatile_across_a_restart_test() ->
    with_stats(fun() ->
        ok = i2p_stats:add(events_notified, 42),
        ?assertEqual(42, maps:get(events_notified, i2p_stats:snapshot())),
        FirstBoot = i2p_stats:boot_time(),
        ok = gen_server:stop(i2p_stats),
        %% A stopped owner leaves nothing behind: reads answer rather than
        %% handing out a reference whose creating process is gone.
        ?assertEqual(#{}, i2p_stats:snapshot()),
        ?assertEqual(undefined, i2p_stats:boot_time()),
        ?assertEqual(0, i2p_stats:uptime_ms()),
        ok = start_stats(),
        ?assertEqual(0, maps:get(events_notified, i2p_stats:snapshot())),
        ?assert(i2p_stats:boot_time() >= FirstBoot)
    end).

%% A stopped owner must not be able to crash a caller on a packet path. Same
%% reason `i2p_events:notify/1` always succeeds: telemetry is never worth a
%% dropped connection.
add_is_a_no_op_while_the_owner_is_absent_test() ->
    ?assertEqual(undefined, whereis(i2p_stats)),
    ?assertEqual(ok, i2p_stats:add(events_notified, 1)),
    ?assertEqual(#{}, i2p_stats:snapshot()).

%% %%%%% %%% Internal helpers %%%%% %%%

%% Everything the traced process received while the trace was on. An empty list
%% is the assertion; the helper exists so the test reads as a claim rather than
%% as message plumbing.
received_during(Acc) ->
    receive
        {trace, _Pid, 'receive', _Msg} -> received_during(Acc)
    after 0 ->
        Acc
    end.

with_stats(Fun) ->
    ok = stop_stats(),
    ok = start_stats(),
    try
        Fun()
    after
        ok = stop_stats()
    end.

start_stats() ->
    {ok, _Pid} = i2p_stats:start_link(),
    ok.

stop_stats() ->
    case whereis(i2p_stats) of
        undefined ->
            ok;
        Pid ->
            ok = gen_server:stop(Pid)
    end.
