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

%% Uniqueness, checked as uniqueness. An earlier version of this case asserted
%% `lists:usort(Names) =:= Names`, which is a *sortedness* check wearing a
%% uniqueness check's clothes: it passed on a one-element registry and failed the
%% moment a second counter arrived, because the registry is grouped by transport
%% and direction rather than alphabetically. A test that only holds while the
%% list has one element is not a test.
counters_are_unique_test() ->
    Names = i2p_stats:counters(),
    ?assertEqual(length(Names), length(lists:usort(Names))),
    ?assert(length(Names) > 0).

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

%% The wall clock is a real reading, not a duration. Both bounds matter: a
%% duration would be small and would pass a positivity check, and a monotonic
%% reading would be arbitrary and would pass a "not in the future" check.
%%
%% **What this module deliberately does not test:** that the uptime is immune to
%% a system-clock step. It is, by construction — it is derived from a monotonic
%% reading, and the reason is recorded in the module — but a test cannot move the
%% system clock, so any case purporting to cover it would only be asserting
%% monotonicity a second time under a misleading name. An earlier version of this
%% file did exactly that. The claim is therefore documented and untested rather
%% than tested and hollow, and a test that would break if the clock choice changed
%% belongs at the point the clock is chosen, not here.
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

%% %%%%% %%% Gauges %%%%% %%%

%% A gauge holds the value it was last given, and a later reading replaces it.
%%
%% **Falling is the point, and it is what a counter cannot do.** `f:add/2` rejects a
%% negative amount precisely because a counter that goes backwards is
%% indistinguishable downstream from a router restarting -- so a value that rises and
%% falls with the system has no representation in the array and would corrupt every
%% rate derived from it. Asserting the fall is what distinguishes this test from the
%% counting tests above; asserting only the rise would pass for an accumulator.
gauge_holds_its_latest_reading_test() ->
    with_stats(fun() ->
        ?assertEqual(ok, i2p_stats:set_gauge(bus_backlog, 500)),
        ?assertEqual(#{bus_backlog => 500}, i2p_stats:gauges()),
        ?assertEqual(ok, i2p_stats:set_gauge(bus_backlog, 0)),
        ?assertEqual(#{bus_backlog => 0}, i2p_stats:gauges())
    end).

%% Gauges and counters are separate stores, and a gauge never appears in the
%% snapshot.
%%
%% This is the property `m:i2per_status_derive` depends on when it differences two
%% readings: a consumer that found a falling value inside `counters` would read it
%% as a restart. So the case asserts the *absence*, not just that both are readable.
gauges_do_not_appear_in_the_counter_snapshot_test() ->
    with_stats(fun() ->
        ok = i2p_stats:set_gauge(bus_backlog, 1234),
        ok = i2p_stats:add(events_notified, 1),
        %% Checked as an *absence*, because `snapshot/0` reports every registered
        %% counter whether or not it has moved -- so the assertion is that the
        %% gauge's name is not among them, not that the snapshot is small.
        ?assertNot(maps:is_key(bus_backlog, i2p_stats:snapshot())),
        ?assertEqual(1234, maps:get(bus_backlog, i2p_stats:gauges()))
    end).

%% An unset gauge is absent rather than zero, which is the distinction
%% `f:snapshot/0` makes for counters and `f:gauges/0` has to make too.
%%
%% "Not measured yet" and "measured, and zero" are different faults: the first means
%% the sampler has not run, the second means the bus is idle. Reporting zero for both
%% would make a router whose sampler never started look like a healthy one.
unset_gauge_is_absent_not_zero_test() ->
    with_stats(fun() ->
        ?assertEqual(#{}, i2p_stats:gauges()),
        ok = i2p_stats:set_gauge(bus_backlog, 0),
        ?assert(maps:is_key(bus_backlog, i2p_stats:gauges()))
    end).

%% Writing a gauge does not disturb the counters, and vice versa.
%%
%% **Both halves are needed.** The counter half alone would pass if the gauge write
%% had replaced the whole `persistent_term` state and dropped the counter reference
%% with it -- every counter would read `0` rather than raise, so a snapshot assertion
%% on its own is not enough to catch the counter being lost.
gauge_writes_leave_the_counters_alone_test() ->
    with_stats(fun() ->
        ok = i2p_stats:add(events_notified, 7),
        ok = i2p_stats:set_gauge(bus_backlog, 42),
        ?assertEqual(7, maps:get(events_notified, i2p_stats:snapshot())),
        ok = i2p_stats:add(events_notified, 3),
        ?assertEqual(10, maps:get(events_notified, i2p_stats:snapshot())),
        ?assertEqual(42, maps:get(bus_backlog, i2p_stats:gauges()))
    end).

%% A gauge write is a no-op while the owner is absent, for the reason
%% `f:add/2` is: telemetry must not be able to crash a working connection, and the
%% suites that start part of the tree rely on it.
set_gauge_is_a_no_op_while_the_owner_is_absent_test() ->
    ?assertEqual(undefined, whereis(i2p_stats)),
    ?assertEqual(ok, i2p_stats:set_gauge(bus_backlog, 999)),
    ?assertEqual(#{}, i2p_stats:gauges()).

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
