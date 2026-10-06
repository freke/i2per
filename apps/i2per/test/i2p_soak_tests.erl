%% The acceptance criterion for the soak harness is not that its self-checks are
%% present. It is that they **fail when their invariant is violated** — because
%% a check that has only ever been seen green is a comment with a function
%% around it, and the whole reason the first version of this harness was
%% discarded is that its three bugs produced confident wrong answers rather than
%% errors.
%%
%% Every case below drives the *same* exported functions the soak run calls, with
%% an input that violates the invariant, and asserts `ok =:= false`. Where a
%% check could pass for the wrong reason, the case pins that too.
-module(i2p_soak_tests).

-include_lib("eunit/include/eunit.hrl").

-define(BYTES, 4 * 1024 * 1024).

%% %%%%% %%% Check 1: the census must not be empty %%%%% %%%

%% This is the shape of the original bug, reproduced exactly rather than
%% described. The broken harness built `{Pid, Info}` pairs out of
%% `erlang:process_info/2`'s **item-list** return — a proplist, not the tuple —
%% so its comprehension matched nothing and it reported an empty census for an
%% entire run.
%% The generator pattern is the bug. Note this case asserts the **measured**
%% shape, which is not what the ticket described: the ticket said the item-list
%% form returns a proplist "and only the no-item form returns the [Pid, Info]
%% pair". It does not. Measured on OTP 28.5, the no-item form also returns a bare
%% proplist, so `{Pid, Info}` matches in *neither* form -- which makes the hazard
%% broader than reported and the fix unconditional.
no_process_info_form_returns_the_pid_alongside_the_readings_test() ->
    %% Both multi-item forms are bare proplists: a list, never a tuple. Only the
    %% single-item form gives back a pair, and that pair is `{Key, Value}` -- it
    %% never mentions the pid either, so the caller always has to supply it.
    ?assertEqual([], [{P, I} || Pid <- erlang:processes(), {P, I} <- [item_list(Pid)]]),
    ?assertEqual([], [
        {P, I}
     || Pid <- erlang:processes(),
        {P, I} <- [erlang:process_info(Pid, [message_queue_len])]
    ]),
    ?assert(is_list(erlang:process_info(self()))),
    ?assertNot(is_tuple(erlang:process_info(self()))),
    ?assertMatch({message_queue_len, _}, erlang:process_info(self(), message_queue_len)).

broken_census_comprehension_yields_nothing_test() ->
    Items = [message_queue_len, total_heap_size],
    Buggy = [{P, I} || Pid <- erlang:processes(), {P, I} <- [item_list(Pid, Items)]],
    ?assertEqual([], Buggy),
    ?assert(length(erlang:processes()) > 1).

empty_census_is_refused_test() ->
    ?assertEqual({error, empty_census}, i2p_soak_census:require_non_empty(#{})).

census_not_empty_fails_on_an_empty_census_test() ->
    ?assertNot(ok_of(i2p_soak_selfcheck:census_not_empty(#{}))).

census_not_empty_passes_on_a_real_census_test() ->
    ?assert(ok_of(i2p_soak_selfcheck:census_not_empty(read_census()))).

%% The fix is that the pairing is built from the pid the reader already holds, so
%% there is nothing to mis-match. This pins the consequence: every process the
%% reader read is present exactly once.
census_pairs_every_process_it_read_test() ->
    Census = read_census(),
    ?assert(maps:is_key(self(), Census)),
    ?assertEqual(map_size(Census), length(lists:usort(maps:keys(Census)))),
    ?assertEqual(
        [binary_bytes, heap_words, mailbox, module, reductions],
        lists:sort(maps:keys(maps:get(self(), Census)))
    ).

%% %%%%% %%% Check 2: a known-bad mailbox must be reported %%%%% %%%

%% A census that read nothing produces no ranking at all, so the flooded pid
%% cannot appear in it. This is the rank going blind in the one shape a
%% census-only check would miss.
known_bad_mailbox_fails_on_an_empty_delta_test() ->
    ?assertNot(ok_of(i2p_soak_selfcheck:known_bad_mailbox_is_bad(empty_delta(), self(), 5000))).

known_bad_mailbox_fails_when_the_fault_is_not_there_test() ->
    Flooded = spawn(fun() ->
        receive
            _ -> ok
        end
    end),
    try
        %% Present, but not growing: a rank that could see the pid and still
        %% report nothing has to fail too.
        Delta = delta(#{Flooded => growth(#{mailbox => 0})}),
        ?assertNot(ok_of(i2p_soak_selfcheck:known_bad_mailbox_is_bad(Delta, Flooded, 5000)))
    after
        exit(Flooded, kill)
    end.

known_bad_mailbox_passes_when_the_fault_is_visible_test() ->
    Flooded = spawn(fun() ->
        receive
            _ -> ok
        end
    end),
    try
        Delta = delta(#{Flooded => growth(#{mailbox => 5000})}),
        ?assert(ok_of(i2p_soak_selfcheck:known_bad_mailbox_is_bad(Delta, Flooded, 5000)))
    after
        exit(Flooded, kill)
    end.

%% %%%%% %%% Check 3: a seeded leak must be flagged %%%%% %%%

seeded_leak_fails_when_the_process_is_absent_test() ->
    Ghost = spawn(fun() -> ok end),
    timer:sleep(20),
    ?assertNot(is_process_alive(Ghost)),
    ?assertNot(ok_of(i2p_soak_selfcheck:seeded_leak_is_flagged(empty_delta(), Ghost))).

%% It has to fail rather than raise: a check that crashed on the fault it found
%% would report nothing at all.
seeded_leak_fails_rather_than_raising_on_an_absent_pid_test() ->
    ?assertNot(ok_of(i2p_soak_selfcheck:seeded_leak_is_flagged(empty_delta(), self()))).

%% This case is why the census reads the `binary` item at all. Measured on this
%% build, a process holding a 4 MB refc binary reports `total_heap_size` 233
%% words and `erlang:process_info(Pid, memory)` 2624 bytes — neither counts the
%% binary. So the same seeded leaker is invisible to a heap-only delta and
%% visible to the real one, which is exactly how the original harness was able to
%% call an 11 GB refc-binary run clean.
census_sees_a_refc_binary_that_heap_readings_cannot_test() ->
    {Leaker, _Ref} = i2p_soak_selfcheck:seed_leaky_process(self(), ?BYTES),
    try
        Before = read_census(),
        Leaker ! {fill, ?BYTES},
        receive
            {leaky, _Pid, Bytes} -> ?assertEqual(?BYTES, Bytes)
        end,
        Delta = i2p_soak_census:delta(Before, read_census()),
        HeapOnly = zero_binary_readings(Delta),
        ?assertNot(ok_of(i2p_soak_selfcheck:seeded_leak_is_flagged(HeapOnly, Leaker))),
        ?assert(ok_of(i2p_soak_selfcheck:seeded_leak_is_flagged(Delta, Leaker)))
    after
        i2p_soak_selfcheck:stop_fixtures([Leaker])
    end.

%% %%%%% %%% The reconnect fixture must prove it can fail %%%%% %%%

%% **Acceptance criterion 4, discharged.** A process count that is flat is only
%% meaningful if it would not have been flat for a fixture that leaked. So this
%% case measures both halves of the same reconnect: fixtures that stop their own
%% children, and fixtures that do not.
%%
%% `restart => temporary` children are never reaped by their supervisor, so the
%% second half has to leave processes behind. If it does not, the criterion is
%% measuring nothing and `fixture_delta` in the report is decoration.
%%
%% All three assertions share one supervisor because its registered name is
%% released asynchronously on teardown, and a second start races the first
%% teardown into `already_started`.
reconnect_cycle_is_flat_only_because_fixtures_clean_up_after_themselves_test_() ->
    {setup, fun start_ssu2_sup/0, fun stop_sup/1, fun(_) ->
        Key = crypto:strong_rand_bytes(32),
        [
            {"fixtures that stop their own children leave the node flat",
                ?_assertEqual(0, cycles(Key, true))},
            {"the harness reports a flat count over that same cycle",
                ?_assertEqual(0, i2p_soak:reconnect_cycle(#{cycles => 3, top => 1}))},
            %% Deliberately last: this one *dirties* the node, by design, so
            %% measuring it before the flat cases would make them non-flat for a
            %% reason that has nothing to do with the fixtures under test. The
            %% supervisor teardown reaps what it leaves.
            {"fixtures that do not stop them are measurable", ?_assert(cycles(Key, false) > 0)}
        ]
    end}.

%% %%%%% %%% The offered rate must be bounded, not clamped %%%%% %%%

rate_is_refused_not_clamped_test() ->
    {error, Evidence} = i2p_soak:parse_rate(1000000),
    ?assert(string:find(Evidence, "1000000") =/= nomatch).

rate_refuses_too_low_test() ->
    ?assertMatch({error, _}, i2p_soak:parse_rate(0)).

%% There is no `rate_bounds/0` to read the numbers from -- that accessor was a
%% second copy of two constants in a shape dialyzer then demanded a spec for, and
%% the behaviour is the only place they need to live. So the boundary is pinned by
%% behaviour: 1 is accepted, 0 is not, and 20000 is the ceiling.
rate_accepts_the_bounds_test() ->
    ?assertMatch({ok, 1}, i2p_soak:parse_rate(1)),
    ?assertMatch({ok, 20000}, i2p_soak:parse_rate(20000)),
    ?assertMatch({error, _}, i2p_soak:parse_rate(20001)),
    ?assertMatch({ok, 500}, i2p_soak:parse_rate("500")).

rate_rejects_a_non_integer_test() ->
    ?assertMatch({error, _}, i2p_soak:parse_rate("fast")).

%% %%%%% %%% The delta must not invent a reading %%%%% %%%

%% The corpse bug, reproduced. An absent pid defaulted to `0`, so a process that
%% died between two snapshots scored `0 - 20941606` and sorted to the top of a
%% table headed *top consumers*.
a_departed_pid_gets_no_growth_and_no_rank_test() ->
    Ghost = spawn(fun() -> ok end),
    timer:sleep(20),
    Before = #{Ghost => sample(#{reductions => 20941606})},
    Delta = i2p_soak_census:delta(Before, #{}),
    ?assertEqual(0, map_size(maps:get(survivors, Delta))),
    ?assert(maps:is_key(Ghost, maps:get(departed, Delta))),
    ?assertEqual([], i2p_soak_census:top_consumers(Delta, 5)).

%% An arrived pid has no earlier reading either, so there is nothing to rank — and
%% a rank that included it would report a growth from zero, which is the same
%% invention from the other direction.
an_arrived_pid_gets_no_growth_test() ->
    Arrived = spawn(fun() ->
        receive
            _ -> ok
        end
    end),
    try
        Delta = i2p_soak_census:delta(#{}, #{Arrived => sample(#{reductions => 20941606})}),
        ?assert(maps:is_key(Arrived, maps:get(arrived, Delta))),
        ?assertEqual(0, map_size(maps:get(survivors, Delta))),
        ?assertEqual([], i2p_soak_census:top_consumers(Delta, 5))
    after
        exit(Arrived, kill)
    end.

%% %%%%% %%% The rank must show the largest first %%%%% %%%

%% `lists:sublist/2` on an ascending list returns the N **smallest**, so reversing
%% afterwards ranks the least interesting rows at the top — a table headed *top
%% consumers* whose every row is zero. The real harness shipped this bug and the
%% mailbox check caught it, so the order is pinned here.
rank_returns_the_largest_first_test() ->
    Delta = delta(#{a => growth(#{}), b => growth(#{mailbox => 900}), c => growth(#{mailbox => 40})}),
    ?assertEqual([b, c], [maps:get(pid, Row) || Row <- i2p_soak_census:top_mailboxes(Delta, 2)]).

rank_names_the_module_it_ranked_test() ->
    Delta = delta(#{a => growth(#{})}),
    [Row] = i2p_soak_census:top_consumers(Delta, 1),
    ?assertEqual(maps:get(a, maps:get(survivors, Delta)) =/= undefined, true),
    ?assertMatch(#{pid := a, module := unknown, growth := #{mailbox := 0}}, Row).

%% %%%%% %%% The verdict must not call a slope a leak %%%%% %%%

%% Acceptance criterion 5: distinguish traffic-proportional retention from
%% traffic-independent caching, and decline to call a slope a leak on its own.
%%
%% Driven on **memory**, because that is what `m:i2p_soak_census` classifies on
%% and the reason is worth pinning: reductions are monotonic, so a reduction-based
%% classifier can never reach its negative branch and every run would answer
%% `traffic_independent`. A verdict that cannot answer any other way is a verdict
%% with one answer.
verdict_separates_the_two_retention_causes_test() ->
    Grown = delta(#{a => growth(#{heap_words => 5000})}),
    Released = delta(#{a => growth(#{heap_words => -5000})}),
    ?assertEqual(traffic_proportional, retention(Grown, Released)),
    ?assertEqual(traffic_independent, retention(Grown, Grown)),
    ?assertEqual(inconclusive, retention(Released, Released)),
    %% Unchanged retention under load is nothing to attribute.
    ?assertEqual(inconclusive, retention(delta(#{}), delta(#{}))).

%% Off-heap binary memory counts toward retention, in words, without being
%% overstated eightfold by being added to a heap reading as if it were words.
verdict_counts_retained_binary_in_words_test() ->
    Binary = delta(#{a => growth(#{heap_words => 0, binary_bytes => 8 * 1048576})}),
    #{slope_words := Words} = i2p_soak_census:verdict(Binary, Binary, 10),
    ?assertEqual(1048576, Words).

%% The verdict's whole claim is that it declines to name a leak, so the case pins
%% two things: that there is no **field** to say it in, and that the prose a reader
%% would act on carries the disclaimer rather than the accusation. The word "leak"
%% appears in that note precisely to deny it, so asserting its absence would be
%% asserting the opposite of the intent.
verdict_carries_no_leak_verdict_test() ->
    Grown = delta(#{a => growth(#{heap_words => 5000})}),
    Verdict = i2p_soak_census:verdict(Grown, Grown, 1000),
    ?assertEqual(
        [note, offered_events, recovered_words, retention, slope_words],
        lists:sort(maps:keys(Verdict))
    ),
    Note = maps:get(note, Verdict),
    ?assertNotEqual(nomatch, string:find(Note, <<"not a leak">>)),
    ?assertNotEqual(nomatch, string:find(Note, <<"slope">>)).

%% %%%%% %%% A negative delta must not print as zero %%%%% %%%

%% The formatter bug: every negative delta printed as exactly `0.00`, so a 7 GB
%% *drop* was reported as `raw 0.00` and read as no change.
words_mb_keeps_the_sign_of_a_drop_test() ->
    ?assertEqual("-54613.33 MB", i2p_soak_census:words_mb(0 - 7158278826)).

words_mb_renders_a_gain_signed_test() ->
    ?assertEqual("54613.33 MB", i2p_soak_census:words_mb(7158278826)).

%% Binary memory is counted in bytes by `process_info/2` and words by
%% `total_heap_size`. Conflating them would overstate every binary figure by 8x.
bytes_mb_and_words_mb_are_different_scales_test() ->
    ?assertEqual("1.00 MB", i2p_soak_census:bytes_mb(1048576)),
    ?assertEqual("1.00 MB", i2p_soak_census:words_mb(131072)).

%% %%%%% %%% %%% Retained heap needs a barrier, not a request %%%%% %%%

%% `erlang:garbage_collect/1` answers `true` once the request has been **sent**.
%% The collection happens when the target is next scheduled, so a reading taken
%% straight afterwards samples whatever the target had already collected. Measured
%% on this build against the router's own processes: `376, 233, 376, 233, 376,
%% 233` for one process asked to collect six times, and `152022, 101621, 148473,
%% 101621, 148473` node-wide.
%%
%% **There is deliberately no case asserting that oscillation.** It is
%% load-dependent -- an idle process gets collected before the read and does not
%% wobble -- so a case pinning it would be red on a quiet runner and green on a
%% loaded one. The maintainer's rule is that such a case is a defect rather than a
%% flake to re-roll, so the property tested is the one below: with the barrier,
%% re-offering the same garbage does not move the reading.
repeated_dirty_then_collect_leaves_the_reading_unchanged_test() ->
    Pid = dirty(),
    try
        First = heap_after(Pid),
        Later = [
            begin
                dirty_in(Pid),
                heap_after(Pid)
            end
         || _ <- lists:seq(1, 5)
        ],
        ?assertEqual(1, length(lists:usort([L - First || L <- Later])))
    after
        exit(Pid, kill)
    end.

%% The barrier must not kill the process it measures, and must not be a
%% `gen_server:call`: this tree's managers die on an unhandled call, and a
%% measurement that takes the router down is not a measurement. `i2p_netdb_srv`
%% is the one that proved it -- a `status` call killed it during the probe that
%% found this.
the_collect_barrier_leaves_the_process_alive_test() ->
    Pid = dirty(),
    try
        ok = i2p_soak_census:collect([Pid]),
        ?assert(is_process_alive(Pid))
    after
        exit(Pid, kill)
    end.

%% A target that cannot answer the barrier -- because it is not a `proc_lib`
%% process -- must cost the timeout once and then be skipped, not stall the run
%% and not be silently treated as collected. Measured at 5000 us against a bare
%% `spawn`, which is why the timeout is 500.
a_target_that_cannot_answer_costs_one_timeout_test() ->
    Bare = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    try
        {Micros, ok} = timer:tc(fun() -> i2p_soak_census:collect([Bare]) end),
        ?assert(Micros >= 500000),
        ?assert(Micros < 2000000),
        ?assert(is_process_alive(Bare))
    after
        exit(Bare, kill)
    end.

%% `f:retained/1` reads only the pids it was given. A reading that swept the node
%% would be both slower and noisier: `sys:get_status/1` against a kernel process
%% takes seconds per call and logs `unexpected message` from `erts_trace_cleaner`,
%% `socket-registry` and the `global_name_server`.
retained_reads_only_the_pids_it_was_given_test() ->
    Pid = dirty(),
    try
        Census = i2p_soak_census:retained([Pid]),
        ?assertEqual([Pid], maps:keys(Census))
    after
        exit(Pid, kill)
    end.

%% The offset-binary blind spot, restated for the retained reading: a process
%% holding a large refc binary reports almost no `total_heap_size`, so a retained
%% reading that ignored `binary` would report a megabyte-holding process as holding
%% nothing.
retained_counts_a_refc_binary_that_heap_alone_cannot_test() ->
    {Leaker, _Ref} = i2p_soak_selfcheck:seed_leaky_process(self(), ?BYTES),
    try
        fill(Leaker),
        Words = i2p_soak_census:words(i2p_soak_census:retained([Leaker])),
        %% The binary contributes its full 4 MB in words; the rest is the one-block
        %% heap the leaker lives on, which is small beside it.
        ?assertMatch(_ when Words >= ?BYTES div 8, Words),
        ?assertMatch(_ when Words < ?BYTES div 8 + 4096, Words)
    after
        i2p_soak_selfcheck:stop_fixtures([Leaker])
    end.

%% **The defect this case exists to pin.** `m:i2p_soak_selfcheck`'s leaker used to
%% bind its binary, measure it with `byte_size/1` and never mention it again, so a
%% forced collection reclaimed it: the fixture meant to prove a census sees
%% retention was actually reporting uncollected garbage, and passed every check
%% built on it because nothing had collected the heap yet.
%%
%% `f:retained/1` forces the collection and waits for it, which is what exposed it
%% -- 4 MB before, 233 words after. Without this case the fixture can go back to
%% allocating and dropping, and every check that uses it will still be green,
%% because the binary is still sitting in a heap nobody has collected.
the_seeded_leaker_retains_rather_than_allocating_and_dropping_test() ->
    {Leaker, _Ref} = i2p_soak_selfcheck:seed_leaky_process(self(), ?BYTES),
    try
        fill(Leaker),
        Words = i2p_soak_census:words(i2p_soak_census:retained([Leaker])),
        ?assertMatch(_ when Words >= ?BYTES div 8, Words),
        %% And it stays that way: a second forced collection must not shrink it,
        %% which is the difference between holding and having merely allocated.
        ?assertEqual(Words, i2p_soak_census:words(i2p_soak_census:retained([Leaker])))
    after
        i2p_soak_selfcheck:stop_fixtures([Leaker])
    end.

%% `f:words/1` is the one place the conversion happens: binary bytes are counted
%% in bytes by `process_info/2` and in words by `total_heap_size`, so adding them
%% raw would overstate every binary figure eightfold.
words_converts_off_heap_binary_into_words_test() ->
    Sample = #{
        module => x, mailbox => 0, reductions => 0, heap_words => 0, binary_bytes => 8 * 1048576
    },
    ?assertEqual(1048576, i2p_soak_census:words(#{p => Sample})).

%% %%%%% %%% %%% ETS %%%%% %%%

%% Named tables only, and a vanished table is skipped rather than recorded as
%% zero -- absence is not a reading of nothing, which is the reason the census
%% treats a dead process the same way.
ets_bytes_reports_named_tables_as_non_negative_test() ->
    Table = ets:new(i2per_soak_named_probe, [named_table, public]),
    true = ets:insert(Table, {k, v}),
    try
        Bytes = i2p_soak_census:ets_bytes(),
        ?assert(is_map_key(i2per_soak_named_probe, Bytes)),
        ?assert(maps:get(i2per_soak_named_probe, Bytes) > 0),
        ?assert(lists:all(fun(V) -> is_integer(V) andalso V >= 0 end, maps:values(Bytes)))
    after
        ets:delete(Table)
    end.

%% %%%%% %%% %%% Helpers %%%%% %%%

%% A `gen_server` that holds a big referenced binary and, on `dirty`, builds and
%% drops a larger one. It must be a `gen_server`, not a bare spawn and not a
%% plain `proc_lib:spawn`: the barrier `f:collect/1` sends a system message, and
%% only a `proc_lib`/`gen` loop handles those. Verified against the router's own
%% children -- all such processes -- where `collect/1` takes **2 us**, not a
%% full timeout.
dirty() ->
    {ok, Pid} = i2p_soak_fixture_server:start(),
    ok = i2p_soak_fixture_server:dirty(Pid),
    Pid.

dirty_in(Pid) ->
    i2p_soak_fixture_server:dirty(Pid),
    ok.

%% The leaker reports **after** allocating, so waiting for the message cannot be
%% reordered before the allocation it reports -- that is what makes it a barrier
%% rather than a hope.
fill(Leaker) ->
    Leaker ! {fill, ?BYTES},
    receive
        {leaky, _Pid, Bytes} -> Bytes
    end.

heap(Pid) ->
    {total_heap_size, Words} = erlang:process_info(Pid, total_heap_size),
    Words.

%% Clamp the fixture with the barrier and return the post-collection reading.
heap_after(Pid) ->
    ok = i2p_soak_census:collect([Pid]),
    heap(Pid).

ok_of(#{ok := Ok}) -> Ok.

item_list(Pid) ->
    erlang:process_info(Pid).

item_list(Pid, Items) ->
    erlang:process_info(Pid, Items).

read_census() ->
    {ok, Census} = i2p_soak_census:snapshot(),
    Census.

sample(Fields) ->
    maps:merge(#{module => unknown, mailbox => 0, heap_words => 0, binary_bytes => 0}, Fields).

growth(Fields) ->
    maps:merge(#{mailbox => 0, heap_words => 0, binary_bytes => 0, reductions => 0}, Fields).

%% Build a delta whose survivors are exactly `Pids`. Atoms are used as keys where
%% a case only cares about ranking, so the figures read as the numbers they mean
%% rather than as `<0.91.0>`.
delta(Pids) ->
    #{
        survivors => maps:map(fun(_P, G) -> #{module => unknown, growth => G} end, Pids),
        arrived => #{},
        departed => #{}
    }.

empty_delta() ->
    #{survivors => #{}, arrived => #{}, departed => #{}}.

%% The same delta with the off-heap reading removed, which is what a census built
%% from `total_heap_size` alone would have produced.
%% `maps:map/2` on a **map** wants the new value alone; returning `{Key, Value}`
%% is the iterator form and silently wraps every entry in a tuple.
zero_binary_readings(Delta) ->
    #{survivors := Survivors} = Delta,
    Delta#{
        survivors => maps:map(
            fun(_Pid, #{growth := G} = Entry) -> Entry#{growth => G#{binary_bytes => 0}} end,
            Survivors
        )
    }.

retention(Loaded, Drained) ->
    maps:get(retention, i2p_soak_census:verdict(Loaded, Drained, 1000)).

%% %%%%% %%% Reconnect measurement %%%%% %%%

%% N cycles of open-then-stop, or open-then-leak when `Stop` is false. Returns
%% the change in the process count across them.
%%
%% This is `m:i2p_soak`'s reconnect fixture with the stop made optional, which is
%% the whole point: the harness's own version cannot leak, so this has to be able
%% to for the harness's count to mean anything.
cycles(Key, Stop) ->
    Before = length(erlang:processes()),
    lists:foreach(fun(_) -> cycle(Key, Stop) end, lists:seq(1, 5)),
    timer:sleep(200),
    length(erlang:processes()) - Before.

cycle(Key, Stop) ->
    case i2p_ssu2_sup:start_charlie(Key) of
        {ok, _Charlie} when Stop ->
            ok = stop_charlies(),
            timer:sleep(20);
        {ok, _Charlie} ->
            timer:sleep(20);
        {error, _Reason} ->
            ok
    end.

%% `terminate_child/2` deletes a `temporary` child as part of the same call, so
%% there is no `delete_child/2` here either -- adding one answers `not_found` on
%% every cycle. Same trap the harness documents in `m:i2p_soak:stop_charlie/0`.
stop_charlies() ->
    lists:foreach(
        fun(Id) -> ok = supervisor:terminate_child(i2p_ssu2_sup, Id) end,
        [
            Id
         || {Id, _Pid, _Type, _Modules} <- supervisor:which_children(i2p_ssu2_sup),
            is_tuple(Id),
            element(1, Id) =:= ssu2_charlie
        ]
    ).

start_ssu2_sup() ->
    {ok, Pid} = i2p_ssu2_sup:start_link(),
    Pid.

stop_sup(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    ok.
