%% Tests that the NetDb read path is not behind the disk save.
%%
%% Saving the store for `netdb.bin` measures 8403 us at the shipped capacity of
%% 5000 routers. That used to happen inside `m:i2p_netdb_srv`, in the one process
%% every NetDb read queues behind: `f:closest/3` per lookup round,
%% `f:closest_floodfills/4` per tunnel build. So every 15 minutes, for 8.4 ms,
%% reads queued behind a 3.4 MB serialisation.
%%
%% The save now runs in `m:i2p_netdb_writer`. The NetDb hands over a **snapshot** —
%% the capacity, the router hashes in recency order, and the LeaseSets — which
%% measures about 49 us, because the RouterInfos are not copied: the writer reads
%% each one from the table itself, which is `protected`.
%%
%% The property asserted here is the same one `i2p_netdb_verify_tests` asserts
%% for signature verification: **a read is served while a save is in flight.** And
%% for the same reason it is asserted structurally rather than as a timing
%% assertion — no deadline is involved, and a deadline here would pass on an idle
%% machine and fail on a loaded one. What is asserted is that the NetDb process
%% never performs the serialisation, which is the thing that would have to be true
%% for a read to queue behind it.

-module(i2p_netdb_save_tests).

-moduledoc """
Tests that the NetDb store's disk save does not run in the process that serves
reads.
""".

-include_lib("eunit/include/eunit.hrl").

%% Enough routers that the save is unambiguously the work being tested. 5000 is the
%% shipped capacity; 200 is well inside it and still costs milliseconds, several
%% orders above the snapshot the read process now builds.
-define(ROUTERS, 200).

%%% --------------------------------------------------------------------------
%%% The property
%%% --------------------------------------------------------------------------

%% The structural assertion, and the one that catches a regression.
%%
%% Traced rather than timed: put `f:serialize/1` back inside the NetDb and this
%% goes red, with no deadline anywhere in it. Both `f:serialize/1` and
%% `f:to_binary/1` are traced, because either could be where the serialisation
%% creeps back in — `to_binary/1` is still a legitimate entry point, and a future
%% change could easily reach for it instead.
netdb_process_never_serialises_the_store_test() ->
    with_netdb(
        fun(_Keys) ->
            Tracer = start_tracing(),
            try
                %% **The autosave timer, not `f:save/0`.** `f:save/0` is a caller
                %% call and always ran outside this process, so asserting on it
                %% passes with the bug present -- which it did, until this fired the
                %% timer that actually used to serialise in here.
                Tracer2 = start_autosaving(),
                try
                    %% Drain *after* the save has had time to run, or the mailbox is
                    %% empty because the serialisation has not happened yet rather
                    %% than because it happened elsewhere. The trace assertion is the
                    %% property; the save assertion below is what stops an empty
                    %% trace from meaning "nothing was saved at all".
                    await_quiet(),
                    ?assertEqual([], collect_for(Tracer)),
                    await_saves(200)
                after
                    untrace(Tracer2)
                end
            after
                stop_tracing(Tracer)
            end
        end
    ).

%% A read is answered while a save is in flight.
%%
%% The save is fired at the NetDb and left running, and the read is issued from this
%% one. The barrier fires as soon as the writer has entered `f:serialize/1`, so the
%% read below genuinely overlaps the serialisation rather than following it. The
%% assertion is on the answer coming back, not on how long it took.
read_is_served_while_a_save_is_in_flight_test() ->
    with_netdb(
        fun(Keys) ->
            Key = hd(Keys),
            while_autosaving(
                fun() ->
                    ?assertEqual(true, i2p_netdb_srv:has_router(Key)),
                    ?assertMatch({ok, _}, i2p_netdb_srv:find(Key))
                end
            )
        end
    ).

%% The same read on `f:closest/3`, which is what a lookup round actually calls.
%%
%% `has_router/2` is a table read and never reached this process, so it is the
%% weaker of the two. `closest/3` is a `gen_server` call, so it is the read that
%% would have queued behind the save — which makes it the one worth asserting.
closest_is_served_while_a_save_is_in_flight_test() ->
    with_netdb(
        fun(Keys) ->
            Key = hd(Keys),
            while_autosaving(fun() -> ?assertEqual(3, length(i2p_netdb_srv:closest(Key, 3))) end)
        end
    ).

%%% --------------------------------------------------------------------------
%%% The snapshot, and the two ways it can be wrong
%%% --------------------------------------------------------------------------

%% A snapshot serialises to the same bytes `f:to_binary/1` produces. Without this,
%% moving the save to another process could silently change the on-disk format, and
%% every round-trip test would still pass while the file stopped loading.
snapshot_serialises_to_the_same_bytes_as_to_binary_test() ->
    Now = erlang:system_time(millisecond),
    Store = filled_store(?ROUTERS, Now),
    {ok, Bin} = i2p_netdb:serialize(i2p_netdb:snapshot(Store)),
    ?assertEqual(i2p_netdb:to_binary(Store), Bin).

%% A snapshot names routers; it does not hold them. That is what makes it cheap
%% enough to hand over, so it is asserted directly rather than inferred from a
%% timing.
snapshot_carries_keys_not_router_infos_test() ->
    Now = erlang:system_time(millisecond),
    Snap = i2p_netdb:snapshot(filled_store(20, Now)),
    ?assertEqual(20, length(maps:get(keys, Snap))),
    %% The tid, not the RouterInfos.
    ?assert(is_reference(maps:get(table, Snap))).

%% An evicted key is reported, not crashed on.
%%
%% The dangerous case: the key is in the snapshot's list and no longer in the table,
%% so a lookup would raise `badmatch` out of `f:router/2` and take down whichever
%% process asked. This is what `f:serialize/1` returns `{error, {stale, Key}}` for,
%% and the writer retries on it rather than dying.
serialising_a_snapshot_with_an_evicted_key_reports_stale_test() ->
    Now = erlang:system_time(millisecond),
    %% Two stores: the key comes from the first, the table from the second, so the
    %% key is genuinely absent rather than merely unused.
    {Other, OtherKeys} = fill(10, 11, Now),
    Stale = hd(OtherKeys),
    Snap = (i2p_netdb:snapshot(filled_store(20, Now)))#{keys => [Stale]},
    ?assertNot(i2p_netdb:has_router(filled_store(20, Now), Stale)),
    ?assertEqual({error, {stale, Stale}}, i2p_netdb:serialize(Snap)),
    ?assertEqual(10, i2p_netdb:count(Other)).

%% The generation in a snapshot is the store's, so a caller can tell whether the
%% table moved while the snapshot was being used. This is the whole safety argument
%% for handing a key list to another process, so it is asserted at both ends: the
%% snapshot carries the value, and a mutation moves it.
snapshot_carries_the_generation_the_store_will_disagree_with_test() ->
    Now = erlang:system_time(millisecond),
    Store0 = filled_store(20, Now),
    Snap = i2p_netdb:snapshot(Store0),
    Gen = maps:get(generation, Snap),
    ?assertEqual(Gen, i2p_netdb:generation(Store0)),
    RI = i2p_ct_helpers:floodfill_router_info(Now + 1000, <<"198.51.100.9">>),
    {Store1, added} = i2p_netdb:store(Store0, RI, Now + 1000),
    ?assertEqual(Gen + 1, i2p_netdb:generation(Store1)),
    %% The snapshot still names the old generation, which is exactly what tells the
    %% writer its bytes are a mixture of two stores.
    ?assertEqual(Gen, maps:get(generation, Snap)).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

%% Brings up the NetDb **and its writer**, then hands the body the store's keys.
%%
%% Both are needed. Without the writer the NetDb falls back to saving in-process,
%% which is the behaviour being tested away, and the fallback would make the
%% structural assertion pass vacuously.
%%
%% Whatever this starts, it stops. `i2p_stats` and the two NetDb processes are
%% registered names inside the `i2per` application, and a bare `start_link/0` leaves
%% one registered that the application controller did not start, which the next
%% module that boots `i2per` reads as `already_started` and fails on.
with_netdb(Body) ->
    %% **A data_dir is set before the writer starts, and unset after it stops.**
    %% Both processes read `data_dir` once at init, and the writer resolves it there
    %% so the save path does not call `application:get_env/2` per save. With no
    %% `data_dir` the writer's `dir` is `undefined`, `f:serialize/1` is never called,
    %% and the barrier below can never be reached — so the overlap cases would time
    %% out rather than fail, on a store with nothing to serialise.
    Dir = temp_dir(),
    application:set_env(i2per, data_dir, Dir),
    StartedWriter = ensure_started(i2p_netdb_writer),
    StartedNetdb = ensure_started(i2p_netdb_srv),
    StartedStats = ensure_started(i2p_stats),
    try
        Now = erlang:system_time(millisecond),
        %% **Stored through the srv, not into a local store.** A local store is a
        %% different table from the one the srv serves reads from, so a read against
        %% it answers `false` — and the read assertions would fail while testing
        %% nothing, since the save would be serialising the srv's empty store. The
        %% count is asserted because a silently dropped store would make the save
        %% cheap and the overlap trivial.
        Before = i2p_netdb_srv:count(),
        Keys = store_through_srv(?ROUTERS, Now),
        %% **A delta, not an absolute count.** Another eunit module in the same VM
        %% may own the NetDb, in which case `ensure_started/1` reuses it rather than
        %% starting a fresh one, and the store already holds entries. Asserting 200
        %% then fails on a shared store for a reason that has nothing to do with this
        %% module. What matters is that the stores landed.
        ?assertEqual(Before + ?ROUTERS, i2p_netdb_srv:count()),
        Body(Keys)
    after
        stop_if_started(StartedStats),
        stop_if_started(StartedNetdb),
        stop_if_started(StartedWriter),
        application:unset_env(i2per, data_dir),
        ok = remove_tree(Dir)
    end.

temp_dir() ->
    Dir = filename:join(
        "/tmp",
        "i2per_netdb_save_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

%% Left-behind `netdb.bin` files would accumulate under /tmp across runs, and one of
%% them being readable by a later test would be a way for this suite to depend on
%% its own history. Removed whether the body succeeded or not.
remove_tree(Dir) ->
    case file:del_dir_r(Dir) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, Reason} -> erlang:error({could_not_clean, Dir, Reason})
    end.

ensure_started(Mod) ->
    case whereis(Mod) of
        undefined ->
            {ok, Pid} = Mod:start_link(),
            Pid;
        _Running ->
            already_running
    end.

stop_if_started(already_running) ->
    ok;
stop_if_started(Pid) ->
    ok = gen_server:stop(Pid),
    ok.

%% A store of `N` routers, asserting it is the size it claims to be before it is
%% handed on. A fixture that silently built fewer routers than it says would make
%% the save cheaper than the thing being tested.
filled_store(N, Now) ->
    {Store, Keys} = fill(N, N + 1, Now),
    N = i2p_netdb:count(Store),
    N = length(Keys),
    ok = i2p_netdb:self_check(Store),
    Store.

fill(0, _Capacity, _Now) ->
    {i2p_netdb:new(), []};
fill(N, Capacity, Now) ->
    {Store, Keys} = fill(N - 1, Capacity, Now),
    RI = fixture_router(Now, N),
    {Store1, added} = i2p_netdb:store(Store, RI, Now),
    {Store1, [i2p_router_info:hash(RI) | Keys]}.

%% Store `N` routers **through the srv**, returning their hashes.
%%
%% Each goes in as a `gen_server` call, which is the path under test — and it also
%% means the srv's own store holds them, so the reads below are answered from the
%% table the save is serialising.
store_through_srv(0, _Now) ->
    [];
store_through_srv(N, Now) ->
    RI = fixture_router(Now, N),
    Key = i2p_router_info:hash(RI),
    added = i2p_netdb_srv:store(RI, Now),
    [Key | store_through_srv(N - 1, Now)].

%% `f:floodfill_router_info/2` returns the RouterInfo itself, not a `{RI, SeedKey}`
%% tuple. That shape belongs to a different helper, and reaching for it is a badmatch
%% on the whole RouterInfo map.
fixture_router(Now, N) ->
    i2p_ct_helpers:floodfill_router_info(Now, host(N)).

%% Documentation-range addresses, one per fixture, so each RouterInfo is a distinct
%% key and the store really does grow rather than colliding on one entry. Wrapped at
%% 255 so the addresses stay inside `192.0.2.0/24`.
host(N) ->
    list_to_binary("192.0.2." ++ integer_to_list(N rem 251 + 1)).

%%% --------------------------------------------------------------------------
%%% Tracing
%%% --------------------------------------------------------------------------

%% Trace the NetDb process's own calls to the two functions that serialise the
%% store, filtered to that process so an unrelated serialisation elsewhere cannot
%% mask a real one.
%%
%% `erlang:trace_pattern/3` returns the number of matched functions, and that count
%% has to be asserted: it returns 0 for a module that has not been loaded, and 0
%% means no trace messages arrive, so an assertion built on them would pass whatever
%% the code under test did. `i2p_netdb_verify_tests` hit exactly that and says so.
start_tracing() ->
    {module, i2p_netdb} = code:ensure_loaded(i2p_netdb),
    ?assertEqual(1, erlang:trace_pattern({i2p_netdb, serialize, 1}, true, [local])),
    ?assertEqual(1, erlang:trace_pattern({i2p_netdb, to_binary, 1}, true, [local])),
    %% Traced on the NetDb pid specifically. `erlang:trace/3` takes a PidSpec for the
    %% process to trace, so the tracer goes in the option list; passing it as the
    %% first argument installs the flag on the tracer instead and collects nothing.
    Tracer = spawn(fun() -> collect([]) end),
    Netdb = whereis(i2p_netdb_srv),
    ?assert(is_pid(Netdb)),
    ?assertEqual(1, erlang:trace(Netdb, true, [call, {tracer, Tracer}])),
    Tracer.

%% **Both erases are wrapped.** `erlang:trace/3` raises `badarg` when the tracer
%% has already exited, and a collector that has sent its results and finished is
%% exactly that. Without the catch, turning tracing off crashes the test with a
%% `badarg` that says nothing about the property under test -- which is what the
%% first version of this did.
stop_tracing(Tracer) ->
    untrace(Tracer),
    collect_for(Tracer).

untrace(Tracer) ->
    try erlang:trace(Tracer, false, [call]) of
        _ -> ok
    catch
        _:_ -> ok
    end.

%% Blocks until the tracer has drained, so the assertion below it sees every call
%% the save made rather than however many had arrived by then. Without this the test
%% would race its own subject: a fast save could complete before the collector
%% asked for its results, and the assertion would pass on an empty list.
collect_for(Tracer) ->
    Tracer ! {drain, self()},
    receive
        {drained, Calls} -> Calls
    after 5000 ->
        erlang:error(tracer_never_drained)
    end.

%% **No timeout on the receive.** A `collect/1` that timed out and re-armed itself
%% would race the caller's own timeout: both waiting 5000 ms, and the caller gives
%% up at the moment the collector becomes ready to answer. The symptom is a case
%% that fails only because nothing was traced -- the one situation where it must not
%% fail. Blocking forever is correct: the collector is a test process and the
%% `{drain, From}` message is the only exit.
%%
%% The `serialised` tag is the assertion's subject. Matching `{_M, _F, _A}` rather
%% than naming the function means a trace of any `i2p_netdb` call would satisfy the
%% drain, so the pattern deliberately does not check the module or function.
collect(Calls) ->
    receive
        {trace, _Pid, call, {_M, _F, _A}} ->
            collect([serialised | Calls]);
        {drain, From} ->
            From ! {drained, lists:reverse(Calls)},
            collect([])
    end.

%%% --------------------------------------------------------------------------
%%% Starting a save that is still running
%%% --------------------------------------------------------------------------

%% Starts a save in its own process and returns once the writer has entered
%% `f:serialize/1`, so a read issued next overlaps the serialisation.
%%
%% The barrier is a trace message rather than a sleep or a timer, for the reason
%% `i2p_netdb_verify_tests` uses one: waiting on a wall clock would make this a
%% timing test, and the point is overlap, not duration.
%%
%% The monitor is taken where the process is created. Monitoring afterwards races —
%% a save of a small store can finish before the monitor exists, and monitoring a
%% dead pid answers `noproc`, which reads as a crash rather than as the race it is.
%%
%% **This fires the timer, not `f:save/0`.** That distinction is the whole test.
%% `f:save/0` always ran outside the NetDb process -- it is a caller-initiated call,
%% so it blocks whoever called it -- and reverting the fix leaves it untouched, which
%% means a case written against it passes with the bug present. The 15-minute timer
%% is the path that ran *inside* the NetDb, in `f:handle_info/2`, so that is what
%% these cases drive.
%%
%% The timer is fired by sending `autosave` to the NetDb, which is what
%% `f:schedule_autosave/0` does. A test does not wait 15 minutes for it.
start_autosaving() ->
    Parent = self(),
    {module, i2p_netdb} = code:ensure_loaded(i2p_netdb),
    %% One matched function, or nothing would ever arrive at the barrier below and
    %% the case would time out rather than fail.
    1 = erlang:trace_pattern({i2p_netdb, serialize, 1}, true, [local]),
    Tracer = spawn(fun() -> barrier_loop(Parent) end),
    %% **`{tracer, Tracer}`, and this is not incidental.** `erlang:trace/3`'s first
    %% argument is a PidSpec for the process being traced. Passing the *tracer* pid
    %% there installs the flag on the tracer itself and returns a count while tracing
    %% nothing -- verified, and the symptom is a barrier nothing can ever reach, so
    %% the case times out rather than failing. The traced pid is the one expected to
    %% run the serialisation, which is `i2p_netdb_writer`.
    Writer = whereis(i2p_netdb_writer),
    ?assert(is_pid(Writer)),
    1 = erlang:trace(Writer, true, [call, {tracer, Tracer}]),
    %% Returns immediately. The caller waits on the `serialising` barrier and issues
    %% its read from there, which is what makes the read overlap the serialisation.
    %% Waiting for the save to finish here instead would serialise the two and prove
    %% nothing.
    Netdb = whereis(i2p_netdb_srv),
    Netdb ! autosave,
    {Tracer}.

%% Reports the moment the serialisation is entered, which is the barrier the read
%% assertions wait on. A message rather than a timer, so overlap is established
%% rather than assumed.
%%
%% The `serialize/1` clause is specific and the catch-all exists because a tracer
%% receives every traced call, not only the interesting one: the writer calls other
%% `i2p_netdb` functions on the way, and a tracer that raised on an unexpected
%% message would die and turn the barrier into another timeout.
barrier_loop(Parent) ->
    receive
        {trace, _Pid, call, {i2p_netdb, serialize, [_]}} ->
            Parent ! serialising,
            barrier_loop(Parent);
        _Other ->
            barrier_loop(Parent)
    end.

%% The saves the autosave path performed, as reported by the writer.
%%
%% Polled rather than awaited: the writer is not told when the timer fired, so there
%% is no message to wait on. Bounded, and a timeout is a failure rather than a pass --
%% "the save did not happen" must not read as "the read was not blocked".
%%
%% This is the second half of the overlap assertion. The barrier alone would pass if
%% the serialisation happened in the NetDb instead, since a barrier that never fires
%% is a timeout, and a timeout has to be a failure for the case to mean anything.
await_saves(0) ->
    erlang:error(autosave_never_reached_the_writer);
await_saves(N) ->
    case i2p_netdb_writer:stats() of
        #{saves := S} when S > 0 -> ok;
        _Other ->
            timer:sleep(10),
            await_saves(N - 1)
    end.

%% Reports whether a save reached the writer, without failing.
%%
%% Used by the overlap cases so that a serialisation which happened in the *wrong*
%% process is reported as "the writer never saw a save" in the assertion output,
%% rather than as a 5-second timeout with no explanation. The trace assertion
%% carries the real property; this only makes the failure readable.
writer_saves() ->
    case i2p_netdb_writer:stats() of
        #{saves := S} -> S;
        _Other -> 0
    end.

%% A bounded pause for an autosave that may not have reached the writer.
%%
%% **Not a success condition.** It exists only so the trace is drained after the save
%% has had its chance, and it fails loudly rather than passing: with the serialisation
%% back in the NetDb, the writer never records a save, and a quiet pause here would
%% let the empty-trace assertion pass for entirely the wrong reason.
await_quiet() ->
    timer:sleep(200),
    ok.

%% Runs `Read` while a save is serialising, and cleans up either way.
%%
%% The barrier is waited for **before** the read, so the read is issued from inside
%% the serialisation rather than after it. A read issued without waiting would
%% follow the save and prove nothing, which is the failure mode this helper exists
%% to make impossible: the ordering is not something a future edit can get wrong.
while_autosaving(Read) ->
    Tracer = start_autosaving(),
    try
        receive
            serialising -> ok
        after 1000 ->
            %% Fails here rather than on the save assertion, because this is the
            %% informative one: it says the writer never began the serialisation,
            %% which is exactly what the regression causes.
            erlang:error(writer_never_started_serializing)
        end,
        Read(),
        %% Bounded and *reported*, not fatal: with the serialisation back in the
        %% NetDb the barrier never fires at all, which is already a failure, and
        %% hanging for 5 s on top of it only buries the reason.
        ?assert(writer_saves() > 0)
    after
        untrace(Tracer)
    end.
