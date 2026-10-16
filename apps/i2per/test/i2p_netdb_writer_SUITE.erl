%% NetDb save-path tests: the structural boundary between the NetDb process
%% and the writer process.
%%
%% Ported from the EUnit module that covered the same ground: the save must
%% never serialise the store inside the NetDb process — it runs in
%% `m:i2p_netdb_writer` — because a serialisation is a full-store pass on the
%% process every read and store call is answered by. The structural assertion
%% is traced rather than timed, so it cannot flake under load.
%%
%% The suite starts the NetDb, the writer and the counters registry standalone
%% (the app may also be running from an earlier suite; both names are
%% acquire-or-reuse and torn down only if we started them).

-module(i2p_netdb_writer_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, suite/0]).

-define(ROUTERS, 200).

suite() ->
    [{timetrap, 30000}].

all() ->
    [netdb_process_never_serialises_the_store, writer_performs_the_save].

%% The structural assertion. The NetDb process is traced for the two calls that
%% serialise the store; the autosave timer is fired (not `save/0`, which always
%% ran outside this process and would pass with the bug present); the trace is
%% drained and must be empty, and a save must have reached the writer.
%%
%% Both `serialize/1` and `to_binary/1` are traced, because either could be
%% where the serialisation creeps back in.
netdb_process_never_serialises_the_store(_Config) ->
    with_netdb(
        fun(_Keys) ->
            Tracer = start_tracing(),
            try
                Netdb = whereis(i2p_netdb_srv),
                Netdb ! autosave,
                %% Drain *after* the save has had time to run, or the mailbox is
                %% empty because the serialisation has not happened yet rather
                %% than because it happened elsewhere.
                await_saves(200),
                Calls = collect_for(Tracer),
                ?assertEqual([], Calls)
            after
                untrace(Tracer)
            end
        end
    ).

%% The save lands on disk through the writer, on both entry paths, and the
%% writer's own stats reflect it. The synchronous `save/2` with no reporter is
%% the path `f:i2p_netdb_srv:save/0` takes, and a state-corrupting answer on it
%% would surface as a crash on this very `stats/0` read — which is how the
%% `report/3` undefined-clause bug was found.
writer_performs_the_save(_Config) ->
    with_netdb(
        fun(_Keys) ->
            #{saves := Before} = i2p_netdb_writer:stats(),
            ok = i2p_netdb_writer:save(i2p_netdb_srv:snapshot(), undefined),
            ok = i2p_netdb_writer:save_async(i2p_netdb_srv:snapshot(), undefined),
            await_saves_at_least(Before + 2, 200)
        end
    ).

%% ----------------------------------------------------------------------
%% Fixture

%% Brings up the NetDb **and its writer**, then hands the body the store's keys.
%% Without the writer the NetDb falls back to saving in-process, which is the
%% behaviour being tested away, and the fallback would make the structural
%% assertion pass vacuously.
with_netdb(Body) ->
    Dir = temp_dir(),
    application:set_env(i2per, data_dir, Dir),
    StartedWriter = ensure_started(i2p_netdb_writer),
    StartedNetdb = ensure_started(i2p_netdb_srv),
    StartedStats = ensure_started(i2p_counters),
    try
        Now = erlang:system_time(millisecond),
        %% Stored through the srv: a local store is a different table from the
        %% one the srv serves reads from. The delta is asserted because another
        %% suite may have left the shared NetDb non-empty.
        Before = i2p_netdb_srv:count(),
        Keys = store_through_srv(?ROUTERS, Now),
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
        "i2per_netdb_writer_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

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

store_through_srv(0, _Now) ->
    [];
store_through_srv(N, Now) ->
    RI = fixture_router(Now, N),
    Key = i2p_router_info:hash(RI),
    added = i2p_netdb_srv:store(RI, Now),
    [Key | store_through_srv(N - 1, Now)].

fixture_router(Now, N) ->
    #{identity := Id, sign_priv := SignSeed} = i2p_keys:generate_with_privkeys(),
    Addr = i2p_router_info:ntcp2_address(
        host(N), 4668, crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(16)
    ),
    i2p_router_info:build(Id, Now, [Addr], #{}, SignSeed).

%% 255 so the addresses stay inside `192.0.2.0/24`.
host(N) ->
    list_to_binary("192.0.2." ++ integer_to_list(N rem 251 + 1)).

%% ----------------------------------------------------------------------
%% Tracing

%% Trace the NetDb process's own calls to the two functions that serialise the
%% store, filtered to that process so an unrelated serialisation elsewhere
%% cannot mask a real one. The trace-pattern match count is asserted: 0 matches
%% for an unloaded module means no messages ever arrive, and an assertion built
%% on them would pass whatever the code did.
start_tracing() ->
    {module, i2p_netdb} = code:ensure_loaded(i2p_netdb),
    ?assertEqual(1, erlang:trace_pattern({i2p_netdb, serialize, 1}, true, [local])),
    ?assertEqual(1, erlang:trace_pattern({i2p_netdb, to_binary, 1}, true, [local])),
    Tracer = spawn(fun() -> collect([]) end),
    Netdb = whereis(i2p_netdb_srv),
    ?assert(is_pid(Netdb)),
    ?assertEqual(1, erlang:trace(Netdb, true, [call, {tracer, Tracer}])),
    Tracer.

%% Both erases are wrapped: `erlang:trace/3` raises `badarg` when the tracer
%% has already exited, and a collector that has sent its results and finished is
%% exactly that.
untrace(Tracer) ->
    try erlang:trace(Tracer, false, [call]) of
        _ -> ok
    catch
        _:_ -> ok
    end.

%% Blocks until the tracer has drained, so the assertion sees every call the
%% save made rather than however many had arrived by then.
collect_for(Tracer) ->
    Tracer ! {drain, self()},
    receive
        {drained, Calls} -> Calls
    after 5000 ->
        erlang:error(tracer_never_drained)
    end.

%% No timeout on the receive: a timed-out collector would race its caller and
%% lose exactly when the answer is slow, which is the case that must not fail.
collect(Calls) ->
    receive
        {trace, _Pid, call, {_M, _F, _A}} ->
            collect([serialised | Calls]);
        {drain, From} ->
            From ! {drained, lists:reverse(Calls)},
            collect([])
    end.

%% The saves, polled rather than awaited: the writer is not told when the timer
%% fired, so there is no message to wait on. A timeout is a failure, never a
%% pass — "the save did not happen" must not read as "all is well".
await_saves(0) ->
    erlang:error(autosave_never_reached_the_writer);
await_saves(N) ->
    case maps:get(saves, i2p_netdb_writer:stats(), 0) > 0 of
        true ->
            ok;
        false ->
            timer:sleep(10),
            await_saves(N - 1)
    end.

await_saves_at_least(Target, 0) ->
    erlang:error({writer_save_not_observed, Target});
await_saves_at_least(Target, N) ->
    case maps:get(saves, i2p_netdb_writer:stats(), 0) >= Target of
        true ->
            ok;
        false ->
            timer:sleep(10),
            await_saves_at_least(Target, N - 1)
    end.
