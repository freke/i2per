%% Tests for the per-frame RouterInfo existence check on the transit relay path.
%%
%% The case that matters here is `relay_path_makes_no_blocking_call_per_frame`.
%% It is the property the ETS move exists for, and it is the one that would
%% silently regress: put a `gen_server:call` back into
%% `m:i2p_tunnel_relay:send_tunnel_data/2` and every other test in the tree stays
%% green, because a round trip to a responsive process is not a failure.
%%
%% So it is asserted directly, by tracing. The alternative -- suspend the NetDb
%% and rely on a hang being reported as a timeout -- would be deterministic in
%% the passing direction but a slow failure in the other one, and this project
%% treats a deadline as a flake with better manners.

-module(i2p_tunnel_relay_tests).

-moduledoc """
Tests for the transit relay's per-frame RouterInfo existence check.
""".

-include_lib("eunit/include/eunit.hrl").

-define(FRAMES, 50).

%%% --------------------------------------------------------------------------
%%% Existence check
%%% --------------------------------------------------------------------------

%% The property, asserted rather than asserted-about: while relaying frames the
%% calling process makes no *blocking* call into the NetDb.
%%
%% **The `after` clause is load-bearing, and it is here because this case can
%% contaminate every module that runs after it.** `f:start_tracing/0` enables two
%% `erlang:trace_pattern/3` match specs -- which are **global**, not per-process --
%% and attaches a tracer to whichever process calls it, which under eunit is a
%% worker shared by the whole tier. `f:collect_calls/1` disables them, but only if
%% `send_frames/2` returns. So a case that leaks is a case that leaks *only when it
%% fails*, and a suite run green cannot see it. See `f:stop_tracing/1`.
%%
%% **The distinction is the claim, so the trace has to distinguish it.** The
%% relay does call `i2p_netdb_srv:has_router/1` once per frame -- that is how it
%% decides whether it can route -- but `has_router/1` is a direct
%% `ets:member/2` against the published table, not a `gen_server:call/2`, and
%% that change is the entire optimisation `m:i2p_tunnel_relay` documents for
%% this path. So "made no call at all" is false, and asserting it would be a
%% test demanding the code be wrong.
%%
%% What must not happen is a `handle_call/3`, which is what blocks behind a NetDb
%% write. So the assertion is over the *callback* entry points rather than over
%% every exported function, and it is exhaustive over them: a new
%% `gen_server`-style entry point added to `i2p_netdb_srv` shows up here as a
%% failure rather than passing unnoticed.
relay_path_makes_no_blocking_call_per_frame_test() ->
    with_netdb(
        fun(Held, Missing) ->
            Traced = start_tracing(),
            try
                send_frames(Held, ?FRAMES),
                send_frames(Missing, ?FRAMES),
                All = collect_calls(Traced),
                ?assertEqual(
                    [], blocking_calls(All) ++ gen_server_calls(All)
                )
            after
                stop_tracing(Traced)
            end
        end
    ).

%% The `gen_server` callbacks out of what the trace saw.
%%
%% **A name list, not a pattern match on `handle_call/3`.** The property is about
%% blocking, and a `gen_server` blocks on any of its callbacks; matching one
%% function name would let a second callback through. Kept next to the assertion
%% so the two are read together.
blocking_calls(Traced) ->
    Blocking = [handle_call, handle_cast, handle_info, handle_continue, terminate],
    [MFA || MFA = {i2p_netdb_srv, Name, _} <- Traced, lists:member(Name, Blocking)].

%% `gen_server:call/4` as the trace reports it: the function traced is
%% `gen_server:call`, so the *name* in the MFA is `call`, not one of the
%% callbacks. Matched on the module and the function name, because that is the
%% shape `trace_pattern({gen_server, call, '_'}, ...)` produces and the one this
%% asserts against.
gen_server_calls(Traced) ->
    [MFA || MFA = {gen_server, call, _} <- Traced].

%% The two answers are one answer, not two. A frame for a router we hold is
%% handed on; a frame for one we do not is dropped, and the drop is counted so
%% "we could not route it" is distinguishable from "we sent it".
%%
%% Asserted on the counter rather than on a mock, because the counter is the thing
%% an operator actually reads.
unknown_next_hop_is_dropped_and_counted_test() ->
    with_netdb(
        fun(_Held, Missing) ->
            Before = drop_counter(),
            ?assertEqual(false, i2p_netdb_srv:has_router(Missing)),
            send_frames(Missing, ?FRAMES),
            ?assertEqual(Before + ?FRAMES, drop_counter())
        end
    ).

held_next_hop_is_sent_and_not_counted_as_dropped_test() ->
    with_netdb(
        fun(Held, _Missing) ->
            Before = drop_counter(),
            ?assertEqual(true, i2p_netdb_srv:has_router(Held)),
            send_frames(Held, ?FRAMES),
            ?assertEqual(Before, drop_counter())
        end
    ).

%% `has_router/1` answers from the table, so it is a read that cannot block
%% behind the NetDb being busy. Suspending the NetDb is the crude version of that
%% claim and it is cheap: with the process suspended a call-based check could not
%% return at all, so this case returning *is* the assertion. It is a companion to
%% the trace case rather than a replacement, because its failure mode is a hang.
has_router_does_not_need_the_netdb_process_test() ->
    with_netdb(
        fun(Held, _Missing) ->
            ok = sys:suspend(i2p_netdb_srv),
            try
                ?assertEqual(true, i2p_netdb_srv:has_router(Held)),
                ?assertEqual(false, i2p_netdb_srv:has_router(rand_hash()))
            after
                ok = sys:resume(i2p_netdb_srv)
            end
        end
    ).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

%% Brings up a NetDb holding one RouterInfo, then hands the body that
%% RouterInfo's hash and a hash nothing holds.
%%
%% **Whatever this starts, it stops.** `i2p_stats` and `i2p_netdb_srv` are
%% registered names inside the `i2per` application, and a bare `start_link/0`
%% leaves one registered that the application controller did not start -- which
%% the next module that boots `i2per` reads as `already_started` and fails on.
%% Stopping only what was started here keeps the module order-independent.
with_netdb(Body) ->
    StartedNetdb = ensure_started(i2p_netdb_srv),
    StartedStats = ensure_started(i2p_stats),
    try
        Now = erlang:system_time(millisecond),
        RI = i2p_ct_helpers:floodfill_router_info(Now, <<"192.0.2.10">>),
        added = i2p_netdb_srv:store(RI, Now),
        Body(i2p_router_info:hash(RI), rand_hash())
    after
        stop_if_started(StartedStats),
        stop_if_started(StartedNetdb)
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

send_frames(Hash, N) ->
    Frame = <<0:32, 0:16, 0:1008>>,
    [ok = i2p_tunnel_relay:send_tunnel_data(Hash, Frame) || _ <- lists:seq(1, N)].

%% `i2p_stats:snapshot/0` is a flat map of counter name to value. (It is
%% `m:i2p_status_data:view/0` that nests them under `counters`.)
drop_counter() ->
    maps:get(transit_frames_dropped_no_route, i2p_stats:snapshot(), 0).

rand_hash() ->
    crypto:strong_rand_bytes(32).

%%% --------------------------------------------------------------------------
%%% Tracing

%% Trace this process's own outgoing calls, keeping only the NetDb's.
%%
%% **The tracer is a process of this case's own, named explicitly.** That is the
%% whole change from the version that took the default: without
%% `{tracer, Tracer}` the tracer is *the calling process*, which under eunit is a
%% worker shared by every module in the tier. A process carries at most one
%% tracer, so any earlier module that left a trace on that worker makes this
%% call raise `badarg` -- `can only have one tracer per process`.
%%
%% That is not hypothetical. It is what this case did, and it failed the moment
%% the tier ran as an explicit module list instead of a whole-tree discovery
%% run: `i2p_netdb_verify_tests` traces the worker with a tracer of its own and
%% does not clear it.
%%
%% A private collector also makes the barrier exact. Reading trace messages out
%% of the case's own mailbox conflates this trace with every other module's
%% leftovers in the shared worker; asking a process nobody else can address
%% cannot.
-spec start_tracing() -> {pid(), pid()}.
start_tracing() ->
    {module, i2p_netdb_srv} = code:ensure_loaded(i2p_netdb_srv),
    {module, gen_server} = code:ensure_loaded(gen_server),
    _ = erlang:trace_pattern({i2p_netdb_srv, '_', '_'}, true, [local]),
    %% `gen_server` alongside the NetDb, because a blocking call is not
    %% identifiable from the callee: `i2p_netdb_srv:count/0` looks like any
    %% other exported function until you see its body reach for `gen_server`.
    %% Tracing both makes the claim "this path blocks" visible at the point where
    %% it blocks, rather than requiring a list of every wrapper that is a
    %% `gen_server:call` in disguise.
    _ = erlang:trace_pattern({gen_server, call, '_'}, true, [local]),
    %% `spawn_link`, as a last resort and **not** as the safety net it looks like:
    %% eunit **catches** a failed assertion, so the worker does not exit and the
    %% link does not fire. The collector is stopped explicitly instead, in an
    %% `after` clause -- see `f:stop_tracing/1`. What this link does still cover is
    %% the worker itself being killed.
    Tracer = spawn_link(fun() -> tracer_loop([]) end),
    _ = erlang:trace(self(), true, [call, {tracer, Tracer}]),
    {self(), Tracer}.

%% Owns the trace messages. Accumulates the NetDb's calls and answers a
%% `{collect, From, Ref}` request with everything seen since the last one, so a
%% second collection does not re-report the first batch.
tracer_loop(Acc) ->
    receive
        {trace, _Pid, call, {M, F, A}} ->
            tracer_loop([{M, F, A} | Acc]);
        {collect, From, Ref} ->
            From ! {collected, Ref, lists:reverse(Acc)},
            tracer_loop([])
    end.

%% Every `i2p_netdb_srv` call this process made under the trace, and the trace off.
%%
%% **The trace is turned off before the collection is requested**, not after.
%% `erlang:trace/3` returns once the flag is set, and the messages it stops
%% sending are already queued in the collector, so the answer that comes back
%% covers every call that had already returned. Collecting first and disabling
%% after would race a call still in flight.
-spec collect_calls({pid(), pid()}) -> [mfa()].
collect_calls({Me, Tracer}) ->
    _ = erlang:trace(Me, false, [call]),
    _ = erlang:trace_pattern({i2p_netdb_srv, '_', '_'}, false, [local]),
    _ = erlang:trace_pattern({gen_server, call, '_'}, false, [local]),
    Ref = make_ref(),
    Tracer ! {collect, self(), Ref},
    receive
        {collected, Ref, Calls} -> Calls
    after 1000 ->
        erlang:error(timeout_collecting_traced_calls)
    end.

%% Everything `f:start_tracing/0` turned on, turned off -- and the collector stopped.
%%
%% **This is the teardown, and it is in an `after` clause because
%% `f:collect_calls/1` cannot be one.** `collect_calls/1` does disable the tracing,
%% but it is reached only if `send_frames/2` returns, and `send_frames/2` is
%% `ok = i2p_tunnel_relay:send_tunnel_data(...)`, which raises on a badmatch. On
%% that path two things used to survive the case and contaminate whatever ran next:
%%
%% - **the two `trace_pattern`s, which are global.** They are not scoped to the
%%   traced process, so leaving them enabled has every traced process in the VM
%%   reporting `i2p_netdb_srv` calls and `gen_server:call` calls.
%% - **the tracer on the shared eunit worker.** A process carries at most one
%%   tracer, so the next module to trace that worker gets `badarg`, *can only have
%%   one tracer per process*.
%%
%% The second is the failure this module's tracer comment describes as the reason
%% for naming the tracer explicitly at all, arriving by the other door. And it is
%% invisible in the passing direction, which is what makes it worth a clause rather
%% than a code path: a case that only leaks when it fails cannot be caught by
%% running the suite green.
%%
%% **Idempotent on purpose.** A passing case has already disabled everything by the
%% time it reaches here, and disabling twice is a no-op rather than an error. That is
%% what lets one clause serve both paths instead of needing to know which one it is.
%%
%% `unlink` before the kill, because a collector killed while still linked takes
%% the worker with it -- the same reason `f:with_netdb/1` drops its link before
%% tearing its fixture down.
stop_tracing({Me, Tracer}) ->
    _ = erlang:trace(Me, false, [call]),
    _ = erlang:trace_pattern({i2p_netdb_srv, '_', '_'}, false, [local]),
    _ = erlang:trace_pattern({gen_server, call, '_'}, false, [local]),
    unlink(Tracer),
    exit(Tracer, kill),
    ok.
