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
%%
%% Tracing brings the same trade with it, so it is resolved the same way twice.
%% Trace delivery is dislocated from the tracee's execution, which makes
%% "the trace is off, so the list is complete" a deadline rather than a fact --
%% see `f:await_trace_delivery/1`. And an assertion that a list contains no
%% blocking call is satisfied by a list that arrived short, which makes the
%% case's own evidence checkable only if something checks it -- see
%% `f:expected_calls/2`.

-module(i2p_tunnel_relay_tests).

-moduledoc """
Tests for the transit relay's per-frame RouterInfo existence check.
""".

-include_lib("eunit/include/eunit.hrl").

-define(FRAMES, 50).

%% How long to wait for each of the two ordering barriers below. One number, so
%% they cannot drift apart: both waits are for a message the runtime promises,
%% so the timeout is there to turn a lost one into a named failure rather than
%% to wait hopefully for something that may never arrive.
-define(BARRIER_MS, 1000).

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
%%
%% **And the collection is asserted complete, and it is asserted last.** An
%% assertion that the list contains no blocking call is satisfied by a list that
%% arrived short, so it cannot be the only one. See `f:expected_calls/2`.
relay_path_makes_no_blocking_call_per_frame_test() ->
    with_netdb(
        fun(Held, Missing) ->
            Traced = start_tracing(),
            try
                send_frames(Held, ?FRAMES),
                send_frames(Missing, ?FRAMES),
                All = collect_calls(Traced),
                %% The property first, then the completeness of the evidence for
                %% it. **In that order on purpose**: a regression that adds a
                %% blocking call also changes what was traced, so asserting
                %% completeness first would report a count diff and hide the
                %% `handle_call` that explains it. Completeness last still cannot
                %% pass on a short list -- it just fails second.
                ?assertEqual(
                    [], blocking_calls(All) ++ gen_server_calls(All)
                ),
                ?assertEqual(expected_calls(Held, Missing), lists:sort(All))
            after
                stop_tracing(Traced)
            end
        end
    ).

%% **The whole collection, matched exactly.**
%%
%% The assertion above is `?assertEqual([], Blocking)`, which is *vacuously true*
%% on an empty `All` -- and an empty `All` is indistinguishable from a truncated
%% delivery, because a list that arrived short and a list where nothing was traced
%% are the same term. So without this the case would prove "no blocking call" from
%% a list that may never have arrived, and it would do so on exactly the failure it
%% exists to catch: a regression that also loses the evidence.
%%
%% Zero misses is only evidence if the count is non-zero. This is that count, and
%% it is matched by argument rather than by length, so a collection of the right
%% size and the wrong calls fails too. It is also the only thing that makes the
%% barrier in `f:collect_calls/1` observable: without an assertion on the count,
%% the barrier and its absence produce the same passing run.
%%
%% One `has_router/1` per frame per `f:send_frames/2` call is the entire traced
%% surface, and it is exhaustive in the way that matters -- a new blocking entry
%% point added to `i2p_netdb_srv` cannot appear without changing this list.
expected_calls(Held, Missing) ->
    lists:sort(
        lists:append([
            [{i2p_netdb_srv, has_router, [Hash]} || _ <- lists:seq(1, ?FRAMES)]
         || Hash <- [Held, Missing]
        ])
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
%% **A delivery barrier comes first, and the trace is turned off after it.**
%% `erlang:trace/3` returning does not mean the trace messages it caused have been
%% received. OTP's own wording: *the delivery of trace messages is dislocated on the
%% time-line compared to other events in the system*. So a message already
%% generated can still be in flight when the collector is asked to answer, and
%% `f:collect_calls/1` would report a list missing calls that really happened --
%% which is the one direction this case cannot afford, since an empty list also
%% asserts clean. `erlang:trace_delivered/1` is the barrier for exactly that gap:
%% on `{trace_delivered, Me, Ref}` every trace message the runtime had to deliver
%% for this process has reached its receiver.
%%
%% **Why the barrier is inside `collect_calls/1` and not in the `after` clause.**
%% `f:stop_tracing/1` is the safety net for a case that *raises*; this is about a
%% case that *succeeds with a short list*, and the `after` clause runs too late to
%% be consulted. So the barrier goes here, before any trace is disabled -- asking
%% after the fact would ask about a trace that has stopped generating.
-spec collect_calls({pid(), pid()}) -> [mfa()].
collect_calls({Me, Tracer}) ->
    await_trace_delivery(Me),
    _ = erlang:trace(Me, false, [call]),
    _ = erlang:trace_pattern({i2p_netdb_srv, '_', '_'}, false, [local]),
    _ = erlang:trace_pattern({gen_server, call, '_'}, false, [local]),
    Ref = make_ref(),
    Tracer ! {collect, self(), Ref},
    receive
        {collected, Ref, Calls} -> Calls
    after ?BARRIER_MS ->
        erlang:error(timeout_collecting_traced_calls)
    end.

%% Wait for the trace the traced process has already generated to have been
%% delivered. **A barrier, not a deadline:** OTP sends the completion message
%% once the delivery has happened, so the receive cannot return early having
%% missed anything. The timeout only bounds a message that never comes, and names
%% which of the two waits gave up.
%%
%% The message arrives **here**, not in the collector: it is sent to the caller of
%% `erlang:trace_delivered/1`, which is this process. The `Ref` is the one that
%% call returned, so an unrelated delivery in flight cannot be mistaken for this
%% one, and `f:tracer_loop/1` needs no clause for it.
await_trace_delivery(Me) ->
    Ref = erlang:trace_delivered(Me),
    receive
        {trace_delivered, Me, Ref} -> ok
    after ?BARRIER_MS ->
        erlang:error(timeout_awaiting_trace_delivery)
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
