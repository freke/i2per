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
%% calling process makes no call into the NetDb.
%%
%% The trace is on `call` events only, and the match pattern keeps just the
%% NetDb's functions, so an unrelated call cannot mask a real one and a real one
%% cannot hide behind an unrelated call. Zero is the assertion; there is no
%% tolerance and no "mostly".
relay_path_makes_no_blocking_call_per_frame_test() ->
    with_netdb(
        fun(Held, Missing) ->
            Traced = start_tracing(),
            try
                send_frames(Held, ?FRAMES),
                send_frames(Missing, ?FRAMES),
                ?assertEqual([], collect_calls(Traced, []))
            after
                stop_tracing(Traced)
            end
        end
    ).

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
%%% --------------------------------------------------------------------------

%% Trace this process's own outgoing calls, keeping only the NetDb's.
start_tracing() ->
    _ = erlang:trace_pattern({i2p_netdb_srv, '_', '_'}, true, [local]),
    _ = erlang:trace(self(), true, [call]),
    self().

stop_tracing(Me) ->
    _ = erlang:trace_pattern({i2p_netdb_srv, '_', '_'}, false, [local]),
    _ = erlang:trace(Me, false, [call]),
    ok.

%% The traced calls arrive as ordinary messages, so draining the mailbox is a
%% barrier rather than a sleep: by the time this runs every traced call has
%% returned and its message is already queued.
collect_calls(Me, Acc) ->
    receive
        {trace, Me, call, MFA, _Ret} ->
            collect_calls(Me, [MFA | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.
