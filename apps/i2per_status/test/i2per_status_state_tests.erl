-module(i2per_status_state_tests).

-moduledoc """
Unit tests for the `m:i2per_status_state` gen_server callbacks: realtime event
counters, node-up/down handling, fallback polling to offline, and the
not-implemented/irrelevant fallthrough clauses.

The callbacks are exercised directly with crafted state maps (they are
exported parts of the gen_server behaviour surface); the live server against a
router is covered end-to-end in `m:i2per_status_tests`.
""".

-include_lib("eunit/include/eunit.hrl").

-define(DEAD_NODE, 'i2per_status_unit@host-invalid').

dead_state() ->
    #{
        router_node => ?DEAD_NODE,
        subscribed => false,
        online => false,
        view => #{},
        events => zero_counters()
    }.

%% Feed one event through handle_info and return the counter map.
counts_for(Event) ->
    State = dead_state(),
    {noreply, State1} = i2per_status_state:handle_info({event, Event}, State),
    maps:get(events, State1).

%% Check one key was bumped to N and everything else stayed at 0.
only_bumped(BumpedKey, N, Counters) ->
    ?assertEqual(N, maps:get(BumpedKey, Counters)),
    maps:fold(
        fun
            (K, _, Acc) when K =:= BumpedKey -> Acc;
            (_, 0, Acc) -> Acc;
            (K, V, _) -> erlang:error({unexpected_bump, K, V})
        end,
        ok,
        Counters
    ).

tunnel_built_counts_test() ->
    only_bumped(tunnel_built, 1, counts_for({tunnel_built, outbound, 3})).

tunnel_failed_counts_test() ->
    only_bumped(tunnel_failed, 1, counts_for({tunnel_failed, inbound, rejected})).

tunnel_expired_counts_test() ->
    only_bumped(tunnel_expired, 1, counts_for({tunnel_expired, outbound})).

leaseset_published_counts_test() ->
    only_bumped(
        leaseset_published, 1, counts_for({leaseset_published, crypto:strong_rand_bytes(32)})
    ).

sam_session_created_counts_test() ->
    only_bumped(sam_session_created, 1, counts_for({sam_session_created, <<"sid">>, stream})).

sam_session_closed_counts_test() ->
    only_bumped(sam_session_closed, 1, counts_for({sam_session_closed, <<"sid">>})).

previously_dropped_event_is_counted_test() ->
    %% This case used to be `unknown_event_ignored_test` and asserted that
    %% `{peer_connected, _}` was *dropped*. That was the defect, written down as
    %% intended behaviour: a peer connecting was an event nobody counted, and the
    %% test said so.
    %%
    %% `peer_connected` is a tag this service knows about -- it is one of the seven
    %% the old catch-all threw away -- so it is counted and *not* flagged.
    C = counts_for({peer_connected, crypto:strong_rand_bytes(32)}),
    ?assertEqual(1, maps:get(peer_connected, C)),
    ?assertEqual(0, maps:get(unrecognised_event, C)).

%% A tag this service has never heard of is counted under its own name *and*
%% flagged, so it is visible as an unrecognised arrival rather than blending into
%% the keys the service does know. Without the flag a future bus event would be
%% recorded and nobody would notice it was not one of the ones being displayed.
unrecognised_event_is_counted_and_flagged_test() ->
    C = counts_for({some_future_event, 1}),
    ?assertEqual(1, maps:get(some_future_event, C)),
    ?assertEqual(1, maps:get(unrecognised_event, C)),
    %% And it is not mistaken for one of the known keys.
    ?assertEqual(0, maps:get(tunnel_expired, C)).

counters_accumulate_across_events_test() ->
    State0 = dead_state(),
    {noreply, State1} =
        i2per_status_state:handle_info({event, {tunnel_failed, inbound, invalid}}, State0),
    {noreply, State2} =
        i2per_status_state:handle_info({event, {tunnel_failed, inbound, invalid}}, State1),
    Counters = maps:get(events, State2),
    ?assertEqual(2, maps:get(tunnel_failed, Counters)).

handle_call_unsupported_test() ->
    {reply, {error, not_implemented}, State} =
        i2per_status_state:handle_call(bogus, undefined, dead_state()),
    ?assertEqual(maps:get(events, dead_state()), maps:get(events, State)).

handle_cast_fallthrough_test() ->
    State = dead_state(),
    {noreply, State} = i2per_status_state:handle_cast(whatever, State).

nodeup_resubscribes_test() ->
    State0 = dead_state(),
    {noreply, State} = in_throwaway(fun() ->
        i2per_status_state:handle_info({nodeup, ?DEAD_NODE}, State0)
    end),
    %% subscribe/1 to an unreachable node collapses to false.
    ?assertEqual(false, maps:get(subscribed, State)).

nodedown_marks_offline_test() ->
    State0 = dead_state(),
    {noreply, State} = in_throwaway(fun() ->
        i2per_status_state:handle_info({nodedown, ?DEAD_NODE}, State0)
    end),
    ?assertEqual(false, maps:get(online, State)),
    ?assertEqual(#{}, maps:get(view, State)).

irrelevant_info_fallthrough_test() ->
    State = dead_state(),
    {noreply, State} = i2per_status_state:handle_info(irrelevant, State).

poll_to_unreachable_goes_offline_test() ->
    %% Previously-online router disappears: next poll must flip the view to
    %% offline_view() instead of keeping the stale snapshot.
    State0 = (dead_state())#{online => true, view => #{stale => 1}},
    {noreply, State} = in_throwaway(fun() ->
        i2per_status_state:handle_info(poll, State0)
    end),
    ?assertEqual(false, maps:get(online, State)),
    ?assertEqual(#{}, maps:get(view, State)).

%% Run a `gen_server` callback in a process that is thrown away afterwards, and
%% return what it answered.
%%
%% **Because the callback re-arms itself, calling it here is a side effect on the
%% shared eunit worker.** `handle_info(poll, ...)` ends by scheduling another
%% `poll` `poll_interval()` into the *calling* process, and `handle_info({nodeup,
%% ...})` schedules the first one. Under eunit that caller is a worker shared by
%% every module in the tier, so the chain keeps firing into a mailbox other
%% modules read: `i2p_peer_tests` collects bus events from that mailbox and
%% asserts on their shape, and a stray `poll` turned into `{case_clause, [poll,
%% {peer_connect_failed, ...}]}` in a module two directories away.
%%
%% Draining the messages does not fix it -- the timer that will produce the next
%% one is still armed, and the interval is five seconds, so a drain that waits
%% long enough to be conclusive is slower than the whole suite. A process that
%% dies takes its timers with it, which is the only thing that is actually true
%% here: `f:handle_info/2` is written for a process whose lifetime is the
%% gen_server's, and the test is not that.
-spec in_throwaway(fun(() -> Result)) -> Result.
in_throwaway(Fun) ->
    Parent = self(),
    Ref = make_ref(),
    {Pid, MRef} = spawn_monitor(fun() -> Parent ! {Ref, catch Fun()} end),
    Reply =
        receive
            {Ref, Result} -> Result
        after 5000 ->
            exit({callback_timeout, Pid})
        end,
    %% Wait for the process to be gone before returning. It is already dead --
    %% it answered and exited -- but the `DOWN` is still in this mailbox, and
    %% leaving it there is the same class of leak this helper exists to stop.
    receive
        {'DOWN', MRef, process, _Pid, _Reason} -> ok
    after 5000 ->
        exit({callback_would_not_die, Pid})
    end,
    Reply.

terminate_and_code_change_test() ->
    State = dead_state(),
    ?assertEqual(ok, i2per_status_state:terminate(any, State)),
    ?assertEqual({ok, State}, i2per_status_state:code_change(0, State, [])).

%% The zero map is whatever the module says it is, read from the module rather
%% than restated here -- a hand-written copy of the key set in the test is exactly
%% the second description that drifts.
zero_counters() ->
    maps:from_list([{Key, 0} || Key <- i2per_status_state:known_event_keys()]).
