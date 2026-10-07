-module(i2p_lookup_srv_tests).

-moduledoc """
Direct-callback unit tests for `m:i2p_lookup_srv`.

Covers the gen_server surface and the pure failure paths (missing pending key,
stale timers, dropped callers, catch-alls), plus the full "no candidates, give
up" orchestration against a live-but-empty `m:i2p_netdb_srv` (no floodfills,
no rows): a `find` arms the pipeline, the single attempt round finds no target
and `fail/2` answers the caller `{error, {lookup_failed, no_answer}}`. The tunnel-carrying
DatabaseLookup chase (`f:i2p_lookup_srv:send_lookup/4`) is driven against a stub
tunnel server here, for the counted case of a send that finds no tunnel; the
chase against live tunnels is covered by `m:i2p_lookup_srv_SUITE`.
""".

-include_lib("eunit/include/eunit.hrl").

-define(HASH, <<16#A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5:256>>).

init_test() ->
    {ok, State} = i2p_lookup_srv:init([?HASH]),
    ?assertEqual(#{pending => #{}, our_hash => ?HASH}, State).

%% stop/0 on a running orchestrator (and idempotently on a stopped one).
stop_test() ->
    Stop = fun() ->
        case whereis(i2p_lookup_srv) of
            undefined ->
                {ok, _} = i2p_lookup_srv:start_link(?HASH),
                ?assertEqual(ok, i2p_lookup_srv:stop());
            _ ->
                ?assertEqual(ok, i2p_lookup_srv:stop())
        end
    end,
    Stop(),
    ?assertEqual(undefined, whereis(i2p_lookup_srv)),
    Stop(),
    ?assertEqual(undefined, whereis(i2p_lookup_srv)).

%% The caller's contract is unchanged: a caller that only cares whether the lookup
%% worked still gets the historical `{error, not_found}`, even though the service
%% being absent has the reason `service_unavailable` and announces it.
%%
%% And `f:find_ls/2` is the opt-in: the same failure, told apart.
not_running_test() ->
    ?assertEqual({error, not_found}, i2p_lookup_srv:find_ls(?HASH)),
    ?assertEqual({error, not_found}, i2p_lookup_srv:find_ri(?HASH)),
    ?assertEqual(
        {error, {lookup_failed, service_unavailable}},
        i2p_lookup_srv:find_ls(?HASH, #{reason => true})
    ),
    ?assertEqual(
        {error, {lookup_failed, service_unavailable}},
        i2p_lookup_srv:find_ri(?HASH, #{reason => true})
    ).

%% A RouterInfo already in the NetDb resolves immediately from cache.
cached_ri_hit_test() ->
    Owner = ensure_netdb(),
    try
        RI = mk_ri(),
        Hash = i2p_router_info:hash(RI),
        added = i2p_netdb_srv:store(RI, erlang:system_time(millisecond)),
        {ok, State} = i2p_lookup_srv:init([?HASH]),
        {reply, {ok, ReplyRI}, State} =
            i2p_lookup_srv:handle_call({find, Hash, router}, {self(), make_ref()}, State),
        ?assertEqual(Hash, i2p_router_info:hash(ReplyRI))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% A DatabaseStore landing for a pending key that still misses the NetDb:
%% answered {error, {lookup_failed, no_answer}} and dropped.
resolve_stored_miss_test() ->
    Owner = ensure_netdb(),
    try
        Key = <<1:256>>,
        {ok, State0} = i2p_lookup_srv:init([?HASH]),
        %#callers empty
        P = pending(),
        Me = self(),
        Ref = make_ref(),
        From = {Me, Ref},
        Entry = P#{callers := [{From, Me, make_ref()}]},
        {noreply, State1} = i2p_lookup_srv:handle_info(
            {db_stored, Key, router, stored}, State0#{pending := #{Key => Entry}}
        ),
        ?assertEqual(#{}, maps:get(pending, State1)),
        %% The store was taken, so this is not a refusal — and because the key still
        %% does not hold a RouterInfo, the reason is `not_resolved`. Before the
        %% reasons existed this replied `{error, not_found}`, the same value the
        %% give-up path sent, which is the whole of the ticket's complaint.
        receive
            {Ref, {error, {lookup_failed, not_resolved}}} -> ok
        after 0 ->
            error(no_reply)
        end
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% Two waiters on the same key share one pending entry (the duplicate-waiter
%% branch); with no floodfill candidates both fail together.
two_callers_shared_pending_test() ->
    Owner = ensure_netdb(),
    try
        Key = <<2:256>>,
        {ok, State} = i2p_lookup_srv:init([?HASH]),
        Me = self(),
        R1 = make_ref(),
        R2 = make_ref(),
        {noreply, State1} =
            i2p_lookup_srv:handle_call({find, Key, lease}, {Me, R1}, State),
        {noreply, State2} =
            i2p_lookup_srv:handle_call({find, Key, lease}, {Me, R2}, State1),
        #{Key := Entry} = maps:get(pending, State2),
        ?assertEqual(2, length(maps:get(callers, Entry))),
        {noreply, State3} = i2p_lookup_srv:handle_info({next_attempt, Key}, State2),
        ?assertEqual(#{}, maps:get(pending, State3)),
        receive
            {R1, {error, {lookup_failed, no_answer}}} -> ok
        after 0 ->
            error(no_reply)
        end,
        receive
            {R2, {error, {lookup_failed, no_answer}}} -> ok
        after 0 ->
            error(no_reply)
        end
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% An entry at the attempt budget caps out: fail-fast without any candidate.
exhausted_attempts_test() ->
    Key = <<3:256>>,
    {ok, State0} = i2p_lookup_srv:init([?HASH]),
    Entry = (pending())#{attempts := 5},
    {noreply, State1} = i2p_lookup_srv:handle_info(
        {next_attempt, Key}, State0#{pending := #{Key => Entry}}
    ),
    ?assertEqual(#{}, maps:get(pending, State1)).

%% A dying caller is dropped from its pending entry; the entry lives while any
%% caller remains and dies with its last one.
drop_caller_test() ->
    Key = <<4:256>>,
    {ok, State0} = i2p_lookup_srv:init([?HASH]),
    Me = self(),
    DeadPid = spawn(fun() -> ok end),
    Ref = make_ref(),
    %% First waiter dies, second lives: entry survives with the live caller.
    S1 = State0#{
        pending := #{
            Key => (pending())#{
                callers := [
                    {{Me, make_ref()}, DeadPid, Ref},
                    {{Me, make_ref()}, Me, make_ref()}
                ]
            }
        }
    },
    {noreply, S2} = i2p_lookup_srv:handle_info({'DOWN', Ref, process, DeadPid, normal}, S1),
    #{Key := K1} = maps:get(pending, S2),
    ?assertEqual(1, length(maps:get(callers, K1))),
    %% The last waiter dies: the whole entry goes with it.
    RefLast = make_ref(),
    S3 = State0#{
        pending := #{
            Key => K1#{
                callers := [
                    {{Me, make_ref()}, Me, RefLast}
                ]
            }
        }
    },
    {noreply, S4} = i2p_lookup_srv:handle_info({'DOWN', RefLast, process, Me, normal}, S3),
    ?assertEqual(#{}, maps:get(pending, S4)).

generic_call_test() ->
    ?assertEqual(
        {reply, ok, base_state()},
        i2p_lookup_srv:handle_call(junk, from(), base_state())
    ).

generic_cast_test() ->
    ?assertEqual({noreply, base_state()}, i2p_lookup_srv:handle_cast(junk, base_state())).

%%%%%%%%% Lookup failures are reported, with a reason %%%%%%%%%

%%%%%%%%% Lookup failures are reported, with a reason %%%%%%%%%

%% The core of #902G3ZN, and the thing that could not be asserted before: a
%% responder's store for this key arrived and the NetDb **refused** it. The
%% orchestrator names the refusal in its reply, and so does the bus.
%%
%% The two reasons are kept apart because they are opposite problems. `no_answer`
%% means nobody answered, and the question of whether this router is on the network is
%% open. `not_stored` means somebody *did* answer, with a record for exactly this key,
%% and this router could not use it -- so this is the difference between "the network
%% is not helping me" and "the network is helping me with something I cannot read".
%% Both used to be the same `{error, not_found}`.
refused_store_is_reported_with_the_stores_own_reason_test() ->
    Owner = ensure_netdb(),
    try
        Key = crypto:strong_rand_bytes(32),
        Reason = {refused_with_reason, older},
        From = caller(),
        Tag = element(2, From),
        Events = i2p_ct_helpers:events_from(
            fun() ->
                resolve_stored_with(Key, lease, {not_stored, Reason}, From),
                %% Inside the observed work, not after it: the helper drains this
                %% mailbox to collect bus events, and the orchestrator's reply is in
                %% the same mailbox. Checking afterwards finds it already drained --
                %% which is a missing reply reported as a working bus.
                expect(Tag, {error, {lookup_failed, {not_stored, Reason}}})
            end
        ),
        ?assertEqual(
            [{lookup_failed, Key, lease, {not_stored, Reason}}],
            events_named(lookup_failed, Events)
        )
    after
        stop_netdb(Owner)
    end.

%% The same path, for a store of a type this router has no parser for. That one is
%% the case worth being certain about: the message decoded perfectly and a peer did
%% its best, so reporting a timeout would send an operator looking for a connectivity
%% fault that does not exist.
unparseable_store_is_reported_as_unreadable_not_as_a_timeout_test() ->
    Owner = ensure_netdb(),
    try
        Key = crypto:strong_rand_bytes(32),
        Reason = {unsupported_type, 5},
        From = caller(),
        Tag = element(2, From),
        Events = i2p_ct_helpers:events_from(
            fun() ->
                resolve_stored_with(Key, lease, {not_stored, Reason}, From),
                expect(Tag, {error, {lookup_failed, {not_stored, Reason}}})
            end
        ),
        ?assertEqual(
            [{lookup_failed, Key, lease, {not_stored, Reason}}],
            events_named(lookup_failed, Events)
        )
    after
        stop_netdb(Owner)
    end.

%% A store that *was* taken but still left the key without what this lookup wanted.
%% Reachable because the pending map is keyed by hash alone, so a LeaseSet can answer
%% a pending RouterInfo lookup for the same hash. The reason says the record arrived
%% and did not resolve the question, which is a third thing again.
taken_store_that_does_not_resolve_reports_not_resolved_test() ->
    Owner = ensure_netdb(),
    try
        Key = crypto:strong_rand_bytes(32),
        From = caller(),
        Tag = element(2, From),
        Events = i2p_ct_helpers:events_from(
            fun() ->
                resolve_stored_with(Key, router, stored, From),
                expect(Tag, {error, {lookup_failed, not_resolved}})
            end
        ),
        ?assertEqual(
            [{lookup_failed, Key, router, not_resolved}], events_named(lookup_failed, Events)
        )
    after
        stop_netdb(Owner)
    end.

%% The other recording point, and the reason that a lookup which heard nothing is
%% distinguishable from one that heard something unusable. The positive control for
%% the two cases above: without it, "a refusal is reported" would also be satisfied by
%% a lookup that reported a refusal whether or not one happened.
give_up_with_nothing_refused_reports_no_answer_test() ->
    Owner = ensure_netdb(),
    try
        Key = crypto:strong_rand_bytes(32),
        Events = i2p_ct_helpers:events_from(
            fun() -> expect(drive_give_up(Key), {error, {lookup_failed, no_answer}}) end
        ),
        ?assertEqual([{lookup_failed, Key, lease, no_answer}], events_named(lookup_failed, Events))
    after
        stop_netdb(Owner)
    end.

%% Deliberately absent: a case asserting that a *successful* lookup publishes
%% nothing.
%%
%% The property is real and the code satisfies it -- the success branch of
%% `f:resolve_stored/4` is `reply_all/2` and nothing else -- but every attempt to
%% assert it here drained a `lookup_failed` event naming this case's own key while
%% the orchestrator replied `{ok, _}` in the same window, with no orchestrator and
%% no tunnel server running and the only handler on the bus being this case's own
%% collector. That is a contradiction I could not explain, and the standing rule
%% here is that a test which cannot be understood is a defect in the test or in the
%% design, not a test to be shipped and re-run until it goes green.
%%
%% So the question is recorded rather than papered over. It is worth a look on its
%% own: something published a failure for a lookup that had just succeeded. The
%% two recording points in `m:i2p_lookup_srv` are the only publishers in the
%% module, and the branch that would have to run is mutually exclusive with the
%% one that produced the successful reply.

%% The opt-in is per call, and the default is genuinely the historical shape. An empty
%% options map and an explicit `reason => false` must both behave exactly like no map
%% at all, because a caller that passes options for some *other* reason must not find
%% the reply silently widened.
opt_in_is_per_call_test() ->
    ?assertEqual({error, not_found}, i2p_lookup_srv:find_ls(?HASH, #{})),
    ?assertEqual({error, not_found}, i2p_lookup_srv:find_ls(?HASH, #{reason => false})),
    ?assertEqual({error, not_found}, i2p_lookup_srv:find_ri(?HASH, #{})),
    ?assertEqual(
        {error, {lookup_failed, service_unavailable}},
        i2p_lookup_srv:find_ri(?HASH, #{reason => true})
    ).

%% The reasons, by name, and the split a consumer makes on them. Every reason is a
%% branch somewhere in `m:i2p_lookup_srv`, and the two the ticket names as its core --
%% nobody answered, and somebody answered with something unusable -- are told apart by
%% an ordinary pattern match, which is what a consumer would actually write.
every_failure_reason_is_distinguishable_test() ->
    Refusals = [{refused_with_reason, R} || R <- [older, from_future, too_old, expired]],
    Reasons = [no_answer, not_resolved, service_unavailable | Refusals],
    ?assertEqual(length(Reasons), length(lists:usort(Reasons))),
    ?assertEqual(nobody_answered, classify(no_answer)),
    ?assertEqual(nobody_answered, classify(not_resolved)),
    ?assertEqual(nobody_answered, classify(service_unavailable)),
    lists:foreach(
        fun(Refusal) -> ?assertEqual(unreadable, classify({not_stored, Refusal})) end,
        Refusals
    ).

classify({not_stored, _Reason}) -> unreadable;
classify(_Reason) -> nobody_answered.

%%%%%%%%% A lookup request that finds no tunnel %%%%%%%%%
%%
%% The third and last injection site, and the only one that charged nothing.
%% `m:i2p_client` and `m:i2p_peer` each count the send they cannot make, so
%% before this a DatabaseLookup that never left was indistinguishable from one
%% nobody answered -- the exact line `t:lookup_failed_reason/0` draws between
%% `no_answer` and everything else.
%%
%% Driven through `f:send_lookup/4` against a stub tunnel server, because that
%% is the only arrangement that produces the condition: the picks must answer
%% `{ok, _}` and the send `error`, and the two are separate calls. A real
%% tunnel manager holding a real tunnel would answer `ok` to both, and retiring
%% one between the two is a race this suite refuses to depend on.

%% The drop is counted, and the answer still comes back to the caller. Both
%% halves matter: `attempt/2` discards the answer, so a fix that propagated
%% instead of counting would break the retry loop while passing a case that
%% only watched the counter.
send_to_a_vanished_tunnel_is_counted_test() ->
    with_lookup_sends(error, fun() ->
        ?assertEqual(0, lookup_request_drops()),
        ?assertEqual(error, i2p_lookup_srv:send_lookup(pending(), <<2:256>>, <<3:256>>, ?HASH)),
        ?assertEqual(1, lookup_request_drops())
    end).

%% The positive control. Without it, "a drop is counted" is also satisfied by
%% a counter that moves on every attempt, which would report a healthy lookup
%% round as a failing one.
send_on_a_live_tunnel_does_not_count_test() ->
    with_lookup_sends(ok, fun() ->
        ?assertEqual(ok, i2p_lookup_srv:send_lookup(pending(), <<2:256>>, <<3:256>>, ?HASH)),
        ?assertEqual(0, lookup_request_drops())
    end).

%% Declared before anything moves, so "measured and zero" is distinguishable
%% from "not measured yet" -- the property that lets a consumer trust the
%% zero it reads before the first drop. Absent from the read API, a consumer
%% would have to treat absent and zero as the same thing.
lookup_request_counter_is_in_the_read_api_before_anything_moves_test() ->
    with_fresh_stats(fun() ->
        ?assertMatch(#{lookup_requests_dropped_no_tunnel := 0}, i2p_stats:snapshot())
    end).

lookup_request_drops() ->
    maps:get(lookup_requests_dropped_no_tunnel, i2p_stats:snapshot()).

%% A stub standing in for the tunnel manager, answering the three requests
%% `f:send_lookup/4` makes and nothing else. The two picks resolve; only the
%% send's answer is the case's subject, which is why `Answer` is passed for the
%% send alone -- a stub that failed the picks would exercise a different branch
%% and count nothing.
with_lookup_sends(Answer, Fun) ->
    with_fresh_stats(fun() ->
        Stub = spawn(fun() -> lookup_srv_stub(Answer) end),
        register(i2p_tunnel_srv, Stub),
        try
            Fun()
        after
            case whereis(i2p_tunnel_srv) of
                Stub -> unregister(i2p_tunnel_srv);
                _ -> ok
            end
        end
    end).

lookup_srv_stub(Answer) ->
    receive
        {'$gen_call', From, pick_lookup_inbound} ->
            gen_server:reply(From, {ok, 1, #{}}),
            lookup_srv_stub(Answer);
        {'$gen_call', From, pick_lookup_outbound} ->
            gen_server:reply(From, {ok, 2, #{}}),
            lookup_srv_stub(Answer);
        {'$gen_call', From, {send_via_outbound, _Tid, _Delivery, _Wire}} ->
            gen_server:reply(From, Answer),
            lookup_srv_stub(Answer)
    end.

%% Counters are cumulative and this module's other cases do not read this one,
%% but eunit runs a module's cases in definition order -- so a counter read by
%% one case would otherwise be whatever the previous case left behind. Restarted
%% per case so every case reads its own zero, the same way `m:i2p_client_tests`
%% does it.
with_fresh_stats(Fun) ->
    ok = stop_stats(),
    {ok, _} = i2p_stats:start_link(),
    try
        Fun()
    after
        ok = stop_stats()
    end.

stop_stats() ->
    case whereis(i2p_stats) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

%%% %%%%% Helpers for the cases above %%%%% %%%

%% Deliver a store wake-up for `Key` to a lookup that is already waiting on it, with
%% `From` as the single caller. Returns nothing; the reply lands in this process's
%% mailbox and is collected by the caller's `expect/2`.
resolve_stored_with(Key, Kind, Outcome, From) ->
    {ok, State0} = i2p_lookup_srv:init([?HASH]),
    {Pid, _Tag} = From,
    Entry = (pending())#{kind => Kind, callers => [{From, Pid, make_ref()}]},
    {noreply, _State1} = i2p_lookup_srv:handle_info(
        {db_stored, Key, Kind, Outcome}, State0#{pending := #{Key => Entry}}
    ),
    ok.

%% Arm a lookup for `Key` and let its single attempt round run out of candidates. The
%% reply is checked by the caller, inside its `events_from/1` work -- see the note on
%% `f:resolve_stored_with/4`.
drive_give_up(Key) ->
    {ok, State0} = i2p_lookup_srv:init([?HASH]),
    Ref = make_ref(),
    {noreply, State1} = i2p_lookup_srv:handle_call({find, Key, lease}, {self(), Ref}, State0),
    {noreply, _State2} = i2p_lookup_srv:handle_info({next_attempt, Key}, State1),
    Ref.

%% A pending entry's caller slot: `{From, Pid, MRef}`, where `From` is *itself* a
%% `{Pid, Tag}` pair. `f:reply_all/2` hands `From` straight to `gen:reply/2`, so a bare
%% tag or a bare pid there raises `function_clause` inside the callback under test --
%% and the failure looks like a bug in the module rather than in the fixture.
caller() ->
    From = {self(), make_ref()},
    From.

%% A `gen_server:reply/2` to this process from a callback driven in this process is a
%% self-send, so by the time `handle_info/2` returns the reply is in the mailbox. The
%% zero timeout is a barrier here, not a wait.
expect(Tag, Expected) ->
    receive
        {Tag, Expected} -> ok
    after 0 ->
        erlang:error({no_reply, Tag, Expected})
    end.

events_named(Tag, Events) -> [E || E = {T, _, _, _} <- Events, T =:= Tag].

stop_netdb(started) -> gen_server:stop(whereis(i2p_netdb_srv));
stop_netdb(existing) -> ok.

generic_info_test() ->
    ?assertEqual({noreply, base_state()}, i2p_lookup_srv:handle_info(junk, base_state())).

%% Missing-key handler paths: every clause degrades to the unchanged state.
missing_key_test() ->
    State = base_state(),
    ?assertEqual({noreply, State}, i2p_lookup_srv:handle_info({next_attempt, <<"x">>}, State)),
    ?assertEqual(
        {noreply, State}, i2p_lookup_srv:handle_info({db_stored, <<"x">>, lease, stored}, State)
    ),
    ?assertEqual({noreply, State}, i2p_lookup_srv:handle_info({search_reply, <<"x">>, []}, State)),
    ?assertEqual(
        {noreply, State},
        i2p_lookup_srv:handle_info({attempt_timeout, <<"x">>, make_ref()}, State)
    ),
    ?assertEqual(
        {noreply, State},
        i2p_lookup_srv:handle_info({'DOWN', make_ref(), process, self(), normal}, State)
    ).

%% Orchestration with a live, empty NetDb: one caller, zero floodfill
%% candidates, so the single attempt round fails with {error, {lookup_failed, no_answer}}.
orchestration_give_up_test() ->
    Owner = ensure_netdb(),
    try
        Key = <<1:256>>,
        Ref = make_ref(),
        {ok, InitState} = i2p_lookup_srv:init([?HASH]),
        {noreply, State1} =
            i2p_lookup_srv:handle_call({find, Key, lease}, {self(), Ref}, InitState),
        Me = self(),
        ?assertMatch(
            #{Key := #{kind := lease, attempts := 0, callers := [{_, Me, _}]}},
            maps:get(pending, State1)
        ),
        {noreply, State2} = i2p_lookup_srv:handle_info({next_attempt, Key}, State1),
        ?assertEqual(#{}, maps:get(pending, State2)),
        receive
            {Ref, {error, {lookup_failed, no_answer}}} ->
                ok
        after 0 ->
            error(no_reply)
        end,
        %% Same give-up when the current attempt timer fires (timer-ref branch).
        Ref2 = make_ref(),
        Entry = #{
            kind => router,
            callers => [],
            tried => [],
            chase => [],
            attempts => 0,
            deadline => erlang:monotonic_time(millisecond) + 1000,
            timer => Ref2
        },
        State3 = base_state(),
        {noreply, State4} = i2p_lookup_srv:handle_info(
            {attempt_timeout, Key, Ref2}, State3#{pending := #{Key => Entry}}
        ),
        ?assertEqual(#{}, maps:get(pending, State4))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% %% %%% Internal %%% %%

base_state() ->
    #{pending => #{}, our_hash => ?HASH}.

from() ->
    {self(), make_ref()}.

%% A well-formed pending entry: no callers, nothing tried, lifetime fresh.
pending() ->
    #{
        kind => router,
        callers => [],
        tried => [],
        chase => [],
        attempts => 0,
        deadline => erlang:monotonic_time(millisecond) + 60_000,
        timer => undefined
    }.

mk_ri() ->
    #{identity := Id, sign_priv := SignSeed} = i2p_keys:generate_with_privkeys(),
    i2p_router_info:build(Id, erlang:system_time(millisecond), [], #{}, SignSeed).

ensure_netdb() ->
    application:unset_env(i2per, data_dir),
    case whereis(i2p_netdb_srv) of
        undefined ->
            {ok, _Pid} = i2p_netdb_srv:start_link(),
            started;
        _Pid ->
            existing
    end.
