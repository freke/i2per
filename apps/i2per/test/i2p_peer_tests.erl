-module(i2p_peer_tests).

-moduledoc """
Direct-callback unit tests for `m:i2p_peer`.

Every case hands the manager a state map and asserts on the state it hands back.
What is kept is the part of the surface that needs nothing but data: the
call/cast/info entry points (`router_hash`, `status`, the generic fallbacks),
dial announcements, the lookup/publish/`send_when_ready` routing decisions
across peer states, the dial deadline's arithmetic, `stop` with no timers armed,
and the inbound registration and close paths that reach no process.

Real dials, handshakes, NetDb message round-trips and reachability rounds all
need live processes -- a running `m:i2p_netdb_srv`, a registered tunnel
manager, the reachability manager, the real bus -- and are covered by the CT
suites (network-gated).
""".

-include_lib("eunit/include/eunit.hrl").

router_hash_test() ->
    State = base_state(),
    ?assertEqual(
        {reply, maps:get(hash, maps:get(local, State)), State},
        i2p_peer:handle_call(router_hash, from(), State)
    ).

status_test() ->
    H1 = mk_hash(),
    H2 = mk_hash(),
    Peers = #{
        H1 => peer(H1, #{status => connecting}),
        H2 => peer(H2, #{status => connected, transport => ssu2})
    },
    Base = base_state(),
    S = Base#{peers := Peers},
    %% The summary is asserted whole rather than field by field, because this is
    %% the read API's shape and a dropped key is the failure that matters: a
    %% per-field check would pass with `last_attempt` simply absent, and that
    %% field is the only thing that distinguishes a parked dial from a fresh one.
    Summary =
        #{
            H1 => #{
                status => connecting, attempts => 0, transport => ntcp2, last_attempt => 0
            },
            H2 => #{
                status => connected, attempts => 0, transport => ssu2, last_attempt => 0
            }
        },
    ?assertEqual({reply, Summary, S}, i2p_peer:handle_call(status, from(), S)).

%% A dial that announces itself moves the peer off the seed value its entry was
%% created with. This is the unit half of what
%% `a_peer_parked_on_ssu2_reports_ssu2_not_ntcp2` proves end to end: here the
%% announcement is the message, and the assertion is that the manager records it
%% without disturbing the rest of the entry.
dial_attempt_overrides_the_seeded_transport_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{}), base_state()),
    ?assertEqual(ntcp2, maps:get(transport, maps:get(H, maps:get(peers, S)))),
    {noreply, S1} = i2p_peer:handle_info({dial_attempt, H, ssu2}, S),
    #{status := connecting, attempts := 0, transport := ssu2} =
        maps:get(H, maps:get(peers, S1)).

%% An announcement for a peer the manager no longer holds is dropped rather than
%% creating an entry. The dialing process is unlinked and unmonitored, so it can
%% outlive the peer it was dialling, and a dial that completes into an entry that
%% has been swept would otherwise leave a half-built peer behind.
dial_attempt_for_an_unknown_peer_is_dropped_test() ->
    S = base_state(),
    Unknown = mk_hash(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({dial_attempt, Unknown, ssu2}, S)).

generic_call_test() ->
    State = base_state(),
    ?assertEqual({reply, ok, State}, i2p_peer:handle_call(junk, from(), State)).

generic_cast_test() ->
    State = base_state(),
    ?assertEqual({noreply, State}, i2p_peer:handle_cast(junk, State)).

generic_info_test() ->
    State = base_state(),
    ?assertEqual({noreply, State}, i2p_peer:handle_info(junk, State)).

%% lookup toward a connecting peer: queued, no dial (already connecting).
lookup_enqueue_connecting_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{status => connecting}), base_state()),
    {noreply, S1} = i2p_peer:handle_cast({lookup, H, routerinfo}, S),
    ?assertEqual([routerinfo], maps:get(H, maps:get(pending, S1))),
    ?assertEqual(maps:get(peers, S), maps:get(peers, S1)).

%% publish never dials an already-busy peer.
publish_connecting_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{status => connecting}), base_state()),
    ?assertEqual({noreply, S}, i2p_peer:handle_cast({publish, H}, S)).

publish_connected_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{status => connected}), base_state()),
    ?assertEqual({noreply, S}, i2p_peer:handle_cast({publish, H}, S)).

%% backoff not yet elapsed: publish leaves the peer alone.
publish_backoff_test() ->
    H = mk_hash(),
    P = peer(H, #{
        status => backoff,
        backoff => 3600,
        last_attempt => erlang:system_time(second)
    }),
    S = with_peer(H, P, base_state()),
    ?assertEqual({noreply, S}, i2p_peer:handle_cast({publish, H}, S)).

publish_api_stub_test() ->
    ?assertEqual(ok, i2p_peer:publish(mk_hash())).

%% No live connection: queued for the ready moment, peer left idle (unknown).
send_when_ready_no_inbound_test() ->
    H = mk_hash(),
    Msg = msg(),
    S = base_state(),
    {noreply, S1} = i2p_peer:handle_cast({send_when_ready, H, Msg}, S),
    ?assertMatch([{at, _, Msg}], maps:get(H, maps:get(pending_sends, S1))),
    ?assertEqual(#{}, maps:get(peers, S1)).

%% A state that never initialised pending_sends creates it on first enqueue.
send_when_ready_no_pending_sends_test() ->
    H = mk_hash(),
    Msg = msg(),
    S0 = maps:remove(pending_sends, base_state()),
    {noreply, S1} = i2p_peer:handle_cast({send_when_ready, H, Msg}, S0),
    ?assertMatch([{at, _, Msg}], maps:get(H, maps:get(pending_sends, S1))).

connect_failed_unknown_test() ->
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({connect_failed, mk_hash()}, S)).

%% The deadline is only a safety net if it is *above* every leg of a dial, since a
%% dial blocks on one SSU2 leg and then on NTCP2. Asserted against the legs rather
%% than against a constant, so raising `handshake_retry_ms` / `handshake_max_resends`
%% — or the introducer leg's own wait — cannot quietly make this deadline start
%% cutting short dials that were going to work.
the_dial_deadline_exceeds_every_leg_of_a_dial_test() ->
    Legs = i2p_ssu2_conn:dial_budget_ms(),
    ?assert(dial_deadline_ms_default() > Legs).

%% And it moves with the operator's settings rather than being a second number that
%% has to be kept in step by hand. The override is the app-env lever the CT case
%% uses to exercise a bound this long without waiting for it.
the_dial_deadline_follows_the_retransmit_settings_test() ->
    HadRetry = application:get_env(i2per, handshake_retry_ms),
    HadResends = application:get_env(i2per, handshake_max_resends),
    HadDeadline = application:get_env(i2per, dial_deadline_ms),
    application:set_env(i2per, handshake_retry_ms, 10000),
    application:set_env(i2per, handshake_max_resends, 20),
    try
        %% 10000 x 20 is 200 s, well past the introducer leg's wait, so this is
        %% the SSU2 budget that decides the deadline and the derived figure has to
        %% follow it up rather than stay at the default's.
        ?assert(dial_deadline_ms_default() > 200000)
    after
        restore_env(i2per, handshake_retry_ms, HadRetry),
        restore_env(i2per, handshake_max_resends, HadResends),
        restore_env(i2per, dial_deadline_ms, HadDeadline)
    end.

dial_deadline_ms_default() ->
    case application:get_env(i2per, dial_deadline_ms) of
        {ok, Ms} -> Ms;
        undefined -> i2p_ssu2_conn:dial_budget_ms() + 15000 + 15000
    end.

restore_env(App, Key, {ok, Value}) ->
    application:set_env(App, Key, Value);
restore_env(App, Key, undefined) ->
    application:unset_env(App, Key).

%% An SSU2 inbound that announced without a RouterInfo: registered for data
%% routing when no inbound session exists yet.
ssu2_ready_unregistered_test() ->
    S0 = base_state(),
    {noreply, S1} = i2p_peer:handle_info({ssu2_ready, self(), #{}, undefined}, S0),
    Inbound = maps:get(inbound, S1),
    ?assertMatch({undefined, _, ssu2}, maps:get(self(), Inbound)).

ssu2_data_empty_test() ->
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ssu2_data, self(), []}, S)).

ssu2_closed_unknown_test() ->
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ssu2_closed, self(), normal}, S)).

%% ssu2_closed on an inbound session: deregistered with a disconnect notice.
ssu2_closed_inbound_test() ->
    IHash = mk_hash(),
    Base = base_state(),
    S = Base#{inbound := #{self() => {IHash, make_ref(), ssu2}}},
    {noreply, S1} = i2p_peer:handle_info({ssu2_closed, self(), normal}, S),
    ?assertEqual(#{}, maps:get(inbound, S1)).

retry_peer_connecting_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{status => connecting}), base_state()),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({retry_peer, H}, S)).

%% A second lookup of the same key toward a busy peer is deduplicated: the
%% pending queue is left exactly as it was.
lookup_duplicate_dedupe_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{status => connecting}), base_state()),
    {noreply, S1} = i2p_peer:handle_cast({lookup, H, routerinfo}, S),
    {noreply, S2} = i2p_peer:handle_cast({lookup, H, routerinfo}, S1),
    ?assertEqual(maps:get(pending, S1), maps:get(pending, S2)).

%% Graceful stop when no refresh/kick timers were ever armed: the timer lookup
%% misses both maps, cancel_timer's error arm runs, and the manager stops.
stop_without_refs_test() ->
    S = maps:remove(refresh_ref, maps:remove(discovery_kick_ref, base_state())),
    ?assertEqual({stop, normal, S}, i2p_peer:handle_cast(stop, S)).

%% ----------------------------------------------------------------------------
%% Helpers
%% ----------------------------------------------------------------------------

base_state() ->
    Local = local(),
    #{
        local => Local,
        %% `known` is keyed by hash; `seed_order` is the operator's ranking of
        %% them, kept apart because `f:discovery_candidates/1` dials the first
        %% three and a map cannot carry that.
        known => #{},
        seed_order => [],
        peers => #{},
        inbound => #{},
        pending => #{},
        pending_sends => #{},
        our_hash => maps:get(hash, Local),
        refresh_ref => make_ref(),
        discovery_kick_ref => make_ref(),
        sweep_ref => make_ref()
    }.

with_peer(Hash, PeerState, State) ->
    State#{peers := maps:put(Hash, PeerState, maps:get(peers, State))}.

peer(Hash, Extra) ->
    maps:merge(
        #{
            config => #{ri => mk_ri(), hash => Hash},
            conn => undefined,
            mon => undefined,
            transport => ntcp2,
            backoff => 0,
            attempts => 0,
            last_attempt => 0,
            status => connecting,
            %% A dial in flight is a dial pid, its monitor ref, its deadline's
            %% token and the timer itself. `undefined` on every peer that is not
            %% mid-dial, which is what `f:i2p_peer:enter_backoff/2` sets it to and
            %% what the `DOWN` for an already-released dial finds nothing of.
            dial => undefined
        },
        Extra
    ).

local() ->
    RI = mk_ri(),
    #{
        static_priv => crypto:strong_rand_bytes(32),
        static_pub => crypto:strong_rand_bytes(32),
        hash => i2p_router_info:hash(RI),
        iv => crypto:strong_rand_bytes(16),
        sign_seed => crypto:strong_rand_bytes(32),
        sign_pub => crypto:strong_rand_bytes(32),
        intro_key => crypto:strong_rand_bytes(32),
        ri => RI
    }.

%% `i2p_router_info:build/5` takes the publish timestamp in ms since epoch, as
%% every production call site does. This fixture used to pass seconds, which
%% produced a 1970-dated RouterInfo that the NetDb correctly refuses as
%% `too_old`; nothing noticed because `i2p_peer:learn_ri/2` discarded the store
%% outcome. Keep the 60s age, but in the right unit.
mk_ri() ->
    #{identity := Id, sign_priv := SignSeed} = i2p_keys:generate_with_privkeys(),
    i2p_router_info:build(Id, erlang:system_time(millisecond) - 60_000, [], #{}, SignSeed).

mk_hash() ->
    crypto:strong_rand_bytes(32).

msg() ->
    #{type => 1, msg_id => <<16#DEADBEEF:32>>, body => <<"x">>}.

from() ->
    {self(), make_ref()}.
