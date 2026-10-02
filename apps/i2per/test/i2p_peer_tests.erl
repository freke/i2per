-module(i2p_peer_tests).

-moduledoc """
Direct-callback unit tests for `m:i2p_peer`.

Covers init, the status/router_hash surface, lookup/publish/send_when_ready
routing across peer states, connection-lifecycle handlers (ready/floodfill
announce, inbound registration, DOWN/backoff/retry), dispatch of SSU2/NTCP2
wire (including junk frames and undecodable I2NP), the floodfill-discovery
kick, and out-of-band `learn_ri`. Real dials, handshakes, and NetDb message
round-trips happen on live sockets with a running tunnel manager and are
covered by the CT suites (network-gated); here outbound sends are a no-op
against a dead connection pid (`is_process_alive/1` short-circuit in
`f:i2p_peer:send_i2np/3`).
""".

-include_lib("eunit/include/eunit.hrl").

init_test() ->
    application:set_env(i2per, floodfill_discovery_delay_ms, 3_600_000),
    try
        Local = local(),
        RI = mk_ri(),
        Hash = i2p_router_info:hash(RI),
        {ok, State} = i2p_peer:init([Local, [RI]]),
        ?assertEqual(#{Hash => #{ri => RI, hash => Hash}}, maps:get(known, State)),
        ?assertEqual(#{}, maps:get(peers, State)),
        ?assertEqual(#{}, maps:get(inbound, State)),
        ?assertEqual(#{}, maps:get(pending, State)),
        ?assertEqual(#{}, maps:get(pending_sends, State)),
        ?assertEqual(maps:get(hash, Local), maps:get(our_hash, State)),
        ?assert(is_reference(maps:get(refresh_ref, State))),
        ?assert(is_reference(maps:get(discovery_kick_ref, State)))
    after
        application:unset_env(i2per, floodfill_discovery_delay_ms)
    end.

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
    Summary =
        #{
            H1 => #{status => connecting, attempts => 0, transport => ntcp2},
            H2 => #{status => connected, attempts => 0, transport => ssu2}
        },
    ?assertEqual({reply, Summary, S}, i2p_peer:handle_call(status, from(), S)).

generic_call_test() ->
    State = base_state(),
    ?assertEqual({reply, ok, State}, i2p_peer:handle_call(junk, from(), State)).

generic_cast_test() ->
    State = base_state(),
    ?assertEqual({noreply, State}, i2p_peer:handle_cast(junk, State)).

generic_info_test() ->
    State = base_state(),
    ?assertEqual({noreply, State}, i2p_peer:handle_info(junk, State)).

%% lookup toward a connected peer: send is a no-op against a dead conn, state
%% unchanged. Transport variants both hit send_i2np's dead-pid short-circuit.
lookup_connected_ntcp2_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    S = with_peer(
        H, peer(H, #{conn => Dead, status => connected, transport => ntcp2}), base_state()
    ),
    ?assertEqual(
        {noreply, S},
        i2p_peer:handle_cast({lookup, H, routerinfo}, S)
    ).

exploratory_lookup_uses_our_router_key_test() ->
    H = mk_hash(),
    Base = base_state(),
    From = maps:get(our_hash, Base),
    Test = self(),
    Conn = spawn(fun() -> capture_loop(Test) end),
    S = with_peer(
        H, peer(H, #{conn => Conn, status => connected, transport => ntcp2}), Base
    ),
    {noreply, _} = i2p_peer:handle_cast({lookup, H, exploratory}, S),
    Block =
        i2p_ct_helpers:wait_msg(
            fun
                ({captured, B}) -> {true, B};
                (_) -> false
            end,
            5000
        ),
    {ok, [#{type := 3, data := Data}]} = i2p_framing:decode_blocks(Block),
    {ok, Msg} = i2p_i2np:decode(Data),
    {ok, Lookup} = i2p_i2np:decode_db_lookup(maps:get(body, Msg)),
    ?assertEqual(From, maps:get(key, Lookup)).

lookup_connected_ssu2_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    S = with_peer(
        H, peer(H, #{conn => Dead, status => connected, transport => ssu2}), base_state()
    ),
    ?assertEqual(
        {noreply, S},
        i2p_peer:handle_cast({lookup, H, leaseset}, S)
    ).

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

send_when_ready_connected_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    Msg = msg(),
    S = with_peer(H, peer(H, #{conn => Dead, status => connected}), base_state()),
    ?assertEqual({noreply, S}, i2p_peer:handle_cast({send_when_ready, H, Msg}, S)).

%% Not connected but an inbound session holds the peer: send over it.
send_when_ready_inbound_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    Msg = msg(),
    Base = base_state(),
    S = Base#{inbound := #{Dead => {H, make_ref(), ntcp2}}},
    ?assertEqual({noreply, S}, i2p_peer:handle_cast({send_when_ready, H, Msg}, S)).

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

stop_test() ->
    H1 = mk_hash(),
    H2 = mk_hash(),
    Dead = dead_pid(),
    Base = base_state(),
    S =
        Base#{
            peers := #{
                H1 => peer(H1, #{conn => undefined, status => connecting}),
                H2 => peer(H2, #{conn => Dead, status => connected})
            },
            inbound := #{Dead => {mk_hash(), make_ref(), ssu2}}
        },
    ?assertMatch({stop, normal, _}, i2p_peer:handle_cast(stop, S)).

%% A conn_started for a peer we do not know: stop the connection, unchanged.
conn_started_unknown_test() ->
    Dead = dead_pid(),
    S = base_state(),
    ?assertEqual(
        {noreply, S},
        i2p_peer:handle_info({conn_started, mk_hash(), Dead, ntcp2}, S)
    ).

%% conn_started for an unknown peer where the live connection never answers
%% the stop handshake: the timeout falls back to an exit signal.
conn_started_live_stop_test() ->
    Conn = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    S = base_state(),
    ?assertEqual(
        {noreply, S},
        i2p_peer:handle_info({conn_started, mk_hash(), Conn, ntcp2}, S)
    ).

connect_failed_unknown_test() ->
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({connect_failed, mk_hash()}, S)).

connect_failed_connecting_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{status => connecting, attempts => 9}), base_state()),
    {noreply, S1} = i2p_peer:handle_info({connect_failed, H}, S),
    #{status := Status, attempts := Attempts} = maps:get(H, maps:get(peers, S1)),
    ?assertEqual(backoff, Status),
    ?assertEqual(10, Attempts).

%%%%%%%%% Connect failures are announced, with the reason and the backoff %%%%%%%%%

%% The reason travels with the failure. `i2p_ntcp2_conn` used to match
%% `{error, _Reason}` and drop it, so the manager knew a connect had failed and
%% not why — and "this peer is backing off" is the same figure for a timeout, a
%% rejected handshake and a key mismatch.
connect_failure_is_announced_with_its_reason_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{attempts => 3}), base_state()),
    ?assertEqual(
        {peer_connect_failed, H, {handshake, timeout}, 8},
        announced(fun() -> i2p_peer:handle_info({connect_failed, H, {handshake, timeout}}, S) end)
    ).

%% A failure with nothing more to report keeps its place rather than being
%% dropped: `ntcp2_connect/4` can only say that the supervisor refused, and
%% inventing a reason would be worse than admitting there is not one.
connect_failure_without_a_reason_is_still_announced_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{attempts => 1}), base_state()),
    ?assertEqual(
        {peer_connect_failed, H, unknown, 2},
        announced(fun() -> i2p_peer:handle_info({connect_failed, H}, S) end)
    ).

%% The backoff is the load-bearing field, and the announced interval is the one
%% actually in force. Asserted against the state the same call produced, because
%% an event carrying a *different* number from the one the router waits would be
%% the worst kind of duplicated figure: it would look right and be wrong.
announced_backoff_is_the_one_in_force_test() ->
    lists:foreach(
        fun(Attempts) ->
            H = mk_hash(),
            S = with_peer(H, peer(H, #{attempts => Attempts}), base_state()),
            Event = announced(fun() -> i2p_peer:handle_info({connect_failed, H, boom}, S) end),
            {peer_connect_failed, H, boom, Announced} = Event,
            {noreply, S1} = i2p_peer:handle_info({connect_failed, H, boom}, S),
            #{backoff := InForce} = maps:get(H, maps:get(peers, S1)),
            ?assertEqual(InForce, Announced)
        end,
        [0, 1, 3, 9]
    ),
    %% And the cap holds, so a long-failing peer announces the ceiling rather than
    %% an ever-growing number.
    H = mk_hash(),
    S = with_peer(H, peer(H, #{attempts => 40}), base_state()),
    ?assertMatch(
        {peer_connect_failed, H, boom, 300},
        announced(fun() -> i2p_peer:handle_info({connect_failed, H, boom}, S) end)
    ).

%% Two peers failing differently are distinguishable. Without the reason and the
%% interval these were one counter, and "retrying in a tight loop" and "given up"
%% were the same number.
different_failures_are_distinguishable_test() ->
    Event = fun(Attempts, Reason) ->
        H = mk_hash(),
        S = with_peer(H, peer(H, #{attempts => Attempts}), base_state()),
        announced(fun() -> i2p_peer:handle_info({connect_failed, H, Reason}, S) end)
    end,
    ?assertNotEqual(Event(0, timeout), Event(9, timeout)),
    ?assertNotEqual(Event(3, timeout), Event(3, protocol_error)).

%% A connect failure for a peer that is not connecting is not a failure of
%% anything: there is no backoff to enter, so nothing is announced. The state is
%% returned untouched, which is what makes this a no-op rather than a spurious
%% event.
failure_for_a_non_connecting_peer_announces_nothing_test() ->
    H = mk_hash(),
    S0 = with_peer(H, peer(H, #{status => connected}), base_state()),
    ?assertEqual(none, announced(fun() -> i2p_peer:handle_info({connect_failed, H, boom}, S0) end)),
    {noreply, S1} = i2p_peer:handle_info({connect_failed, H, boom}, S0),
    ?assertEqual(S0, S1).

%% A *drop* is not a failed connect and must not be reported as one. The two share
%% `enter_backoff/2`, which is exactly why this case is here: instrumenting the
%% backoff rather than the failure would have announced every disconnect as a
%% connect failure, and the two mean opposite things — one was never established,
%% the other was and has gone.
drop_is_not_reported_as_a_connect_failure_test() ->
    H = mk_hash(),
    Conn = i2p_ct_helpers:dead_pid(),
    Mon = make_ref(),
    S = with_peer(H, peer(H, #{conn => Conn, mon => Mon, attempts => 4}), base_state()),
    ?assertEqual(
        {peer_disconnected, H},
        announced(fun() -> i2p_peer:handle_info({'DOWN', Mon, process, Conn, boom}, S) end)
    ),
    ?assertEqual(
        [],
        peer_connect_failures(fun() ->
            i2p_peer:handle_info({'DOWN', Mon, process, Conn, boom}, S)
        end)
    ).

%%%%%%%%% Event observation %%%%%%%%%

%% `i2p_ct_helpers:events_from/1` waits for a *known* event to come back from the
%% bus before draining, rather than draining on a zero timeout. `i2p_events:notify/1`
%% returning proves nothing about delivery: `gen_event` queues the event and
%% dispatches it to the handlers afterwards, in its own process. The first version
%% of these helpers drained immediately and every case passed for the wrong reason.

announced(Fun) ->
    case i2p_ct_helpers:events_from(Fun) of
        [Event] -> Event;
        [] -> none
    end.

%% As `announced/1`, but for the case where the point is that a particular event
%% did not fire and others may have. The barrier means the absence is a real
%% absence: the bus was demonstrably live, and had already delivered everything
%% the work under test announced, by the time the list came back.
peer_connect_failures(Fun) ->
    [E || E <- i2p_ct_helpers:events_from(Fun), is_connect_failure(E)].

is_connect_failure({peer_connect_failed, _, _, _}) -> true;
is_connect_failure(_) -> false.

ntcp2_ready_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    S0 = with_peer(H, peer(H, #{conn => Dead, status => connecting, attempts => 1}), base_state()),
    S1 = S0#{pending := #{H => [exploratory]}},
    S2 = S1#{pending_sends := #{H => [{at, erlang:system_time(millisecond), msg()}]}},
    {noreply, S3} = i2p_peer:handle_info({ntcp2_ready, Dead, mk_ri()}, S2),
    Peer = maps:get(H, maps:get(peers, S3)),
    ?assertEqual(connected, maps:get(status, Peer)),
    ?assertEqual(0, maps:get(attempts, Peer)),
    ?assertEqual(ntcp2, maps:get(transport, Peer)),
    ?assertEqual(#{}, maps:get(pending, S3)),
    ?assertEqual(#{}, maps:get(pending_sends, S3)).

%% Floodfill-flagged peers get the token-carrying announce instead of the
%% plain self-announce; the flag is cleared once used.
ntcp2_ready_floodfill_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    S0 = with_peer(
        H,
        peer(H, #{conn => Dead, status => connecting, ff_publish => true}),
        base_state()
    ),
    {noreply, S1} = i2p_peer:handle_info({ntcp2_ready, Dead, mk_ri()}, S0),
    ?assertNot(maps:is_key(ff_publish, maps:get(H, maps:get(peers, S1)))),
    ?assertEqual(connected, maps:get(status, maps:get(H, maps:get(peers, S1)))).

ssu2_ready_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    S0 = with_peer(H, peer(H, #{conn => Dead, status => connecting}), base_state()),
    {noreply, S1} = i2p_peer:handle_info({ssu2_ready, Dead, #{}, undefined}, S0),
    Peer = maps:get(H, maps:get(peers, S1)),
    ?assertEqual(connected, maps:get(status, Peer)),
    ?assertEqual(0, maps:get(attempts, Peer)),
    %% unlike the NTCP2 path, ssu2_ready does not rewrite transport
    ?assertEqual(ntcp2, maps:get(transport, Peer)).

%% Floodfill-flagged SSU2 peers get the token announce; the flag is cleared.
ssu2_ready_floodfill_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    S0 = with_peer(
        H, peer(H, #{conn => Dead, status => connecting, ff_publish => true}), base_state()
    ),
    {noreply, S1} = i2p_peer:handle_info({ssu2_ready, Dead, #{}, undefined}, S0),
    ?assertEqual(
        connected,
        maps:get(status, maps:get(H, maps:get(peers, S1)))
    ),
    ?assertNot(maps:is_key(ff_publish, maps:get(H, maps:get(peers, S1)))).

%% An SSU2 inbound carrying a learnable RouterInfo is registered without an
%% outbound peer entry (line 365), learned into the NetDb, and announced back.
ssu2_ready_with_remote_ri_test() ->
    Owner = ensure_netdb(),
    try
        RI = mk_ri(),
        Hash = i2p_router_info:hash(RI),
        {noreply, S1} = i2p_peer:handle_info({ssu2_ready, self(), #{}, RI}, base_state()),
        ?assertMatch({Hash, _, ssu2}, maps:get(self(), maps:get(inbound, S1))),
        ?assertEqual(#{Hash => #{ri => RI, hash => Hash}}, maps:get(known, S1))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% A second inbound session for the same peer hash replaces the first.
ssu2_ready_replace_inbound_test() ->
    Owner = ensure_netdb(),
    try
        RI = mk_ri(),
        Hash = i2p_router_info:hash(RI),
        Old = dead_pid(),
        {noreply, S1} = i2p_peer:handle_info({ssu2_ready, Old, #{}, RI}, base_state()),
        ?assertMatch({Hash, _, ssu2}, maps:get(Old, maps:get(inbound, S1))),
        Other = dead_pid(),
        OtherHash = mk_hash(),
        S2i = S1#{
            inbound := maps:put(Other, {OtherHash, make_ref(), ntcp2}, maps:get(inbound, S1))
        },
        {noreply, S2} = i2p_peer:handle_info({ssu2_ready, self(), #{}, RI}, S2i),
        Inbound = maps:get(inbound, S2),
        ?assertEqual([], maps:keys(Inbound) -- [self(), Other]),
        ?assertMatch({Hash, _, ssu2}, maps:get(self(), Inbound)),
        ?assertMatch({OtherHash, _, ntcp2}, maps:get(Other, Inbound))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% An SSU2 inbound that announced without a RouterInfo: registered for data
%% routing when no inbound session exists yet.
ssu2_ready_unregistered_test() ->
    S0 = base_state(),
    {noreply, S1} = i2p_peer:handle_info({ssu2_ready, self(), #{}, undefined}, S0),
    Inbound = maps:get(inbound, S1),
    ?assertMatch({undefined, _, ssu2}, maps:get(self(), Inbound)).

%% ... but ignored while any inbound session is already registered.
ssu2_ready_unregistered_nonempty_test() ->
    Base = base_state(),
    S0 = Base#{inbound := #{dead_pid() => {mk_hash(), make_ref(), ntcp2}}},
    ?assertEqual(
        {noreply, S0},
        i2p_peer:handle_info({ssu2_ready, self(), #{}, undefined}, S0)
    ).

ssu2_data_empty_test() ->
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ssu2_data, self(), []}, S)).

%% SSU2 I2NP blocks: garlic/forwardable forwarded (tunnel manager absent -> ok),
%% type 10 ignored, unknown type ignored, state unchanged.
ssu2_data_forward_test() ->
    S = base_state(),
    Blocks = [
        {i2np, 11, 16#10, 1, <<>>},
        {i2np, 10, 16#20, 1, <<>>},
        {i2np, 7, 16#30, 1, <<>>}
    ],
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ssu2_data, self(), Blocks}, S)).

%% Forwarded I2NP reaches a registered tunnel manager with the resolved peer
%% hash (inbound connections resolve through the inbound table).
ssu2_forward_tunnel_cast_test() ->
    Me = self(),
    Stub = spawn(fun StubLoop() ->
        receive
            {'$gen_cast', {i2np, ConnPid, PeerHash, Msg}} ->
                Me ! {tunnel_cast, ConnPid, PeerHash, Msg},
                StubLoop();
            {'$gen_cast', _} ->
                StubLoop()
        end
    end),
    register(i2p_tunnel_srv, Stub),
    try
        H = mk_hash(),
        Base = base_state(),
        S = Base#{inbound := #{self() => {H, make_ref(), ssu2}}},
        {noreply, _S1} =
            i2p_peer:handle_info({ssu2_data, self(), [{i2np, 11, 1, 1, <<>>}]}, S),
        #{conn := ConnPid, peer_hash := PeerHash} =
            i2p_ct_helpers:wait_msg(
                fun
                    ({tunnel_cast, C, P, #{type := 11}}) ->
                        {true, #{conn => C, peer_hash => P}};
                    (_) ->
                        false
                end,
                5000
            ),
        ?assertEqual(self(), ConnPid),
        ?assertEqual(H, PeerHash)
    after
        case whereis(i2p_tunnel_srv) of
            Stub -> unregister(i2p_tunnel_srv);
            _ -> ok
        end
    end.

%% DatabasesStore / DatabaseLookup with an undecodable body: connection torn
%% down, state unchanged.
ssu2_db_bad_test() ->
    Dead = dead_pid(),
    S = base_state(),
    ?assertEqual(
        {noreply, S},
        i2p_peer:handle_info(
            {ssu2_data, Dead, [{i2np, 1, 1, 1, <<0>>}, {i2np, 2, 2, 1, <<0>>}]},
            S
        )
    ).

ssu2_closed_unknown_test() ->
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ssu2_closed, self(), normal}, S)).

ssu2_closed_peer_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{conn => self(), status => connected, attempts => 9}), base_state()),
    {noreply, S1} = i2p_peer:handle_info({ssu2_closed, self(), normal}, S),
    Peer = maps:get(H, maps:get(peers, S1)),
    ?assertEqual(backoff, maps:get(status, Peer)),
    ?assertEqual(undefined, maps:get(conn, Peer)),
    ?assertEqual(10, maps:get(attempts, Peer)).

%% ssu2_closed on an inbound session: deregistered with a disconnect notice.
ssu2_closed_inbound_test() ->
    IHash = mk_hash(),
    Base = base_state(),
    S = Base#{inbound := #{self() => {IHash, make_ref(), ssu2}}},
    {noreply, S1} = i2p_peer:handle_info({ssu2_closed, self(), normal}, S),
    ?assertEqual(#{}, maps:get(inbound, S1)).

%% Junk NTCP2 frame: framing decode fails, connection torn down, state kept.
ntcp2_frame_junk_test() ->
    Dead = dead_pid(),
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, <<0, 1, 2>>}, S)).

%% Well-framed but undecodable I2NP inside: same degrade path.
ntcp2_frame_bad_i2np_test() ->
    Dead = dead_pid(),
    Payload = i2p_framing:encode_block(3, <<0, 1, 2>>),
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S)).

down_unknown_test() ->
    S = base_state(),
    ?assertEqual(
        {noreply, S},
        i2p_peer:handle_info({'DOWN', make_ref(), process, self(), normal}, S)
    ).

down_peer_test() ->
    H = mk_hash(),
    Mon = make_ref(),
    S = with_peer(H, peer(H, #{mon => Mon, status => connected, attempts => 9}), base_state()),
    {noreply, S1} = i2p_peer:handle_info({'DOWN', Mon, process, self(), normal}, S),
    Peer = maps:get(H, maps:get(peers, S1)),
    ?assertEqual(backoff, maps:get(status, Peer)),
    ?assertEqual(10, maps:get(attempts, Peer)).

down_inbound_test() ->
    IHash = mk_hash(),
    Mon = make_ref(),
    ConnPid = dead_pid(),
    Base = base_state(),
    S = Base#{inbound := #{ConnPid => {IHash, Mon, ntcp2}}},
    {noreply, S1} = i2p_peer:handle_info({'DOWN', Mon, process, ConnPid, normal}, S),
    ?assertEqual(#{}, maps:get(inbound, S1)).

retry_peer_connecting_test() ->
    H = mk_hash(),
    S = with_peer(H, peer(H, #{status => connecting}), base_state()),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({retry_peer, H}, S)).

%% Boot kick: idle seeds get an exploratory lookup (a no-op cast here), busy
%% seeds are left alone, and the state never changes.
kick_floodfill_discovery_test() ->
    Owner = ensure_netdb(),
    try
        H1 = mk_hash(),
        H2 = mk_hash(),
        Known = #{H1 => #{hash => H1, ri => mk_ri()}, H2 => #{hash => H2, ri => mk_ri()}},
        Base = base_state(),
        S = Base#{
            known => Known,
            %% The operator's ranking, which is what `discovery_candidates/1`
            %% walks. H1 first and dialing, H2 second and already connecting, so
            %% only H1 produces a lookup.
            seed_order => [H1, H2],
            peers := #{H2 => peer(H2, #{status => connecting})}
        },
        ?assertEqual({noreply, S}, i2p_peer:handle_info(kick_floodfill_discovery, S))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

kick_ignores_nonpublished_seed_test() ->
    Owner = ensure_netdb(),
    try
        Hash = mk_hash(),
        RI = nonpublished_ri(),
        S = (base_state())#{known => #{Hash => #{hash => Hash, ri => RI}}},
        ?assertEqual({noreply, S}, i2p_peer:handle_info(kick_floodfill_discovery, S))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% Out-of-band RouterInfo: stored into the NetDb and remembered; duplicates no-op.
learn_ri_test() ->
    Owner = ensure_netdb(),
    try
        RI = mk_ri(),
        Hash = i2p_router_info:hash(RI),
        S = base_state(),
        {noreply, S1} = i2p_peer:handle_cast({learn_ri, RI}, S),
        ?assertEqual(#{Hash => #{ri => RI, hash => Hash}}, maps:get(known, S1)),
        {noreply, S2} = i2p_peer:handle_cast({learn_ri, RI}, S1),
        ?assertEqual(maps:get(known, S1), maps:get(known, S2))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% A RouterInfo the NetDb refuses for clock reasons must NOT enter the known
%% list, because it is not in the NetDb and is therefore not dialable. This is
%% the half of learn_ri/2 that used to be invisible: the store outcome was
%% discarded, so a refusal still called remember_ri/2 and looked like success.
learn_ri_too_old_not_remembered_test() ->
    Owner = ensure_netdb(),
    try
        #{identity := Id, sign_priv := SignSeed} = i2p_keys:generate_with_privkeys(),
        %% Older than the NetDb's 27h expiry window.
        Stale = erlang:system_time(millisecond) - (28 * 60 * 60 * 1000),
        RI = i2p_router_info:build(Id, Stale, [], #{}, SignSeed),
        S = base_state(),
        {noreply, S1} = i2p_peer:handle_cast({learn_ri, RI}, S),
        ?assertEqual(maps:get(known, S), maps:get(known, S1)),
        ?assertEqual(not_found, i2p_netdb_srv:find(i2p_router_info:hash(RI)))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% ----------------------------------------------------------------------------
%% Additional direct-callback coverage for reachable peer-manager clauses.
%% ----------------------------------------------------------------------------

%% Rendering with an unknown block type: framing decode succeeds, the I2NP
%% dispatcher falls through to the block catch-all.
ntcp2_frame_unknown_block_type_test() ->
    Dead = dead_pid(),
    Payload = i2p_framing:encode_block(4, <<9, 9, 9>>),
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S)).

%% A DatabaseStore of a garbage LeaseSet (store_type 1): routed to the LS
%% store, which rejects it; state untouched.
db_store_ls_garbage_test() ->
    Owner = ensure_netdb(),
    try
        Dead = dead_pid(),
        Key = mk_hash(),
        Msg = i2p_i2np:db_store(Key, 1, 0, undefined, <<0, 1, 2, 3>>),
        Payload = framed(Msg),
        S = base_state(),
        ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% A DatabaseStore of a valid signed LeaseSet (store_type 3): stored by the
%% NetDb, no replication (not a floodfill), state untouched.
db_store_ls_valid_test() ->
    Owner = ensure_netdb(),
    try
        Dead = dead_pid(),
        Key = mk_hash(),
        LS = mk_ls(),
        Msg = i2p_i2np:db_store(Key, 3, 0, undefined, i2p_leaset:to_binary(LS)),
        Payload = framed(Msg),
        S = base_state(),
        ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% A DatabaseStore with a direct-reply gateway we hold no live connection to:
%% the DeliveryStatus ack is dropped, then the RI store hits the parse-error
%% arm (garbage body).
db_store_reply_gateway_missing_test() ->
    Dead = dead_pid(),
    Key = mk_hash(),
    Gateway = mk_hash(),
    Msg = i2p_i2np:db_store(Key, 0, 1, {0, Gateway}, <<1, 2, 3>>),
    Payload = framed(Msg),
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S)).

%% A well-formed gzip wrapper whose gunzipped RouterInfo does not decode: the
%% NetDb store returns {error, _}, kept and counted.
db_store_ri_undecodable_test() ->
    Owner = ensure_netdb(),
    try
        Dead = dead_pid(),
        Key = mk_hash(),
        Junk = <<0:256>>,
        Gz = i2p_i2np:gzip_router_info(Junk),
        Data = <<(byte_size(Gz)):16/big, Gz/binary>>,
        Msg = i2p_i2np:db_store(Key, 0, 0, undefined, Data),
        Payload = framed(Msg),
        S = base_state(),
        ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

db_store_ri_remembered_without_dial_test() ->
    Owner = ensure_netdb(),
    try
        Dead = dead_pid(),
        RI = nonpublished_ri(),
        Hash = i2p_router_info:hash(RI),
        Data = i2p_i2np:router_info_data(i2p_router_info:to_binary(RI)),
        Msg = i2p_i2np:db_store(Hash, 0, 0, undefined, Data),
        S = base_state(),
        {noreply, S1} = i2p_peer:handle_info({ntcp2_frame, Dead, framed(Msg)}, S),
        ?assertEqual(#{Hash => #{ri => RI, hash => Hash}}, maps:get(known, S1)),
        ?assertEqual(#{}, maps:get(peers, S1))
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% An exploratory DatabaseLookup (direct reply, empty NetDb): answered with a
%% search reply naming nobody; send is a no-op against a dead conn.
db_lookup_exploratory_test() ->
    Owner = ensure_netdb(),
    try
        Dead = dead_pid(),
        Key = mk_hash(),
        From = maps:get(our_hash, base_state()),
        Msg = i2p_i2np:db_lookup(Key, From, i2p_i2np:lookup_type_exploratory(), []),
        Payload = framed(Msg),
        S = base_state(),
        {noreply, S1} = i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S),
        ?assertEqual(S, S1)
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% A tunnel-replied DatabaseLookup for a key we don't hold and a tunnel pick
%% that fails: search-reply is built then dropped, state untouched. Exercises
%% the tunnel delivery branch of handle_db_lookup.
db_lookup_tunnel_reply_test() ->
    Owner = ensure_netdb(),
    try
        Stub = spawn(fun TunnelLoop() ->
            receive
                {'$gen_call', {FromPid, Tag}, _Request} ->
                    FromPid ! {Tag, error},
                    TunnelLoop();
                _ ->
                    TunnelLoop()
            end
        end),
        true = register(i2p_tunnel_srv, Stub),
        try
            Dead = dead_pid(),
            Key = mk_hash(),
            From = maps:get(our_hash, base_state()),
            Msg = i2p_i2np:db_lookup_via_tunnel(
                Key, From, i2p_i2np:lookup_type_routerinfo(), 7, []
            ),
            Payload = framed(Msg),
            S = base_state(),
            {noreply, S1} = i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S),
            ?assertEqual(S, S1)
        after
            case whereis(i2p_tunnel_srv) of
                Stub -> unregister(i2p_tunnel_srv);
                _ -> ok
            end
        end
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

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

%% SSU2 ready on a state that never had a pending-sends queue (defensive
%% fallback): connected state reached, no crash.
ssu2_ready_no_pending_sends_test() ->
    H = mk_hash(),
    S0 = base_state(),
    S = S0#{peers := #{H => peer(H, #{conn => self(), status => connected, transport => ssu2})}},
    SNoPS = maps:remove(pending_sends, S),
    {noreply, S1} = i2p_peer:handle_info({ssu2_ready, self(), #{}, undefined}, SNoPS),
    ?assertMatch(#{H := #{status := connected}}, maps:get(peers, S1)).

%% Data forwarded outbound resolves through the peers table: the cast carries
%% the peer hash of the live (here: self) connection.
ssu2_forward_outbound_conn_test() ->
    Me = self(),
    Stub = spawn(fun ForwardLoop() ->
        receive
            {'$gen_cast', {i2np, ConnPid, PeerHash, Msg}} ->
                Me ! {forward_cast, ConnPid, PeerHash, Msg},
                ForwardLoop();
            _ ->
                ForwardLoop()
        end
    end),
    register(i2p_tunnel_srv, Stub),
    try
        H = mk_hash(),
        S0 = base_state(),
        S = S0#{
            peers := #{H => peer(H, #{conn => self(), status => connected, transport => ssu2})}
        },
        {noreply, _S1} =
            i2p_peer:handle_info({ssu2_data, self(), [{i2np, 11, 1, 1, <<>>}]}, S),
        #{conn := ConnPid, peer_hash := PeerHash} =
            i2p_ct_helpers:wait_msg(
                fun
                    ({forward_cast, C, P, #{type := 11}}) ->
                        {true, #{conn => C, peer_hash => P}};
                    (_) ->
                        false
                end,
                5000
            ),
        ?assertEqual(self(), ConnPid),
        ?assertEqual(H, PeerHash)
    after
        case whereis(i2p_tunnel_srv) of
            Stub -> unregister(i2p_tunnel_srv);
            _ -> ok
        end
    end.

%% A DatabaseStore with an unsupported store type: neither the RI nor the LS
%% path is taken; the store is only a replication candidate.
db_store_unsupported_store_type_test() ->
    Dead = dead_pid(),
    Key = mk_hash(),
    Msg = i2p_i2np:db_store(Key, 9, 0, undefined, <<7, 7, 7>>),
    Payload = framed(Msg),
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S)).

%% A DatabaseStore whose DeliveryStatus ack is requested through a tunnel the
%% sender does not hold a connection to: ack dropped, state untouched.
db_store_reply_tunnel_not_in_peers_test() ->
    Dead = dead_pid(),
    Key = mk_hash(),
    Gateway = mk_hash(),
    Msg = i2p_i2np:db_store(Key, 0, 9, {7, Gateway}, <<1, 2, 3>>),
    Payload = framed(Msg),
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S)).

%% A DatabaseSearchReply from a connection that is not ours: ignored.
db_search_reply_unknown_conn_test() ->
    Dead = dead_pid(),
    Key = mk_hash(),
    From = maps:get(our_hash, base_state()),
    Msg = i2p_i2np:db_search_reply(Key, [], From),
    Payload = framed(Msg),
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S)).

%% A DatabaseSearchReply whose body does not decode: ignored.
db_search_reply_bad_body_test() ->
    Dead = dead_pid(),
    Msg = i2p_i2np:encode_std(#{
        type => 3, msg_id => <<1:32>>, expiration_ms => 60_000, body => <<0, 0, 0>>
    }),
    Payload = i2p_framing:encode_block(3, Msg),
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_peer:handle_info({ntcp2_frame, Dead, Payload}, S)).

%% Sending lookups for the remaining flags: `any` and `exploratory`.
lookup_any_flag_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    S = with_peer(H, peer(H, #{conn => Dead, status => connected}), base_state()),
    ?assertEqual({noreply, S}, i2p_peer:handle_cast({lookup, H, any}, S)).

lookup_exploratory_flag_test() ->
    H = mk_hash(),
    Dead = dead_pid(),
    S = with_peer(H, peer(H, #{conn => Dead, status => connected}), base_state()),
    ?assertEqual({noreply, S}, i2p_peer:handle_cast({lookup, H, exploratory}, S)).

%% Re-storing a strictly newer LeaseSet for the same destination: the NetDb
%% returns `updated` and the peer manager replicates it (line 953).
db_store_ls_updated_test() ->
    Owner = ensure_netdb(),
    try
        #{identity := Id, sign_priv := Sign} = i2p_keys:generate_with_privkeys(),
        GW = mk_hash(),
        EndDate = erlang:system_time(second) + 86_400,
        LS1 = i2p_leaset:build(
            Id,
            erlang:system_time(second) - 5,
            1,
            [#{gateway => GW, tunnel_id => 1, end_date => EndDate}],
            Sign
        ),
        LS2 = i2p_leaset:build(
            Id,
            erlang:system_time(second) + 5,
            1,
            [#{gateway => GW, tunnel_id => 1, end_date => EndDate}],
            Sign
        ),
        Dead = dead_pid(),
        Key = mk_hash(),
        S = base_state(),
        Msg1 = i2p_i2np:db_store(Key, 3, 0, undefined, i2p_leaset:to_binary(LS1)),
        {noreply, S1} = i2p_peer:handle_info({ntcp2_frame, Dead, framed(Msg1)}, S),
        Msg2 = i2p_i2np:db_store(Key, 3, 0, undefined, i2p_leaset:to_binary(LS2)),
        {noreply, S2} = i2p_peer:handle_info({ntcp2_frame, Dead, framed(Msg2)}, S1),
        ?assertEqual(S, S1),
        ?assertEqual(S, S2)
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% ----------------------------------------------------------------------------
%% A lookup reply whose tunnel went away between the pick and the send.
%% ----------------------------------------------------------------------------
%%
%% This is the #MCVQ6D6 fix, and the race that reaches it is not buildable
%% through `f:tunnel_lookup_reply/2`: `f:pick_lookup_outbound/0` returns a pool
%% *key* and `f:find_outbound/2` searches both pools, so after a successful pick
%% the id always resolves. Only a concurrent removal makes the send answer
%% `error`, and reaching that needs a timing assumption -- a flake, not a case.
%%
%% So the state is constructed rather than raced to. A stub tunnel manager that
%% answers `error` is *exactly* what the race leaves behind, and driving
%% `f:reply_via_outbound/3` against it puts a red case on the line that changed
%% instead of a green one on the drop path beside it. Against the old `ok = ` it
%% raises `badmatch`; against the fix it answers `ok` and counts.
lookup_reply_lost_tunnel_is_counted_not_asserted_test() ->
    with_lookup_reply_count(error, fun() ->
        ?assertEqual(0, lookup_reply_drops()),
        ?assertEqual(ok, i2p_peer:reply_via_outbound(4242, local, <<"wire">>)),
        ?assertEqual(1, lookup_reply_drops())
    end).

%% The success path must not count. Otherwise the counter is measuring "a reply
%% was attempted" rather than "a reply was lost", which is the difference
%% between an operator fact and a heartbeat.
lookup_reply_delivered_does_not_count_test() ->
    with_lookup_reply_count(ok, fun() ->
        ?assertEqual(ok, i2p_peer:reply_via_outbound(4242, local, <<"wire">>)),
        ?assertEqual(0, lookup_reply_drops())
    end).

%% ----------------------------------------------------------------------------
%% Helpers
%% ----------------------------------------------------------------------------

lookup_reply_drops() ->
    maps:get(lookup_replies_dropped_no_tunnel, i2p_stats:snapshot()).

with_lookup_reply_count(Answer, Fun) ->
    HadStats = ensure_stats(),
    Stub = spawn(fun StubLoop() ->
        receive
            {'$gen_call', From, {send_via_outbound, _Tid, _Delivery, _Wire}} ->
                gen_server:reply(From, Answer),
                StubLoop();
            {'$gen_call', From, _Other} ->
                gen_server:reply(From, error),
                StubLoop()
        end
    end),
    register(i2p_tunnel_srv, Stub),
    try
        Fun()
    after
        case whereis(i2p_tunnel_srv) of
            Stub -> unregister(i2p_tunnel_srv);
            _ -> ok
        end,
        case HadStats of
            started -> ok = gen_server:stop(whereis(i2p_stats));
            existing -> ok
        end
    end.

ensure_stats() ->
    case whereis(i2p_stats) of
        undefined ->
            {ok, _} = i2p_stats:start_link(),
            started;
        _Pid ->
            existing
    end.

framed(I2NPMsg) ->
    i2p_framing:encode_block(3, i2p_i2np:encode(I2NPMsg)).

mk_ls() ->
    #{identity := Id, sign_priv := Sign} = i2p_keys:generate_with_privkeys(),
    GW = mk_hash(),
    i2p_leaset:build(
        Id,
        erlang:system_time(second),
        1,
        [#{gateway => GW, tunnel_id => 1, end_date => erlang:system_time(second) + 86_400}],
        Sign
    ).

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
            status => connecting
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

nonpublished_ri() ->
    #{identity := Id, sign_priv := SignSeed} = i2p_keys:generate_with_privkeys(),
    Addr = i2p_router_info:ntcp2_nonpublished_address(ipv4, crypto:strong_rand_bytes(32)),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Id, erlang:system_time(millisecond), [Addr], Opts, SignSeed).

mk_hash() ->
    crypto:strong_rand_bytes(32).

msg() ->
    #{type => 1, msg_id => <<16#DEADBEEF:32>>, body => <<"x">>}.

from() ->
    {self(), make_ref()}.

dead_pid() ->
    Pid = spawn(fun() -> ok end),
    MRef = erlang:monitor(process, Pid),
    receive
        {'DOWN', MRef, process, Pid, _} -> Pid
    end.

%% Stands in for a transport connection: takes frames and hands them to the test.
%% The shape is `{send, Payload}` with no reply and no sender, because that is
%% what `m:i2p_ntcp2_conn:send/2` sends now — a cast. A fake that answered would
%% be testing the old protocol, and the point of the cast is that no caller waits.
capture_loop(Test) ->
    receive
        {send, Payload} ->
            Test ! {captured, Payload},
            capture_loop(Test)
    end.

ensure_netdb() ->
    case whereis(i2p_netdb_srv) of
        undefined ->
            {ok, _} = i2p_netdb_srv:start_link(),
            started;
        _Pid ->
            existing
    end.
