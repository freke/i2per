%% That `m:i2p_peer` forwards the blocks the introducer coordinators route to
%% them, split by coordinator, and that a disabled router forwards nothing.
%% The coordinator processes here are sink processes registered under the names
%% the attach shape registers, forwarding what they receive to the test, so the
%% forwarding logic is driven without a live router.

-module(i2p_coord_forwarding_tests).

-moduledoc """
Tests that `m:i2p_peer`'s SSU2 data path forwards the introducer-relay shapes
to `m:i2p_relay_coord` and the peer-test and RouterInfo shapes to
`m:i2p_peertest_coord` when they are enabled, and that the shapes neither
claims are still announced as unhandled. Also pins the attach-mode
coordinators' behavior without a Charlie session: a message 1 is held, not
answered, and a dead session is forgotten rather than retained.
""".

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% The forwarding split
%% --------------------------------------------------------------------------

%% The five relay shapes reach `m:i2p_relay_coord`, the peer-test and
%% RouterInfo shapes reach `m:i2p_peertest_coord`, each set in block order, and
%% the shape neither claims stays here and is announced as unhandled. A split
%% that dropped a shape, doubled one, or reordered a set is a coordinator
%% reading a block it was never sent.
forwarded_blocks_reach_the_coordinators_test() ->
    with_sinks(fun() ->
        S0 = state_with_peer(peer_hash(1)),
        Conn = conn_of(S0, peer_hash(1)),
        Msg1 =
            {peertest, 1, 0, 0, <<0:256>>, 2, 1, 0, <<127, 0, 0, 1>>, <<127, 0, 0, 1>>, <<0:512>>},
        {noreply, S1} =
            i2p_peer:handle_info(
                {ssu2_data, Conn, [
                    {relay_tag, 7},
                    Msg1,
                    {router_info, 0, <<"ri">>},
                    {path_challenge, <<"x">>}
                ]},
                S0
            ),
        %% The relay tag is the peer manager's own: it is stored against the
        %% peer's hash and is not forwarded to either coordinator, so the
        %% router_info is all the relay coordinator receives.
        ?assertEqual([{ssu2_data, Conn, [{router_info, 0, <<"ri">>}]}], drain_relay()),
        ?assertEqual(#{7 => peer_hash(1)}, maps:get(relay_tags, S1)),
        %% The RouterInfo is the one shape both coordinators claim: the
        %% peer-test coordinator needs it to learn Alice's hash for a message 1,
        %% the relay coordinator to verify her signature for a RelayIntro.
        ?assertEqual([{ssu2_data, Conn, [Msg1, {router_info, 0, <<"ri">>}]}], drain_pt()),
        ?assertEqual([path_challenge], announced())
    end).

%% Several relay shapes in one message travel together, in order — the
%% coordinators route between sessions on the set, so a per-block forward that
%% lost the grouping would change what a coordinator can see at once.
a_relay_group_travels_in_order_test() ->
    with_sinks(fun() ->
        S0 = state_with_peer(peer_hash(1)),
        Conn = conn_of(S0, peer_hash(1)),
        Request = {relay_request, 0, 1, 7, 0, 2, 1, <<127, 0, 0, 1>>, <<0:512>>},
        Response = {relay_response, 0, 1, 7, 0, 2, 0, <<>>, <<0:512>>, <<0:512>>},
        Intro = {relay_intro, 0, 1, 7, 0, 2, 1, <<127, 0, 0, 1>>, <<0:512>>, <<0:512>>},
        {noreply, _} =
            i2p_peer:handle_info(
                {ssu2_data, Conn, [relay_tag_request, Request, Response, Intro]},
                S0
            ),
        ?assertEqual(
            [{ssu2_data, Conn, [relay_tag_request, Request, Response, Intro]}], drain_relay()
        ),
        ?assertEqual([], drain_pt()),
        ?assertEqual([], announced())
    end).

%% Disabled (the default), nothing is forwarded and every non-I2NP shape that
%% nothing claims is still announced as unhandled — the state
%% `i2p_peer_block_flood_tests` pins. The relay tag is the exception: it is
%% claimed by the peer manager's own storage on either path, so it is stored
%% rather than announced. This case is the distinction: the sinks are
%% registered, the keys off — so a forward that ignored the gate would land in
%% a sink and fail the assertion.
disabled_router_forwards_nothing_test() ->
    with_sinks(fun() ->
        ok = application:unset_env(i2per, relay_coord),
        ok = application:unset_env(i2per, live_network),
        ok = application:unset_env(i2per, peertest_coord),
        S0 = state_with_peer(peer_hash(1)),
        Conn = conn_of(S0, peer_hash(1)),
        {noreply, S1} =
            i2p_peer:handle_info(
                {ssu2_data, Conn, [{relay_tag, 7}, {path_challenge, <<"x">>}]},
                S0
            ),
        ?assertEqual([], drain_relay()),
        ?assertEqual([], drain_pt()),
        ?assertEqual(#{7 => peer_hash(1)}, maps:get(relay_tags, S1)),
        ?assertEqual([path_challenge], announced())
    end).

%% --------------------------------------------------------------------------
%% Attach mode without a Charlie
%% --------------------------------------------------------------------------

%% The attach-mode peer-test coordinator holds a message 1 until a Charlie
%% session is dialed, and does not answer the session that sent it: no Charlie
%% is the ordinary state in attach mode, and routing one is the
%% Charlie-selection work this release does not do. Sending to no session at
%% all would raise the process, which is what this case pins as fixed.
attach_coord_buffers_msg1_without_a_charlie_test() ->
    BobLocal = bob_local(),
    {ok, Coord} = i2p_peertest_coord:start_attach(BobLocal),
    Session = spawn_sink(session),
    try
        RIData = maps:get(binary, maps:get(ri, BobLocal)),
        i2p_peertest_coord !
            {ssu2_data, Session, [
                {peertest, 1, 0, 0, <<0:256>>, 2, 1, 0, <<127, 0, 0, 1>>, <<127, 0, 0, 1>>, <<
                    0:512
                >>},
                {router_info, 0, RIData}
            ]},
        %% Alice's hash was learned and the request buffered: nothing answered.
        ?assertEqual([], drain(session)),
        true = is_process_alive(Coord)
    after
        catch gen_server:stop(Coord),
        exit(Session, kill)
    end.

%% The attach-mode relay coordinator records the session a relay-tag request
%% came from as the tagged peer, refuses the tag itself (no listener owns a
%% registry here — the same refusal channel as the registry at capacity), and
%% forgets the tagged session when its death is announced.
attach_relay_coord_records_then_forgot_the_tagged_session_test() ->
    BobLocal = bob_local(),
    {ok, Coord} = i2p_relay_coord:start_attach(BobLocal),
    Session = spawn_sink(session),
    try
        %% The requester's RouterInfo arrives with its handshake: this is the
        %% `{ssu2_ready, ...}` forward of an inbound session.
        i2p_relay_coord ! {ssu2_ready, Session, undefined, maps:get(ri, BobLocal)},
        i2p_relay_coord ! {ssu2_data, Session, [relay_tag_request]},
        Session = i2p_relay_coord:tagged_sess(Coord),
        ?assertEqual([], drain(session)),
        exit(Session, kill),
        i2p_relay_coord ! {ssu2_closed, Session, closed},
        undefined = i2p_relay_coord:tagged_sess(Coord)
    after
        catch gen_server:stop(Coord)
    end.

%% --------------------------------------------------------------------------
%% Fixtures
%% --------------------------------------------------------------------------

peer_hash(N) ->
    <<N:8, 0:248>>.

%% One peer holding a connection pid, so `f:find_conn_peer/2` resolves the pid
%% a block arrived on and the unhandled announce carries a real identity.
state_with_peer(Hash) ->
    #{peers => #{Hash => live_peer(Hash)}}.

live_peer(Hash) ->
    Conn = spawn_sink(conn),
    #{config => #{hash => Hash, ri => #{}}, conn => Conn, mon => undefined, status => connected}.

conn_of(State, Hash) ->
    maps:get(conn, maps:get(Hash, maps:get(peers, State))).

%% A router identity with a signed RouterInfo, in the shape the relay suite's
%% `bob_local/0` provides: the full local keys map, `ri` carrying its own wire
%% bytes under the `binary` key.
bob_local() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19152, Pub, IntroKey),
    RI =
        i2p_router_info:build(
            Identity,
            erlang:system_time(millisecond),
            [Addr],
            #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
            Seed
        ),
    #{
        static_priv => Priv,
        static_pub => Pub,
        intro_key => IntroKey,
        sign_seed => Seed,
        sign_pub => SignPub,
        hash => i2p_router_info:hash(RI),
        ri => RI
    }.

%% A sink process that forwards everything it receives to the test, named so
%% several can share one mailbox stream. A mailbox is only readable by its
%% owner, which is why the forwarding goes through here.
spawn_sink(Name) ->
    Test = self(),
    spawn(fun() -> sink(Test, Name) end).

sink(Test, Name) ->
    receive
        stop ->
            ok;
        Msg ->
            Test ! {sink_msg, Name, Msg},
            sink(Test, Name)
    end.

%% Everything one sink delivered, in order.
drain(Name) ->
    drain_loop(Name, []).

drain_loop(Name, Acc) ->
    receive
        {sink_msg, Name, Msg} -> drain_loop(Name, [Msg | Acc])
    after 100 ->
        lists:reverse(Acc)
    end.

drain_relay() ->
    drain(i2p_relay_coord).

drain_pt() ->
    drain(i2p_peertest_coord).

announced() ->
    drain_events([]).

drain_events(Acc) ->
    receive
        {event, {ssu2_block_unhandled, Name}} -> drain_events([Name | Acc])
    after 100 ->
        lists:reverse(Acc)
    end.

%% Both the bus and the counter home (the announce is the event, the total is
%% the counter), the enable keys set, and a sink process registered under each
%% coordinator's name — the name the attach shape registers, so
%% `f:i2p_peer:send_coord/2` finds it. Everything is restored: the names, the
%% keys, the processes.
with_sinks(Fun) ->
    ok = stop(i2p_counters),
    ok = stop(i2p_events),
    {ok, _} = i2p_counters:start_link(),
    {ok, _} = i2p_events:start_link(),
    ok = gen_event:add_handler(i2p_events, i2p_events_forward, [self()]),
    RelaySink = spawn_sink(i2p_relay_coord),
    PtSink = spawn_sink(i2p_peertest_coord),
    true = register(i2p_relay_coord, RelaySink),
    true = register(i2p_peertest_coord, PtSink),
    ok = application:set_env(i2per, relay_coord, true),
    ok = application:set_env(i2per, live_network, true),
    ok = application:set_env(i2per, peertest_coord, true),
    try
        Fun()
    after
        ok = application:unset_env(i2per, relay_coord),
        ok = application:unset_env(i2per, live_network),
        ok = application:unset_env(i2per, peertest_coord),
        unregister(i2p_relay_coord),
        unregister(i2p_peertest_coord),
        exit(RelaySink, kill),
        exit(PtSink, kill),
        _ = gen_event:delete_handler(i2p_events, i2p_events_forward, []),
        ok = stop(i2p_events),
        ok = stop(i2p_counters)
    end.

stop(Name) ->
    case whereis(Name) of
        undefined ->
            ok;
        Pid ->
            gen_server:stop(Pid)
    end.
