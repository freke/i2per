%% Tunnel-manager integration tests. The suite covers transit ShortTunnelBuild
%% acceptance and forwarding, bandwidth limits, inbound and outbound builds,
%% garlic dispatch, gateway injection, client tunnel pools, LeaseSet
%% publication, and SAM delivery.
%%
%% Each case owns the application lifecycle and the tunnel manager. Transit and
%% data-path entries are created through the public build path. Waits use
%% deadline-bounded `i2p_ct_helpers` polling, with no fixed sleep gating an
%% assertion.

-module(i2p_tunnel_srv_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    stb_transit_accept_and_forward/1,
    build_pacing_limits_transit_acceptance/1,
    transit_bandwidth_unlimited_by_default/1,
    transit_bandwidth_drops_over_budget_frames/1,
    transit_bytes_counted_per_carried_frame/1,
    tunnel_outcome_counted_with_and_without_a_consumer/1,
    transit_bytes_counted_when_budget_allows_every_frame/1,
    stb_endpoint_role_accepted/1,
    stb_unaddressed_dropped/1,
    inbound_build_roundtrip/1,
    one_hop_inbound_build_activates/1,
    inbound_data_delivery/1,
    rgarlic_reply_activation/1,
    tg_gateway_injection/1,
    garlic_db_store_router_dispatch/1,
    garlic_db_store_lease_dispatch/1,
    garlic_unknown_clove_ignored/1,
    sup_wiring/1,
    fresh_status/1,
    build_timeout_clears_pending/1,
    otbrm_roundtrip/1,
    pool_disabled_without_env/1,
    pool_queues_builds_to_target/1,
    pick_returns_active_entry/1,
    demand_builds_demanded_inbound_length/1,
    demand_builds_demanded_outbound_length/1,
    demand_cleared_on_session_death/1,
    preferred_pick_by_length/1,
    e2e_garlic_delivered_to_stream_session/1,
    send_via_outbound_roundtrip_single/1,
    send_via_outbound_roundtrip_multi/1,
    outbound_injection_roundtrip/1,
    client_sends_are_not_gated_by_each_other/1,
    an_unrecognised_request_takes_the_manager_down/1,
    transit_denial_reports_capacity/1,
    transit_denial_reports_duplicate_receive_id/1,
    transit_denial_reports_build_budget_drained/1,
    transit_acceptance_announces_no_denial/1,
    publish_lease_stores_ls/1,
    leaseset_publish_with_no_floodfill_reports_failure/1,
    leaseset_publish_with_no_inbound_tunnel_reports_failure/1,
    pending_publication_is_announced_once/1,
    publish_retries_on_pool_tick/1,
    publish_prefers_demanded_length/1
]).

-include_lib("eunit/include/eunit.hrl").

-define(APP, i2per).
suite() ->
    [{timetrap, 30000}].
all() ->
    [
        stb_transit_accept_and_forward,
        build_pacing_limits_transit_acceptance,
        transit_bandwidth_unlimited_by_default,
        transit_bandwidth_drops_over_budget_frames,
        transit_bytes_counted_per_carried_frame,
        transit_bytes_counted_when_budget_allows_every_frame,
        tunnel_outcome_counted_with_and_without_a_consumer,
        stb_endpoint_role_accepted,
        stb_unaddressed_dropped,
        inbound_build_roundtrip,
        one_hop_inbound_build_activates,
        inbound_data_delivery,
        rgarlic_reply_activation,
        tg_gateway_injection,
        garlic_db_store_router_dispatch,
        garlic_db_store_lease_dispatch,
        garlic_unknown_clove_ignored,
        sup_wiring,
        fresh_status,
        build_timeout_clears_pending,
        otbrm_roundtrip,
        pool_disabled_without_env,
        pool_queues_builds_to_target,
        pick_returns_active_entry,
        demand_builds_demanded_inbound_length,
        demand_builds_demanded_outbound_length,
        demand_cleared_on_session_death,
        preferred_pick_by_length,
        e2e_garlic_delivered_to_stream_session,
        send_via_outbound_roundtrip_single,
        send_via_outbound_roundtrip_multi,
        outbound_injection_roundtrip,
        client_sends_are_not_gated_by_each_other,
        an_unrecognised_request_takes_the_manager_down,
        transit_denial_reports_capacity,
        transit_denial_reports_duplicate_receive_id,
        transit_denial_reports_build_budget_drained,
        transit_acceptance_announces_no_denial,
        publish_lease_stores_ls,
        leaseset_publish_with_no_floodfill_reports_failure,
        leaseset_publish_with_no_inbound_tunnel_reports_failure,
        pending_publication_is_announced_once,
        publish_retries_on_pool_tick,
        publish_prefers_demanded_length
    ].

init_per_testcase(_Case, Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    Config.
end_per_testcase(_Case, _Config) ->
    application:unset_env(?APP, tunnel_build_rate),
    application:unset_env(?APP, transit_bandwidth_kbps),
    application:unset_env(?APP, i2p_peer),
    application:unset_env(?APP, tunnel_pool),
    application:unset_env(?APP, transit_max_tunnels),
    %% sup_wiring stops and restarts the app within its own case; when it
    %% leaves the app down, stopping again here is already-done, not an error.
    case application:stop(?APP) of
        ok -> ok;
        {error, {not_started, ?APP}} -> ok
    end,
    ok.
%%%%%%%%% Transit STB handling: accept + forward %%%%%%%%%

%% We are the FIRST hop of a remote creator's tunnel: the addressed record
%% creates a transit entry and the modified STB is forwarded onward.
stb_transit_accept_and_forward(_Config) ->
    [OurRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 3)],
    AllRouters = [OurRouter | HopRouters],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        AllRouters
    ),
    {Pid, _Local} = start_tunnel_srv(OurRouter),
    try
        CreatorHash = crypto:strong_rand_bytes(32),
        HopHashes = [maps:get(hash, R) || R <- HopRouters],
        ObepPos = 2,
        Plaintexts = [
            i2p_tunnel:build_request_record(
                300, 301, lists:nth(1, HopHashes), #{}
            ),
            i2p_tunnel:build_request_record(
                301, 302, lists:nth(2, HopHashes), #{}
            ),
            i2p_tunnel:build_request_record(302, 0, CreatorHash, #{endpoint => true})
        ],
        AllHashes = [maps:get(hash, OurRouter) | HopHashes],
        HopDescs = [
            #{
                eph_priv => EPriv,
                hop_pub => Pub,
                id_hash => Hash
            }
         || {Pub, Hash, {_EPub, EPriv}} <- lists:zip3(
                [maps:get(static_pub, R) || R <- AllRouters],
                AllHashes,
                [i2p_crypto:x25519_keygen() || _ <- lists:seq(1, 3)]
            )
        ],
        {EncRecords, _CreatorHops} =
            i2p_ecies:encrypt_build_records(HopDescs, Plaintexts, ObepPos),
        Stb = i2p_i2np:short_tunnel_build(EncRecords),
        MsgID = crypto:strong_rand_bytes(4),
        i2p_tunnel_srv ! {i2np, self(), CreatorHash, Stb#{msg_id := MsgID}},

        ok = await_transit(300),
        [#{info := Info}] = maps:values(transit_status()),
        ?assertEqual(transit, maps:get(role, Info)),
        ?assertEqual(300, maps:get(recv_tunnel_id, Info)),
        ?assertEqual(301, maps:get(next_tunnel_id, Info)),
        ?assertEqual(hd(HopHashes), maps:get(next_hash, Info)),
        ?assertEqual(0, maps:get(layer_enc_type, Info)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Build pacing: tunnel_build_rate caps transit acceptances %%%%%%%%%

%% rate=1 accept/s with a four-second burst: exactly four STBs fit, the fifth
%% is denied until the refill. The bucket comes from the env key read at
%% server init — no state injection.
build_pacing_limits_transit_acceptance(_Config) ->
    ok = application:set_env(?APP, tunnel_build_rate, 1),
    [OurRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 3)],
    AllRouters = [OurRouter | HopRouters],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        AllRouters
    ),
    {Pid, _Local} = start_tunnel_srv(OurRouter),
    try
        lists:foreach(
            fun(Base) ->
                Stb = build_transit_stb(OurRouter, HopRouters, Base),
                MsgID = crypto:strong_rand_bytes(4),
                i2p_tunnel_srv !
                    {i2np, self(), crypto:strong_rand_bytes(32), Stb#{msg_id := MsgID}}
            end,
            [500, 510, 520, 530, 540]
        ),

        #{transit := Transit} = i2p_tunnel_srv:status(),
        ?assertEqual(4, maps:size(Transit)),
        lists:foreach(
            fun(Base) -> ?assert(maps:is_key(Base, Transit)) end,
            [500, 510, 520, 530]
        ),
        ?assertNot(maps:is_key(540, Transit)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Transit relay bandwidth: unlimited when the key is unset %%%%%%%%%

%% With no `transit_bandwidth_kbps` env the bucket is `none`: every frame is
%% relayed. The transit entry is created behaviourally by a crafted STB.
transit_bandwidth_unlimited_by_default(_Config) ->
    [Router, Next] = [make_router() || _ <- lists:seq(1, 2)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Router, Next]
    ),
    {Pid, _Local} = start_tunnel_srv(Router),
    TestPid = self(),
    try
        ok = create_transit_entry(Router, Next, 910),
        MockPeer = spawn(fun() -> mock_peer_loop(TestPid) end),
        true = register(i2p_peer, MockPeer),
        lists:foreach(
            fun(I) -> deliver_transit_frame(910, I) end,
            lists:seq(1, 4)
        ),
        Wires = receive_frames(4, []),
        ?assertEqual(4, length(Wires)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Transit relay bandwidth: over-budget frames are dropped %%%%%%%%%

%% A 1 kbps bucket holds a ~4-frame burst (rate 1024 tokens/s, capacity 4096,
%% frame charge 1028): the first three frames relay, the fourth is out of
%% budget and dropped silently. The bucket is configured from
%% `transit_bandwidth_kbps` at server init — behaviourally, like production.
transit_bandwidth_drops_over_budget_frames(_Config) ->
    ok = application:set_env(?APP, transit_bandwidth_kbps, 1),
    [Router, Next] = [make_router() || _ <- lists:seq(1, 2)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Router, Next]
    ),
    {Pid, _Local} = start_tunnel_srv(Router),
    TestPid = self(),
    try
        ok = create_transit_entry(Router, Next, 920),
        MockPeer = spawn(fun() -> mock_peer_loop(TestPid) end),
        true = register(i2p_peer, MockPeer),
        lists:foreach(
            fun(I) -> deliver_transit_frame(920, I) end,
            lists:seq(1, 4)
        ),
        Wires = receive_frames(3, []),
        ?assertEqual(3, length(Wires)),
        %% The fourth frame was dropped at the token bucket, not queued: no
        %% wire arrives inside the window. 400ms is comfortably below the
        %% ~1s refill cadence yet generous enough that a load-delayed wire
        %% would surface here; keep it tied to the bucket rate.
        assert_quiet(400),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Transit bytes: counted per frame actually carried %%%%%%%%%

%% What is counted is the **wire** figure, and the reason is not an
%% approximation. A transit hop never decrypts tunnel data, so the payload inside
%% the frame belongs to two parties who are not this router and who have never
%% told it what is in there. The honest number is what crossed the relay: the
%% full 1028-byte tunnel-data frame, most of which is a tunnel id, an IV and a
%% layered cipher. These figures are therefore an upper bound on client traffic
%% carried, and are deliberately not comparable with the transport-boundary byte
%% counters, which do measure real framing.
%%
%% The interesting assertion is the one about the frame that was **refused**.
%% With a 1 kbit/s budget only three of four delivered frames fit, and the
%% outbound total is checked against the bytes that actually appeared on the
%% wire — captured from the mock peer, not from the counter. So a charge for the
%% refused frame would make the counter exceed the wire, and a charge for nothing
%% at all would make it fall short. Both fail.
transit_bytes_counted_per_carried_frame(_Config) ->
    ok = application:set_env(?APP, transit_bandwidth_kbps, 1),
    [Router, Next] = [make_router() || _ <- lists:seq(1, 2)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Router, Next]
    ),
    {Pid, _Local} = start_tunnel_srv(Router),
    TestPid = self(),
    try
        ok = create_transit_entry(Router, Next, 930),
        MockPeer = spawn(fun() -> mock_peer_loop(TestPid) end),
        true = register(i2p_peer, MockPeer),
        #{transit_bytes_in := In0, transit_bytes_out := Out0} = i2p_stats:snapshot(),

        lists:foreach(
            fun(I) -> deliver_transit_frame(930, I) end,
            lists:seq(1, 4)
        ),
        Wires = receive_frames(3, []),
        OnWire = lists:sum([byte_size(W) || W <- Wires]),

        %% What left the router is what left the router.
        ?assertEqual(OnWire, maps:get(transit_bytes_out, i2p_stats:snapshot()) - Out0),
        %% A transit hop does not alter the body, so carried in equals carried
        %% out, frame for frame.
        ?assertEqual(
            maps:get(transit_bytes_out, i2p_stats:snapshot()) - Out0,
            maps:get(transit_bytes_in, i2p_stats:snapshot()) - In0
        ),
        %% And it is the wire frame, not the payload inside it. Three frames at
        %% the tunnel-data frame size; a fourth would mean the refused frame was
        %% charged, and a payload-sized figure would mean we had somehow measured
        %% what we cannot decrypt.
        ?assertEqual(3 * 1028, OnWire),
        ?assertEqual(1028, byte_size(hd(Wires)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%% The same thing with the budget wide open, so the figure tracks the number of
%% frames carried rather than being a constant the over-budget case happens to
%% agree with. Four in, four counted, in each direction.
transit_bytes_counted_when_budget_allows_every_frame(_Config) ->
    application:unset_env(?APP, transit_bandwidth_kbps),
    [Router, Next] = [make_router() || _ <- lists:seq(1, 2)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Router, Next]
    ),
    {Pid, _Local} = start_tunnel_srv(Router),
    TestPid = self(),
    try
        ok = create_transit_entry(Router, Next, 931),
        MockPeer = spawn(fun() -> mock_peer_loop(TestPid) end),
        true = register(i2p_peer, MockPeer),
        #{transit_bytes_in := In0, transit_bytes_out := Out0} = i2p_stats:snapshot(),

        N = 4,
        lists:foreach(
            fun(I) -> deliver_transit_frame(931, I) end,
            lists:seq(1, N)
        ),
        Wires = receive_frames(N, []),
        ?assertEqual(N * 1028, maps:get(transit_bytes_out, i2p_stats:snapshot()) - Out0),
        ?assertEqual(N * 1028, maps:get(transit_bytes_in, i2p_stats:snapshot()) - In0),
        ?assertEqual(N * 1028, lists:sum([byte_size(W) || W <- Wires]))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Tunnel lifecycle counters %%%%%%%%%

%% The defect this exists to close: the only tunnel tallies in the tree used to
%% live in the separate status application, zero-initialised when it started. So
%% the success ratio was answerable only from the moment something attached to
%% watch — a router nobody watched reported no builds at all, and one watched for
%% an hour reported an hour rather than its lifetime.
%%
%% So the same build is driven twice and the two deltas compared. **Not** a
%% comparison against a magic number: whatever the build path counts internally,
%% it counts identically whether a consumer is attached or not, and that equality
%% is the property. It is also exact — both runs do the same work, so there is
%% nothing to tolerate.
%%
%% The "without" half is the regression, and it is the *default* state: no
%% `gen_event` handler is installed on the bus at all when the first build runs.
tunnel_outcome_counted_with_and_without_a_consumer(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Local | Hops]
    ),
    {Pid, _Local} = start_tunnel_srv(Local),
    %% The bus really is bare for the first half, and that is load-bearing rather
    %% than tidiness. An earlier version of this case compared a run with a
    %% collector against a run without *one of its own*, and a leftover
    %% `i2p_events_forward` from an earlier suite was installed on the bus the
    %% whole time — so both halves had a handler and the comparison could not have
    %% told a core-owned counter from a subscriber-owned one. That is exactly the
    %% distinction under test.
    %%
    %% Clearing the bus is safe here because no suite relies on inheriting a
    %% handler: every consumer in the test tree installs its own, and the ones
    %% left behind are the accident this is removing for the length of the case.
    ok = clear_event_handlers(),
    try
        Without = drive_one_build(Local, Hops),

        ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
        try
            With = drive_one_build(Local, Hops),
            %% Identical. Whatever the build path counts internally, it counts the
            %% same with a consumer attached and with none. Also exact: both runs
            %% do the same work, so there is nothing to tolerate.
            ?assertEqual(Without, With),
            %% And the figure is not the "nothing happened" answer, so the
            %% equality above is not two zeroes.
            ?assert(maps:get(tunnels_built_outbound, With) >= 1),
            ?assert(maps:get(tunnels_built_inbound, With) >= 1)
        after
            _ = gen_event:delete_handler(i2p_events, i2p_events_tests_collector, [])
        end
    after
        %% Same teardown the neighbouring build cases use, and for the same
        %% reason: the mock peer registered for a build is process state that
        %% outlives the case unless it is explicitly removed, and a case that
        %% leaves it behind breaks the next one that registers its own.
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%% Remove every handler currently on the bus. Used by the case above to reach a
%% genuinely unobserved state.
%% Event observation for this suite, via `f:i2p_ct_helpers:events_from/1`.
%%
%% That helper waits for a *known* event to come back from the bus before it drains,
%% rather than draining on a zero timeout. The first version of this suite's own
%% helper did drain on a zero timeout, on the reasoning that the
%% `i2p_tunnel_srv:status()` call at the end of `deliver_stbs/3` was a barrier --
%% and it was not. `i2p_events:notify/1` returns as soon as `gen_event` has
%% *queued* the event; the handler is called afterwards, in the manager's own
%% process. A status call on the tunnel server orders the announce against the
%% server, not against the manager, so the message may not have been sent yet.
%% The suite passed three runs in a row, which is exactly what a race does.
%%
%% Only the denials are filtered by the cases, so an assertion is about the thing
%% under test and not about whatever else the build path announces.
with_events(Fun) ->
    i2p_ct_helpers:events_from(Fun).

denials(Events) -> [E || E = {transit_denied, _, _} <- Events].

publish_failures(Events) -> [E || E = {leaseset_publish_failed, _, _} <- Events].

%% Deliver one STB per receive ID. `build_transit_stb/3` claims the receive ID
%% from `Base`, so repeating a `Base` is what produces a duplicate.
deliver_stbs(OurRouter, HopRouters, Bases) ->
    lists:foreach(
        fun(Base) ->
            Stb = build_transit_stb(OurRouter, HopRouters, Base),
            i2p_tunnel_srv !
                {i2np, self(), crypto:strong_rand_bytes(32), Stb#{
                    msg_id := crypto:strong_rand_bytes(4)
                }}
        end,
        Bases
    ),
    %% Every STB was sent to the server before this call, and messages from one
    %% process to another arrive in order, so by the time it returns every record
    %% has been decided. What it does *not* establish is delivery to this mailbox;
    %% `with_events/1` waits for that.
    _ = i2p_tunnel_srv:status().

clear_event_handlers() ->
    lists:foreach(
        fun(Handler) ->
            _ = gen_event:delete_handler(i2p_events, Handler, [])
        end,
        gen_event:which_handlers(i2p_events)
    ).

%% Build one inbound and one outbound tunnel over `Hops`, and return the movement
%% in every tunnel counter. Counting is at the point the build succeeds, so the
%% delta is the build's own — and it is read after both builds have been consumed
%% from the tunnel server, which is the barrier.
drive_one_build(Local, Hops) ->
    Before = tunnel_counters(),
    Inbound = build_an_inbound(Local, Hops),
    _ = build_an_outbound(Hops, Inbound),
    After = tunnel_counters(),
    maps:map(fun(_K, V) -> V - maps:get(_K, Before, 0) end, After).

tunnel_counters() ->
    Snap = i2p_stats:snapshot(),
    maps:with(
        [K || K <- maps:keys(Snap), lists:prefix("tunnels_", atom_to_list(K))],
        Snap
    ).

%%%%%%%%% Endpoint roles are accepted; reply rides the record's path %%%%%%%%%

%% We are the LAST hop (endpoint position) of a 2-hop tunnel whose reply path
%% is the creator's inbound gateway: accepted as the outbound endpoint with
%% RGarlic material for assembling the reply.
stb_endpoint_role_accepted(_Config) ->
    [OurRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 2)],
    AllRouters = [OurRouter | HopRouters],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        AllRouters
    ),
    {Pid, _Local} = start_tunnel_srv(OurRouter),
    try
        CreatorHash = crypto:strong_rand_bytes(32),
        ObepPos = 1,
        OtherRouter = hd(HopRouters),
        Plaintexts = [
            i2p_tunnel:build_request_record(
                400, 401, maps:get(hash, OurRouter), #{}
            ),
            i2p_tunnel:build_request_record(401, 999, CreatorHash, #{endpoint => true})
        ],
        BuildOrder = [OtherRouter, OurRouter],
        HopDescs = [
            #{
                eph_priv => EPriv,
                hop_pub => Pub,
                id_hash => Hash
            }
         || {Pub, Hash, {_EPub, EPriv}} <- lists:zip3(
                [maps:get(static_pub, R) || R <- BuildOrder],
                [maps:get(hash, R) || R <- BuildOrder],
                [i2p_crypto:x25519_keygen() || _ <- lists:seq(1, 2)]
            )
        ],
        {EncRecords, _CreatorHops} =
            i2p_ecies:encrypt_build_records(HopDescs, Plaintexts, ObepPos),

        %% Slot 0 (OtherRouter) processes first — its runtime layering
        %% cancels its build-time concealment of OUR slot, making our record
        %% prefix readable — then hands the STB to us.
        {ok, HopInfo0} =
            i2p_tunnel:process_short_tunnel_build(
                maps:get(static_priv, OtherRouter),
                maps:get(static_pub, OtherRouter),
                maps:get(hash, OtherRouter),
                EncRecords
            ),
        Records1 = i2p_tunnel:apply_build_reply(HopInfo0, 0, EncRecords),
        Stb = i2p_i2np:short_tunnel_build(Records1),
        MsgID = crypto:strong_rand_bytes(4),
        i2p_tunnel_srv ! {i2np, self(), CreatorHash, Stb#{msg_id := MsgID}},

        ok = await_transit(401),
        [#{info := Info}] = maps:values(transit_status()),
        ?assertEqual(endpoint, maps:get(role, Info)),
        ?assert(maps:get(rgarlic_key, Info) =/= undefined),
        ?assertEqual(8, byte_size(maps:get(rgarlic_tag, Info))),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Unaddressed STBs are dropped silently %%%%%%%%%

stb_unaddressed_dropped(_Config) ->
    Router = make_router(),
    Other = make_router(),
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Router, Other]
    ),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        ObepPos = 0,
        Plaintexts = [
            i2p_tunnel:build_request_record(500, 0, crypto:strong_rand_bytes(32), #{
                endpoint => true
            })
        ],
        HopDesc = #{
            eph_priv => element(2, i2p_crypto:x25519_keygen()),
            hop_pub => maps:get(static_pub, Other),
            id_hash => maps:get(hash, Other)
        },
        {EncRecords, _CreatorHops} =
            i2p_ecies:encrypt_build_records([HopDesc], Plaintexts, ObepPos),
        Stb = i2p_i2np:short_tunnel_build(EncRecords),
        i2p_tunnel_srv ! {i2np, self(), crypto:strong_rand_bytes(32), Stb},

        ?assertEqual(#{}, transit_status()),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        stop_tunnel_srv(Pid)
    end.
%%%%%%%%% Harness %%%%%%%%%

transit_status() ->
    #{transit := Transit} = i2p_tunnel_srv:status(),
    Transit.

%% Wait until a transit entry under RecvID exists — the STB acceptance is
%% handled in the server's mailbox, so poll status() on a deadline.
await_transit(RecvID) ->
    ok = i2p_ct_helpers:await(
        fun() -> maps:is_key(RecvID, transit_status()) end,
        5000
    ),
    ok.

make_router() ->
    make_router(#{}).

make_floodfill() ->
    make_router(#{<<"caps">> => <<"Of">>}).

make_router(ExtraOptions) ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Port = free_port(),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, StaticPub, IV),
    Opts = maps:merge(
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        ExtraOptions
    ),
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        iv => IV,
        seed => Seed,
        identity => Identity,
        ri => RI,
        hash => i2p_router_info:hash(RI)
    }.

free_port() ->
    {ok, L} = gen_tcp:listen(0, [{reuseaddr, true}]),
    {ok, Port} = inet:port(L),
    gen_tcp:close(L),
    Port.

store_netdb(RI) ->
    NowMs = erlang:system_time(millisecond),
    {ok, _} = i2p_netdb_srv:store_binary(i2p_router_info:to_binary(RI), NowMs),
    ok.

start_tunnel_srv(Router) ->
    RI = maps:get(ri, Router),
    Local = #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => i2p_router_info:hash(RI),
        iv => maps:get(iv, Router),
        ri => RI
    },
    {ok, Pid} = i2p_tunnel_srv:start_link(Local),
    {Pid, Local}.

stop_tunnel_srv(Pid) ->
    Ref = erlang:monitor(process, Pid),
    i2p_tunnel_srv:stop(),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after 5000 ->
        erlang:demonitor(Ref, [flush]),
        erlang:error({tunnel_srv_stop_timeout, Pid})
    end.

%% build_transit_stb/3 — a three-record STB whose record 0 is addressed to
%% us (transit role) and continues through HopRouters to a fictional
%% creator. Base anchors the requested tunnel IDs so each call claims a
%% distinct receive ID.
build_transit_stb(OurRouter, HopRouters, Base) ->
    CreatorHash = crypto:strong_rand_bytes(32),
    HopHashes = [maps:get(hash, R) || R <- HopRouters],
    Plaintexts = [
        i2p_tunnel:build_request_record(Base, Base + 1, lists:nth(1, HopHashes), #{}),
        i2p_tunnel:build_request_record(Base + 1, Base + 2, lists:nth(2, HopHashes), #{}),
        i2p_tunnel:build_request_record(Base + 2, 0, CreatorHash, #{endpoint => true})
    ],
    AllRouters = [OurRouter | HopRouters],
    HopDescs = [
        #{eph_priv => EPriv, hop_pub => maps:get(static_pub, R), id_hash => maps:get(hash, R)}
     || {R, {_EPub, EPriv}} <-
            lists:zip(
                AllRouters,
                [i2p_crypto:x25519_keygen() || _ <- AllRouters]
            )
    ],
    {EncRecords, _CreatorHops} = i2p_ecies:encrypt_build_records(HopDescs, Plaintexts, 2),
    i2p_i2np:short_tunnel_build(EncRecords).

%% create_transit_entry/3 — install a transit entry for recv tunnel Base
%% behaviourally: a 2-record STB (we are the transit hop pointing at Next as
%% the endpoint) is built and delivered to the server as if from the creator.
%% Returns once the entry appears in status(). The build-reply forward during
%% acceptance goes to an unregistered i2p_peer and is a harmless no-op, so
%% the mock peer for frame counting is registered only afterwards.
create_transit_entry(Local, Next, Base) ->
    create_transit_entry(Local, Next, Base, #{}).

%% create_transit_entry/4 — as /3, with record-0 options for the addressed
%% slot: #{gateway => true} installs the inbound-gateway role whose next
%% pointer is the requested tunnel ID (a TG payload can then be injected).
create_transit_entry(Local, Next, Base, Flags) ->
    NextHash = maps:get(hash, Next),
    Gateway = maps:get(gateway, Flags, false),
    Plaintexts = [
        i2p_tunnel:build_request_record(Base, Base + 1, NextHash, #{gateway => Gateway}),
        i2p_tunnel:build_request_record(
            Base + 1, 0, crypto:strong_rand_bytes(32), #{endpoint => true}
        )
    ],
    HopDescs = [
        #{eph_priv => EPriv, hop_pub => maps:get(static_pub, R), id_hash => maps:get(hash, R)}
     || {R, {_EPub, EPriv}} <-
            lists:zip(
                [Local, Next],
                [i2p_crypto:x25519_keygen() || _ <- lists:seq(1, 2)]
            )
    ],
    {EncRecords, _CreatorHops} = i2p_ecies:encrypt_build_records(HopDescs, Plaintexts, 1),
    Stb = i2p_i2np:short_tunnel_build(EncRecords),
    MsgID = crypto:strong_rand_bytes(4),
    i2p_tunnel_srv ! {i2np, self(), crypto:strong_rand_bytes(32), Stb#{msg_id := MsgID}},
    await_transit(Base).

%% deliver_transit_frame/2 — push one 1028-byte TunnelData frame at a
%% transit entry, as a peer would.
deliver_transit_frame(RecvID, I) ->
    Body =
        <<RecvID:32/big, (crypto:strong_rand_bytes(16))/binary,
            (crypto:strong_rand_bytes(1008))/binary>>,
    Msg = #{
        type => 18,
        msg_id => <<0:16, I:16/big>>,
        expiration => erlang:system_time(second) + 60,
        body => Body
    },
    i2p_tunnel_srv ! {i2np, self(), crypto:strong_rand_bytes(32), Msg}.

%% Unregister (and kill) the mock i2p_peer installed for frame counting.
unregister_peer() ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            unregister(i2p_peer),
            exit(Pid, kill)
    end.

mock_peer_loop(TestPid) ->
    receive
        {'$gen_cast', Cast} ->
            TestPid ! {peer_sent, Cast},
            mock_peer_loop(TestPid);
        _Other ->
            mock_peer_loop(TestPid)
    end.

receive_frames(N, Acc) when length(Acc) =:= N ->
    lists:reverse(Acc);
receive_frames(N, Acc) ->
    %% Each frame traverses the mock peer relay + gateway fragmentation, which
    %% can exceed a fixed window under load; wait on a deadline per frame,
    %% draining any unrelated mailbox messages.
    Body =
        i2p_ct_helpers:wait_msg(
            fun(Msg) ->
                case Msg of
                    {peer_sent, {send_when_ready, _Hash, M}} -> {true, maps:get(body, M)};
                    _ -> false
                end
            end,
            5000
        ),
    receive_frames(N, [Body | Acc]).

%% assert_quiet/1 — assert that no frame wire arrives within Window ms. Uses a
%% deadline (not a fixed sleep): any `{peer_sent, ...}` before the deadline
%% fails the case; a stale deadline just drains the mailbox.
assert_quiet(Window) ->
    Deadline = erlang:monotonic_time(millisecond) + Window,
    assert_quiet_until(Deadline).

assert_quiet_until(Deadline) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            ok;
        false ->
            receive
                {peer_sent, {send_when_ready, _, _}} ->
                    erlang:error(transit_frame_not_dropped);
                _Other ->
                    assert_quiet_until(Deadline)
            after erlang:max(0, Deadline - erlang:monotonic_time(millisecond)) ->
                ok
            end
    end.
%%%%%%%%% Inbound builds: garlic STB out, layered STB home %%%%%%%%%

%% We drive one of our own inbound builds: the server wraps an STB garlic
%% to the first hop, every participant seals ret 0 in build order, the
%% modified STB returns to us, and finish_inbound activates the client
%% inbound entry keyed by our receive tunnel ID.
inbound_build_roundtrip(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(fun(R) -> store_netdb(maps:get(ri, R)) end, [Local | Hops]),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        Info = build_an_inbound(Local, Hops),
        Entry = maps:get(entry, Info),
        ?assertEqual(
            lists:sort([maps:get(hash, R) || R <- Hops]),
            lists:sort(maps:get(router_hashes, Info))
        ),
        ?assertEqual(maps:get(tunnel_ids, Info), maps:get(tunnel_ids, Entry)),
        ?assertEqual(maps:get(router_hashes, Info), maps:get(router_hashes, Entry)),
        lists:foreach(
            fun({Layer, HopKey}) ->
                ?assertEqual(maps:get(layer_key, HopKey), maps:get(layer_key, Layer)),
                ?assertEqual(maps:get(iv_key, HopKey), maps:get(iv_key, Layer))
            end,
            lists:zip(maps:get(layers, Entry), maps:get(hop_keys, Info))
        ),
        ?assertEqual(#{}, pending_in_status()),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%% A single-hop build is just the inward half of the roundtrip: one record
%% addressed to the gateway hop whose next pointer closes on us. The sealed
%% one-record STB still activates a 2-ID inbound entry (hop + ours). The
%% default build_inbound() always asks for ?NUM_HOPS hops, so a 1-hop build
%% is reached through the demand path: set_lengths(1,1) + the pool tick.
one_hop_inbound_build_activates(_Config) ->
    [Local, Hop] = [make_router() || _ <- lists:seq(1, 2)],
    lists:foreach(fun(R) -> store_netdb(maps:get(ri, R)) end, [Local, Hop]),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        DemandOneHop =
            fun() ->
                ok = i2p_tunnel_srv:set_lengths(self(), 1, 1),
                i2p_tunnel_srv ! pool_tick,
                ok
            end,
        Info = build_an_inbound(Local, [Hop], DemandOneHop),
        Entry = maps:get(entry, Info),
        ?assertEqual([maps:get(hash, Hop)], maps:get(router_hashes, Info)),
        ?assertEqual([maps:get(hash, Hop)], maps:get(router_hashes, Entry)),
        ?assertEqual(2, length(maps:get(tunnel_ids, Entry))),
        ?assertEqual(#{}, pending_in_status()),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%% A DatabaseStore for a fresh router rides the inbound tunnel out of a
%% garlic clove: after the layered roundtrip activation, the data path (IBGW
%% gateway -> participant layers -> our recv ID) lands the store in the
%% NetDb under the remote router's hash.
inbound_data_delivery(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(fun(R) -> store_netdb(maps:get(ri, R)) end, [Local | Hops]),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        Info = build_an_inbound(Local, Hops),
        {RiHash, Clove} = db_router_store_clove(),
        GarlicMsg = i2p_garlic:wrap_router([Clove], maps:get(static_pub, Local)),
        StdMsg = i2p_i2np:encode_std(GarlicMsg#{expiration_ms => 60000}),
        Frames = frame_through_inbound(maps:get(entry, Info), StdMsg),
        IbgwHash = maps:get(ibgw_hash, Info),
        lists:foreach(
            fun(DataBody) ->
                Msg = #{
                    type => 18,
                    msg_id => i2p_i2np:fresh_msg_id(),
                    expiration => erlang:system_time(second) + 60,
                    body => DataBody
                },
                i2p_tunnel_srv ! {i2np, self(), IbgwHash, Msg}
            end,
            Frames
        ),
        %% The status call is a processing barrier: the i2np messages — and the
        %% synchronous netdb store they trigger — complete before it returns.
        _ = i2p_tunnel_srv:status(),
        ?assertMatch({ok, _}, i2p_netdb_srv:find(RiHash)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Outbound builds: the OTBRM comes home through the inbound %%%%%%%%%

%% pick_reply_path names our first active inbound tunnel; the OBEP wraps
%% the OTBRM in an Existing Session (RGarlic) garlic addressed there, the
%% inbound data path delivers it, and the outbound build activates.
rgarlic_reply_activation(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(fun(R) -> store_netdb(maps:get(ri, R)) end, [Local | Hops]),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        Inbound = build_an_inbound(Local, Hops),

        ok = i2p_tunnel_srv:build_outbound(),
        RoutersByHash = maps:from_list([{maps:get(hash, R), R} || R <- Hops]),
        {OutIbgwHash, GarlicMsg} = await_build_garlic(),
        {MsgID, Records} = stb_from_garlic(GarlicMsg, maps:get(OutIbgwHash, RoutersByHash)),
        #{pending := Pending} = i2p_tunnel_srv:status(),
        #{MsgID := Build} = Pending,
        TunnelIds = maps:get(tunnel_ids, Build),
        HopKeys = maps:get(hop_keys, Build),

        Stop = fun(Info, _Next) -> maps:get(role, Info) =:= endpoint end,
        {_Infos, FinalRecords} = forward_stb(RoutersByHash, OutIbgwHash, Records, Stop),

        OTBRM = i2p_i2np:outbound_tunnel_build_reply(FinalRecords),
        #{rgarlic_key := RKey, rgarlic_tag := RTag} = lists:last(HopKeys),
        Clove = #{
            delivery => local,
            type => 26,
            msg_id => MsgID,
            expiration => erlang:system_time(second) + 60,
            data => maps:get(body, OTBRM)
        },
        GarlicMsg1 = i2p_garlic:wrap_existing_session([Clove], RKey, RTag),
        StdMsg = i2p_i2np:encode_std(GarlicMsg1#{expiration_ms => 60000}),

        Frames = frame_through_inbound(maps:get(entry, Inbound), StdMsg),
        lists:foreach(
            fun(DataBody) ->
                Msg = #{
                    type => 18,
                    msg_id => i2p_i2np:fresh_msg_id(),
                    expiration => erlang:system_time(second) + 60,
                    body => DataBody
                },
                i2p_tunnel_srv ! {i2np, self(), maps:get(ibgw_hash, Inbound), Msg}
            end,
            Frames
        ),
        FirstTunID = hd(TunnelIds),
        ok = await_outbound(FirstTunID),

        #{pending := Pending1, tunnels := Tunnels} = i2p_tunnel_srv:status(),
        ?assertEqual(#{}, Pending1),
        [{FirstTunID, Entry}] = maps:to_list(Tunnels),
        ?assertEqual(TunnelIds, maps:get(tunnel_ids, Entry)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% TunnelGateway: transit entry with the inbound-gateway flag %%%%%%%%%

%% TG injection targets our inbound-gateway transit slot: the entry was
%% installed with is_gateway = true and the payload is fragmented into the
%% entry's gw_state, which we can see on status().
tg_gateway_injection(_Config) ->
    Router = make_router(),
    Next = make_router(),
    lists:foreach(fun(R) -> store_netdb(maps:get(ri, R)) end, [Router, Next]),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        RecvID = 800,
        ok = create_transit_entry(Router, Next, RecvID, #{gateway => true}),
        register_mock_peer(self()),

        PayloadMsg = #{
            type => 18,
            msg_id => i2p_i2np:fresh_msg_id(),
            expiration_ms => 60000,
            body => crypto:strong_rand_bytes(64)
        },
        TGMsg = i2p_i2np:tunnel_gateway(RecvID, i2p_i2np:encode_std(PayloadMsg)),
        PeerHash = crypto:strong_rand_bytes(32),
        i2p_tunnel_srv ! {i2np, self(), PeerHash, TGMsg#{msg_id := i2p_i2np:fresh_msg_id()}},

        [{RecvID, Entry}] = maps:to_list(transit_status()),
        ?assertEqual(true, maps:get(is_gateway, maps:get(info, Entry))),
        ?assert(maps:is_key(gw_state, Entry)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Garlic DB cloves: DatabaseStore dispatches to netdb_srv %%%%%%%%%

%% A direct-delivery garlic carrying a router DatabaseStore lands its
%% RouterInfo in the NetDb after the status() barrier.
garlic_db_store_router_dispatch(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        {RiHash, Clove} = db_router_store_clove(),
        garlic_to_tunnel(self(), Router, [Clove]),
        _ = i2p_tunnel_srv:status(),
        ?assertMatch({ok, _}, i2p_netdb_srv:find(RiHash)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        stop_tunnel_srv(Pid)
    end.

%% A direct-delivery garlic carrying a LeaseSet DatabaseStore is dispatched
%% without crashing the tunnel server (lease payloads are opaque here).
garlic_db_store_lease_dispatch(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        DestHash = crypto:strong_rand_bytes(32),
        StoreBody = <<DestHash/binary, 1:8, 0:32/big, (crypto:strong_rand_bytes(128))/binary>>,
        Clove = #{
            delivery => local,
            type => 1,
            msg_id => crypto:strong_rand_bytes(4),
            expiration => erlang:system_time(second) + 300,
            data => StoreBody
        },
        garlic_to_tunnel(self(), Router, [Clove]),
        _ = i2p_tunnel_srv:status(),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        stop_tunnel_srv(Pid)
    end.

%% An unknown-type clove is ignored: the server keeps serving and no tunnel
%% state appears.
garlic_unknown_clove_ignored(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        Clove = #{
            delivery => local,
            type => 99,
            msg_id => crypto:strong_rand_bytes(4),
            expiration => erlang:system_time(second) + 300,
            data => <<"unknown stuff">>
        },
        garlic_to_tunnel(self(), Router, [Clove]),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv))),
        #{pending := Pending, tunnels := Tunnels} = i2p_tunnel_srv:status(),
        ?assertEqual(#{}, Pending),
        ?assertEqual(#{}, Tunnels)
    after
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% App wiring: i2p_tunnel_srv starts from the i2p_peer env %%%%%%%%%

%% With the i2p_peer application env set before startup, the tunnel server
%% is a supervisor child like any other service and starts empty.
sup_wiring(_Config) ->
    Router = make_router(),
    SeedRI = maps:get(ri, Router),
    Local = #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => maps:get(hash, Router),
        iv => maps:get(iv, Router),
        ri => SeedRI
    },
    application:unset_env(?APP, i2p_peer),
    ok = application:stop(?APP),
    application:set_env(?APP, i2p_peer, #{local => Local, seeds => [SeedRI]}),
    try
        {ok, _} = application:ensure_all_started(?APP),
        Pid = whereis(i2p_tunnel_srv),
        ?assert(is_pid(Pid)),
        ?assert(is_process_alive(Pid)),
        #{pending := Pending, tunnels := Tunnels} = i2p_tunnel_srv:status(),
        ?assertEqual(#{}, Pending),
        ?assertEqual(#{}, Tunnels)
    after
        application:stop(?APP),
        application:unset_env(?APP, i2p_peer)
    end.
%%%%%%%%% Inbound-build harness %%%%%%%%%

pending_in_status() ->
    #{pending_in := PendingIn} = i2p_tunnel_srv:status(),
    PendingIn.

%% Install the capturing mock i2p_peer. Must precede any build cast: the
%% server casts send_when_ready to the registered name, which a silent no-op
%% for an unregistered process would swallow. Idempotent: a case that drives
%% several builds back to back (e.g. a second inbound after a demanded-length
%% one) reuses the peer already installed.
register_mock_peer(TestPid) ->
    case whereis(i2p_peer) of
        undefined ->
            MockPeer = spawn(fun() -> mock_peer_loop(TestPid) end),
            true = register(i2p_peer, MockPeer),
            MockPeer;
        _Registered ->
            ok
    end.

%% await_build_garlic/0 — the peel of the first garlic STB the mock peer is
%% handed. Genearls the 3-message inbox (database stores stay invisible).
await_build_garlic() ->
    i2p_ct_helpers:wait_msg(
        fun(Msg) ->
            case Msg of
                {peer_sent, {send_when_ready, Hash, #{type := 11} = G}} ->
                    {true, {Hash, G}};
                _ ->
                    false
            end
        end,
        5000
    ).

%% stb_from_garlic/2 — open a Noise-N garlic wrap under a hop's static key
%% and pull out the STB clove: its msg_id names the build and its data is
%% the `<<Num:8, ...>>` record stream.
stb_from_garlic(GarlicMsg, Router) ->
    {ok, #{data := Encrypted}} =
        i2p_i2np:decode_garlic(maps:get(body, GarlicMsg)),
    {ok, Blocks} = i2p_garlic:unwrap_router(Encrypted, maps:get(static_priv, Router)),
    [Clove] = i2p_garlic:extract_cloves(Blocks),
    {ok, #{records := Records}} = i2p_i2np:decode_short_tunnel_build(maps:get(data, Clove)),
    {maps:get(msg_id, Clove), Records}.

%% forward_stb/4 — walk a build STB through its hops. Each participant
%% processes the records under its static key, seals its own reply slot (ret
%% 0), and hands the list on toward Its next pointer, until Stop(Info, Next)
%% returns true. Returns the collected hop info and the fully-sealed records.
forward_stb(HopMap, Hash, Records, Stop) ->
    forward_stb(HopMap, Hash, Records, Stop, []).

forward_stb(HopMap, Hash, Records, Stop, RevInfos) ->
    Router = maps:get(Hash, HopMap),
    {ok, Info} = i2p_tunnel:process_short_tunnel_build(
        maps:get(static_priv, Router),
        maps:get(static_pub, Router),
        maps:get(hash, Router),
        Records
    ),
    Records1 = i2p_tunnel:apply_build_reply(Info, 0, Records),
    Next = maps:get(next_hash, Info),
    case Stop(Info, Next) of
        true ->
            {lists:reverse([Info | RevInfos]), Records1};
        false ->
            forward_stb(HopMap, Next, Records1, Stop, [Info | RevInfos])
    end.

%% build_an_inbound/2 — start one of our own inbound builds and drive it to
%% activation: capture the garlic STB, walk the hops until one points back at
%% us, return the sealed STB, await the entry under our receive ID, and read
%% back the activated build metadata. Returns #{ibgw_hash, tunnel_ids,
%% router_hashes, hop_keys, entry, recv_id}. Uses the default hop count, so
%% the NetDb must hold that many remote hops.
build_an_inbound(Local, HopRouters) ->
    build_an_inbound(Local, HopRouters, fun i2p_tunnel_srv:build_inbound/0).

%% build_an_inbound/3 — variant with a caller-supplied build trigger, for
%% lengths the demand path alone can reach (e.g. a 1-hop build when the NetDb
%% holds a single remote hop).
build_an_inbound(Local, HopRouters, Trigger) ->
    OurHash = maps:get(hash, Local),
    RoutersByHash = maps:from_list([{maps:get(hash, R), R} || R <- HopRouters]),
    register_mock_peer(self()),
    ok = Trigger(),
    {IbgwHash, GarlicMsg} = await_build_garlic(),
    {MsgID, Records} = stb_from_garlic(GarlicMsg, maps:get(IbgwHash, RoutersByHash)),
    #{pending_in := PendingIn} = i2p_tunnel_srv:status(),
    #{MsgID := Build} = PendingIn,
    TunnelIds = maps:get(tunnel_ids, Build),
    Stop = fun(_Info, Next) -> Next =:= OurHash end,
    {_Infos, FinalRecords} = forward_stb(RoutersByHash, IbgwHash, Records, Stop),
    StbMsg = i2p_i2np:short_tunnel_build(FinalRecords),
    i2p_tunnel_srv ! {i2np, self(), IbgwHash, StbMsg#{msg_id := MsgID}},
    RecvID = lists:last(TunnelIds),
    ok = await_inbound(RecvID),
    #{inbound := Inbound} = i2p_tunnel_srv:status(),
    #{
        ibgw_hash => IbgwHash,
        tunnel_ids => TunnelIds,
        router_hashes => maps:get(router_hashes, Build),
        hop_keys => maps:get(hop_keys, Build),
        entry => maps:get(RecvID, Inbound),
        recv_id => RecvID
    }.

await_inbound(RecvID) ->
    ok = i2p_ct_helpers:await(
        fun() ->
            #{inbound := Inbound} = i2p_tunnel_srv:status(),
            maps:is_key(RecvID, Inbound)
        end,
        5000
    ),
    ok.

await_outbound(TunID) ->
    ok = i2p_ct_helpers:await(
        fun() ->
            #{tunnels := Tunnels} = i2p_tunnel_srv:status(),
            maps:is_key(TunID, Tunnels)
        end,
        5000
    ),
    ok.

%% db_router_store_clove/0 — a garlic clove whose DatabaseStore advertises a
%% fresh RouterInfo under its own hash (store_type 0). The test asserts the
%% store lands in the NetDb.
db_router_store_clove() ->
    RiRouter = make_router(),
    RiBin = i2p_router_info:to_binary(maps:get(ri, RiRouter)),
    RiHash = i2p_router_info:hash(maps:get(ri, RiRouter)),
    StoreBody = <<RiHash/binary, 0:8, 0:32/big, RiBin/binary>>,
    {RiHash, #{
        delivery => local,
        type => 1,
        msg_id => crypto:strong_rand_bytes(4),
        expiration => erlang:system_time(second) + 300,
        data => StoreBody
    }}.

%% garlic_to_tunnel/3 — deliver a direct-delivery garlic (Noise N, wrapped to
%% the router's static key) to the tunnel server as if from PeerHash.
garlic_to_tunnel(ConnPid, Router, Cloves) ->
    GarlicMsg = i2p_garlic:wrap_router(Cloves, maps:get(static_pub, Router)),
    i2p_tunnel_srv ! {i2np, ConnPid, crypto:strong_rand_bytes(32), GarlicMsg},
    ok.

%% frame_through_inbound/2 — push a standard-header message down an active
%% inbound tunnel the way production data travels: the gateway fragments it,
%% every participant seals one wire layer in hop order, and the frames come
%% out addressed to our receive ID.
frame_through_inbound(Entry, StdMsg) ->
    Layers = maps:get(layers, Entry),
    TunnelIds = maps:get(tunnel_ids, Entry),
    GwRecvID = hd(TunnelIds),
    {Frames, _GwState} = i2p_tunnel:gateway_all(GwRecvID, local, undefined, StdMsg),
    [wire_layer(Layers, TunnelIds, Frame) || Frame <- Frames].

wire_layer(Layers, [_GwRecvID, NextID | _] = TunnelIds, Frame0) ->
    <<_:32/big, Rest0/binary>> = Frame0,
    IBGW = hd(Layers),
    Wire1 = i2p_tunnel:encrypt_layer(
        <<NextID:32/big, Rest0/binary>>,
        maps:get(layer_key, IBGW),
        maps:get(iv_key, IBGW)
    ),
    lists:foldl(
        fun({Layer, TargetID}, Wire) ->
            {ok, W} = i2p_tunnel:process_tunnel_data(
                Wire, Layer, TargetID, i2p_i2np:fresh_msg_id()
            ),
            W
        end,
        Wire1,
        lists:zip(tl(Layers), lists:sublist(TunnelIds, 3, length(Layers)))
    ).
%%%%%%%%% Pool management and outbound build scenarios %%%%%%%%%

%% A freshly started tunnel server has empty pending and active maps.
fresh_status(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        #{pending := Pending, tunnels := Tunnels, transit := Transit} =
            i2p_tunnel_srv:status(),
        ?assertEqual(#{}, Pending),
        ?assertEqual(#{}, Tunnels),
        ?assertEqual(#{}, Transit)
    after
        stop_tunnel_srv(Pid)
    end.

%% A build_timeout message clears the pending build under its MsgID.
build_timeout_clears_pending(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        MsgID = crypto:strong_rand_bytes(4),
        Build = #{
            tunnel_ids => [100, 101, 102],
            router_hashes => [<<1:32/unit:8>>, <<2:32/unit:8>>, <<3:32/unit:8>>],
            hop_keys =>
                [
                    #{
                        reply_key => crypto:strong_rand_bytes(32),
                        layer_key => crypto:strong_rand_bytes(32),
                        iv_key => crypto:strong_rand_bytes(32),
                        noise_h => crypto:strong_rand_bytes(32)
                    }
                 || _ <- lists:seq(1, 3)
                ],
            timer_ref => make_ref()
        },
        ok = inject_pending_build(MsgID, Build),
        #{pending := Pending1} = i2p_tunnel_srv:status(),
        ?assert(maps:is_key(MsgID, Pending1)),
        i2p_tunnel_srv ! {build_timeout, MsgID},
        #{pending := Pending2} = i2p_tunnel_srv:status(),
        ?assertNot(maps:is_key(MsgID, Pending2))
    after
        stop_tunnel_srv(Pid)
    end.

%% Full OTBRM round-trip: 4 routers, 3-hop build, sealed records
%% delivered back — the tunnel activates with correct per-hop layer keys.
otbrm_roundtrip(_Config) ->
    [LocalRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 4)],
    AllRouters = [LocalRouter | HopRouters],
    lists:foreach(fun(R) -> store_netdb(maps:get(ri, R)) end, AllRouters),
    {Pid, Local} = start_tunnel_srv(LocalRouter),
    LocalHash = maps:get(hash, Local),
    try
        HopHashes = [maps:get(hash, R) || R <- HopRouters],
        TunnelIds = [200, 201, 202],
        ObepPos = 2,
        Plaintexts = [
            i2p_tunnel:build_request_record(200, 201, lists:nth(2, HopHashes), #{}),
            i2p_tunnel:build_request_record(201, 202, lists:nth(3, HopHashes), #{}),
            i2p_tunnel:build_request_record(202, 0, LocalHash, #{endpoint => true})
        ],
        HopDescs = [
            #{
                eph_priv => EPriv,
                hop_pub => maps:get(static_pub, R),
                id_hash => maps:get(hash, R)
            }
         || {R, {_EPub, EPriv}} <- lists:zip(HopRouters, [
                i2p_crypto:x25519_keygen()
             || _ <- lists:seq(1, 3)
            ])
        ],
        {EncRecords, CreatorHops} =
            i2p_ecies:encrypt_build_records(HopDescs, Plaintexts, ObepPos),

        FinalRecords =
            lists:foldl(
                fun({_I, Router}, Records) ->
                    {ok, Info} = i2p_tunnel:process_short_tunnel_build(
                        maps:get(static_priv, Router),
                        maps:get(static_pub, Router),
                        maps:get(hash, Router),
                        Records
                    ),
                    i2p_tunnel:apply_build_reply(Info, 0, Records)
                end,
                EncRecords,
                lists:zip(lists:seq(1, 3), HopRouters)
            ),

        MsgID = crypto:strong_rand_bytes(4),
        ok = inject_pending_build(MsgID, #{
            tunnel_ids => TunnelIds,
            router_hashes => HopHashes,
            hop_keys => CreatorHops,
            timer_ref => make_ref()
        }),

        OTBRMMsg = i2p_i2np:outbound_tunnel_build_reply(FinalRecords),
        i2p_tunnel_srv !
            {i2np, self(), hd(HopHashes), OTBRMMsg#{msg_id := MsgID}},

        #{pending := Pending, tunnels := Tunnels} = i2p_tunnel_srv:status(),
        ?assertNot(maps:is_key(MsgID, Pending)),
        ?assertEqual(1, maps:size(Tunnels)),
        [{_TunID, Entry}] = maps:to_list(Tunnels),
        ?assertEqual(HopHashes, maps:get(router_hashes, Entry)),
        ?assertEqual(TunnelIds, maps:get(tunnel_ids, Entry)),
        lists:foreach(
            fun({Layer, CreatorHop}) ->
                ?assertEqual(maps:get(layer_key, CreatorHop), maps:get(layer_key, Layer)),
                ?assertEqual(maps:get(iv_key, CreatorHop), maps:get(iv_key, Layer))
            end,
            lists:zip(maps:get(layers, Entry), CreatorHops)
        )
    after
        stop_tunnel_srv(Pid)
    end.

%% With no tunnel_pool env, the pool tick does nothing and picks fail.
pool_disabled_without_env(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        seed_netdb(3),
        i2p_tunnel_srv ! pool_tick,
        #{pending := Pending, pending_in := PendingIn} = i2p_tunnel_srv:status(),
        ?assertEqual(#{}, Pending),
        ?assertEqual(#{}, PendingIn),
        ?assertEqual(error, i2p_tunnel_srv:pick_outbound()),
        ?assertEqual(error, i2p_tunnel_srv:pick_inbound())
    after
        stop_tunnel_srv(Pid)
    end.

%% A pool_tick queues exactly one inbound build to the target count;
%% a second tick must not duplicate it.
pool_queues_builds_to_target(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        ok = application:set_env(?APP, tunnel_pool, #{outbound => 1, inbound => 1}),
        seed_netdb(3),
        i2p_tunnel_srv ! pool_tick,
        #{pending := Pending, pending_in := PendingIn} = i2p_tunnel_srv:status(),
        ?assertEqual(#{}, Pending),
        ?assertEqual(1, maps:size(PendingIn)),
        i2p_tunnel_srv ! pool_tick,
        #{pending := Pending2, pending_in := PendingIn2} = i2p_tunnel_srv:status(),
        ?assertEqual(#{}, Pending2),
        ?assertEqual(1, maps:size(PendingIn2))
    after
        stop_tunnel_srv(Pid)
    end.

%% An injected outbound entry is returned by pick_outbound/0.
pick_returns_active_entry(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        Entry = entry(10, 3),
        ok = inject_outbound_entry(777, Entry),
        {ok, 777, Entry} = i2p_tunnel_srv:pick_outbound()
    after
        stop_tunnel_srv(Pid)
    end.

%% A session's inbound length demand makes the tick build an inbound
%% tunnel of the demanded hop count; the outbound arm waits.
demand_builds_demanded_inbound_length(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        seed_netdb(4),
        ok = i2p_tunnel_srv:set_lengths(self(), 1, 2),
        i2p_tunnel_srv ! pool_tick,
        #{pending := Pending, pending_in := PendingIn} = i2p_tunnel_srv:status(),
        ?assertEqual(1, maps:size(PendingIn)),
        [InBuild] = maps:values(PendingIn),
        ?assertEqual(1, length(maps:get(router_hashes, InBuild))),
        ?assertEqual(#{}, Pending)
    after
        stop_tunnel_srv(Pid)
    end.

%% With a demanded-length inbound already active, the tick serves the
%% outbound demand at its exact hop count.
demand_builds_demanded_outbound_length(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        seed_netdb(4),
        GwHash = crypto:strong_rand_bytes(32),
        RecvID = 640,
        ok = inject_inbound_entry(RecvID, #{
            tunnel_ids => [RecvID],
            router_hashes => [GwHash],
            layers => [],
            frag_map => #{},
            built_at => erlang:system_time(second)
        }),
        ok = i2p_tunnel_srv:set_lengths(self(), 1, 2),
        i2p_tunnel_srv ! pool_tick,
        #{pending := Pending, pending_in := PendingIn} = i2p_tunnel_srv:status(),
        ?assertEqual(#{}, PendingIn),
        ?assertEqual(1, maps:size(Pending)),
        [OutBuild] = maps:values(Pending),
        ?assertEqual(2, length(maps:get(router_hashes, OutBuild))),
        ?assertEqual(2, length(maps:get(tunnel_ids, OutBuild)))
    after
        stop_tunnel_srv(Pid)
    end.

%% The demand disappears with its session process: no builds afterwards.
demand_cleared_on_session_death(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        seed_netdb(4),
        {MonRef, Mon} =
            erlang:spawn_monitor(fun() ->
                receive
                    never -> ok
                end
            end),
        ok = i2p_tunnel_srv:set_lengths(MonRef, 1, 1),
        exit(MonRef, kill),
        receive
            {'DOWN', Mon, process, MonRef, _} -> ok
        after 5000 ->
            erlang:error(no_down)
        end,
        i2p_tunnel_srv ! pool_tick,
        #{pending_in := PendingIn} = i2p_tunnel_srv:status(),
        ?assertEqual(#{}, PendingIn)
    after
        stop_tunnel_srv(Pid)
    end.

%% Preferred picks return tunnels of exactly the requested hop count
%% and fall back to any tunnel when no entry matches.
preferred_pick_by_length(_Config) ->
    Router = make_router(),
    {Pid, _Local} = start_tunnel_srv(Router),
    try
        OneHop = entry(700, 1),
        ThreeHops = entry(701, 3),
        ok = inject_outbound_entry(700, OneHop),
        ok = inject_outbound_entry(701, ThreeHops),
        {ok, 700, OneHop} = i2p_tunnel_srv:pick_outbound(1),
        {ok, 701, ThreeHops} = i2p_tunnel_srv:pick_outbound(3),
        {ok, _, _} = i2p_tunnel_srv:pick_outbound(2),

        InOne = entry(710, 1),
        InThree = entry(711, 3),
        ok = inject_inbound_entry(710, InOne#{frag_map => #{}}),
        ok = inject_inbound_entry(711, InThree#{frag_map => #{}}),
        {ok, 710, _} = i2p_tunnel_srv:pick_inbound(1),
        {ok, 711, _} = i2p_tunnel_srv:pick_inbound(3),
        {ok, _, _} = i2p_tunnel_srv:pick_inbound(2)
    after
        stop_tunnel_srv(Pid)
    end.
%%%%%%%%% Pool management helpers %%%%%%%%%

%% seed_netdb/1 — store N random RouterInfos so pool builds can pick hops.
seed_netdb(N) ->
    lists:foreach(
        fun(_) ->
            R = make_router(),
            NowMs = erlang:system_time(millisecond),
            {ok, _} = i2p_netdb_srv:store_binary(
                i2p_router_info:to_binary(maps:get(ri, R)), NowMs
            )
        end,
        lists:seq(1, N)
    ).

%% inject_pending_build/2 — insert a pending outbound build record via
%% sys:replace_state.  Confined to pool-management tests whose seam is
%% the tick/pick logic, not the encrypted build path.
inject_pending_build(MsgID, Build) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{pending := Pending} = State) ->
        State#{pending := maps:put(MsgID, Build, Pending)}
    end),
    ok.

%% inject_outbound_entry/2 — insert an active outbound tunnel entry.
inject_outbound_entry(TunID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{tunnels := Tunnels} = State) ->
        State#{tunnels := maps:put(TunID, Entry, Tunnels)}
    end),
    ok.

%% inject_inbound_entry/2 — insert an active inbound tunnel entry.
inject_inbound_entry(RecvID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{inbound := Inbound} = State) ->
        State#{inbound := maps:put(RecvID, Entry, Inbound)}
    end),
    ok.

%% entry/2 — build a minimal active tunnel entry with Hops random router
%% hashes starting at tunnel ID Base.
entry(Base, Hops) ->
    Hashes = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, Hops)],
    #{
        tunnel_ids => [Base + I || I <- lists:seq(0, Hops - 1)],
        router_hashes => Hashes,
        layers => [
            #{layer_key => crypto:strong_rand_bytes(32), iv_key => crypto:strong_rand_bytes(32)}
         || _ <- Hashes
        ],
        built_at => erlang:system_time(second)
    }.
%%%%%%%%% End-to-end garlic delivery to a SAM session %%%%%%%%%

%% A destination-keyed garlic message rides an inbound tunnel as tunnel data,
%% is unwrapped at our endpoint, and — because our router key cannot open it —
%% is offered to the registered STREAM session holding the matching ECIES
%% private key; the session receives the raw payload. The session registry
%% lives in `i2p_sam_sup`'s ETS table, so the case starts a standalone
%% no-listener supervisor; the init_per_testcase boot starts only the base
%% children.
e2e_garlic_delivered_to_stream_session(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Local | Hops]
    ),
    {ok, SamSup} = i2p_sam_sup:start_link(),
    {Pid, _Local} = start_tunnel_srv(Local),

    %% Mock STREAM session registered with the destination's privkey
    TestPid = self(),
    MockSession =
        spawn(fun F() ->
            receive
                {stream_data, Data} ->
                    TestPid ! {session_got, Data},
                    F()
            after 5000 ->
                ok
            end
        end),
    try
        {DPub, DPriv} = i2p_crypto:x25519_keygen(),
        DestHash = crypto:hash(sha256, DPub),
        Payload = <<"ping through the tunnel">>,

        true =
            i2p_sam_sup:session_register(<<"T1">>, MockSession, DestHash, stream, DPriv),

        %% Destination-keyed garlic inside a standard-header type-11 message
        {ok, GarlicBody} = i2p_client:wrap_payload(DPub, Payload),
        StdMsg =
            i2p_i2np:encode_std(#{
                type => 11,
                msg_id => <<9, 9, 9, 9>>,
                expiration_ms => 60000,
                body => GarlicBody
            }),

        %% Frame it down a freshly activated inbound tunnel and deliver
        Inbound = build_an_inbound(Local, Hops),
        Frames = frame_through_inbound(maps:get(entry, Inbound), StdMsg),
        lists:foreach(
            fun(DataBody) ->
                Msg = #{
                    type => 18,
                    msg_id => i2p_i2np:fresh_msg_id(),
                    expiration => erlang:system_time(second) + 60,
                    body => DataBody
                },
                i2p_tunnel_srv ! {i2np, self(), maps:get(ibgw_hash, Inbound), Msg}
            end,
            Frames
        ),

        Got =
            i2p_ct_helpers:wait_msg(
                fun(Msg) ->
                    case Msg of
                        {session_got, Payload} -> {true, Payload};
                        _ -> false
                    end
                end,
                5000
            ),
        ?assertEqual(Payload, Got),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        catch i2p_sam_sup:session_unregister(<<"T1">>),
        catch exit(MockSession, kill),
        catch supervisor:stop(SamSup),
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% Outbound gateway send path %%%%%%%%%

%% A real outbound tunnel is built through the full OTBRM round-trip; the
%% activated entry's layer keys drive a send whose wire frames are captured at
%% the (mock) peer, then every participant hop decrypts its layer locally and
%% the standard-header message reassembles exactly.
%%
%% **Run over both entry points, because they must produce identical bytes.**
%% `Send` is the only difference between them and it is the whole of what
%% #G9HZK8F changed: the manager-side `f:send_via_outbound/3` the lookup paths
%% use, and the caller-side `f:inject/3` a client connection uses. Identical
%% wire output is the property -- a client whose frames differed by one byte
%% would be a client no far end could open.
send_via_outbound_roundtrip_single(_Config) ->
    run_outbound_roundtrip(<<"hello tunnel">>, fun manager_send/2).

send_via_outbound_roundtrip_multi(_Config) ->
    run_outbound_roundtrip(crypto:strong_rand_bytes(3000), fun manager_send/2).

outbound_injection_roundtrip(_Config) ->
    run_outbound_roundtrip(crypto:strong_rand_bytes(3000), fun caller_send/2).

manager_send(TunID, StdMsg) ->
    i2p_tunnel_srv:send_via_outbound(TunID, local, StdMsg).

%% The client path, played by hand rather than through `m:i2p_client:send_wire/2`,
%% which wraps its own destination-addressed garlic first. This case is about
%% the tunnel frames; `i2p_client_tests` covers the wrapping.
caller_send(TunID, StdMsg) ->
    {ok, Injection} = i2p_tunnel_srv:outbound_injection(TunID),
    i2p_tunnel_srv:inject(Injection, local, StdMsg).

run_outbound_roundtrip(Payload, Send) ->
    {Local, Hops} = local_with_hops(),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        Inbound = build_an_inbound(Local, Hops),
        #{tun_id := TunID, entry := Entry} = build_an_outbound(Hops, Inbound),
        HopKeys = maps:get(layers, Entry),
        ?assertEqual(length(Hops), length(HopKeys)),

        StdMsg = std_msg(Payload),
        ok = Send(TunID, StdMsg),

        %% The number of frames is decided by the pure fragmentation
        {ExpectedFrames, _} = i2p_tunnel:gateway_all(TunID, local, undefined, StdMsg),
        Wires = receive_frames(length(ExpectedFrames), []),
        ?assertEqual(length(ExpectedFrames), length(Wires)),

        %% Play every participant hop on each captured wire frame
        ?assertEqual(StdMsg, rebuild_at_far_end(Wires, HopKeys, TunID)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%% ---------------------------------------------------------------------------
%% Neither client's send waits on the other's, or on the manager's other work
%% ---------------------------------------------------------------------------
%%
%% Determined by suspension rather than by timing, because timing cannot show
%% this. Both senders take their injection while the manager is healthy -- that
%% call is a map read, and it is the only one either of them makes -- and then
%% the manager is *suspended*. Every frame that arrives after that has been
%% framed, layered and handed over by a caller, because the manager cannot run
%% anything at all.
%%
%% Under the arrangement this replaced, where `f:send_via_outbound/3` did the
%% framing inside the manager, both senders block until CT's 30 s timetrap and
%% the case fails. It cannot pass by accident, which a two-session timing
%% comparison could: interleaving favourably would satisfy a rate assertion
%% while the work was still serialised.
%%
%% **What this does not prove:** that two senders *overlap* rather than merely
%% both completing. That is not observable without a hostile scheduler, and it
%% is not the property worth having. What is proven is that neither send is
%% gated by a shared process at all -- and the only shared process in this
%% arrangement is the one that is suspended. `outbound_injection_roundtrip`
%% pins the other half: the work is `inject/3`, called by the sender.
client_sends_are_not_gated_by_each_other(_Config) ->
    {Local, Hops} = local_with_hops(),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        Inbound = build_an_inbound(Local, Hops),
        #{tun_id := TunID, entry := Entry} = build_an_outbound(Hops, Inbound),
        HopKeys = maps:get(layers, Entry),

        %% Each sender pins its own outbound tunnel, exactly as a route does.
        {ok, Injection} = i2p_tunnel_srv:outbound_injection(TunID),

        PayloadA = <<"first session's bytes">>,
        PayloadB = crypto:strong_rand_bytes(400),
        MsgA = std_msg(PayloadA),
        MsgB = std_msg(PayloadB),

        true = erlang:suspend_process(Pid),
        try
            TagA = spawn_sender(fun() -> i2p_tunnel_srv:inject(Injection, local, MsgA) end),
            TagB = spawn_sender(fun() -> i2p_tunnel_srv:inject(Injection, local, MsgB) end),
            %% Barriers, not a deadline: each `{sent, Tag}` is sent by that
            %% sender *after* its inject/3 returned, and message order from one
            %% process to another is the runtime's to keep, not a hope.
            ok = await_sender(TagA),
            ok = await_sender(TagB),

            %% One frame each: both payloads fit a single 1008-byte plaintext
            %% fragment, so the count is a fact about fragmentation and not a
            %% race against it.
            Wires = receive_frames(2, []),
            %% Arrival order belongs to the scheduler, so the two messages are
            %% compared as a set. Sorting the rebuilt binaries is deterministic
            %% and the two are distinct, so this is not a weaker claim than an
            %% ordered comparison -- it is the same claim without the race.
            Rebuilt = [rebuild_at_far_end([W], HopKeys, TunID) || W <- Wires],
            ?assertEqual(lists:sort([MsgA, MsgB]), lists:sort(Rebuilt))
        after
            %% `resume_process/1` answers `true` for a process that is not
            %% suspended, so this runs whether or not the assertions above
            %% reached it -- the manager must not be left suspended for the
            %% next case.
            _ = erlang:resume_process(Pid)
        end,
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

local_with_hops() ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(fun(R) -> store_netdb(maps:get(ri, R)) end, [Local | Hops]),
    {Local, Hops}.

%% An unrecognised request takes the manager down, loudly, and says which one.
%%
%% This clause used to answer `ok` to anything it did not recognise. That is
%% survivable until a request changes shape: a caller not threaded through then
%% *silently succeeds*, so a client send that never happened is
%% indistinguishable from one that did. This is the same defect class as the
%% two false-claim tickets on this board, and #G9HZK8F's own entry point change
%% is what made it a live landmine rather than a theoretical one.
%%
%% Asserting that the *process* dies, rather than that the callback raises,
%% because the dying is what reaches an operator. The manager is a `permanent`
%% child, so the supervisor restarts it and the pool rebuilds — loudly, and
%% having lost every tunnel, which is the right price for a caller invoking a
%% request that does not exist.
an_unrecognised_request_takes_the_manager_down(_Config) ->
    {Local, _Hops} = local_with_hops(),
    {Pid, _Local} = start_tunnel_srv(Local),
    %% The manager is linked to this process, so its death arrives here as an
    %% exit signal too. Trapping for the length of the case is what lets the
    %% case *observe* the death rather than be killed by it.
    Trapping = process_flag(trap_exit, true),
    Ref = erlang:monitor(process, Pid),
    try
        %% Provoked deliberately: the exit is the assertion, so it is caught
        %% rather than allowed to fail the case. What must not happen is a
        %% reply -- that is the whole claim.
        %% `i2p_tunnel_srv` by name, not `?MODULE`: the manager registers under
        %% its own name, and this suite is `i2p_tunnel_srv_SUITE`. A call to
        %% `?MODULE` would exit on `noproc` and never reach the manager at all
        %% -- which would make this case pass for the wrong reason.
        ?assertMatch({'EXIT', _}, catch gen_server:call(i2p_tunnel_srv, no_such_request)),
        receive
            {'DOWN', Ref, process, Pid, Reason} ->
                ?assertMatch({i2p_tunnel_srv, unhandled_call, no_such_request}, Reason)
        after 5000 ->
            erlang:error({manager_survived_an_unrecognised_request, Pid})
        end
    after
        process_flag(trap_exit, Trapping)
    end.

std_msg(Payload) ->
    i2p_i2np:encode_std(#{
        type => 11,
        %% A fresh message ID per message, as `m:i2p_client` does: two sends on
        %% one tunnel must not be able to collide on a fixed fixture value, and
        %% nothing here depends on the ID being reproducible.
        msg_id => crypto:strong_rand_bytes(4),
        expiration_ms => 60000,
        body => Payload
    }).

%% spawn_sender/1 — a stand-in for a connection's own worker: it plays the
%% outbound-gateway role and then says so. Reports failure rather than dying
%% quietly, so a broken inject/3 surfaces as this case's failure and not as a
%% missing message.
spawn_sender(Send) ->
    TestPid = self(),
    Tag = make_ref(),
    _ = spawn(fun() ->
        Result =
            try
                Send()
            catch
                Class:Reason -> {raised, Class, Reason}
            end,
        TestPid ! {sent, Tag, Result}
    end),
    Tag.

await_sender(Tag) ->
    receive
        {sent, Tag, ok} ->
            ok;
        {sent, Tag, Other} ->
            erlang:error({client_send_failed, Tag, Other})
    after 5000 ->
        %% Reached only if the sender is blocked inside inject/3, which is the
        %% defect: a named error rather than a case that hangs until the timetrap.
        erlang:error({client_send_blocked, Tag})
    end.

%% rebuild_at_far_end/3 — play every participant hop on each captured wire
%% frame, then reassemble the fragments. This is the far end's half, run
%% locally: what the hops would recover is what the sender's crypto produced.
rebuild_at_far_end(Wires, HopKeys, TunID) ->
    Plains =
        lists:map(
            fun(Wire) ->
                Final =
                    lists:foldl(
                        fun(Hop, M) ->
                            {ok, M1} =
                                i2p_tunnel:process_tunnel_data(M, Hop, TunID, <<0, 0, 0, 0>>),
                            M1
                        end,
                        Wire,
                        HopKeys
                    ),
                <<_:32/big, IV:16/binary, Plain:1008/binary>> = Final,
                {Plain, IV}
            end,
            Wires
        ),
    FragLists =
        lists:map(
            fun({Plain, IV}) ->
                {ok, Fs, _} = i2p_tunnel:parse_tunnel_data(Plain, IV, #{}),
                Fs
            end,
            Plains
        ),
    AllFrags = lists:append(FragLists),
    [First] = [F || F <- AllFrags, maps:get(type, F) =:= first],
    ?assertEqual(local, maps:get(delivery, First)),
    Rebuilt =
        case [F || F <- AllFrags, maps:get(type, F) =:= follow_on] of
            [] ->
                maps:get(data, First);
            FollowOns ->
                Ordered =
                    [
                        maps:get(data, F)
                     || N <- lists:seq(1, length(FollowOns)),
                        F <- FollowOns,
                        maps:get(frag_num, F) =:= N
                    ],
                iolist_to_binary([maps:get(data, First) | Ordered])
        end,
    Rebuilt.

%% build_an_outbound/2 — drive one of our own outbound builds through the full
%% OTBRM: the OBEP wraps the reply in an Existing-Session garlic to the last
%% hop's RGarlic session, the inbound data path delivers it home, and the
%% outbound tunnel activates. Returns #{tun_id, entry, hop_keys}.
build_an_outbound(Hops, Inbound) ->
    ok = i2p_tunnel_srv:build_outbound(),
    RoutersByHash = maps:from_list([{maps:get(hash, R), R} || R <- Hops]),
    {OutIbgwHash, GarlicMsg} = await_build_garlic(),
    {MsgID, Records} = stb_from_garlic(GarlicMsg, maps:get(OutIbgwHash, RoutersByHash)),
    #{pending := Pending} = i2p_tunnel_srv:status(),
    #{MsgID := Build} = Pending,
    TunnelIds = maps:get(tunnel_ids, Build),
    HopKeys = maps:get(hop_keys, Build),

    Stop = fun(Info, _Next) -> maps:get(role, Info) =:= endpoint end,
    {_Infos, FinalRecords} = forward_stb(RoutersByHash, OutIbgwHash, Records, Stop),
    OTBRM = i2p_i2np:outbound_tunnel_build_reply(FinalRecords),
    #{rgarlic_key := RKey, rgarlic_tag := RTag} = lists:last(HopKeys),
    Clove = #{
        delivery => local,
        type => 26,
        msg_id => MsgID,
        expiration => erlang:system_time(second) + 60,
        data => maps:get(body, OTBRM)
    },
    GarlicMsg1 = i2p_garlic:wrap_existing_session([Clove], RKey, RTag),
    StdMsg = i2p_i2np:encode_std(GarlicMsg1#{expiration_ms => 60000}),

    Frames = frame_through_inbound(maps:get(entry, Inbound), StdMsg),
    lists:foreach(
        fun(DataBody) ->
            Msg = #{
                type => 18,
                msg_id => i2p_i2np:fresh_msg_id(),
                expiration => erlang:system_time(second) + 60,
                body => DataBody
            },
            i2p_tunnel_srv ! {i2np, self(), maps:get(ibgw_hash, Inbound), Msg}
        end,
        Frames
    ),

    FirstTunID = hd(TunnelIds),
    ok = await_outbound(FirstTunID),
    #{tunnels := Tunnels} = i2p_tunnel_srv:status(),
    #{tun_id => FirstTunID, entry => maps:get(FirstTunID, Tunnels), hop_keys => HopKeys}.

%%%%%%%%% Transit denials are reported, with the reason %%%%%%%%%

%% A full transit pool. `transit_max_tunnels` is 1, so the second build record
%% is refused on capacity. Before this the decision was a bare ret 30 sealed into
%% the record: correct on the wire, and invisible everywhere else, so a router that
%% was refusing every transit tunnel looked exactly like one nobody was asking.
transit_denial_reports_capacity(_Config) ->
    ok = application:set_env(?APP, transit_max_tunnels, 1),
    [OurRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 3)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [OurRouter | HopRouters]
    ),
    {Pid, _Local} = start_tunnel_srv(OurRouter),
    try
        Events = with_events(
            fun() ->
                deliver_stbs(OurRouter, HopRouters, [600, 610])
            end
        ),
        ?assertEqual([{transit_denied, 610, capacity}], denials(Events))
    after
        stop_tunnel_srv(Pid)
    end.

%% The receive ID is already in the transit map. This is a different operator
%% problem from capacity -- the creator is retrying into a tunnel it already
%% holds, and no amount of raising the cap helps -- which is exactly why the two
%% were separated rather than both reported as "denied".
transit_denial_reports_duplicate_receive_id(_Config) ->
    [OurRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 3)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [OurRouter | HopRouters]
    ),
    {Pid, _Local} = start_tunnel_srv(OurRouter),
    try
        Events = with_events(
            fun() ->
                deliver_stbs(OurRouter, HopRouters, [620, 620])
            end
        ),
        ?assertEqual([{transit_denied, 620, duplicate_receive_id}], denials(Events)),
        %% And the first copy really was accepted, so the second was refused for
        %% being a duplicate rather than both being refused for some other reason.
        #{transit := Transit} = i2p_tunnel_srv:status(),
        ?assertEqual([620], maps:keys(Transit))
    after
        stop_tunnel_srv(Pid)
    end.

%% The build-pacing budget is drained. A rate-limit decision, not a refusal on the
%% merits, and the one reason an operator can act on by raising `tunnel_build_rate`.
%%
%% Five records, because a bucket holds four seconds' worth of tokens (see
%% `m:i2p_tunnel_srv:init_bucket/2`) — the same arithmetic the neighbouring
%% `build_pacing_limits_transit_acceptance/1` case depends on. Four are accepted and
%% the fifth is the denial; the earlier four appearing in `transit_status/0` is what
%% shows the denial was the budget and not something else about the fifth record.
transit_denial_reports_build_budget_drained(_Config) ->
    ok = application:set_env(?APP, tunnel_build_rate, 1),
    [OurRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 3)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [OurRouter | HopRouters]
    ),
    {Pid, _Local} = start_tunnel_srv(OurRouter),
    try
        Bases = [630, 640, 650, 660, 670],
        Events = with_events(
            fun() ->
                deliver_stbs(OurRouter, HopRouters, Bases)
            end
        ),
        ?assertEqual([{transit_denied, 670, build_budget_drained}], denials(Events)),
        #{transit := Transit} = i2p_tunnel_srv:status(),
        ?assertEqual([630, 640, 650, 660], lists:sort(maps:keys(Transit)))
    after
        stop_tunnel_srv(Pid)
    end.

%% An accepted record announces nothing. The three cases above would all still pass
%% if the event were moved onto the common path, and a bus that announced a denial
%% for every tunnel it accepted would be worse than no event at all.
transit_acceptance_announces_no_denial(_Config) ->
    [OurRouter | HopRouters] = [make_router() || _ <- lists:seq(1, 3)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [OurRouter | HopRouters]
    ),
    {Pid, _Local} = start_tunnel_srv(OurRouter),
    try
        Events = with_events(
            fun() ->
                deliver_stbs(OurRouter, HopRouters, [650])
            end
        ),
        ?assertEqual([], denials(Events)),
        #{transit := Transit} = i2p_tunnel_srv:status(),
        ?assert(maps:is_key(650, Transit))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%%%%%%%%% LeaseSet publication failures are reported %%%%%%%%%

%% The case that was silently wrong. The NetDb holds no floodfill, so the LeaseSet
%% is signed and stored locally and then handed to nobody. `leaseset_published`
%% used to be announced on that path unconditionally, so a router that had not yet
%% learned a floodfill reported every client lease as published while being
%% unreachable to the entire network.
%%%%%%%%% Client LeaseSet publication %%%%%%%%%

%% Publishing records a LeaseSet2 in the NetDb whose lease points at the
%% freshly activated inbound tunnel's gateway and receive ID, then sends the
%% LeaseSet2 DatabaseStore to an eligible floodfill.
%%
%% The three cases after `publish_lease_stores_ls/1` cover the paths where that
%% does not happen.
%%%%%%%%% LeaseSet publication failures are reported %%%%%%%%%

leaseset_publish_with_no_floodfill_reports_failure(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Local | Hops]
    ),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        _Inbound = build_an_inbound(Local, Hops),
        #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
        DestHash = i2p_keys:hash(Id),
        Events = with_events(
            fun() ->
                ok = i2p_tunnel_srv:publish_lease_set(Id, Seed),
                %% The status call is the barrier: the publish cast was sent before
                %% it, and the announcement happens inside the cast's handler, so by
                %% the time this returns the event is already in this mailbox.
                _ = i2p_tunnel_srv:status()
            end
        ),
        ?assertEqual(
            [{leaseset_publish_failed, DestHash, no_floodfill_targets}],
            publish_failures(Events)
        ),
        %% And the success event did not fire. This is the assertion that was
        %% impossible to write before, because the success event was on the same
        %% clause as the attempt and fired either way.
        ?assertEqual([], [E || E = {leaseset_published, _} <- Events]),
        unregister_peer()
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%% A client with no inbound tunnel has no gateway to point a lease at. This is the
%% most common way a lease never goes out, and before this it left no trace
%% anywhere: the destination sat in the published map with `until_sec => 0` and
%% nothing said why.
leaseset_publish_with_no_inbound_tunnel_reports_failure(_Config) ->
    [Local | _Hops] = [make_router() || _ <- lists:seq(1, 2)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Local | _Hops]
    ),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
        DestHash = i2p_keys:hash(Id),
        Events = with_events(
            fun() ->
                ok = i2p_tunnel_srv:publish_lease_set(Id, Seed),
                _ = i2p_tunnel_srv:status()
            end
        ),
        ?assertEqual(
            [{leaseset_publish_failed, DestHash, no_inbound_tunnel}],
            publish_failures(Events)
        ),
        %% The destination is still recorded, so the pool tick retries it.
        ?assertEqual([], [E || E = {leaseset_published, _} <- Events])
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%% The pool tick retries a pending publication about every 30 seconds, forever.
%% Re-announcing the same unresolved condition on each retry would be a periodic
%% flood of something that has not changed, so the retry is silent and the first
%% attempt is the only report.
pending_publication_is_announced_once(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Local | Hops]
    ),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
        DestHash = i2p_keys:hash(Id),
        First = with_events(
            fun() ->
                ok = i2p_tunnel_srv:publish_lease_set(Id, Seed),
                _ = i2p_tunnel_srv:status()
            end
        ),
        ?assertEqual(
            [{leaseset_publish_failed, DestHash, no_inbound_tunnel}],
            publish_failures(First)
        ),
        %% The retry, which is the pool tick doing its job. Silent.
        Later = with_events(
            fun() ->
                i2p_tunnel_srv ! pool_tick,
                _ = i2p_tunnel_srv:status()
            end
        ),
        ?assertEqual([], publish_failures(Later)),
        %% And the destination is still outstanding rather than dropped, which is
        %% what makes the retry meaningful. `status/0` does not expose the
        %% published map, so this is observed the way an operator would see it: the
        %% LeaseSet is still nowhere to be found, and the neighbouring
        %% `publish_retries_on_pool_tick/1` case shows it appears once a tunnel does.
        ?assertEqual(not_found, i2p_netdb_srv:find_ls(DestHash)),
        unregister_peer()
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

publish_lease_stores_ls(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Local | Hops]
    ),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        Inbound = build_an_inbound(Local, Hops),
        Floodfill = make_floodfill(),
        ok = store_netdb(maps:get(ri, Floodfill)),
        #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
        DestHash = i2p_keys:hash(Id),
        ok = i2p_tunnel_srv:publish_lease_set(Id, Seed),
        ok = wait_for_ls(DestHash),
        {ok, LS} = i2p_netdb_srv:find_ls(DestHash),
        [Lease] = i2p_leaset:leases(LS),
        ?assertEqual(maps:get(ibgw_hash, Inbound), maps:get(gateway, Lease)),
        ?assertEqual(hd(maps:get(tunnel_ids, Inbound)), maps:get(tunnel_id, Lease)),
        Store = await_publication_store(maps:get(hash, Floodfill), DestHash),
        ?assertEqual(3, maps:get(store_type, Store)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

%% A publication requested before any inbound tunnel exists is retried by the
%% periodic tick once a tunnel activates.
publish_retries_on_pool_tick(_Config) ->
    [Local | Hops] = [make_router() || _ <- lists:seq(1, 4)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Local | Hops]
    ),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
        DestHash = i2p_keys:hash(Id),
        ok = i2p_tunnel_srv:publish_lease_set(Id, Seed),
        %% The status call is a processing barrier: the publish cast — and its
        %% synchronous "no inbound tunnel yet" decision — completes before it returns.
        _ = i2p_tunnel_srv:status(),
        ?assertEqual(not_found, i2p_netdb_srv:find_ls(DestHash)),

        %% Tunnel appears; the next tick must publish the pending lease
        Inbound = build_an_inbound(Local, Hops),
        i2p_tunnel_srv ! pool_tick,
        ok = wait_for_ls(DestHash),
        {ok, LS} = i2p_netdb_srv:find_ls(DestHash),
        [Lease] = i2p_leaset:leases(LS),
        ?assertEqual(hd(maps:get(tunnel_ids, Inbound)), maps:get(tunnel_id, Lease)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.

wait_for_ls(DestHash) ->
    %% The LeaseSet publication round-trips publish_lease_set -> tick -> garlic
    %% -> netdb asynchronously; poll on a deadline instead of a fixed sleep.
    ok = i2p_ct_helpers:await(
        fun() ->
            case i2p_netdb_srv:find_ls(DestHash) of
                {ok, _} -> true;
                not_found -> false
            end
        end,
        10_000
    ),
    ok.

await_publication_store(PeerHash, Key) ->
    i2p_ct_helpers:wait_msg(
        fun(Msg) ->
            case Msg of
                {peer_sent, {send_when_ready, SentTo, #{type := 1, body := Body}}} when
                    SentTo =:= PeerHash
                ->
                    case i2p_i2np:decode_db_store(Body) of
                        {ok, Store} ->
                            case maps:get(key, Store) =:= Key of
                                true -> {true, Store};
                                false -> false
                            end;
                        error ->
                            false
                    end;
                _ ->
                    false
            end
        end,
        5000
    ).

%% publish_lease_set/3 pins the lease to an inbound tunnel of the demanded
%% hop count even when a fresher tunnel of another length exists.
publish_prefers_demanded_length(_Config) ->
    [Local, OneHop | ThreeHops] = [make_router() || _ <- lists:seq(1, 5)],
    lists:foreach(
        fun(R) -> store_netdb(maps:get(ri, R)) end,
        [Local, OneHop]
    ),
    {Pid, _Local} = start_tunnel_srv(Local),
    try
        %% The demanded 1-hop tunnel is built first (older); the 3-hop tunnel
        %% built afterwards is fresher but of the wrong length and must lose.
        DemandOneHop =
            fun() ->
                ok = i2p_tunnel_srv:set_lengths(self(), 1, 1),
                i2p_tunnel_srv ! pool_tick,
                ok
            end,
        InOne = build_an_inbound(Local, [OneHop], DemandOneHop),
        removed = i2p_netdb_srv:remove(maps:get(hash, OneHop)),
        lists:foreach(
            fun(R) -> store_netdb(maps:get(ri, R)) end,
            ThreeHops
        ),
        _InThree = build_an_inbound(Local, ThreeHops),

        #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
        DestHash = i2p_keys:hash(Id),
        ok = i2p_tunnel_srv:publish_lease_set(Id, Seed, 1),
        ok = wait_for_ls(DestHash),
        {ok, LS} = i2p_netdb_srv:find_ls(DestHash),
        [Lease] = i2p_leaset:leases(LS),
        ?assertEqual(maps:get(ibgw_hash, InOne), maps:get(gateway, Lease)),
        ?assertEqual(hd(maps:get(tunnel_ids, InOne)), maps:get(tunnel_id, Lease)),
        ?assert(is_process_alive(whereis(i2p_tunnel_srv)))
    after
        unregister_peer(),
        stop_tunnel_srv(Pid)
    end.
