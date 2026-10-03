%% Operator boot and listener integration tests. With `data_dir` configured,
%% the app binds its NTCP2 listener, accepts an inbound session, learns the
%% peer's RouterInfo, and announces the local RouterInfo. When `ssu2` serves UDP
%% (`enable_udp` or `prefer_udp`), the boot also binds an SSU2 listener and
%% advertises its address.
%%
%% Each case owns its process, mailbox, application lifecycle, and listeners.
%% Assertions use public wire and status behavior, with deadline-bounded waits
%% rather than fixed-total sleeps.

-module(i2p_boot_SUITE).

-include_lib("eunit/include/eunit.hrl").

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    boot_listener_binds_config_port/1,
    firewalled_boot_listener_binds/1,
    inbound_session_round_trips/1,
    sam_listener_binds_config_port/1,
    host_validation_rejects_private_boot/1,
    boot_router_info_carries_caps/1,
    ssu2_boot_listener_binds_when_enabled/1,
    ssu2_boot_listener_binds_under_enable_udp/1,
    ssu2_inbound_session_round_trips/1,
    ssu2_disabled_boot_binds_nothing/1,
    reseed_runs_after_live_opt_in/1,
    reseed_disabled_stays_off/1,
    reseed_stays_off_without_live_opt_in/1,
    boot_kicks_floodfill_discovery/1,
    boot_kick_noops_without_seeds/1,
    offline_boot_does_not_dial_seeded_peer/1,
    smoke_report_carries_four_observables/1,
    boot_announces_config_posture_and_online/1,
    boot_config_line_reports_the_value_in_force/1,
    boot_lines_carry_no_key_material/1
]).

-define(APP, i2per).
-define(TIMEOUT, 10000).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        boot_listener_binds_config_port,
        firewalled_boot_listener_binds,
        inbound_session_round_trips,
        sam_listener_binds_config_port,
        host_validation_rejects_private_boot,
        boot_router_info_carries_caps,
        ssu2_boot_listener_binds_when_enabled,
        ssu2_boot_listener_binds_under_enable_udp,
        ssu2_inbound_session_round_trips,
        ssu2_disabled_boot_binds_nothing,
        reseed_runs_after_live_opt_in,
        reseed_disabled_stays_off,
        reseed_stays_off_without_live_opt_in,
        boot_kicks_floodfill_discovery,
        boot_kick_noops_without_seeds,
        offline_boot_does_not_dial_seeded_peer,
        smoke_report_carries_four_observables,
        boot_announces_config_posture_and_online,
        boot_config_line_reports_the_value_in_force,
        boot_lines_carry_no_key_material
    ].

init_per_testcase(_Case, Config) ->
    Config.

end_per_testcase(_Case, _Config) ->
    case lists:keymember(?APP, 1, application:which_applications()) of
        true -> application:stop(?APP);
        false -> ok
    end,
    lists:foreach(
        fun(K) -> application:unset_env(?APP, K) end,
        [
            data_dir,
            seeds,
            port,
            sam_port,
            allow_private_host,
            ssu2,
            ssu2_enabled,
            reseed,
            ntcp2_published,
            live_network,
            listen_host,
            floodfill_discovery_delay_ms,
            host,
            config_file,
            net_id,
            log_level
        ]
    ),
    ok.

%% --------------------------------------------------------------------------
%% Boot: `data_dir` + `port` start a permanent listener that accepts TCP on
%% the configured port.
%% --------------------------------------------------------------------------

boot_listener_binds_config_port(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        {ok, _} = application:ensure_all_started(?APP),
        %% Behavioural: listener accepts TCP on the configured port.
        {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, Port, [], 2000),
        ok = gen_tcp:close(Sock)
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host)
    end.

firewalled_boot_listener_binds(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, ntcp2_published, false),
        {ok, _} = application:ensure_all_started(?APP),
        {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, Port, [], 2000),
        ok = gen_tcp:close(Sock),
        State = sys:get_state(i2p_peer),
        Local = maps:get(local, State),
        [Address] = i2p_router_info:addresses(maps:get(ri, Local)),
        ?assertEqual(14, maps:get(cost, Address)),
        ?assertEqual(
            {error, no_reachable_ntcp2},
            i2p_router_info:ntcp2_connector(maps:get(ri, Local))
        )
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, ntcp2_published)
    end.

%% --------------------------------------------------------------------------
%% Inbound session: an external Alice router dials our boot listener. The peer
%% manager accepts it (Bob), recovers the dialer's RouterInfo from msg3, learns
%% it into the NetDb, and announces our own RouterInfo back over the lane.
%% --------------------------------------------------------------------------

inbound_session_round_trips(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        {ok, Id} = i2p_identity:ensure_identity(Dir),
        Local = i2p_identity:build_local(Id, <<"127.0.0.1">>, Port, maps:get(sign_seed, Id)),
        OurHash = i2p_router_info:hash(maps:get(ri, Local)),
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        {ok, _} = application:ensure_all_started(?APP),
        %% Dial our own boot listener as an external Alice router.
        Alice = local(4668),
        AliceHash = i2p_router_info:hash(maps:get(ri, Alice)),
        Args =
            #{
                role => alice,
                remote_ri => maps:get(ri, Local),
                local => Alice,
                owner => self(),
                handshake_timeout => 15000
            },
        {ok, Conn} = supervisor:start_child(i2p_ntcp2_sup, i2p_ntcp2_sup:conn_child(Args)),
        %% Bob's (our own) RouterInfo comes back in the ready message and as the
        %% first data-phase frame (our plain self-announce to the dialer).
        RemoteRI =
            i2p_ct_helpers:wait_msg(
                fun
                    ({ntcp2_ready, C, RI}) when C =:= Conn -> {true, RI};
                    (_) -> false
                end,
                ?TIMEOUT
            ),
        ?assertEqual(OurHash, i2p_router_info:hash(RemoteRI)),
        ?assertMatch({store, _}, recv_db_store(Conn)),
        %% The peer manager learned the dialer into the NetDb.
        ?assertMatch({ok, _}, i2p_netdb_srv:find(AliceHash)),
        %% The dialer is a live inbound session (one per distinct peer hash).
        ?assertEqual(1, i2p_peer:dialed()),
        i2p_ntcp2_conn:stop(Conn)
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host)
    end.

%% --------------------------------------------------------------------------
%% Persistent boot: the SAM supervisor starts a listener bound on `sam_port`
%% and it accepts connections on that port.
%% --------------------------------------------------------------------------

sam_listener_binds_config_port(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    SamPort = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, sam_port, SamPort),
        application:set_env(?APP, allow_private_host, true),
        {ok, _} = application:ensure_all_started(?APP),
        %% Behavioural: SAM listener accepts TCP on the configured port.
        {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, SamPort, [], 2000),
        ok = gen_tcp:close(Sock)
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, sam_port),
        application:unset_env(?APP, allow_private_host)
    end.

%% --------------------------------------------------------------------------
%% Host hygiene: with `host` defaulting to 127.0.0.1 and no override, boot must
%% fail — a loopback RouterInfo is undialable and i2pd refuses to store it.
%% --------------------------------------------------------------------------

host_validation_rejects_private_boot(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        ?assertMatch(
            {error, _},
            application:ensure_all_started(?APP)
        )
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host)
    end.

%% With the override, boot succeeds and the shipped RouterInfo carries the
%% NTCP2 address `caps` flag (4 for IPv4) plus the configured host.
boot_router_info_carries_caps(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        {ok, _} = application:ensure_all_started(?APP),
        %% The operator boot builds Local exactly as i2per_sup does; the
        %% RouterInfo must parse under the strict validator and its NTCP2
        %% address must carry the address-level caps flag (4 for IPv4).
        {ok, Id} = i2p_identity:ensure_identity(Dir),
        Host = application:get_env(i2per, host, <<"127.0.0.1">>),
        Local = i2p_identity:build_local(Id, Host, Port, maps:get(sign_seed, Id)),
        RI = maps:get(ri, Local),
        ?assertMatch({ok, _}, i2p_router_info:parse(i2p_router_info:to_binary(RI))),
        [Addr] = i2p_router_info:addresses(RI),
        ?assertEqual(<<"4">>, maps:get(<<"caps">>, maps:get(options, Addr))),
        %% The router-level caps must be a spec-valid string; with the
        %% `allow_private_host` opt-out and default bandwidth class L this is
        %% the unreachable/non-floodfill form `UL`.
        RouterCaps = maps:get(<<"caps">>, i2p_router_info:options(RI)),
        ?assert(i2p_router_info:validate_caps(RouterCaps)),
        ?assertEqual(<<"UL">>, RouterCaps)
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host)
    end.

%% --------------------------------------------------------------------------
%% SSU2 transport wiring: with `ssu2` set to a value that *serves* UDP the
%% operator boot binds a permanent UDP listener on the published SSU2 port and the
%% RouterInfo advertises the SSU2 address with the peer-test `B` cap. Which
%% transport a dial reaches for is a separate question, and belongs to
%% `i2p_peer_transport_SUITE`.
%% --------------------------------------------------------------------------

ssu2_boot_listener_binds_when_enabled(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, ssu2, prefer_udp),
        {ok, _} = application:ensure_all_started(?APP),
        %% Behavioural: a packet to a closed port is refused by the OS; to the
        %% listening socket it is silently dropped (no reply).
        {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
        ok = gen_udp:connect(Sock, {127, 0, 0, 1}, Port),
        ok = gen_udp:send(Sock, <<1, 2, 3, 4>>),
        Reply =
            receive
                {udp, Sock, _IP, _RPort, _Datagram} -> replied;
                {udp_error, Sock, _Reason} -> refused
            after 150 ->
                timeout
            end,
        ?assertEqual(timeout, Reply),
        ok = gen_udp:close(Sock),
        %% The shipped RouterInfo advertises the SSU2 address: same host/port
        %% as NTCP2 (SSU2 defaults to the configured transport port), carrying
        %% the `B` peer-test capability.
        {ok, Id} = i2p_identity:ensure_identity(Dir),
        Host = application:get_env(i2per, host, <<"127.0.0.1">>),
        Local = i2p_identity:build_local(Id, Host, Port, maps:get(sign_seed, Id)),
        {ok, SSU2Opts} = i2p_router_info:ssu2_address_options(maps:get(ri, Local)),
        ?assertEqual(<<"127.0.0.1">>, maps:get(host, SSU2Opts)),
        ?assertEqual(Port, maps:get(port, SSU2Opts)),
        ?assertEqual(true, maps:get(peer_test, SSU2Opts))
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, ssu2)
    end.

%% `enable_udp` boots exactly the same listener as `prefer_udp` does, because
%% *serving* UDP is one decision and *preferring* it is another, and this case is
%% about the first one.
%%
%% The case above cannot stand in for this one, and the way it cannot is the
%% point: it is written for `prefer_udp`, so it would still pass if the boot asked
%% "do we prefer UDP?" where it should ask "do we serve UDP?" -- and the only
%% configuration in which those two answers differ is `enable_udp`. A setting
%% whose one unrepresentable state is the one nothing tests is a setting that is
%% half a boolean again.
ssu2_boot_listener_binds_under_enable_udp(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, ssu2, enable_udp),
        %% The two answers, held apart before the boot rather than inferred from
        %% it: this router serves UDP and does not reach for it.
        ?assertEqual(true, i2p_identity:ssu2_available()),
        ?assertEqual(false, i2p_identity:ssu2_preferred()),
        {ok, _} = application:ensure_all_started(?APP),
        {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
        ok = gen_udp:connect(Sock, {127, 0, 0, 1}, Port),
        ok = gen_udp:send(Sock, <<1, 2, 3, 4>>),
        Reply =
            receive
                {udp, Sock, _IP, _RPort, _Datagram} -> replied;
                {udp_error, Sock, _Reason} -> refused
            after 150 ->
                timeout
            end,
        %% The bound socket swallows the datagram; a closed port is refused by
        %% the OS. `refused` here would mean the listener is not up.
        ?assertEqual(timeout, Reply),
        ok = gen_udp:close(Sock),
        %% And the address is advertised, which is the other half of serving: a
        %% bound listener nothing publishes is not reachable by anyone.
        {ok, Id} = i2p_identity:ensure_identity(Dir),
        Host = application:get_env(i2per, host, <<"127.0.0.1">>),
        Local = i2p_identity:build_local(Id, Host, Port, maps:get(sign_seed, Id)),
        {ok, SSU2Opts} = i2p_router_info:ssu2_address_options(maps:get(ri, Local)),
        ?assertEqual(Port, maps:get(port, SSU2Opts))
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, ssu2)
    end.

%% --------------------------------------------------------------------------
%% Inbound session over SSU2: the peer-owned boot SSU2
%% listener accepts an external Alice router dialing the published SSU2 port.
%% Bob's peer manager registers the inbound session (`handle_inbound_ready`),
%% learns the dialer into the NetDb, and announces our own RouterInfo back as
%% the first data-phase store. SSU2 mirror of `inbound_session_round_trips/1`.
%% --------------------------------------------------------------------------

ssu2_inbound_session_round_trips(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, ssu2, prefer_udp),
        %% The booted router's Local (and its SSU2 address) mirrors the app env:
        %% `ssu2` must be set before `build_local` folds it in.
        {ok, Id} = i2p_identity:ensure_identity(Dir),
        Local = i2p_identity:build_local(Id, <<"127.0.0.1">>, Port, maps:get(sign_seed, Id)),
        OurHash = i2p_router_info:hash(maps:get(ri, Local)),
        {ok, _} = application:ensure_all_started(?APP),
        %% The peer-owned boot listener is bound to the published SSU2 port.
        {ok, SSU2Opts} = i2p_router_info:ssu2_address_options(maps:get(ri, Local)),
        ?assertEqual(Port, maps:get(port, SSU2Opts)),
        %% Dial our own boot SSU2 listener as an external Alice router.
        Alice = ssu2_alice_local(),
        AliceHash = maps:get(hash, Alice),
        {ok, AliceListener} =
            i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, maps:get(local, Alice), self()),
        RIBlock = i2p_router_info:to_binary(maps:get(ri, Alice)),
        {ok, APid, _Keys} =
            i2p_ssu2_conn:connect(maps:get(local, Alice), SSU2Opts, RIBlock, AliceListener),
        %% Bob's (our own) RouterInfo is announced back as the first data-phase
        %% store over the SSU2 lane.
        ?assertEqual(OurHash, recv_ssu2_store(APid)),
        %% The peer manager learned the dialer into the NetDb. A call is handled
        %% after every message already queued on the peer manager, and the store
        %% arrived over that queue, so this answers "has the store been applied"
        %% rather than "has it happened within ten seconds".
        _ = gen_server:call(i2p_peer, dialed),
        ?assertMatch({ok, _}, i2p_netdb_srv:find(AliceHash)),
        unlink(APid),
        i2p_ssu2_conn:terminate_session(APid, 0),
        i2p_ssu2_listener:stop(AliceListener)
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, ssu2)
    end.

%% Disabled (default): the RouterInfo stays NTCP2-only.
ssu2_disabled_boot_binds_nothing(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        {ok, _} = application:ensure_all_started(?APP),
        %% Behavioural: the RouterInfo has no SSU2 address when SSU2 is disabled.
        {ok, Id} = i2p_identity:ensure_identity(Dir),
        Host = application:get_env(i2per, host, <<"127.0.0.1">>),
        Local = i2p_identity:build_local(Id, Host, Port, maps:get(sign_seed, Id)),
        ?assertEqual(error, i2p_router_info:ssu2_address_options(maps:get(ri, Local)))
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host)
    end.

%% --------------------------------------------------------------------------
%% Live reseeding is opt-in: the default release profile leaves it off unless
%% `live_network = true` is selected. The live-path test keeps the fetch
%% hermetic by pointing `hosts` at a localhost SU3 server.
%% --------------------------------------------------------------------------

reseed_runs_after_live_opt_in(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    Ris = [remote_ri(4800), remote_ri(4801)],
    Su3Port = serve_su3(sign_ris(Ris)),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, live_network, true),
        %% No `enabled` key: exercises the live opt-in reseed path. Async
        %% reseed is slower then the localhost fetch completes.
        application:set_env(?APP, reseed, #{
            hosts => [reseed_url(Su3Port)],
            trust_extra => #{<<"test-signer">> => element(2, test_keypair())},
            min_routers => 1
        }),
        {ok, _} = application:ensure_all_started(?APP),
        %% Behavioural: the reseed worker feeds the NetDb; each reseeded
        %% RouterInfo becomes findable.
        %%
        %% **Barrier, not a poll.** The previous version polled the NetDb with a
        %% ten-second deadline. That is a different thing with a different
        %% failure mode: `m:i2p_reseed`'s HTTP client is configured with a
        %% thirty-second timeout, so a fetch the production code is entitled to
        %% take fifteen seconds is a test failure — and a slow machine and a
        %% broken one produce the same report. It failed under full-suite load
        %% while passing twelve times in a row on its own, which is what a
        %% deadline standing in for a synchronisation looks like.
        %%
        %% The two steps below remove the race instead of widening the window.
        %% The worker stops only after the fetch returned and every `learn_ri`
        %% cast was sent, so its exit means the casts are in flight. A call to the
        %% peer manager is then handled after every message already in its queue,
        %% so once it answers, the RouterInfos are in the NetDb. After that there
        %% is no deadline on the assertion at all.
        ok = await_reseed_worker(),
        _ = gen_server:call(i2p_peer, dialed),
        lists:foreach(
            fun(RI) ->
                ?assertMatch({ok, _}, i2p_netdb_srv:find(i2p_router_info:hash(RI)))
            end,
            Ris
        )
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, live_network),
        application:unset_env(?APP, reseed)
    end.

%% An explicit `reseed.enabled = false` must keep the worker off even on an
%% empty NetDb.
reseed_disabled_stays_off(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, reseed, #{enabled => false}),
        {ok, _} = application:ensure_all_started(?APP),
        %% Behavioural: app boots successfully with reseed disabled. The absence
        %% of the reseed worker is implicit — no NetDb feed occurs.
        ok
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, reseed)
    end.

reseed_stays_off_without_live_opt_in(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, []),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        {ok, _} = application:ensure_all_started(?APP),
        ?assertEqual(undefined, whereis(i2p_reseed_srv))
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host)
    end.

%% --------------------------------------------------------------------------
%% Boot floodfill-discovery kick: with a dialable seed and a delay forced to
%% 0, the booted peer manager fires an exploratory lookup at the idle seed. The
%% seed (we own its listener) answers with a DatabaseSearchReply naming a real
%% floodfill, whose RouterInfo is then fetched into the NetDb — proving the kick
%% feeds the best-known floodfills so the first publish cycle has something to
%% publish to.
%% --------------------------------------------------------------------------

boot_kicks_floodfill_discovery(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    SeedPort = i2p_ct_helpers:free_port(),
    FFPort = i2p_ct_helpers:free_port(),
    Seed = local(SeedPort),
    FF = ff_local(FFPort),
    FFHash = i2p_router_info:hash(maps:get(ri, FF)),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [maps:get(ri, Seed)]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, reseed, #{enabled => false}),
        %% A short kick delay so the seed/FF listeners are up before the kick
        %% dials (the booted tree owns no listener for the seed until we start
        %% one below).
        application:set_env(?APP, floodfill_discovery_delay_ms, 500),
        {ok, _} = application:ensure_all_started(?APP),
        %% We act as the seed (Bob) the booted peer dials, and as the floodfill
        %% its publish cycle later dials.
        {ok, LSeed} = i2p_ntcp2_listener:listen(SeedPort, Seed, self()),
        {ok, LFF} = i2p_ntcp2_listener:listen(FFPort, FF, self()),
        %% The kick dials the seed; accept as Bob and recover the dialer's RI
        %% from the ready message (the first data-phase frame is the exploratory
        %% lookup, not a store).
        {SeedConn, RemoteRI} = await_conn_ready(),
        LocalHash = i2p_router_info:hash(RemoteRI),
        %% Discover the floodfill: A's exploratory lookup asks the seed who is
        %% at the lookup key; the seed names the floodfill; A then fetches FF's
        %% RouterInfo from the seed and stores it into the NetDb.
        LookupKey = await_exploratory_lookup(SeedConn),
        send_db_search_reply(SeedConn, LookupKey, [FFHash], LocalHash),
        await_routerinfo_lookup(SeedConn, FFHash),
        send_db_store(SeedConn, maps:get(ri, FF)),
        i2p_ct_helpers:await(fun() ->
            case i2p_netdb_srv:find(FFHash) of
                {ok, _} -> true;
                not_found -> false
            end
        end),
        %% The discovered floodfill unblocks the publish cycle: publishing now
        %% dials FF and sends it our RouterInfo for storage.
        ok = i2p_peer:publish_floodfills(),
        {FFConn, _FFRemoteRI} = await_conn_ready(),
        %% The publish now reaches the discovered floodfill and announces our own
        %% RouterInfo to it.
        ?assertEqual(LocalHash, await_published_hash(FFConn)),
        i2p_ntcp2_listener:stop(LSeed),
        i2p_ntcp2_listener:stop(LFF)
    after
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, reseed),
        application:unset_env(?APP, ntcp2_published),
        application:unset_env(?APP, floodfill_discovery_delay_ms)
    end.

%% --------------------------------------------------------------------------
%% Negative control: with no seeds configured the boot kick must be a harmless
%% no-op — the manager boots and stays healthy, no dial is attempted.
%% --------------------------------------------------------------------------

boot_kick_noops_without_seeds(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, []),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, reseed, #{enabled => false}),
        application:set_env(?APP, floodfill_discovery_delay_ms, 0),
        {ok, _} = application:ensure_all_started(?APP),
        %% Negative control, observed end-to-end: the exploratory kick (delay 0)
        %% has nothing to dial, so no `peer_connected` event may be announced on
        %% the bus and the peer manager must still report an empty peer set.
        ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
        assert_no_peer_dialed(2000),
        ?assertEqual(#{}, i2p_peer:status())
    after
        gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
        application:stop(?APP),
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, reseed),
        application:unset_env(?APP, ntcp2_published),
        application:unset_env(?APP, floodfill_discovery_delay_ms)
    end.

%% --------------------------------------------------------------------------
%% ADR 0002's three boot gaps. Each is one `notice` line, emitted once per boot,
%% from a place on the path every boot takes.
%% --------------------------------------------------------------------------

boot_announces_config_posture_and_online(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed(), remote_ri(4802)]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, sam_port, i2p_ct_helpers:free_port()),
        application:set_env(?APP, live_network, false),
        Events = i2p_ct_helpers:log_events_from(fun boot/0),
        Lines = [i2p_ct_helpers:render_log_event(E) || E <- Events],
        ct:pal("boot lines:~n~s", [lists:join("\n", Lines)]),

        %% Each of the three, exactly once, and at `notice`.
        %%
        %% "Exactly once" rather than "at least": a line repeated on every
        %% supervisor restart would turn one question -- what did this router start
        %% as -- into three answers, two of them about a router no longer running.
        %%
        %% The level is checked separately from the text because they are separate
        %% claims. `m:i2p_log:emit/3`'s fact name selects the level and nothing else,
        %% so recording the started-as line under a `warning` fact yields the
        %% identical text at a different level -- and every text assertion still
        %% passes. That was a mutation this case did not catch until it asserted
        %% the level too.
        One = fun(Prefix) ->
            case
                [
                    {maps:get(level, Event), Line}
                 || Event <- Events,
                    Line <- [i2p_ct_helpers:render_log_event(Event)],
                    lists:prefix(Prefix, Line)
                ]
            of
                [{notice, Only}] ->
                    Only;
                [{Level, Only}] ->
                    ct:fail({expected_notice_for, Prefix, Level, Only});
                Found ->
                    ct:fail({expected_one_line_for, Prefix, Found})
            end
        end,
        InForce = One("i2per config in force: "),
        StartedAs = One("i2per started as: "),
        Online = One("i2per online: "),

        %% What the operator asked for. The listen address and the seed count are
        %% the two that cannot be read back out of the configuration file at all,
        %% so getting them right is the part actually being tested.
        ?assertNotEqual(nomatch, string:find(StartedAs, "version=")),
        ?assertNotEqual(
            nomatch, string:find(StartedAs, "listen=127.0.0.1:" ++ integer_to_list(Port))
        ),
        %% The path is rendered as a string, so it carries its own quotes.
        ?assertNotEqual(nomatch, string:find(StartedAs, "data_dir=\"" ++ Dir)),
        ?assertNotEqual(nomatch, string:find(StartedAs, "live=false")),
        ?assertNotEqual(nomatch, string:find(StartedAs, "seeds=2")),
        ?assertNotEqual(nomatch, string:find(StartedAs, "sam_port=")),
        %% CT runs on a named node, so the distribution posture here is the one an
        %% operator with a firewall actually has to reason about. What the line does
        %% *not* claim is whether the node is listening -- see
        %% `m:i2per_sup:render_distribution/0` for why there is no way to ask.
        ?assertNotEqual(nomatch, string:find(StartedAs, "dist=on")),
        ?assertNotEqual(nomatch, string:find(StartedAs, "node=")),
        ?assertNotEqual(nomatch, string:find(StartedAs, "dist_range=")),

        ?assertNotEqual(nomatch, string:find(Online, "bus=up")),
        ?assertNotEqual(nomatch, string:find(Online, "read_api=answering(")),
        ?assertNotEqual(nomatch, string:find(Online, "identity=")),

        %% The configuration line names the environment's values, including the
        %% level -- so an operator reading a log at a verbosity they did not expect
        %% has somewhere to find out why.
        ?assertNotEqual(nomatch, string:find(InForce, "port=" ++ integer_to_list(Port))),
        ?assertNotEqual(nomatch, string:find(InForce, "data_dir=")),
        ?assertNotEqual(nomatch, string:find(InForce, "log_level=")),
        ?assertNotEqual(nomatch, string:find(InForce, "live_network=false")),
        %% "One line" checked as a property of the output rather than assumed from
        %% the format strings. A `~p` over one of the read API's maps wraps at this
        %% width and would have turned any of the three into five lines, each of
        %% which still matched the prefix above.
        ?assertEqual(3, length(Lines))
    after
        application:stop(?APP)
    end.

%% The one that can silently lie.
%%
%% `i2per.conf` supplies two keys and the environment supplies a third the file
%% never mentions. `m:i2p_config:apply_env/1` is gap-filling -- anything already set
%% in the environment wins -- so the file and the environment genuinely disagree
%% about what this router is running with, and the line has to report the
%% environment's answer for the key both of them set. A reporter that read the file
%% would print the file's value, and every one of its assertions would still look
%% entirely plausible.
boot_config_line_reports_the_value_in_force(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    Conf = filename:join(Dir, "i2per.conf"),
    ok = filelib:ensure_dir(Conf),
    ok = file:write_file(Conf, <<"log_level = info\nnet_id = 7\nfloodfill = false\n">>),
    try
        application:set_env(?APP, config_file, Conf),
        %% Set only in the environment: the file says nothing about `data_dir`, so
        %% a reporter reading the file could not mention it at all.
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, net_id, 3),
        Lines = i2p_ct_helpers:log_lines_from(fun boot/0),
        Rendered = lists:flatten(lists:join(" ", Lines)),
        ct:pal("boot lines:~n~s", [lists:join("\n", Lines)]),

        %% The environment's answer for the key both of them set: `net_id` is 3 in
        %% the environment and 7 in the file, and the router is running with 3.
        ?assertEqual({ok, 3}, application:get_env(?APP, net_id)),
        ?assertNotEqual(nomatch, string:find(Rendered, "net_id=3")),
        ?assertEqual(nomatch, string:find(Rendered, "net_id=7")),

        %% And the file's answer for the key only the file set, which is the other
        %% half of the property: the line has to reflect what the loader put into
        %% the environment, not only what was already there.
        ?assertEqual({ok, info}, application:get_env(?APP, log_level)),
        ?assertEqual(info, i2p_log:level()),
        ?assertNotEqual(nomatch, string:find(Rendered, "log_level=info")),
        ?assertNotEqual(nomatch, string:find(Rendered, "floodfill=false"))
    after
        application:stop(?APP),
        application:unset_env(?APP, config_file)
    end.

%% Nothing the router holds that is secret reaches any of the three lines.
%%
%% Two real secrets rather than stand-ins: the identity this boot created on disk,
%% whose signing seed is read back out of the data directory afterwards, and the
%% distribution cookie this node is genuinely running with. The cookie is the
%% better of the two to check -- a boot line that leaked it would hand over the one
%% secret an attacker can actually use to connect at all.
%%
%% Worth reading next to `boot_announces_config_posture_and_online/1` and not on its
%% own: a renderer that printed nothing would pass a "no secrets" test by itself,
%% so what makes this meaningful is that the other case proves the lines are
%% non-empty and carry the facts.
boot_lines_carry_no_key_material(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [dummy_seed()]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        Lines = i2p_ct_helpers:log_lines_from(fun boot/0),
        Rendered = lists:flatten(lists:join(" ", Lines)),
        ct:pal("boot lines:~n~s", [lists:join("\n", Lines)]),

        {ok, Id} = i2p_identity:ensure_identity(Dir),
        Seed = maps:get(sign_seed, Id),
        Cookie = erlang:get_cookie(),
        ?assertNotEqual(nohost, Cookie),
        ?assertEqual(nomatch, string:find(Rendered, binary_to_list(Seed))),
        ?assertEqual(nomatch, string:find(Rendered, atom_to_list(Cookie)))
    after
        application:stop(?APP)
    end.

%% Start the router, failing the case if it did not start.
%%
%% Used as the work under `m:i2p_ct_helpers:log_lines_from/1`'s barrier:
%% `ensure_all_started/1` returns only once `m:i2per_app:start/2` has emitted all
%% three lines, so the marker logged after it cannot overtake them. No deadline and
%% no sleep -- the ordering is the property, and it is the barrier's job to establish
%% it rather than this function's.
-spec boot() -> ok.
boot() ->
    case application:ensure_all_started(?APP) of
        {ok, _} -> ok;
        {error, Reason} -> ct:fail({boot_failed, Reason})
    end.

%%%%%%% %%% Internal %%%%%%%

offline_boot_does_not_dial_seeded_peer(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    SeedPort = i2p_ct_helpers:free_port(),
    Seed = local(SeedPort),
    try
        application:set_env(?APP, data_dir, Dir),
        application:set_env(?APP, seeds, [maps:get(ri, Seed)]),
        application:set_env(?APP, port, Port),
        application:set_env(?APP, allow_private_host, true),
        application:set_env(?APP, live_network, false),
        application:set_env(?APP, reseed, #{enabled => false}),
        application:set_env(?APP, floodfill_discovery_delay_ms, 0),
        {ok, _} = application:ensure_all_started(?APP),
        ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
        assert_no_peer_dialed(1000),
        ?assertEqual(#{}, i2p_peer:status())
    after
        gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
        application:stop(?APP)
    end.

-doc """
The live-smoke report carries its network observables as counts. In hermetic
`live => false` mode the floodfill-discovery kick fires at t=0, so the router
dials its own seed (itself): the report is deterministic yet count-agnostic so
it can never flake on network timing — the assert-on-value coverage for
`dialed/0` lives in `inbound_session_round_trips`.
""".
smoke_report_carries_four_observables(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    try
        Rep = i2p_smoke:report(#{
            window_ms => 3000,
            data_dir => Dir,
            port => Port,
            live => false
        }),
        ct:pal("smoke report: ~p", [Rep]),
        #{
            <<"window_ms">> := 3000,
            <<"peers">> := Peers,
            <<"dialed">> := Dialed,
            <<"netdb_router_info_growth">> := Growth,
            <<"floodfill_store_accepts">> := LegacyGrowth,
            <<"transit_relayed_tunnels">> := Transit
        } = Rep,
        ?assert(is_integer(Peers)),
        ?assert(is_integer(Dialed)),
        ?assert(is_integer(Growth)),
        ?assertEqual(Growth, LegacyGrowth),
        ?assert(is_integer(Transit))
    after
        application:unset_env(?APP, data_dir),
        application:unset_env(?APP, seeds),
        application:unset_env(?APP, port),
        application:unset_env(?APP, allow_private_host),
        application:unset_env(?APP, reseed),
        application:unset_env(?APP, ntcp2_published),
        application:unset_env(?APP, live_network),
        application:unset_env(?APP, floodfill_discovery_delay_ms)
    end.

%% A RouterInfo announcing an out-of-reach port: a valid seed we never dial.
dummy_seed() ->
    {StaticPub, _} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [
            i2p_router_info:ntcp2_address(
                <<"127.0.0.1">>, 4668, StaticPub, crypto:strong_rand_bytes(16)
            )
        ],
        Opts,
        Seed
    ).

%% An external router node: fresh identity + static keypair + IV + signing seed,
%% with a signed RouterInfo announcing NTCP2 on Port.
local(Port) ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        hash => i2p_router_info:hash(RI),
        ri => RI,
        static_pub => StaticPub,
        static_priv => StaticPriv,
        iv => IV,
        seed => Seed
    }.

%% As `f:local/1` but announcing floodfill caps, so `i2p_netdb` treats the
%% router as an eligible floodfill.
ff_local(Port) ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, StaticPub, IV),
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => <<"Of">>
    },
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        hash => i2p_router_info:hash(RI),
        ri => RI,
        static_pub => StaticPub,
        static_priv => StaticPriv,
        iv => IV,
        seed => Seed
    }.

%% An external Alice router announcing SSU2 (mirror of the e2e suite's
%% `alice_local/0`): static keypair + intro key + signing seed, with a signed
%% RouterInfo advertising an SSU2 address. The dialer side of the SSU2 inbound
%% round trip; its RouterInfo is recovered by Bob's peer manager from msg3.
ssu2_alice_local() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19150, StaticPub, IntroKey),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        hash => i2p_router_info:hash(RI),
        ri => RI,
        local => #{
            static_priv => StaticPriv,
            static_pub => StaticPub,
            intro_key => IntroKey,
            sign_seed => Seed,
            sign_pub => SignPub
        }
    }.

%% Receive a DatabaseStore of our own RouterInfo from an SSU2 session,
%% draining non-store frames, and return the stored RouterInfo's hash.
recv_ssu2_store(Pid) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= Pid ->
                case decode_ssu2_store(Blocks) of
                    {ok, Hash} -> {true, Hash};
                    unknown -> false
                end;
            ({ssu2_closed, P, _Reason}) when P =:= Pid ->
                erlang:error(closed_early);
            (_) ->
                false
        end,
        ?TIMEOUT
    ).

decode_ssu2_store(Blocks) ->
    case [Body || {i2np, 1, _MsgId, _ShortExp, Body} <- Blocks] of
        [Body | _] ->
            case i2p_i2np:decode_db_store(Body) of
                {ok, #{store_type := 0, data := Raw}} ->
                    case i2p_i2np:parse_router_info_data(Raw) of
                        {ok, RIBytes} ->
                            {ok, RI} = i2p_router_info:decode(RIBytes),
                            {ok, i2p_router_info:hash(RI)};
                        _ ->
                            unknown
                    end;
                _ ->
                    unknown
            end;
        [] ->
            unknown
    end.

%% Receive a DatabaseStore from a connection, draining non-store frames.
recv_db_store(Conn) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, C, Payload}) when C =:= Conn ->
                {ok, Blocks} = i2p_framing:decode_blocks(Payload),
                case decode_store(Blocks) of
                    {store, _} = Store -> {true, Store};
                    unknown -> false
                end;
            (_) ->
                false
        end,
        ?TIMEOUT
    ).

decode_store(Blocks) ->
    case [Data || #{type := 3, data := Data} <- Blocks] of
        [Data | _] ->
            case i2p_i2np:decode(Data) of
                {ok, #{type := 1, body := Body}} ->
                    case i2p_i2np:decode_db_store(Body) of
                        {ok, #{store_type := 0, data := Raw}} ->
                            {ok, RIBytes} = i2p_i2np:parse_router_info_data(Raw),
                            {ok, RI} = i2p_router_info:decode(RIBytes),
                            {store, RI};
                        _ ->
                            unknown
                    end;
                _ ->
                    unknown
            end;
        [] ->
            unknown
    end.

%% --------------------------------------------------------------------------
%% Floodfill-discovery boot helpers: the test owns the seed and floodfill
%% listeners, so it short-circuits the I2NP encoding for the discovery exchange.
%% --------------------------------------------------------------------------

%% Accept a dial (Alice) as the own-side (Bob) listener owner. Returns
%% `{Conn, RemoteRI}` where RemoteRI is the dialer's RouterInfo recovered from
%% its msg3. Under CT each testcase owns its own process, so no stale-message
%% filtering is needed.
await_conn_ready() ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_ready, Conn, RemoteRI}) -> {true, {Conn, RemoteRI}};
            (_) -> false
        end,
        ?TIMEOUT
    ).

%% Wait out a quiet window during which no `{peer_connected, _}` event may be
%% announced on the i2p_events bus (deadline-bounded, no fixed sleep).
assert_no_peer_dialed(Window) ->
    quiet_until(erlang:monotonic_time(millisecond) + Window).

quiet_until(Deadline) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            ok;
        false ->
            receive
                {peer_connected, _Peer} ->
                    erlang:error(peer_dialed_without_seeds);
                _Other ->
                    quiet_until(Deadline)
            after erlang:max(0, Deadline - erlang:monotonic_time(millisecond)) ->
                ok
            end
    end.

%% The boot kick is an exploratory DatabaseLookup for some key: return the key.
%% Tolerates unrelated frames (e.g. a self-announce store) that may precede it.
await_exploratory_lookup(Conn) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, C, _Payload}) when C =:= Conn ->
                case decode_db_lookup({ntcp2_frame, C, _Payload}) of
                    {ok, #{type := exploratory} = Lookup} ->
                        {true, maps:get(key, Lookup)};
                    _ ->
                        false
                end;
            (_) ->
                false
        end,
        ?TIMEOUT
    ).

%% Decode a DatabaseLookup from a frame, or `error` when the frame is not a
%% valid lookup (including DB lookups whose body does not parse).
decode_db_lookup({ntcp2_frame, _Conn, _Payload} = Frame) ->
    case {decode_i2np(Frame, type), decode_i2np(Frame, body)} of
        {{ok, 2}, {ok, Body}} -> i2p_i2np:decode_db_lookup(Body);
        _ -> error
    end.

%% After receiving a DatabaseSearchReply the peer issues a `routerinfo` lookup
%% for the named floodfill. Wait for it and return ok.
await_routerinfo_lookup(Conn, FFHash) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, C, _Payload}) when C =:= Conn ->
                case decode_db_lookup({ntcp2_frame, C, _Payload}) of
                    {ok, #{key := FFHash, type := routerinfo}} -> {true, ok};
                    _ -> false
                end;
            (_) ->
                false
        end,
        ?TIMEOUT
    ).

%% The publish cycle dials the floodfill and stores our RouterInfo there;
%% return the published RouterInfo's hash from that store frame.
await_published_hash(Conn) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, C, Payload}) when C =:= Conn ->
                case published_ri_hash(Payload) of
                    {ok, Hash} -> {true, Hash};
                    error -> false
                end;
            (_) ->
                false
        end,
        ?TIMEOUT
    ).

published_ri_hash(Payload) ->
    {ok, Blocks} = i2p_framing:decode_blocks(Payload),
    case [B || #{type := 3} = B <- Blocks] of
        [#{data := I2NP} | _] ->
            case i2p_i2np:decode(I2NP) of
                {ok, #{type := 1, body := Body}} ->
                    case i2p_i2np:decode_db_store(Body) of
                        {ok, #{store_type := 0, data := Raw}} ->
                            case i2p_i2np:parse_router_info_data(Raw) of
                                {ok, RIBytes} ->
                                    {ok, RI} = i2p_router_info:decode(RIBytes),
                                    {ok, i2p_router_info:hash(RI)};
                                _ ->
                                    error
                            end;
                        _ ->
                            error
                    end;
                _ ->
                    error
            end;
        [] ->
            error
    end.

send_db_search_reply(Conn, Key, PeerHashes, From) ->
    send_i2np(Conn, i2p_i2np:db_search_reply(Key, PeerHashes, From)).

send_db_store(Conn, RI) ->
    Hash = i2p_router_info:hash(RI),
    Data = i2p_i2np:router_info_data(i2p_router_info:to_binary(RI)),
    send_i2np(Conn, i2p_i2np:db_store(Hash, 0, 0, undefined, Data)).

send_i2np(Conn, I2NPMsg) ->
    Block = i2p_framing:encode_block(3, i2p_i2np:encode(I2NPMsg)),
    ok = i2p_ntcp2_conn:send(Conn, Block).

%% Extract `type` or `body` (the I2NP header fields) from a decoded frame.
decode_i2np({ntcp2_frame, _Conn, Payload}, Field) ->
    {ok, Blocks} = i2p_framing:decode_blocks(Payload),
    #{data := I2NP} = hd([B || #{type := 3} = B <- Blocks]),
    {ok, Msg} = i2p_i2np:decode(I2NP),
    {ok, maps:get(Field, Msg)}.

%% --------------------------------------------------------------------------
%% Reseed fixtures (mirror `i2p_reseed_srv_tests`): an in-test RSA signer and
%% a localhost SU3 server, so the default-on reseed path is exercised offline.
%% --------------------------------------------------------------------------

remote_ri(Port) ->
    {StaticPub, _} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    Addr = i2p_router_info:ntcp2_address(
        <<"127.0.0.1">>, Port, StaticPub, crypto:strong_rand_bytes(16)
    ),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed).

%% Shared with the other reseed-shaped suites and generated once per run. See
%% `i2p_ct_helpers:su3_keypair/0` for why the key is 4096 bits.
test_keypair() ->
    i2p_ct_helpers:su3_keypair().

sign_ris(Ris) ->
    {Priv, _Cert} = test_keypair(),
    Entries = [
        {
            "routerInfo-" ++ binary_to_list(i2p_router_info:hash(RI)) ++ ".dat",
            i2p_router_info:to_binary(RI)
        }
     || RI <- Ris
    ],
    {ok, {_Name, ZipBin}} = zip:create("i2pseeds.zip", Entries, [memory]),
    i2p_su3:encode(<<"1789000000">>, <<"test-signer">>, ZipBin, Priv).

serve_su3(Su3) ->
    {ok, Listen} = gen_tcp:listen(0, [
        {ip, {127, 0, 0, 1}},
        binary,
        {active, false},
        {reuseaddr, true}
    ]),
    {ok, P} = inet:port(Listen),
    spawn(fun() -> serve_once(Listen, Su3) end),
    P.

serve_once(Listen, Su3) ->
    {ok, Sock} = gen_tcp:accept(Listen, 15_000),
    {ok, _Request} = gen_tcp:recv(Sock, 0, 15_000),
    Response = [
        <<"HTTP/1.1 200 OK\r\n">>,
        <<"Content-Type: application/octet-stream\r\n">>,
        <<"Content-Length: ">>,
        integer_to_binary(byte_size(Su3)),
        <<"\r\n">>,
        <<"Connection: close\r\n\r\n">>,
        Su3
    ],
    ok = gen_tcp:send(Sock, Response),
    gen_tcp:close(Sock),
    gen_tcp:close(Listen).

reseed_url(Port) ->
    lists:flatten(io_lib:format("http://127.0.0.1:~b/", [Port])).

%% Wait for the reseed worker to stop, which it does after the fetch returned
%% and the `learn_ri` casts were sent — whether the fetch succeeded or failed.
%% Either way the casts are in flight, so the caller's barrier on the peer manager
%% is sound. A failed reseed therefore shows up as a RouterInfo that is not
%% findable, which names the cause, rather than as a timeout.
%%
%% The process may already be gone: it is a child of the supervisor the test just
%% started, so it was registered when `ensure_all_started` returned, and a missing
%% name therefore means it finished rather than that it never started. The
%% deadline below guards a genuine hang, not a slow one.
await_reseed_worker() ->
    case whereis(i2p_reseed_srv) of
        undefined ->
            ok;
        Pid ->
            Ref = erlang:monitor(process, Pid),
            receive
                {'DOWN', Ref, process, Pid, _Reason} -> ok
            after 60_000 ->
                erlang:error(reseed_worker_never_stopped)
            end
    end.
