%% SSU2 PeerTest and RouterInfo delivery tests. The cases cover in-session
%% messages 1-4, the out-of-session Charlie response, explicit role handling,
%% RouterInfo delivery to the session owner, the three-peer coordinator relay,
%% and the complete seven-message exchange.
%%
%% Network-backed cases own their process, mailbox, application lifecycle, and
%% event collector. The pure signature case starts neither an application nor a
%% collector. Every network wait drains non-matching mail through
%% `i2p_ct_helpers:wait_msg/2`. Handshake recovery is covered separately by
%% `i2p_ssu2_handshake_SUITE` with deterministic fault injection.

-module(i2p_ssu2_peertest_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    alice_initiation_reject/1,
    charlie_responder_peertest/1,
    charlie_reply_block_signs_correctly/1,
    in_session_charlie_responder/1,
    explicit_peer_test_role_override/1,
    router_info_block_delivered_to_owner/1,
    coordinator_relay_loopback/1,
    full_seven_message_peertest_loopback/1,
    charlie_dial_failure_returns_error/1,
    auto_select_dial_failure_rejects_alice/1
]).

-define(APP, i2per).
-define(DATA_WINDOW, 25000).
-define(RELAY_WINDOW, 30000).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        alice_initiation_reject,
        charlie_responder_peertest,
        charlie_reply_block_signs_correctly,
        in_session_charlie_responder,
        explicit_peer_test_role_override,
        router_info_block_delivered_to_owner,
        coordinator_relay_loopback,
        full_seven_message_peertest_loopback,
        charlie_dial_failure_returns_error,
        auto_select_dial_failure_rejects_alice
    ].

%% ---------------------------------------------------------------------------
%% Per-case lifecycle: the full app is started so the SSU2 session/listener
%% tree (temporary children of i2p_ssu2_sup) comes up and is torn down by app
%% stop — nothing leaks into the next testcase. The pure block-signature case
%% needs neither an app nor a socket and runs with no lifecycle at all.
%% ---------------------------------------------------------------------------

init_per_testcase(charlie_reply_block_signs_correctly, Config) ->
    Config;
init_per_testcase(Case, Config) ->
    i2p_ct_helpers:start_ssu2_trace(),
    start_app(
        Config,
        case Case of
            full_seven_message_peertest_loopback -> 40000;
            _ -> 30000
        end
    ).

start_app(Config, Timetrap) ->
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, Timetrap} | Config].

end_per_testcase(charlie_reply_block_signs_correctly, _Config) ->
    ok;
end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    i2p_ct_helpers:stop_ssu2_trace(),
    ok.

%% ---------------------------------------------------------------------------
%% Peer-test relay
%% ---------------------------------------------------------------------------

%% An explicitly `alice`-tagged session is the test target and can originate a
%% peer test: it builds and signs message 1, sends it in-session to the
%% introducer, and when the message-4 "no Charlie available" reject returns,
%% validates it and emits the typed `peertest_result` outcome (`unknown` with
%% reason `no_charlie_report`).
alice_initiation_reject(_Config) ->
    {Events, Started} = start_events(),
    ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
    try
        {BobLocal, _BobRIBlock} = bob_local(),
        BobHash = maps:get(hash, BobLocal),
        {ok, BobListener} =
            i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),

        {AliceLocal, AliceRIBlock} = alice_local(),
        {ok, AliceListener} =
            i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, AliceLocal, self()),
        AlicePort = i2p_ssu2_listener:port(AliceListener),
        RemoteOpts =
            #{
                host => <<"127.0.0.1">>,
                port => i2p_ssu2_listener:port(BobListener),
                static_key => maps:get(static_pub, BobLocal),
                intro_key => maps:get(intro_key, BobLocal)
            },
        {ok, AlicePid, _} =
            i2p_ssu2_conn:connect(AliceLocal, RemoteOpts, AliceRIBlock, AliceListener, alice),
        unlink(AlicePid),

        Ip = <<127, 0, 0, 1>>,
        ok = i2p_ssu2_conn:initiate_peertest(AlicePid, BobHash, AlicePort, Ip),

        ok =
            i2p_ct_helpers:wait_msg(
                fun
                    ({ssu2_data, P, Blocks}) when P =:= AlicePid ->
                        case lists:keyfind(peertest, 1, Blocks) of
                            {peertest, 4, 2, 0, _, 2, _Nonce, _Ts, _Port, Ip, _Sig} ->
                                {true, ok};
                            Other ->
                                erlang:error({unexpected_peertest_reply, Other})
                        end;
                    (_) ->
                        false
                end,
                ?DATA_WINDOW
            ),

        ok =
            i2p_ct_helpers:wait_msg(
                %% A reject is the introducer chain failing before Charlie's
                %% confirmation — the typed outcome, not a verdict about our
                %% own reachability.
                fun
                    ({peertest_result, ipv4, {unknown, no_charlie_report}}) -> {true, ok};
                    (_) -> false
                end,
                ?DATA_WINDOW
            )
    after
        gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
        case Started of
            true -> catch gen_server:stop(Events);
            false -> ok
        end
    end.

%% The tested peer (Charlie): an out-of-session PeerTest (type 7) message 6 is
%% answered directly with a message 7 reply to the source endpoint, echoing the
%% nonce — no Alice-role session exists, so the listener handles it from an
%% established-less state.
charlie_responder_peertest(_Config) ->
    {CPub, CPriv} = i2p_crypto:x25519_keygen(),
    CBik = crypto:strong_rand_bytes(32),
    CharlieLocal = #{static_priv => CPriv, static_pub => CPub, intro_key => CBik},
    {ok, Listener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, CharlieLocal, self()),
    CPort = i2p_ssu2_listener:port(Listener),

    Nonce = 16#12345678,
    Dst = i2p_peertest:src_conn_id(Nonce),
    Src = i2p_peertest:dst_conn_id(Nonce),
    Block =
        i2p_peertest:block(
            6,
            0,
            0,
            <<>>,
            2,
            Nonce,
            1_700_000_000,
            4567,
            <<127, 0, 0, 1>>,
            <<>>
        ),
    {ok, Packet} = i2p_ssu2:encode_peertest(CBik, 0, Dst, Src, [Block]),
    {ok, Sock} = gen_udp:open(0, [binary]),
    ok = gen_udp:send(Sock, {127, 0, 0, 1}, CPort, Packet),
    Reply =
        i2p_ct_helpers:wait_msg(
            fun
                ({udp, S, _IP, _RPort, Datagram}) when S =:= Sock -> {true, Datagram};
                (_) -> false
            end,
            ?DATA_WINDOW
        ),
    {ok, #{blocks := [{peertest, 7, _Code, _Flags, _Hash, 2, Nonce, _Ts, _Port, _Ip, _Sig}]}} =
        i2p_ssu2:decode_peertest(CBik, Reply),
    CPort = i2p_ssu2_listener:port(Listener),
    gen_udp:close(Sock),
    ok.

%% Charlie's in-session message-3 reply is signed over bhash (the introducer
%% Bob) and ahash (Alice): the pure block builder produces a signature that
%% verifies, and a wrong key does not.
charlie_reply_block_signs_correctly(_Config) ->
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Local = #{sign_seed => Seed},
    BobHash = <<1:256>>,
    AliceHash = <<2:256>>,
    Nonce = 16#0A0B0C0D,
    Ts = 1_700_000_000,
    Port = 4567,
    Ip = <<127, 0, 0, 1>>,
    Block = i2p_ssu2_conn:charlie_reply_block(AliceHash, Nonce, Ts, Port, Ip, Local, BobHash),
    {peertest, 3, 0, 0, _, 2, Nonce, Ts, Port, Ip, Sig} = Block,
    <<>> = element(5, Block),
    true =
        i2p_peertest:verify(
            BobHash, AliceHash, 2, Nonce, Ts, Port, Ip, Sig, SignPub
        ),
    false =
        i2p_peertest:verify(
            BobHash, AliceHash, 2, Nonce, Ts, Port, Ip, Sig, crypto:strong_rand_bytes(32)
        ),
    ok.

%% An established Bob-role session that receives a message 2 peer test replies
%% a message 3 (the Charlie responder) without crashing, and the reply
%% signature verifies against Bob's (dialer's) hash and Alice's hash.
in_session_charlie_responder(_Config) ->
    {CharlieLocal, CharlieRI} = charlie_local(),
    {ok, CharlieListener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, CharlieLocal, self()),
    CharliePort = i2p_ssu2_listener:port(CharlieListener),

    {BobLocal, BobRIBlock} = bob_local(),
    {ok, BobListener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => CharliePort,
            static_key => maps:get(static_pub, CharlieLocal),
            intro_key => maps:get(intro_key, CharlieLocal)
        },
    {ok, DialerPid, _} =
        i2p_ssu2_conn:connect(BobLocal, RemoteOpts, BobRIBlock, BobListener),
    unlink(DialerPid),

    Nonce = 16#DEADBEEF,
    Ts = 1_700_000_000,
    Port = 4567,
    Ip = <<127, 0, 0, 1>>,
    AliceHash = i2p_router_info:hash(CharlieRI),
    Msg2 = i2p_peertest:block(2, 0, 0, AliceHash, 2, Nonce, Ts, Port, Ip, <<>>),
    i2p_ssu2_conn:send_peertest(DialerPid, Msg2),

    ok =
        i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_data, P, Blocks}) when P =:= DialerPid ->
                    case lists:keyfind(peertest, 1, Blocks) of
                        {peertest, 3, 0, 0, _, 2, Nonce, Ts, Port, Ip, Sig} ->
                            BobHash = i2p_router_info:hash(maps:get(ri, BobLocal)),
                            true =
                                i2p_peertest:verify(
                                    BobHash,
                                    AliceHash,
                                    2,
                                    Nonce,
                                    Ts,
                                    Port,
                                    Ip,
                                    Sig,
                                    maps:get(sign_pub, CharlieLocal)
                                ),
                            {true, ok};
                        _ ->
                            erlang:error({unexpected_blocks, Blocks})
                    end;
                (_) ->
                    false
            end,
            ?DATA_WINDOW
        ).

%% An explicit peer-test role on a dial-out session wins over the default
%% handshake-role inference: a handshake-`alice` dialer tagged `bob` must act
%% as the introducer and answer a message-1 request with the deterministic
%% "no Charlie available" reject (message 4).
explicit_peer_test_role_override(_Config) ->
    {BobLocal, _BobRIBlock} = bob_local(),
    {ok, BobListener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),

    {AliceLocal, AliceRIBlock} = alice_local(),
    {ok, AliceListener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, AliceLocal, self()),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => i2p_ssu2_listener:port(BobListener),
            static_key => maps:get(static_pub, BobLocal),
            intro_key => maps:get(intro_key, BobLocal)
        },
    {ok, DialerPid, _} =
        i2p_ssu2_conn:connect(AliceLocal, RemoteOpts, AliceRIBlock, AliceListener, bob),
    unlink(DialerPid),

    Nonce = 16#CAFEBABE,
    Ts = 1_750_000_000,
    Port = 9999,
    Ip = <<127, 0, 0, 1>>,
    Msg1 = i2p_peertest:block(1, 0, 0, <<0:256>>, 2, Nonce, Ts, Port, Ip, <<>>),
    i2p_ssu2_conn:send_peertest(DialerPid, Msg1),

    ok =
        i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_data, P, Blocks}) when P =:= DialerPid ->
                    case lists:keyfind(peertest, 1, Blocks) of
                        {peertest, 4, 2, 0, _, 2, Nonce, Ts, Port, Ip, _Sig} ->
                            {true, ok};
                        Other ->
                            erlang:error({unexpected_peertest_reply, Other})
                    end;
                (_) ->
                    false
            end,
            ?DATA_WINDOW
        ).

%% ---------------------------------------------------------------------------
%% RouterInfo-block delivery
%% ---------------------------------------------------------------------------

%% A `router_info` block sent in-session by one peer is delivered to the other
%% peer's owner inside a {ssu2_data, Pid, Blocks} message. The owner recovers
%% the SSU2 intro key from the relayed RouterInfo — the exact path the Bob
%% introducer needs for relaying Charlie's RouterInfo back to Alice.
router_info_block_delivered_to_owner(_Config) ->
    {BobLocal, BobRIBlock} = bob_local(),
    {ok, BobListener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    {CharlieLocal, _} = charlie_local(),
    {ok, CharlieListener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, CharlieLocal, self()),
    CharliePort = i2p_ssu2_listener:port(CharlieListener),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => CharliePort,
            static_key => maps:get(static_pub, CharlieLocal),
            intro_key => maps:get(intro_key, CharlieLocal)
        },
    {ok, BobPid, _} =
        i2p_ssu2_conn:connect(BobLocal, RemoteOpts, BobRIBlock, BobListener),
    unlink(BobPid),

    {CPub, _CPriv} = i2p_crypto:x25519_keygen(),
    {CSignPub, CSeed} = i2p_crypto:ed25519_keygen(),
    CIntroKey = crypto:strong_rand_bytes(32),
    CIdentity = i2p_keys:from_keys(CPub, CSignPub),
    CAddr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19152, CPub, CIntroKey),
    CRI = i2p_router_info:build(
        CIdentity,
        erlang:system_time(millisecond),
        [CAddr],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        CSeed
    ),
    CRIBin = i2p_router_info:to_binary(CRI),

    i2p_ssu2_conn:send_router_info(BobPid, 0, CRIBin),
    ok = wait_router_info(CIntroKey).

%% ---------------------------------------------------------------------------
%% Coordinator + full seven-message relay
%% ---------------------------------------------------------------------------

%% The full in-session PeerTest relay (messages 1-4) across three loopback
%% peers: Alice dials Bob (an `i2p_peertest_coord`), Bob relays to Charlie;
%% Charlie's role-bob session answers message 3, which Bob relays back to Alice
%% as message 4 preceded by Charlie's RouterInfo.
coordinator_relay_loopback(_Config) ->
    {BobLocal, _BobRIBlock} = bob_local(),
    {ok, Coord} = i2p_peertest_coord:start_link(BobLocal),
    try
        BobPort = i2p_peertest_coord:port(Coord),

        {CharlieListener, _CPort, CharlieLocal} = listen_full_local(<<"127.0.0.1">>),
        CharlieRI = maps:get(ri, CharlieLocal),
        CharlieOpts =
            #{
                host => <<"127.0.0.1">>,
                port => i2p_ssu2_listener:port(CharlieListener),
                static_key => maps:get(static_pub, CharlieLocal),
                intro_key => maps:get(intro_key, CharlieLocal)
            },
        ok = i2p_peertest_coord:dial_charlie(Coord, CharlieOpts, CharlieRI),

        {AliceListener, _APort, AliceLocal} = listen_full_local(<<"127.0.0.1">>),
        AliceRIBlock = maps:get(ri_binary, AliceLocal),
        AlicePort = i2p_ssu2_listener:port(AliceListener),
        RemoteOpts =
            #{
                host => <<"127.0.0.1">>,
                port => BobPort,
                static_key => maps:get(static_pub, BobLocal),
                intro_key => maps:get(intro_key, BobLocal)
            },
        {ok, AlicePid, _} =
            i2p_ssu2_conn:connect(AliceLocal, RemoteOpts, AliceRIBlock, AliceListener, alice),
        unlink(AlicePid),

        BobHash = maps:get(hash, BobLocal),
        Ip = <<127, 0, 0, 1>>,
        ok = i2p_ssu2_conn:send_router_info(AlicePid, 0, AliceRIBlock),
        ok = i2p_ssu2_conn:initiate_peertest(AlicePid, BobHash, AlicePort, Ip),

        CharlieIntroKey = maps:get(intro_key, CharlieLocal),
        ok = wait_relay_result(AlicePid, CharlieRI, Ip, CharlieIntroKey, false, false)
    after
        catch i2p_peertest_coord:stop(Coord)
    end.

%% The full seven-message PeerTest loopback across three loopback peers. The
%% in-session leg (1-4, each prefixed by the relaying of the tested peer's
%% RouterInfo) is followed by the out-of-session leg (5, 6, 7); with all of
%% 4/5/7 observed the result resolves to `ok`.
full_seven_message_peertest_loopback(_Config) ->
    {Events, Started} = start_events(),
    ok = gen_event:add_handler(i2p_events, i2p_events_tests_collector, [self()]),
    {BobLocal, _BobRIBlock} = bob_local(),
    {ok, Coord} = i2p_peertest_coord:start_link(BobLocal),
    try
        BobPort = i2p_peertest_coord:port(Coord),

        {CharlieListener, _CPort, CharlieLocal} = listen_full_local(<<"127.0.0.1">>),
        CharlieRI = maps:get(ri, CharlieLocal),
        CharlieOpts =
            #{
                host => <<"127.0.0.1">>,
                port => i2p_ssu2_listener:port(CharlieListener),
                static_key => maps:get(static_pub, CharlieLocal),
                intro_key => maps:get(intro_key, CharlieLocal)
            },
        ok = i2p_peertest_coord:dial_charlie(Coord, CharlieOpts, CharlieRI),

        {AliceListener, _APort, AliceLocal} = listen_full_local(<<"127.0.0.1">>),
        AliceRIBlock = maps:get(ri_binary, AliceLocal),
        AlicePort = i2p_ssu2_listener:port(AliceListener),
        RemoteOpts =
            #{
                host => <<"127.0.0.1">>,
                port => BobPort,
                static_key => maps:get(static_pub, BobLocal),
                intro_key => maps:get(intro_key, BobLocal)
            },
        {ok, AlicePid, _} =
            i2p_ssu2_conn:connect(AliceLocal, RemoteOpts, AliceRIBlock, AliceListener, alice),
        unlink(AlicePid),

        BobHash = maps:get(hash, BobLocal),
        Ip = <<127, 0, 0, 1>>,
        ok = i2p_ssu2_conn:send_router_info(AlicePid, 0, AliceRIBlock),
        ok = i2p_ssu2_conn:initiate_peertest(AlicePid, BobHash, AlicePort, Ip),

        ok = observe_for_result(?RELAY_WINDOW)
    after
        catch i2p_peertest_coord:stop(Coord),
        gen_event:delete_handler(i2p_events, i2p_events_tests_collector, []),
        case Started of
            true -> catch gen_server:stop(Events);
            false -> ok
        end
    end.

%% A dial to an unreachable Charlie must answer the caller with a tagged
%% error and leave the coordinator alive: candidates come from the NetDb, so
%% an unreachable one is the ordinary case, and this gen_server owns the
%% intro-side listener. The handshake budget is shrunk so the failure lands
%% in milliseconds instead of the default ~9 s.
charlie_dial_failure_returns_error(_Config) ->
    ok = application:set_env(?APP, handshake_retry_ms, 100),
    ok = application:set_env(?APP, handshake_max_resends, 1),
    try
        {BobLocal, _BobRIBlock} = bob_local(),
        {ok, Coord} = i2p_peertest_coord:start_link(BobLocal),
        try
            DeadPort = i2p_ct_helpers:free_port(),
            {CharlieLocal, CharlieRI} = charlie_local(),
            CharlieOpts =
                #{
                    host => <<"127.0.0.1">>,
                    port => DeadPort,
                    static_key => maps:get(static_pub, CharlieLocal),
                    intro_key => maps:get(intro_key, CharlieLocal)
                },
            {error, {dial_failed, _Reason}} =
                i2p_peertest_coord:dial_charlie(Coord, CharlieOpts, CharlieRI),
            %% The coordinator survived the failed dial and still answers.
            true = is_process_alive(Coord),
            BobPort = i2p_peertest_coord:port(Coord),
            true = is_integer(BobPort)
        after
            catch i2p_peertest_coord:stop(Coord)
        end
    after
        ok = application:unset_env(?APP, handshake_retry_ms),
        ok = application:unset_env(?APP, handshake_max_resends)
    end.

%% The auto-select path against an unreachable NetDb candidate: the dial
%% fails, and Alice — who asked for a peer test — receives the deterministic
%% code-2 "no Charlie available" reject instead of silence, the coordinator
%% survives, and the rejected counter records the failure.
auto_select_dial_failure_rejects_alice(_Config) ->
    ok = application:set_env(?APP, handshake_retry_ms, 100),
    ok = application:set_env(?APP, handshake_max_resends, 1),
    try
        {BobLocal, _BobRIBlock} = bob_local(),
        {ok, Coord} = i2p_peertest_coord:start_link(BobLocal),
        try
            %% One qualifying candidate in the NetDb, on a dead port: the
            %% ordinary unreachable-candidate case the selection draws from.
            CharlieLocal = charlie_local_on(i2p_ct_helpers:free_port()),
            {ok, _} = i2p_netdb_srv:store_binary(
                i2p_router_info:to_binary(maps:get(ri, CharlieLocal)),
                erlang:system_time(millisecond)
            ),
            BobPort = i2p_peertest_coord:port(Coord),

            {AliceListener, _APort, AliceLocal} = listen_full_local(<<"127.0.0.1">>),
            AliceRIBlock = maps:get(ri_binary, AliceLocal),
            AlicePort = i2p_ssu2_listener:port(AliceListener),
            RemoteOpts =
                #{
                    host => <<"127.0.0.1">>,
                    port => BobPort,
                    static_key => maps:get(static_pub, BobLocal),
                    intro_key => maps:get(intro_key, BobLocal)
                },
            {ok, AlicePid, _} =
                i2p_ssu2_conn:connect(AliceLocal, RemoteOpts, AliceRIBlock, AliceListener, alice),
            unlink(AlicePid),

            BobHash = maps:get(hash, BobLocal),
            Ip = <<127, 0, 0, 1>>,
            ok = i2p_ssu2_conn:send_router_info(AlicePid, 0, AliceRIBlock),
            ok = i2p_ssu2_conn:initiate_peertest(AlicePid, BobHash, AlicePort, Ip),

            ok = wait_no_charlie_reject(AlicePid, Ip),
            true = is_process_alive(Coord),
            Counters = i2p_counters:snapshot(),
            1 = maps:get(charlie_selections_rejected, Counters, 0)
        after
            catch i2p_peertest_coord:stop(Coord)
        end
    after
        ok = application:unset_env(?APP, handshake_retry_ms),
        ok = application:unset_env(?APP, handshake_max_resends)
    end.

%% Wait for the in-session message-4 code-2 "no Charlie available" reject.
wait_no_charlie_reject(AlicePid, Ip) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= AlicePid ->
                case lists:keyfind(peertest, 1, Blocks) of
                    {peertest, 4, 2, 0, _, 2, _Nonce, _Ts, _Port, Ip, _Sig} -> {true, ok};
                    _ -> false
                end;
            (_) ->
                false
        end,
        ?DATA_WINDOW
    ).

%% ---------------------------------------------------------------------------
%% PeerTest relay helpers
%% ---------------------------------------------------------------------------

%% Accumulate the relayed message 4 (carrying Charlie's router hash) and a
%% matching forwarded RouterInfo for Charlie; the two arrive as separate data
%% messages that may land in either order, so each signal accumulates
%% independently across however many {ssu2_data, ...} messages carry them.
wait_relay_result(AlicePid, CharlieRI, Ip, CharlieIntroKey, SeenMsg4, SeenRI) ->
    Deadline = erlang:monotonic_time(millisecond) + ?RELAY_WINDOW,
    wait_relay_result(AlicePid, CharlieRI, Ip, CharlieIntroKey, SeenMsg4, SeenRI, Deadline).

wait_relay_result(_AlicePid, _CharlieRI, _Ip, _CharlieIntroKey, true, true, _Deadline) ->
    ok;
wait_relay_result(AlicePid, CharlieRI, Ip, CharlieIntroKey, SeenMsg4, SeenRI, Deadline) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            erlang:error(no_relay_result);
        false ->
            receive
                {ssu2_data, AlicePid, Blocks} ->
                    SeenMsg4_1 =
                        case SeenMsg4 of
                            true ->
                                true;
                            false ->
                                case lists:keyfind(peertest, 1, Blocks) of
                                    {peertest, 4, 0, 0, CharlieHash, 2, _Nonce, _Ts, _Port, Ip,
                                        _Sig} ->
                                        CharlieHash = i2p_router_info:hash(CharlieRI),
                                        true;
                                    _ ->
                                        false
                                end
                        end,
                    SeenRI1 =
                        SeenRI orelse has_charlie_router_info(Blocks, CharlieRI, CharlieIntroKey),
                    wait_relay_result(
                        AlicePid, CharlieRI, Ip, CharlieIntroKey, SeenMsg4_1, SeenRI1, Deadline
                    );
                _ ->
                    wait_relay_result(
                        AlicePid, CharlieRI, Ip, CharlieIntroKey, SeenMsg4, SeenRI, Deadline
                    )
            after erlang:max(0, Deadline - erlang:monotonic_time(millisecond)) ->
                erlang:error(no_relay_result)
            end
    end.

has_charlie_router_info(Blocks, CharlieRI, CharlieIntroKey) ->
    case lists:keyfind(router_info, 1, Blocks) of
        {router_info, 0, RIData} ->
            {ok, Decoded} = i2p_router_info:decode(RIData),
            {ok, Opts} = i2p_router_info:ssu2_address_options(Decoded),
            CharlieIntroKey = maps:get(intro_key, Opts),
            CharlieHash = i2p_router_info:hash(CharlieRI),
            CharlieHash = i2p_router_info:hash(Decoded),
            true;
        _ ->
            false
    end.

wait_router_info(CIntroKey) ->
    Deadline = erlang:monotonic_time(millisecond) + ?DATA_WINDOW,
    wait_router_info(CIntroKey, Deadline).

wait_router_info(CIntroKey, Deadline) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            erlang:error(no_router_info_block);
        false ->
            receive
                {ssu2_data, _Pid, Blocks} ->
                    case lists:keyfind(router_info, 1, Blocks) of
                        {router_info, 0, RIData} ->
                            assert_intro_key(RIData, CIntroKey);
                        _ ->
                            wait_router_info(CIntroKey, Deadline)
                    end;
                _ ->
                    wait_router_info(CIntroKey, Deadline)
            after erlang:max(0, Deadline - erlang:monotonic_time(millisecond)) ->
                erlang:error(no_router_info_block)
            end
    end.

assert_intro_key(RIData, CIntroKey) ->
    {ok, Decoded} = i2p_router_info:decode(RIData),
    {ok, Opts} = i2p_router_info:ssu2_address_options(Decoded),
    CIntroKey = maps:get(intro_key, Opts),
    ok.

%% Collect during the settle window and report the trace on failure, both for
%% the passing assert and for diagnosing a missing result.
observe_for_result(Timeout) ->
    try
        i2p_ct_helpers:wait_msg(
            %% Message 5 arrived: Charlie reached us directly — the punch
            %% landed and the test resolved to `reachable`.
            fun
                ({peertest_result, ipv4, {reachable, undefined}}) ->
                    {true, ok};
                (_) ->
                    false
            end,
            Timeout
        )
    catch
        error:timeout ->
            M = process_info(self(), messages),
            erlang:error({no_peertest_ok_result, M})
    end.

%% Bring up the `i2p_events` bus for a test that must observe emitted events,
%% tolerating a manager already started by another test in the same run.
%% Returns `{Pid, Started}` where `Started` is true only when this call created
%% the manager (and is therefore responsible for stopping it).
start_events() ->
    case whereis(i2p_events) of
        undefined ->
            {ok, Pid} = i2p_events:start_link(),
            erlang:unlink(Pid),
            {Pid, true};
        Pid ->
            {Pid, false}
    end.

%% ---------------------------------------------------------------------------
%% Fixtures
%% ---------------------------------------------------------------------------

alice_local() ->
    {APub, APriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(APub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19150, APub, IntroKey),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr],
        Opts,
        Seed
    ),
    ALocal = #{static_priv => APriv, static_pub => APub, intro_key => IntroKey},
    {ALocal#{sign_seed => Seed, sign_pub => SignPub}, maps:get(binary, RI)}.

%% A test peer with the full local map (static keys, signing keys, hash, RI)
%% plus its own intro key, as production `i2per_sup:ssu2_local/1` provides.
peer_local() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19151, Pub, IntroKey),
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr, i2p_router_info:ntcp2_address(<<"127.0.0.1">>, 9152, Pub, <<0:128>>)],
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

bob_local() ->
    #{ri := RI} = Local = peer_local(),
    {Local, maps:get(binary, RI)}.

%% Create a listener and a matching full local map whose advertised SSU2 port
%% equals the listener's real (kernel-assigned) port, so out-of-session
%% PeerTest messages addressed to the advertised RouterInfo address reach the
%% live socket. Returns `{Listener, Port, Local}`.
listen_full_local(Host) ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Base =
        #{
            static_priv => Priv,
            static_pub => Pub,
            intro_key => IntroKey,
            sign_seed => Seed,
            sign_pub => SignPub
        },
    {ok, Listener} = i2p_ssu2_listener:listen(Host, 0, Base, self()),
    Port = i2p_ssu2_listener:port(Listener),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(Host, Port, Pub, IntroKey),
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        Seed
    ),
    Local =
        Base#{
            hash => i2p_router_info:hash(RI),
            ri => RI,
            ri_binary => maps:get(binary, RI)
        },
    {Listener, Port, Local}.

charlie_local() ->
    #{ri := RI} = Local = peer_local(),
    {Local, RI}.

%% Like `peer_local/0`, but the published SSU2 address advertises `Port` —
%% so a selection fixture can point a candidate at a dead endpoint.
charlie_local_on(Port) ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, Port, Pub, IntroKey),
    RI = i2p_router_info:build(
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
