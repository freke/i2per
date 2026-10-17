%% Peer discovery and NetDb-answer tests. Each case owns its process, mailbox,
%% peer manager, and listeners. The wire assertions cover exploratory fills,
%% inbound answers, DeliveryStatus acknowledgements, LeaseSet2 storage and
%% lookup, and floodfill publication.
%%
%% Every receive drains non-matching mail through
%% `i2p_ct_helpers:wait_msg/2`, and peer-status polls use deadline-based
%% `i2p_ct_helpers:await/2`. Listeners bind at port 0 and close in `after`
%% blocks, so no state leaks into the next case.

-module(i2p_peer_discovery_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    discovery_fills_netdb/1,
    answers_inbound_lookup/1,
    delivery_status_replies/1,
    ls2_store_and_lookup/1,
    floodfill_publish/1
]).

-define(APP, i2per).
-define(TIMEOUT, 10000).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        discovery_fills_netdb,
        answers_inbound_lookup,
        delivery_status_replies,
        ls2_store_and_lookup,
        floodfill_publish
    ].

%% The cases need the full app (NetDb service included) and nothing else; the
%% peer manager is started per case by `start_peer/2`. App stop in
%% end_per_testcase leaves a clean envelope for the next case.
init_per_testcase(_Case, Config) ->
    ok = application:set_env(?APP, live_network, true),
    {ok, _} = application:ensure_all_started(?APP),
    Config.

end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    ok = application:unset_env(?APP, live_network),
    ok.

%% --------------------------------------------------------------------------
%% Discovery: exploratory lookup -> search reply -> RouterInfo fetches fill
%% the local NetDb without turning every learned router into a dial.
%% --------------------------------------------------------------------------

discovery_fills_netdb(_Config) ->
    {A, B, C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    {ok, LC} = i2p_ntcp2_listener:listen(0, C, self()),
    try
        BRI = ri_at(listen_port(LB), B),
        CRI = ri_at(listen_port(LC), C),
        BHash = i2p_router_info:hash(BRI),
        CHash = i2p_router_info:hash(CRI),
        AHash = maps:get(hash, A),
        start_peer(A, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        %% B (the test) accepts A's connection; A's first frame is the pending
        %% exploratory lookup, followed by its self-announcement.
        {CB, {lookup, Exploratory}} = await_frame(),
        #{type := exploratory, key := AHash, from := AHash} = Exploratory,
        {store, _} = recv_db_store(CB),
        %% B replies with a search reply naming itself and C.
        send_db_search_reply(CB, BHash, [BHash, CHash], BHash),
        %% A asks for both RouterInfos over the same connection.
        #{type := routerinfo, key := BHash} = recv_db_lookup(CB),
        send_db_store(CB, BRI),
        #{type := routerinfo, key := CHash} = recv_db_lookup(CB),
        send_db_store(CB, CRI),
        %% A stores both, but a newly learned RouterInfo is not an implicit
        %% dial request. Discovery chooses peers explicitly and remains bounded.
        false = maps:is_key(CHash, i2p_peer:status()),
        await_stored(BHash),
        await_stored(CHash),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB),
        i2p_ntcp2_listener:stop(LC)
    end.

%% --------------------------------------------------------------------------
%% Answering inbound lookups: a RouterInfo we hold is returned as a
%% DatabaseStore; an unknown key gets a DatabaseSearchReply.
%% --------------------------------------------------------------------------

answers_inbound_lookup(_Config) ->
    {A, B, C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        BRI = ri_at(listen_port(LB), B),
        CRI = ri_at(4668, C),
        BHash = i2p_router_info:hash(BRI),
        CHash = i2p_router_info:hash(CRI),
        start_peer(A, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        {CB, {lookup, Exploratory}} = await_frame(),
        #{type := exploratory} = Exploratory,
        {store, _} = recv_db_store(CB),
        NowMs = erlang:system_time(millisecond),
        {ok, _} = i2p_netdb_srv:store_binary(i2p_router_info:to_binary(CRI), NowMs),
        send_db_lookup(CB, CHash, routerinfo, BHash),
        {store, StoredRI} = recv_db_store(CB),
        CHash = i2p_router_info:hash(StoredRI),
        Unknown = crypto:strong_rand_bytes(32),
        send_db_lookup(CB, Unknown, routerinfo, BHash),
        #{key := Unknown, peers := _} = recv_db_search_reply(CB),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB)
    end.

%% --------------------------------------------------------------------------
%% DeliveryStatus: a DatabaseStore with a nonzero reply token gets an
%% acknowledgement (direct reply, tunnel 0, same connection); the 0xFFFFFFFF
%% "ignore" token suppresses it.
%% --------------------------------------------------------------------------

delivery_status_replies(_Config) ->
    {A, B, _C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        BRI = ri_at(listen_port(LB), B),
        BHash = i2p_router_info:hash(BRI),
        start_peer(A, [BRI]),
        ok = i2p_peer:lookup(BHash, routerinfo),
        {CB, {lookup, #{type := routerinfo}}} = await_frame(),
        {store, _} = recv_db_store(CB),
        %% A DatabaseStore of B's RouterInfo asking for a DeliveryStatus back to B
        %% (the direct-reply gateway is the sender's hash).
        Data = i2p_i2np:router_info_data(i2p_router_info:to_binary(BRI)),
        AckedMsgID = <<16#DEADBEEF:32/big>>,
        StoreBody =
            <<BHash/binary, 0:8, 4242:32/big, 0:32/big, BHash/binary, Data/binary>>,
        StoreMsg = #{
            type => 1,
            msg_id => AckedMsgID,
            expiration => now_ms(),
            body => StoreBody
        },
        send_i2np(CB, StoreMsg),
        %% A must reply with a DeliveryStatus whose message ID is the store's
        %% reply token (4242), not the store's own I2NP message id.
        {delivery_status, AckedReplyToken, _} = db_msg(recv_msg(CB)),
        <<4242:32/big>> = AckedReplyToken,
        %% The 0xFFFFFFFF reply token must not be acknowledged.
        IgnoreBody =
            <<BHash/binary, 0:8, 16#FFFFFFFF:32/big, 0:32/big, BHash/binary, Data/binary>>,
        IgnoreMsg = #{
            type => 1,
            msg_id => <<16#CAFEBABE:32/big>>,
            expiration => now_ms(),
            body => IgnoreBody
        },
        send_i2np(CB, IgnoreMsg),
        %% Negative window: the 0xFFFFFFFF ''ignore'' reply token must NOT be
        %% acknowledged. ''No ack'' cannot be event-driven, so this is a
        %% documented load-safe silence window — 400ms is generous enough that a
        %% load-delayed ack would surface here.
        receive
            {ntcp2_frame, CB, _} ->
                error(ignored_token_was_acked)
        after 400 ->
            ok
        end,
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB)
    end.

%% --------------------------------------------------------------------------
%% LeaseSets: an inbound LeaseSet2 DatabaseStore is stored in the NetDb, and a
%% leaseset lookup is answered with the stored LeaseSet (or a search reply when
%% unknown).
%% --------------------------------------------------------------------------

ls2_store_and_lookup(_Config) ->
    {A, B, _C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        BRI = ri_at(listen_port(LB), B),
        BHash = i2p_router_info:hash(BRI),
        start_peer(A, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        {CB, {lookup, #{type := exploratory}}} = await_frame(),
        {store, _} = recv_db_store(CB),
        %% A LeaseSet2 for a fresh destination, stored into A's NetDb.
        %% end_date is 32-bit on wire; pre-truncate to match the roundtrip.
        {DIdent, DSeed} = dest(),
        DestHash = i2p_keys:hash(DIdent),
        EndMs = (now_ms() + 60 * 1000) band 16#FFFFFFFF,
        Lease = #{gateway => BHash, tunnel_id => 0, end_date => EndMs},
        LS = i2p_leaset:build(DIdent, now_sec(), 7, [Lease], DSeed),
        send_ls_store(CB, DestHash, LS),
        %% Asking A for that LeaseSet must return the exact stored LeaseSet.
        send_db_lookup(CB, DestHash, leaseset, BHash),
        {store, LSReply} = recv_ls_store(CB),
        DestHash = i2p_leaset:hash(LSReply),
        LS = LSReply,
        %% An unknown LeaseSet gets a search reply.
        Unknown = crypto:strong_rand_bytes(32),
        send_db_lookup(CB, Unknown, leaseset, BHash),
        #{key := Unknown, peers := _} = recv_db_search_reply(CB),
        %% A's own outbound leaseset lookup is queued and sent like any other.
        i2p_peer:lookup(BHash, leaseset),
        #{type := leaseset, key := BHash} = recv_db_lookup(CB),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB)
    end.

%% --------------------------------------------------------------------------
%% Floodfill publish: our RouterInfo goes to the 3 closest eligible floodfills
%% with a reply token and a direct reply target; the receiving floodfills
%% acknowledge with DeliveryStatus.
%% --------------------------------------------------------------------------

floodfill_publish(_Config) ->
    {A, B, C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    {ok, LC} = i2p_ntcp2_listener:listen(0, C, self()),
    try
        BRI = ff_ri_at(listen_port(LB), B),
        CRI = ff_ri_at(listen_port(LC), C),
        AHash = maps:get(hash, A),
        BHash = i2p_router_info:hash(BRI),
        CHash = i2p_router_info:hash(CRI),
        NowMs = erlang:system_time(millisecond),
        {ok, _} = i2p_netdb_srv:store_binary(i2p_router_info:to_binary(BRI), NowMs),
        {ok, _} = i2p_netdb_srv:store_binary(i2p_router_info:to_binary(CRI), NowMs),
        start_peer(A, []),
        ok = i2p_peer:publish_floodfills(),
        %% Both floodfills receive our RouterInfo as their first frame, with a
        %% reply token and a direct reply target back to A.
        {CB, StoreMsgB} = await_raw_frame(),
        {CC, StoreMsgC} = await_raw_frame(),
        true = CB =/= CC,
        MsgB = maps:get(msg_id, StoreMsgB),
        MsgC = maps:get(msg_id, StoreMsgC),
        lists:foreach(
            fun(StoreMsg) ->
                1 = maps:get(type, StoreMsg),
                {ok, Store} = i2p_i2np:decode_db_store(maps:get(body, StoreMsg)),
                0 = maps:get(store_type, Store),
                true = maps:get(reply_token, Store) =/= 0,
                true = maps:get(reply_token, Store) =/= 16#FFFFFFFF,
                {0, AHash} = maps:get(reply, Store),
                {ok, RIBytes} = i2p_i2np:parse_router_info_data(maps:get(data, Store)),
                {ok, RI} = i2p_router_info:decode(RIBytes),
                AHash = i2p_router_info:hash(RI)
            end,
            [StoreMsgB, StoreMsgC]
        ),
        %% The floodfills acknowledge; A stays healthy and both stay connected.
        send_i2np(CB, i2p_i2np:delivery_status(MsgB, now_ms())),
        send_i2np(CC, i2p_i2np:delivery_status(MsgC, now_ms())),
        await_peer_status(BHash, connected),
        await_peer_status(CHash, connected),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB),
        i2p_ntcp2_listener:stop(LC)
    end.

%% ---------------------------------------------------------------------------
%% Discovery-suite helpers. Wire receipts use `m:i2p_ct_helpers:wait_msg/2`,
%% and peer-status polls use `m:i2p_ct_helpers:await/2`.
%% ---------------------------------------------------------------------------

%% A router node: identity, static keypair, IV, signing seed.
router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        sign_pub => SignPub,
        iv => IV,
        seed => Seed,
        identity => Identity
    }.

%% The full local-keys map with a signed RouterInfo announcing NTCP2 on Port.
local(#{identity := Identity, static_pub := Pub, iv := IV, seed := Seed} = N, Port) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, now_ms(), [Addr], Opts, Seed),
    N#{sign_seed => Seed, hash => i2p_router_info:hash(RI), ri => RI}.

%% Three distinct router nodes (placeholder port 4668; listeners rebind via
%% ri_at/2 before use).
trio() ->
    {local(router(), 4668), local(router(), 4668), local(router(), 4668)}.

%% Re-sign a router's RouterInfo announcing the actual bound listener port.
ri_at(Port, #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed}) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, now_ms(), [Addr], Opts, Seed).

%% As `f:ri_at/2` but announcing floodfill caps, so `i2p_netdb` treats the
%% router as an eligible floodfill.
ff_ri_at(Port, #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed}) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => <<"Of">>
    },
    i2p_router_info:build(Identity, now_ms(), [Addr], Opts, Seed).

now_ms() ->
    erlang:system_time(millisecond).

%% Stop any previous manager (async, so wait for its death) and start a fresh
%% one linked to the test process.
start_peer(Local, Seeds) ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            i2p_peer:stop(),
            MRef = erlang:monitor(process, Pid),
            receive
                {'DOWN', MRef, process, Pid, _} -> ok
            after 5000 ->
                error(stop_timeout)
            end
    end,
    {ok, _} = i2p_peer:start_link(Local, Seeds),
    ok.

listen_port(Listener) ->
    i2p_ntcp2_listener:port(Listener).

%% Wait for the first data-phase frame (we own the bob-side connection), and
%% return the connection pid together with the decoded database message:
%% `{store, Map}` | `{lookup, Map}` | `{search_reply, Map}` |
%% `{delivery_status, MsgID, TimeMs}`.
await_frame() ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, Conn, Payload}) -> {true, {Conn, db_msg(decode_msg(Payload))}};
            (_) -> false
        end,
        ?TIMEOUT
    ).

%% As `f:await_frame/0` but returns the raw decoded I2NP message (header
%% included) instead of the database-message view.
await_raw_frame() ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, Conn, Payload}) -> {true, {Conn, decode_msg(Payload)}};
            (_) -> false
        end,
        ?TIMEOUT
    ).

decode_msg(Payload) ->
    {ok, Blocks} = i2p_framing:decode_blocks(Payload),
    [#{type := 3, data := Data}] = [B || #{type := 3} = B <- Blocks],
    {ok, Msg} = i2p_i2np:decode(Data),
    Msg.

db_msg(#{type := 1, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_store(Body),
    {store, M};
db_msg(#{type := 2, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_lookup(Body),
    {lookup, M};
db_msg(#{type := 3, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_search_reply(Body),
    {search_reply, M};
db_msg(#{type := 10, body := Body}) ->
    {ok, MsgID, TimeMs} = i2p_i2np:decode_delivery_status(Body),
    {delivery_status, MsgID, TimeMs}.

%% Deadline-bounded poll for the peer manager to reach a status (10s budget);
%% 25ms cadence via `m:i2p_ct_helpers` `await/2`, no fixed-total sleep.
await_peer_status(Hash, Status) ->
    i2p_ct_helpers:await(
        fun() ->
            case i2p_peer:status() of
                #{Hash := #{status := S}} -> S =:= Status;
                _ -> false
            end
        end,
        ?TIMEOUT
    ).

%% Deadline-bounded poll for a RouterInfo to land in the local NetDb (10s
%% budget; 25ms cadence via `m:i2p_ct_helpers` `await/2`, no fixed-total
%% sleep). `send_db_store/2` returns once the conn process has written the
%% frame, but the receiving peer still has to read it off its socket and store
%% it, so a bare `find/1` right afterwards races that read instead of checking
%% the result.
await_stored(Hash) ->
    i2p_ct_helpers:await(
        fun() ->
            case i2p_netdb_srv:find(Hash) of
                {ok, _} -> true;
                not_found -> false
            end
        end,
        ?TIMEOUT
    ).

%% The next I2NP message on Conn, decoded — the receive drains anything that is
%% not a frame from this exact connection.
recv_msg(Conn) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, P, Payload}) when P =:= Conn -> {true, decode_msg(Payload)};
            (_) -> false
        end,
        ?TIMEOUT
    ).

recv_db_lookup(Conn) ->
    #{type := 2, body := Body} = recv_msg(Conn),
    {ok, DbLookup} = i2p_i2np:decode_db_lookup(Body),
    DbLookup.

recv_db_search_reply(Conn) ->
    #{type := 3, body := Body} = recv_msg(Conn),
    {ok, DbSearchReply} = i2p_i2np:decode_db_search_reply(Body),
    DbSearchReply.

recv_db_store(Conn) ->
    #{type := 1, body := Body} = recv_msg(Conn),
    {ok, #{store_type := 0, data := Data}} = i2p_i2np:decode_db_store(Body),
    {ok, RIBytes} = i2p_i2np:parse_router_info_data(Data),
    {ok, RI} = i2p_router_info:decode(RIBytes),
    {store, RI}.

%% A DatabaseStore carrying a LeaseSet2 (store_type 3), decoded.
recv_ls_store(Conn) ->
    #{type := 1, body := Body} = recv_msg(Conn),
    {ok, #{store_type := 3, data := Data}} = i2p_i2np:decode_db_store(Body),
    {ok, LS} = i2p_leaset:decode(Data),
    {store, LS}.

send_i2np(Conn, I2NPMsg) ->
    Block = i2p_framing:encode_block(3, i2p_i2np:encode(I2NPMsg)),
    ok = i2p_ntcp2_conn:send(Conn, Block).

send_db_lookup(Conn, Key, LookupType, From) ->
    Flags = lookup_type_flag(LookupType),
    send_i2np(Conn, i2p_i2np:db_lookup(Key, From, Flags, [])).
send_db_search_reply(Conn, Key, Peers, From) ->
    send_i2np(Conn, i2p_i2np:db_search_reply(Key, Peers, From)).

send_db_store(Conn, RI) ->
    Hash = i2p_router_info:hash(RI),
    Data = i2p_i2np:router_info_data(i2p_router_info:to_binary(RI)),
    send_i2np(Conn, i2p_i2np:db_store(Hash, 0, 0, undefined, Data)).

send_ls_store(Conn, DestHash, LS) ->
    send_i2np(
        Conn,
        i2p_i2np:db_store(DestHash, i2p_leaset:store_type(), 0, undefined, i2p_leaset:to_binary(LS))
    ).

%% A fresh Destination identity + signing seed for LeaseSet fixtures.
dest() ->
    {StaticPub, _StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    {Identity, Seed}.

now_sec() ->
    erlang:system_time(second).

lookup_type_flag(any) -> i2p_i2np:lookup_type_any();
lookup_type_flag(leaseset) -> i2p_i2np:lookup_type_leaseset();
lookup_type_flag(routerinfo) -> i2p_i2np:lookup_type_routerinfo();
lookup_type_flag(exploratory) -> i2p_i2np:lookup_type_exploratory().
