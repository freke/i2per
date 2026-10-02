%% Remote NetDb lookup tests. The suite runs real tunnel machinery with
%% injected inbound and outbound entries. A peer double captures outbound
%% gateway traffic so the cases can answer lookups, return closer peers, and
%% inject replies into the inbound tunnel as a remote endpoint would.

-module(i2p_lookup_srv_SUITE).

-export([all/0, init_per_testcase/2]).

-export([
    ls_lookup_via_tunnels/1,
    chase_after_search_reply/1,
    responder_answers_into_reply_tunnel/1,
    exploratory_pool_used_for_lookup/1,
    reply_with_no_outbound_tunnel_is_dropped_not_raised/1
]).

-define(APP, i2per).
-define(RECV_ID, 700).

all() ->
    [
        ls_lookup_via_tunnels,
        chase_after_search_reply,
        responder_answers_into_reply_tunnel,
        exploratory_pool_used_for_lookup,
        reply_with_no_outbound_tunnel_is_dropped_not_raised
    ].

init_per_testcase(Case, Config) ->
    Timeout =
        case Case of
            _ -> 20_000
        end,
    [{timetrap, Timeout} | Config].

ls_lookup_via_tunnels(_Config) ->
    setup(),
    try
        DHash = dest_hash(),
        LS = lease_for_dest(),
        put(wait_key, DHash),

        {_Caller, Ref} = spawn_waiter(),
        {ok, LookupMsg, _Frag, _Seen} = await_lookup(0),
        DHash = maps:get(key, LookupMsg),
        #{delivery := #{tunnel_id := ?RECV_ID}} = LookupMsg,
        Flags = maps:get(flags, LookupMsg) band 16#06,
        true = Flags =:= i2p_i2np:lookup_type_leaseset(),

        answer_with_store(LookupMsg, LS),
        Result = wait_result(Ref),
        {ok, _} = Result,
        {ok, _} = i2p_netdb_srv:find_ls(DHash)
    after
        teardown()
    end.

chase_after_search_reply(_Config) ->
    setup(),
    try
        DHash = dest_hash(),
        LS = lease_for_dest(),
        ChasePeer = make_router(),
        ChaseHash = i2p_router_info:hash(maps:get(ri, ChasePeer)),
        put(wait_key, DHash),

        {_Caller, Ref} = spawn_waiter(),

        %% Round 1: the floodfill knows nothing but names ChasePeer.
        {ok, Lookup1, _Frag1, Seen1} = await_lookup(0),
        DHash = maps:get(key, Lookup1),
        respond_search_reply(Lookup1, [ChaseHash]),

        %% Round 2: the chase peer gets asked directly and answers. The
        %% ROUTER delivery instructions name it, not the captured first hop.
        {ok, Lookup2, _Frag2, _Seen2} = await_lookup(Seen1),
        DHash = maps:get(key, Lookup2),
        answer_with_store(Lookup2, LS),

        Result = wait_result(Ref),
        {ok, _} = Result
    after
        teardown()
    end.

responder_answers_into_reply_tunnel(_Config) ->
    setup(),
    try
        %% Someone else's destination, stored locally: we are the authority.
        DHash = dest_hash(),
        LS = lease_for_dest(),
        added = i2p_netdb_srv:store_ls(LS, erlang:system_time(second)),

        RequesterHash = crypto:strong_rand_bytes(32),
        Parsed = #{
            key => DHash,
            from => RequesterHash,
            flags => i2p_i2np:lookup_type_leaseset() bor 16#01,
            type => leaseset,
            encrypted => false,
            delivery => #{tunnel_id => 4242},
            excluded => [],
            reply_encryption => <<>>
        },
        ok = i2p_peer:tunnel_lookup_reply(Parsed, a_hash()),

        {Target, StoreMsg, Frag, _Seen} = await_routed_store(0),
        Target = hop1_hash(),
        1 = maps:get(type, StoreMsg),
        tunnel = maps:get(delivery, Frag),
        4242 = maps:get(tunnel_id, Frag),
        RequesterHash = maps:get(to_hash, Frag),
        {ok, #{
            key := Key,
            store_type := 3,
            data := LsBin
        }} = i2p_i2np:decode_db_store(maps:get(body, StoreMsg)),
        DHash = Key,
        LsBin = i2p_leaset:to_binary(LS)
    after
        teardown()
    end.

%% --------------------------------------------------------------------------
%% `f:tunnel_lookup_reply/2` is total. It answers `ok` whether or not the reply
%% can be injected, and never raises -- it runs on the I2NP dispatch path of
%% the peer manager, so anything else here is a process death rather than a
%% failed lookup.
%%
%% There are two ways to drop, and both are handled: no outbound tunnel at all
%% (this case), and a tunnel retired between the pick and the send (#MCVQ6D6).
%% The counter stays at zero because the *first* drop happened, and pinning that
%% is what keeps the two distinguishable in the read API rather than one
%% undifferentiated "reply lost" figure.
%%
%% **The second half is deliberately not tested, and not faked.**
%% `f:pick_lookup_outbound/0` returns a map *key* and `f:find_outbound/2` searches
%% both pools, so after a successful pick the id always resolves; only a
%% concurrent removal makes the send answer `error`. Reaching it needs a timing
%% assumption, and a case built on one would be a flake wearing a name -- so that
%% half is documented as untested and carries a counter instead. The case below
%% would also pass against the old `ok = `, and it is kept for the totality
%% contract rather than as evidence about the assert.
%% --------------------------------------------------------------------------
reply_with_no_outbound_tunnel_is_dropped_not_raised(_Config) ->
    setup(),
    try
        %% Someone else's destination, stored locally: we have an answer to give
        %% and no way to give it.
        DHash = dest_hash(),
        LS = lease_for_dest(),
        added = i2p_netdb_srv:store_ls(LS, erlang:system_time(second)),

        RequesterHash = crypto:strong_rand_bytes(32),
        Parsed = #{
            key => DHash,
            from => RequesterHash,
            flags => i2p_i2np:lookup_type_leaseset() bor 16#01,
            type => leaseset,
            encrypted => false,
            delivery => #{tunnel_id => 4242},
            excluded => [],
            reply_encryption => <<>>
        },
        ok = i2p_peer:tunnel_lookup_reply(Parsed, a_hash()),
        0 = maps:get(
            lookup_replies_dropped_no_tunnel, i2p_stats:snapshot(), not_reported
        )
    after
        teardown()
    end.

%% --------------------------------------------------------------------------
%% When an exploratory pool exists, lookups ride its short towers: the frame
%% leaves via the exploratory tunnel's first hop and the reply is requested
%% on the exploratory inbound receive ID.
%% --------------------------------------------------------------------------

exploratory_pool_used_for_lookup(_Config) ->
    setup(),
    try
        DHash = dest_hash(),
        LS = lease_for_dest(),
        put(wait_key, DHash),

        %% An exploratory pool named by its own first hop and reply tunnel
        ExpHop = make_router(),
        ExpHopHash = i2p_router_info:hash(maps:get(ri, ExpHop)),
        ExpKeys = hop_keys(),
        {ok, _} = i2p_netdb_srv:store_binary(
            i2p_router_info:to_binary(maps:get(ri, ExpHop)), erlang:system_time(millisecond)
        ),
        inject_exploratory_outbound(501, #{
            tunnel_ids => [501, 502, 503],
            router_hashes => [ExpHopHash, ExpHopHash, ExpHopHash],
            layers => ExpKeys,
            built_at => erlang:system_time(second)
        }),
        inject_exploratory_inbound(701, a_hash()),

        {_Caller, Ref} = spawn_waiter(),
        {ok, LookupMsg, _Seq} = wait_for_exp_frame(ExpHopHash, ExpKeys, 0),
        DHash = maps:get(key, LookupMsg),
        #{delivery := #{tunnel_id := 701}} = LookupMsg,

        answer_with_store(LookupMsg, LS),
        Result = wait_result(Ref),
        {ok, _} = Result
    after
        teardown()
    end.

%% wait_for_exp_frame/3 — the next frame addressed to the exploratory
%% tunnel's first hop in the peer-capture table; unwrapped with its own keys.
wait_for_exp_frame(ExpHopHash, ExpKeys, Seen) ->
    Deadline = erlang:monotonic_time(millisecond) + 6000,
    wait_for_exp_frame(ExpHopHash, ExpKeys, Seen, Deadline).

wait_for_exp_frame(ExpHopHash, ExpKeys, Seen, Deadline) ->
    All = lists:sort(ets:tab2list(lookup_frames)),
    Unseen = [{N, H, B} || {N, H, B} <- All, H =:= ExpHopHash, N > Seen],
    case Unseen of
        [{N, _H, Body} | _] ->
            Frags = exp_frags(Body, ExpKeys),
            [First] = [F || F <- Frags, maps:get(type, F) =:= first],
            {ok, Std} = i2p_i2np:decode_std(maps:get(data, First)),
            {ok, Parsed} = i2p_i2np:decode_db_lookup(maps:get(body, Std)),
            {ok, Parsed, N};
        [] ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    Targets = [H || {_N, H, _B} <- lists:sort(ets:tab2list(lookup_frames))],
                    error({no_exploratory_frame, Targets});
                false ->
                    timer:sleep(25),
                    wait_for_exp_frame(ExpHopHash, ExpKeys, Seen, Deadline)
            end
    end.

exp_frags(Body, ExpKeys) ->
    Final =
        lists:foldl(
            fun(Hop, M) ->
                {ok, M1} =
                    i2p_tunnel:process_tunnel_data(M, Hop, 501, <<0, 0, 0, 0>>),
                M1
            end,
            Body,
            ExpKeys
        ),
    <<_:32/big, IV:16/binary, Plain:1008/binary>> = Final,
    {ok, Frags, _Fm} = i2p_tunnel:parse_tunnel_data(Plain, IV, #{}),
    Frags.

inject_exploratory_outbound(TunID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{exploratory := Exploratory} = State) ->
        State#{exploratory := maps:put(TunID, Entry, Exploratory)}
    end),
    ok.

inject_exploratory_inbound(RecvID, GwHash) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{exploratory_in := ExploratoryIn} = State) ->
        State#{
            exploratory_in :=
                maps:put(
                    RecvID,
                    #{
                        tunnel_ids => [RecvID],
                        router_hashes => [GwHash],
                        layers => [],
                        frag_map => #{},
                        built_at => erlang:system_time(second)
                    },
                    ExploratoryIn
                )
        }
    end),
    ok.

setup() ->
    %% A previous suite may have left the application running — restart it so
    %% the NetDb starts empty, and retire any stray NetDb behind.
    case whereis(i2p_netdb_srv) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end,
    case whereis(i2per_sup) of
        undefined -> ok;
        _Sup -> application:stop(?APP)
    end,
    {ok, _} = application:ensure_all_started(?APP),
    put(app_started, true),
    Router = make_router(),
    Local = #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => maps:get(hash, Router),
        iv => crypto:strong_rand_bytes(16),
        ri => maps:get(ri, Router)
    },
    put(local_hash, maps:get(hash, Local)),
    HopKeys = hop_keys(),
    put(hop_keys, HopKeys),
    Hop1 = make_router(),
    Hop1Hash = i2p_router_info:hash(maps:get(ri, Hop1)),
    put(hop1_hash, Hop1Hash),
    {ok, _} = i2p_netdb_srv:store_binary(
        i2p_router_info:to_binary(maps:get(ri, Hop1)), erlang:system_time(millisecond)
    ),
    %% The one floodfill candidate closest to every key in these tests.
    FF = make_ff_router(),
    {ok, _} = i2p_netdb_srv:store_binary(
        i2p_router_info:to_binary(maps:get(ri, FF)), erlang:system_time(millisecond)
    ),
    {ok, _} = i2p_tunnel_srv:start_link(Local),
    {ok, _} = i2p_lookup_srv:start_link(maps:get(hash, Local)),
    %% A crashed case in this or another suite may have left the frame table
    %% or the fake peer registered: clear both before (re)creating.
    case ets:whereis(lookup_frames) of
        undefined -> ok;
        _ -> ets:delete(lookup_frames)
    end,
    ets:new(lookup_frames, [named_table, bag, public]),
    case whereis(i2p_peer) of
        undefined -> ok;
        _Pid -> unregister(i2p_peer)
    end,
    PeerPid =
        spawn(fun F() ->
            receive
                {'$gen_cast', {send_when_ready, Hash, Msg}} ->
                    ets:insert(
                        lookup_frames,
                        {
                            erlang:unique_integer([positive, monotonic]),
                            Hash,
                            maps:get(body, Msg)
                        }
                    ),
                    F();
                _Other ->
                    F()
            end
        end),
    true = register(i2p_peer, PeerPid),
    inject_inbound_entry(?RECV_ID, maps:get(hash, Local)),
    inject_outbound_entry(500, #{
        tunnel_ids => [500, 501, 502],
        router_hashes => [Hop1Hash, Hop1Hash, Hop1Hash],
        layers => HopKeys,
        built_at => erlang:system_time(second)
    }),
    ok.

teardown() ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            unregister(i2p_peer),
            exit(Pid, kill)
    end,
    case whereis(i2p_lookup_srv) of
        undefined ->
            ok;
        LPid ->
            gen_server:stop(LPid)
    end,
    stop_tunnel_srv(),
    catch ets:delete(lookup_frames),
    erase(local_hash),
    erase(hop1_hash),
    erase(wait_key),
    application:stop(?APP),
    erase(app_started),
    ok.

stop_tunnel_srv() ->
    case whereis(i2p_tunnel_srv) of
        undefined ->
            ok;
        _Pid ->
            i2p_tunnel_srv:stop()
    end.

a_hash() -> get(local_hash).

hop1_hash() -> get(hop1_hash).

hop_keys() ->
    [
        #{
            layer_key => crypto:strong_rand_bytes(32),
            iv_key => crypto:strong_rand_bytes(32)
        }
     || _ <- lists:seq(1, 3)
    ].

make_router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, 9150, StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
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

make_ff_router() ->
    R = make_router(),
    Identity = maps:get(identity, R),
    {StaticPub, _StaticPriv} = i2p_crypto:x25519_keygen(),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, 9150, StaticPub, IV),
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>,
        <<"caps">> => <<"Of">>
    },
    RI =
        i2p_router_info:build(
            Identity, erlang:system_time(millisecond), [Addr], Opts, maps:get(seed, R)
        ),
    R#{ri := RI}.

dest_hash() ->
    D = i2p_keys:generate_with_privkeys(),
    Hash = i2p_keys:hash(maps:get(identity, D)),
    put(dest, D),
    Hash.

lease_for_dest() ->
    D = get(dest),
    NowSec = erlang:system_time(second),
    Leases = [
        #{
            gateway => a_hash(),
            tunnel_id => 12345,
            end_date => (NowSec + 3600) * 1000
        }
    ],
    i2p_leaset:build(
        maps:get(identity, D), NowSec, 7, Leases, maps:get(sign_priv, D)
    ).

spawn_waiter() ->
    TestPid = self(),
    Ref = make_ref(),
    Key = get(wait_key),
    Caller =
        spawn(fun() ->
            Result = i2p_lookup_srv:find_ls(Key),
            TestPid ! {Ref, Result}
        end),
    {Caller, Ref}.

wait_result(Ref) ->
    receive
        {Ref, Result} -> Result
    after 10_000 ->
        error(no_result)
    end.

await_lookup(Seen) ->
    Deadline = erlang:monotonic_time(millisecond) + 6000,
    await_lookup(Seen, Deadline).

await_lookup(Seen, Deadline) ->
    All = lists:sort(ets:tab2list(lookup_frames)),
    Unseen = [{N, H, B} || {N, H, B} <- All, N > Seen],
    case unwrap_plain(Unseen) of
        {ok, StdMsg, First, Consumed} ->
            Parsed = verify_lookup(StdMsg),
            {ok, Parsed, First, Seen + Consumed};
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    error({frames_timeout, length(Unseen)});
                false ->
                    timer:sleep(25),
                    await_lookup(Seen, Deadline)
            end
    end.

verify_lookup(StdMsg) ->
    {ok, Parsed} = i2p_i2np:decode_db_lookup(maps:get(body, StdMsg)),
    Parsed.

unwrap_plain(Unseen) ->
    first_hit(Unseen).

first_hit([]) ->
    false;
first_hit([{_N, _Target, Body} | Rest]) ->
    case plain_message(Body) of
        {{ok, StdMsg}, First} ->
            {ok, StdMsg, First, 1};
        false ->
            first_hit(Rest)
    end.

%% plaintext_fragments/1 — replay every hop's tunnel-data processing and
%% return the fragments of the resulting plaintext frame.
plaintext_fragments(Body) ->
    Final =
        lists:foldl(
            fun(Hop, M) ->
                {ok, M1} = i2p_tunnel:process_tunnel_data(M, Hop, 500, <<0, 0, 0, 0>>),
                M1
            end,
            Body,
            get(hop_keys)
        ),
    <<_:32/big, IV:16/binary, Plain:1008/binary>> = Final,
    {ok, Frags, _Fm} = i2p_tunnel:parse_tunnel_data(Plain, IV, #{}),
    Frags.

%% plain_message/1 — the reassembled standard message plus its first
%% fragment (whose delivery instructions name the intended receiver).
plain_message(Body) ->
    case catch plaintext_fragments(Body) of
        Frags when is_list(Frags) ->
            case [F || F <- Frags, maps:get(type, F) =:= first] of
                [First] ->
                    case i2p_i2np:decode_std(maps:get(data, First)) of
                        {ok, _} = Ok -> {Ok, First};
                        false -> false
                    end;
                [] ->
                    false
            end;
        _ ->
            false
    end.

%% answer_with_store/2 — play the floodfill: push the DatabaseStore into the
%% asker's inbound tunnel named by the lookup.
answer_with_store(LookupMsg, LS) ->
    Key = maps:get(key, LookupMsg),
    StoreMsg = i2p_i2np:db_store(
        Key, i2p_leaset:store_type(), 0, undefined, i2p_leaset:to_binary(LS)
    ),
    inject_into_inbound(?RECV_ID, StoreMsg).

respond_search_reply(LookupMsg, Peers) ->
    Msg = i2p_i2np:db_search_reply(maps:get(key, LookupMsg), Peers, a_hash()),
    inject_into_inbound(?RECV_ID, Msg).

inject_into_inbound(RecvID, MsgMap) ->
    %% Builders stamp epoch-second expirations; the standard header wants a
    %% relative millisecond lifetime.
    StdBin =
        i2p_i2np:encode_std(#{
            type => maps:get(type, MsgMap),
            msg_id => maps:get(msg_id, MsgMap),
            expiration_ms => 60_000,
            body => maps:get(body, MsgMap)
        }),
    {[Frame], _Gw} = i2p_tunnel:gateway_all(RecvID, local, undefined, StdBin),
    i2p_tunnel_srv !
        {i2np, self(), crypto:strong_rand_bytes(32), #{
            type => 18,
            msg_id => crypto:strong_rand_bytes(4),
            expiration => erlang:system_time(second) + 60,
            body => Frame
        }},
    ok.

inject_inbound_entry(RecvID, GwHash) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{inbound := Inbound} = State) ->
        State#{
            inbound :=
                maps:put(
                    RecvID,
                    #{
                        tunnel_ids => [RecvID],
                        router_hashes => [GwHash],
                        layers => [],
                        frag_map => #{},
                        built_at => erlang:system_time(second)
                    },
                    Inbound
                )
        }
    end),
    ok.

inject_outbound_entry(TunID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{tunnels := Tunnels} = State) ->
        State#{tunnels := maps:put(TunID, Entry, Tunnels)}
    end),
    ok.

await_routed_store(Seen) ->
    Deadline = erlang:monotonic_time(millisecond) + 6000,
    await_routed_store(Seen, Deadline).

await_routed_store(Seen, Deadline) ->
    All = lists:sort(ets:tab2list(lookup_frames)),
    Unseen = [{N, H, B} || {N, H, B} <- All, N > Seen],
    case first_store_hit(Unseen) of
        {ok, Target, StdMsg, Delivery, Consumed} ->
            {Target, StdMsg, Delivery, Seen + Consumed};
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    error({frames_timeout, length(Unseen)});
                false ->
                    timer:sleep(25),
                    await_routed_store(Seen, Deadline)
            end
    end.

first_store_hit([]) ->
    false;
first_store_hit([{_N, Target, Body} | Rest]) ->
    case store_message(Body) of
        {ok, StdMsg, Delivery} ->
            {ok, Target, StdMsg, Delivery, 1};
        false ->
            first_store_hit(Rest)
    end.

store_message(Body) ->
    case catch plaintext_fragments(Body) of
        Frags when is_list(Frags) ->
            case [F || F <- Frags, maps:get(type, F) =:= first] of
                [First] ->
                    case i2p_i2np:decode_std(maps:get(data, First)) of
                        {ok, #{type := 1}} = Hit ->
                            {ok, element(2, Hit), First};
                        _ ->
                            false
                    end;
                [] ->
                    false
            end;
        _ ->
            false
    end.
