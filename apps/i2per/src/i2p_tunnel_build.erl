-module(i2p_tunnel_build).

-moduledoc """
Creator-side tunnel construction for `m:i2p_tunnel_srv`: outbound and inbound
ECIES builds, OTBRM processing, and the returning-STB validation that
activates local inbound tunnels.

The functions here are pure state transformers over
`t:i2p_tunnel_srv:tunnel_srv_state/0` — they pick hops from the NetDb,
generate fresh tunnel IDs, encrypt per-record build requests via `m:i2p_ecies`,
wrap them in garlic via `m:i2p_garlic`, and send the STB (type 25) to the
first hop through `m:i2p_peer`. Replies are matched by I2NP message ID and
peeled via `m:i2p_tunnel:process_otbrm/2`; an all-zero ret-code set activates
the tunnel.

## Usage

These functions are called by the `m:i2p_tunnel_srv` GenServer and its
`m:i2p_tunnel_relay` / `m:i2p_tunnel_publish` helpers, not directly by user
code:

```erlang
%% Queue an outbound 3-hop build from a handle_cast clause
State1 = i2p_tunnel_build:do_build_outbound(State),

%% Queue an inbound build of exactly 2 remote hops
State2 = i2p_tunnel_build:do_build_inbound(State1, 2),

%% Queue an exploratory 2-hop outbound build for the lookup pool.
State3 = i2p_tunnel_build:do_build_outbound(State2, 2, exploratory),

%% An OTBRM arrived over the wire: match it against pending builds
State4 = i2p_tunnel_build:handle_otbrm(Msg, State3).
```

The `pool` tag (`client` or `exploratory`) travels with every build: the
pool tick routes `client` tunnels into the regular `tunnels` / `inbound`
maps used by client traffic, while `exploratory` tunnels land in the
`exploratory` / `exploratory_in` maps used for NetDb lookups. All
public entry points default to the `client` pool, so manual builds and
existing callers are unaffected.
""".

-export([
    do_build_outbound/1,
    do_build_outbound/2,
    do_build_outbound/3,
    do_build_inbound/1,
    do_build_inbound/2,
    do_build_inbound/3,
    handle_otbrm/2,
    handle_returned_stb/2,
    generate_tunnel_id_base/0
]).

-export_type([pool/0]).

-define(BUILD_TIMEOUT_MS, 30000).
-define(NUM_HOPS, 3).
-define(MAX_TUNNEL_ID, 16#FFFFFFFF).
%% Client LeaseSet publication: leases die with their tunnel; republish
%% this many seconds before lease end so lookups never see a gap.
-define(REPLY_RET_OFFSET, 201).
%% How many additional distance-closest candidates to fetch beyond the `Len`
%% hops required, so a repeatedly unreliable peer can be replaced by a
%% slightly farther reliable one without starving the build.
-define(SELECT_MARGIN, 8).

-doc "Which tunnel pool a build belongs to: the client pool or the exploratory lookup pool.".
-type pool() :: client | exploratory.

%%%%%%% %%% Public API %%%%%%%

-spec do_build_outbound(i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
do_build_outbound(State) ->
    do_build_outbound(State, ?NUM_HOPS).

-doc """
An outbound build of exactly `Len` remote hops.

Input: `State` — the tunnel manager state; `Len` — the hop count to build.
Output: the updated state; when fewer than `Len` usable routers exist in the
NetDb, or no reply path exists yet, the state passes through unchanged (the
latter triggers an inbound build instead, which the next tick will follow
with an outbound one).
""".
-spec do_build_outbound(i2p_tunnel_srv:tunnel_srv_state(), pos_integer()) ->
    i2p_tunnel_srv:tunnel_srv_state().
do_build_outbound(State, Len) ->
    do_build_outbound(State, Len, client).

-doc """
An outbound build of `Len` remote hops for a specific tunnel pool.

Input: `State` — the tunnel manager state; `Len` — the hop count to build;
`Pool` — `client` (streams, SAM, stores) or `exploratory` (lookup pool).
Output: the updated state with the build tagged `Pool`; it is queued into
the matching pool's pending map and, on success, activates in that pool
(`tunnels` / `exploratory`). Reply paths prefer a tunnel from the same pool
(an exploratory outbound builds an exploratory inbound first when none is
active). Hops are selected from the closest NetDb routers.
`m:i2p_peer_rep` marks unreliable peers as skipped whenever enough reliable
candidates remain.
""".
-spec do_build_outbound(i2p_tunnel_srv:tunnel_srv_state(), pos_integer(), pool()) ->
    i2p_tunnel_srv:tunnel_srv_state().
do_build_outbound(#{local := Local, next_tunnel_id := Base} = State, Len, Pool) ->
    OurHash = maps:get(hash, Local),
    %% Pick `Len` hops from the NetDb, excluding our own hash, skipping peers
    %% the reliability store calls out (when reliable alternatives exist).
    HopHashes = select_hops(OurHash, Len),
    case length(HopHashes) >= Len of
        false ->
            %% Not enough hops in NetDb yet; silently skip
            State;
        true ->
            case pick_reply_path(State, Pool) of
                error ->
                    %% No inbound tunnel to receive the reply on yet; build
                    %% one first and retry outbound on a later round.
                    do_build_inbound(State, Len, Pool);
                {ok, ReplyPath} ->
                    SelectedHashes = lists:sublist(HopHashes, Len),
                    do_build_outbound(SelectedHashes, Base, ReplyPath, State, Len, Pool)
            end
    end.

-doc """
Initiate an inbound tunnel build of the default hop count (`f:do_build_inbound/2`
with the configured default).

Input: `State` — the tunnel manager state.
Output: the updated state with a new pending inbound build, or unchanged when
the NetDb cannot supply enough hops yet.
""".
-spec do_build_inbound(i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
do_build_inbound(State) ->
    do_build_inbound(State, ?NUM_HOPS).

-doc """
An inbound tunnel of exactly `Len` remote hops (we are the endpoint).

Input: `State` — the tunnel manager state; `Len` — the hop count to build.
Output: the updated state; the records point back at us so the sealed STB
travels `IBGW → … → us`, and a fourth fake record conceals that the path
terminates at its originator.
""".
-spec do_build_inbound(i2p_tunnel_srv:tunnel_srv_state(), pos_integer()) ->
    i2p_tunnel_srv:tunnel_srv_state().
do_build_inbound(State, Len) ->
    do_build_inbound(State, Len, client).

-doc """
An inbound tunnel of `Len` remote hops for a specific tunnel pool.

Input: `State` — the tunnel manager state; `Len` — the hop count to build;
`Pool` — `client` (streams, SAM, stores) or `exploratory` (lookup pool).
Output: the updated state with the build tagged `Pool`, queued into the
matching pending map and activating in `inbound` / `exploratory_in` on
success. Hops are selected from the closest NetDb routers.
`m:i2p_peer_rep` marks unreliable peers as skipped whenever enough reliable
candidates remain.
""".
-spec do_build_inbound(i2p_tunnel_srv:tunnel_srv_state(), pos_integer(), pool()) ->
    i2p_tunnel_srv:tunnel_srv_state().
do_build_inbound(
    #{local := Local, pending_in := PendingIn, next_tunnel_id := Base} = State, Len, Pool
) ->
    OurHash = maps:get(hash, Local),
    HopHashes = select_hops(OurHash, Len),
    case length(HopHashes) >= Len of
        false ->
            %% Not enough hops in NetDb yet; silently skip
            State;
        true ->
            SelectedHashes = lists:sublist(HopHashes, Len),
            TunnelIds = [Base + I || I <- lists:seq(0, Len)],
            case extract_hop_descs(SelectedHashes) of
                {ok, RealDescs} ->
                    %% RealDescs comes back reversed (farthest hop first, the
                    %% inbound gateway), so the records' next-hop chains must
                    %% follow the same order: IBGW → … → nearest → us.
                    Plaintexts = build_inbound_plaintext_records(
                        TunnelIds, lists:reverse(SelectedHashes), OurHash, Len
                    ),
                    %% Fake record addressed to ourselves: our truncated hash
                    %% prefix with a fresh ephemeral, Noise-N encrypted to our
                    %% own static key so we can validate integrity on return.
                    FakeDesc = #{
                        eph_priv => element(2, i2p_crypto:x25519_keygen()),
                        hop_pub => maps:get(static_pub, Local),
                        id_hash => OurHash
                    },
                    {EncRecords, AllKeys} =
                        i2p_ecies:encrypt_build_records(
                            RealDescs ++ [FakeDesc], Plaintexts, none
                        ),
                    {HopKeys, [_FakeKey]} = lists:split(Len, AllKeys),
                    MsgID = i2p_i2np:fresh_msg_id(),
                    STBMsg = i2p_i2np:short_tunnel_build(EncRecords),
                    #{hop_pub := IbgwPub, id_hash := IbgwHash} = hd(RealDescs),
                    GarlicClove = #{
                        delivery => {router, IbgwHash},
                        type => 25,
                        msg_id => MsgID,
                        expiration => erlang:system_time(millisecond) div 1000 + 60,
                        data => maps:get(body, STBMsg)
                    },
                    GarlicMsg = i2p_garlic:wrap_router([GarlicClove], IbgwPub),
                    i2p_peer:send_when_ready(IbgwHash, GarlicMsg),
                    TimerRef = erlang:send_after(?BUILD_TIMEOUT_MS, self(), {build_timeout, MsgID}),
                    Build = #{
                        tunnel_ids => TunnelIds,
                        router_hashes => lists:reverse(SelectedHashes),
                        hop_keys => HopKeys,
                        timer_ref => TimerRef,
                        pool => Pool
                    },
                    State#{
                        pending_in := maps:put(MsgID, Build, PendingIn),
                        next_tunnel_id := Base + Len + 1
                    };
                error ->
                    State
            end
    end.

-doc """
Process an OutboundTunnelBuildReply (type 26) for one of our pending
outbound builds.

Input: `Msg` — the OTBRM I2NP message; `State` — the manager state.
Output: the state with the pending build removed and, when every hop
accepted, the activated tunnel added. Unmatched message IDs and undecodable
bodies leave the state unchanged.
""".
-spec handle_otbrm(map(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
handle_otbrm(Msg, State) ->
    MsgID = maps:get(msg_id, Msg, undefined),
    #{pending := Pending} = State,
    case maps:find(MsgID, Pending) of
        error ->
            State;
        {ok, Build} ->
            _ = erlang:cancel_timer(maps:get(timer_ref, Build)),
            State0 = State#{pending := maps:remove(MsgID, Pending)},
            case i2p_i2np:decode_outbound_tunnel_build_reply(maps:get(body, Msg)) of
                {ok, #{records := Records}} ->
                    finish_build(Build, Records, State0);
                error ->
                    State0
            end
    end.

-doc """
Validate our own returning ShortTunnelBuild: an inbound build's modified
type-25 message has come back over the wire.

Input: `Msg` — the returned STB I2NP message; `State` — the manager state.
Output: the state with the pending inbound build removed and, when all reply
layers peel cleanly, the activated local inbound tunnel added.
""".
-spec handle_returned_stb(map(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
handle_returned_stb(Msg, State) ->
    MsgID = maps:get(msg_id, Msg),
    #{pending_in := PendingIn} = State,
    {ok, Build} = maps:find(MsgID, PendingIn),
    _ = erlang:cancel_timer(maps:get(timer_ref, Build)),
    State0 = State#{pending_in := maps:remove(MsgID, PendingIn)},
    case i2p_i2np:decode_short_tunnel_build(maps:get(body, Msg)) of
        {ok, #{records := Records}} ->
            finish_inbound(Build, Records, State0);
        error ->
            State0
    end.

-doc "A fresh random 32-bit tunnel-ID base for a new build batch.".
-spec generate_tunnel_id_base() -> non_neg_integer().
generate_tunnel_id_base() ->
    <<Base:32/big>> = crypto:strong_rand_bytes(4),
    Base band ?MAX_TUNNEL_ID.

%%%%%%% %%% Internal %%%%%%%

%% select_hops/2 — distance-ordered hop candidates with unreliable peers
%% skipped when reliable alternatives exist. Fetches a handful more than `Len`
%% closest candidates so an avoided peer can be replaced by a slightly farther
%% reliable one, then tops up from the avoided set when the NetDb cannot
%% supply `Len` reliable hops (a build must never starve over reputation).
%% Without the reliability store running, `f:i2p_peer_rep:avoided/1` answers
%% `false` for everyone and the first `Len` closest are returned, unchanged
%% from distance-only selection.
-spec select_hops(i2p_crypto:hash(), pos_integer()) -> [i2p_crypto:hash()].
select_hops(OurHash, Len) ->
    Candidates = i2p_netdb_srv:closest(OurHash, Len + 1 + ?SELECT_MARGIN) -- [OurHash],
    {Reliable, Avoided} = lists:partition(
        fun(Hash) -> not i2p_peer_rep:avoided(Hash) end,
        Candidates
    ),
    TopUp = lists:sublist(Avoided, max(0, Len - length(Reliable))),
    Reliable ++ TopUp.

%% pick_reply_path/2 — the OBEP sends the OTBRM back through one of our
%% active inbound tunnels; its gateway hop and receive ID name the path.
%% Exploratory builds prefer an exploratory inbound tunnel so the lookup pool
%% stays self-contained, falling back to the client pool only when no
%% exploratory inbound is active.
-spec pick_reply_path(i2p_tunnel_srv:tunnel_srv_state(), pool()) ->
    {ok, {i2p_crypto:hash(), 0..16#FFFFFFFF}} | error.
pick_reply_path(State, Pool) ->
    InboundMap =
        case Pool of
            exploratory ->
                case maps:get(exploratory_in, State, #{}) of
                    M when map_size(M) > 0 ->
                        M;
                    _ ->
                        maps:get(inbound, State, #{})
                end;
            client ->
                maps:get(inbound, State, #{})
        end,
    case map_size(InboundMap) of
        0 ->
            error;
        _ ->
            [Entry | _] = maps:values(InboundMap),
            #{router_hashes := [IbgwHash | _], tunnel_ids := [IbgwRecvID | _]} = Entry,
            {ok, {IbgwHash, IbgwRecvID}}
    end.

-spec do_build_outbound(
    [i2p_crypto:hash()],
    non_neg_integer(),
    {i2p_crypto:hash(), 0..16#FFFFFFFF},
    i2p_tunnel_srv:tunnel_srv_state(),
    pos_integer(),
    pool()
) -> i2p_tunnel_srv:tunnel_srv_state().
do_build_outbound(SelectedHashes, Base, {ReplyHash, ReplyTunID}, State, Len, Pool) ->
    #{pending := Pending} = State,
    TunnelIds = [Base + I || I <- lists:seq(0, Len - 1)],
    case extract_hop_descs(SelectedHashes) of
        {ok, HopDescs} ->
            %% HopDescs comes back reversed (farthest hop first, the outbound
            %% gateway the STB is delivered to), so the records' next-hop
            %% chains must follow the same order: OBGW → … → OBEP.
            Plaintexts = build_plaintext_records(
                TunnelIds, lists:reverse(SelectedHashes), ReplyHash, ReplyTunID, Len
            ),
            ObepPos = Len - 1,
            {EncRecords, CreatorHops} =
                i2p_ecies:encrypt_build_records(HopDescs, Plaintexts, ObepPos),
            MsgID = i2p_i2np:fresh_msg_id(),
            STBMsg = i2p_i2np:short_tunnel_build(EncRecords),
            #{hop_pub := FirstPub, id_hash := FirstHash} = hd(HopDescs),
            GarlicClove = #{
                delivery => {router, FirstHash},
                type => 25,
                msg_id => MsgID,
                expiration => erlang:system_time(millisecond) div 1000 + 60,
                data => maps:get(body, STBMsg)
            },
            GarlicMsg = i2p_garlic:wrap_router([GarlicClove], FirstPub),
            i2p_peer:send_when_ready(FirstHash, GarlicMsg),
            TimerRef = erlang:send_after(?BUILD_TIMEOUT_MS, self(), {build_timeout, MsgID}),
            Build = #{
                tunnel_ids => TunnelIds,
                router_hashes => lists:reverse(SelectedHashes),
                hop_keys => CreatorHops,
                timer_ref => TimerRef,
                pool => Pool
            },
            State#{
                pending := maps:put(MsgID, Build, Pending),
                next_tunnel_id := Base + Len
            };
        error ->
            State
    end.

-spec extract_hop_descs([i2p_crypto:hash()]) -> {ok, [i2p_ecies:hop_desc()]} | error.
extract_hop_descs(Hashes) ->
    lists:foldl(
        fun
            (_Hash, error) ->
                error;
            (Hash, {ok, Acc}) ->
                case i2p_netdb_srv:find(Hash) of
                    {ok, RI} ->
                        Identity = i2p_router_info:identity(RI),
                        HopPub = i2p_keys:public_key(Identity),
                        {_EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
                        {ok, [
                            #{
                                eph_priv => EphPriv,
                                hop_pub => HopPub,
                                id_hash => i2p_router_info:hash(RI)
                            }
                            | Acc
                        ]};
                    not_found ->
                        error
                end
        end,
        {ok, []},
        Hashes
    ).

-spec build_plaintext_records(
    [0..16#FFFFFFFF], [i2p_crypto:hash()], i2p_crypto:hash(), 0..16#FFFFFFFF, pos_integer()
) ->
    [binary()].
build_plaintext_records(TunnelIds, HopHashes, ReplyHash, ReplyTunID, Len) ->
    %% For hop i: RecvID = TunnelIds[i], NextID = TunnelIds[i+1], NextHash = HopHashes[i+1]
    %% Last hop (endpoint): NextID/NextHash name the reply path — the gateway
    %% of one of our active inbound tunnels (java: pairedTunnel peer(0) /
    %% receiveTunnelId(0)).
    lists:map(
        fun({I, {RecvID, _Hash}}) ->
            IsEndpoint = (I =:= Len - 1),
            case IsEndpoint of
                true ->
                    i2p_tunnel:build_request_record(RecvID, ReplyTunID, ReplyHash, #{
                        endpoint => true
                    });
                false ->
                    NextID = lists:nth(I + 2, TunnelIds),
                    NextHash = lists:nth(I + 2, HopHashes),
                    i2p_tunnel:build_request_record(RecvID, NextID, NextHash, #{})
            end
        end,
        lists:zip(lists:seq(0, Len - 1), lists:zip(TunnelIds, HopHashes))
    ).

-spec finish_build(
    i2p_tunnel_srv:pending_build(), [binary()], i2p_tunnel_srv:tunnel_srv_state()
) -> i2p_tunnel_srv:tunnel_srv_state().
finish_build(Build, Records, State) ->
    Pool = maps:get(pool, Build, client),
    {PoolMapKey, PoolMap} = pool_map(State, Pool, outbound),
    HopKeys = maps:get(hop_keys, Build),
    case i2p_tunnel:process_otbrm(Records, HopKeys) of
        {ok, Plains} ->
            Rets = [Ret || <<_:?REPLY_RET_OFFSET/binary, Ret:8>> <- Plains],
            case lists:all(fun(R) -> R =:= 0 end, Rets) of
                true ->
                    Entry = #{
                        tunnel_ids => maps:get(tunnel_ids, Build),
                        router_hashes => maps:get(router_hashes, Build),
                        layers =>
                            [
                                #{layer_key => LK, iv_key => IVK}
                             || #{layer_key := LK, iv_key := IVK} <- HopKeys
                            ],
                        built_at => erlang:system_time(second)
                    },
                    FirstTunID = hd(maps:get(tunnel_ids, Build)),
                    i2p_tunnel_outcome:built(
                        outbound, length(maps:get(router_hashes, Build))
                    ),
                    State#{PoolMapKey := maps:put(FirstTunID, Entry, PoolMap)};
                false ->
                    %% At least one hop rejected or dropped silently; the
                    %% tunnel is unusable — drop the whole build.
                    i2p_tunnel_outcome:failed(outbound, rejected),
                    State
            end;
        error ->
            i2p_tunnel_outcome:failed(outbound, invalid),
            State
    end.

%% build_inbound_plaintext_records/4 — records for an inbound tunnel of
%% `Len` remote hops.
%% Data path is IBGW (farthest) → … → nearest → us; the build travels the
%% same direction as the records' next pointers (toward us), so:
%%   hop 0 (IBGW):  gateway flag set, next = hop 1
%%   middle hops:   next = following hop
%%   last hop:      next = us (the creator), tunnel ID 0 like java's inbound
%%   fake slot:     addressed to us by hash prefix only; contents arbitrary
-spec build_inbound_plaintext_records(
    [0..16#FFFFFFFF], [i2p_crypto:hash()], i2p_crypto:hash(), pos_integer()
) ->
    [binary()].
build_inbound_plaintext_records(TunnelIds, HopHashes, OurHash, Len) ->
    RecvIds = lists:sublist(TunnelIds, Len),
    lists:map(
        fun({I, RecvID}) ->
            Gateway = (I =:= 0),
            IsLast = (I =:= Len - 1),
            case IsLast of
                true ->
                    i2p_tunnel:build_request_record(RecvID, 0, OurHash, #{gateway => Gateway});
                false ->
                    NextID = lists:nth(I + 2, TunnelIds),
                    NextHash = lists:nth(I + 2, HopHashes),
                    Gateway = (I =:= 0),
                    i2p_tunnel:build_request_record(RecvID, NextID, NextHash, #{
                        gateway => Gateway
                    })
            end
        end,
        lists:zip(lists:seq(0, Len - 1), RecvIds)
    ) ++ [crypto:strong_rand_bytes(154)].

%% finish_inbound/3 — validate our returning STB: peel the real slots'
%% surviving relay layers, require all-zero ret codes, and open our fake
%% record (its Noise-N layers cancel pairwise, leaving our ciphertext).
-spec finish_inbound(
    i2p_tunnel_srv:pending_inbound(), [binary()], i2p_tunnel_srv:tunnel_srv_state()
) -> i2p_tunnel_srv:tunnel_srv_state().
finish_inbound(Build, Records, State) ->
    Pool = maps:get(pool, Build, client),
    {PoolMapKey, PoolMap} = pool_map(State, Pool, inbound),
    HopKeys = maps:get(hop_keys, Build),
    #{local := Local} = State,
    NumReal = length(HopKeys),
    case process_inbound_records(Records, NumReal, HopKeys, Local) of
        error ->
            i2p_tunnel_outcome:failed(inbound, invalid),
            State;
        ok ->
            OurRecvID = lists:last(maps:get(tunnel_ids, Build)),
            Entry = #{
                tunnel_ids => maps:get(tunnel_ids, Build),
                router_hashes => maps:get(router_hashes, Build),
                layers =>
                    [
                        #{layer_key => LK, iv_key => IVK}
                     || #{layer_key := LK, iv_key := IVK} <- HopKeys
                    ],
                frag_map => #{},
                built_at => erlang:system_time(second)
            },
            i2p_tunnel_outcome:built(inbound, NumReal),
            State#{PoolMapKey := maps:put(OurRecvID, Entry, PoolMap)}
    end.

%% pool_map/3 — which state map a finished build activates in, tagged by
%% pool and direction: `client` → `tunnels` / `inbound`, `exploratory` →
%% `exploratory` / `exploratory_in`.
-spec pool_map(i2p_tunnel_srv:tunnel_srv_state(), pool(), outbound | inbound) ->
    {atom(), map()}.
pool_map(State, Pool, Direction) ->
    {Key, Map} =
        case {Pool, Direction} of
            {client, outbound} -> {tunnels, maps:get(tunnels, State, #{})};
            {client, inbound} -> {inbound, maps:get(inbound, State, #{})};
            {exploratory, outbound} -> {exploratory, maps:get(exploratory, State, #{})};
            {exploratory, inbound} -> {exploratory_in, maps:get(exploratory_in, State, #{})}
        end,
    {Key, Map}.

%% process_inbound_records/4 — peel + ret-check the real slots and Noise-open
%% the fake record. Any failure invalidates the whole build.
-spec process_inbound_records([binary()], non_neg_integer(), [i2p_ecies:hop_build_keys()], map()) ->
    ok | error.
process_inbound_records(Records, NumReal, _HopKeys, _Local) when
    NumReal > length(Records)
->
    error;
process_inbound_records(Records, NumReal, HopKeys, Local) ->
    {RealRecords, [FakeRecord]} = lists:split(NumReal, Records),
    case i2p_tunnel:process_otbrm(RealRecords, HopKeys) of
        error ->
            error;
        {ok, Plains} ->
            Rets = [Ret || <<_:?REPLY_RET_OFFSET/binary, Ret:8>> <- Plains],
            FakeOk =
                i2p_ecies:decrypt_build_request_record(
                    maps:get(static_priv, Local),
                    maps:get(static_pub, Local),
                    FakeRecord
                ),
            case {lists:all(fun(R) -> R =:= 0 end, Rets), FakeOk} of
                {true, {ok, _, _, _}} -> ok;
                _ -> error
            end
    end.
