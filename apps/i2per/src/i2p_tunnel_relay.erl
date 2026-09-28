-module(i2p_tunnel_relay).

-moduledoc """
Tunnel message routing for `m:i2p_tunnel_srv`: every participant role that
reacts to I2NP traffic arriving over a peer connection or out of an inbound
tunnel.

This module implements the hop-side of ECIES tunnel participation:

- **Dispatch** (`f:handle_routed_i2np/4`) routes an incoming I2NP message by
  type: type 25 (STB) to inbound-build completion (`m:i2p_tunnel_build`) or
  the hop-side processor, type 26 (OTBRM) to the outbound creator path,
  type 18 (TunnelData) to the transit relay or our local inbound endpoint,
  type 19 (TunnelGateway) to the inbound-gateway injector, and type 11
  (garlic) cloves to their handlers.
- **Transit** accepts or rejects build records for other routers' tunnels,
  seals reply codes into the record list, forwards modified STBs onward, and
  relays TunnelData one layer inward.

Participation is rate-limited by two opt-in token buckets configured on the
router (see `m:i2p_config`): `transit_bandwidth_kbps` charges one token per
relayed 1028-byte TunnelData frame, and `tunnel_build_rate` charges one
token per build-record decision. A denied acceptance is sealed as ret 30;
a denied relayed frame is dropped silently. With either key unset the
corresponding work stream is unlimited.
- **Inbound gateway** fragments TunnelGateway payloads into plaintext frames
  and pushes them toward the creator.
- **Local endpoint** unwraps every layer of data arriving on our own inbound
  tunnels, reassembles fragments, and dispatches complete messages locally;
  garlic our router key cannot open is offered to registered SAM sessions as
  end-to-end client payloads.
- **Outbound endpoint** converts sealed records into an OTBRM and delivers it
  down the reply path named in our record (direct router delivery, or
  RGarlic-wrapped into the creator's inbound tunnel).

All functions are pure state transformers over
`t:i2p_tunnel_srv:tunnel_srv_state/0`.

## Usage

Called by `m:i2p_tunnel_srv` and its helpers, not directly by user code:

```erlang
%% An I2NP message arrived from a peer connection
State1 = i2p_tunnel_relay:handle_routed_i2np(ConnPid, PeerHash, Msg, State),

%% Creator injection hands its pre-built frames to the first hop
ok = i2p_tunnel_relay:send_tunnel_data(FirstHopHash, Frame).
```
""".

-export([
    handle_routed_i2np/4,
    send_tunnel_data/2
]).

-define(DEFAULT_MAX_TRANSIT, 1000).
-define(REPLY_RET_OFFSET, 201).
-define(TRANSIT_FRAME_BYTES, 1028).

%%%%%%% %%% Public API %%%%%%%

-doc """
Dispatch an I2NP message forwarded by `m:i2p_peer`.

Input: `ConnPid` — the NTCP2 connection that delivered it; `PeerHash` — the
sending router; `Msg` — the decoded short-header I2NP message; `State` — the
tunnel manager state.
Output: the updated state after the type-appropriate handler ran; unknown
types pass through unchanged.
""".
-spec handle_routed_i2np(pid(), i2p_crypto:hash(), map(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
handle_routed_i2np(_ConnPid, _PeerHash, #{type := 25, msg_id := MsgID} = Msg, State) when
    is_map_key(MsgID, map_get(pending_in, State))
->
    i2p_tunnel_build:handle_returned_stb(Msg, State);
handle_routed_i2np(_ConnPid, _PeerHash, #{type := 25} = Msg, State) ->
    handle_stb(Msg, State);
handle_routed_i2np(_ConnPid, _PeerHash, #{type := 26} = Msg, State) ->
    i2p_tunnel_build:handle_otbrm(Msg, State);
handle_routed_i2np(_ConnPid, _PeerHash, #{type := 18} = Msg, State) ->
    handle_tunnel_data(Msg, State);
handle_routed_i2np(_ConnPid, _PeerHash, #{type := 19} = Msg, State) ->
    handle_tunnel_gateway(Msg, State);
handle_routed_i2np(ConnPid, PeerHash, #{type := 11, body := GarlicBody}, State) ->
    case unwrap_garlic_cloves(GarlicBody, State) of
        {ok, Cloves, State1} ->
            dispatch_garlic_cloves(ConnPid, PeerHash, Cloves, State1);
        error ->
            %% Direct-delivery garlic we cannot open may still be an
            %% end-to-end client payload addressed to a SAM destination.
            try_stream_delivery(GarlicBody),
            State
    end;
handle_routed_i2np(_ConnPid, _PeerHash, _Msg, State) ->
    State.

-doc """
Send one encrypted TunnelData frame to a router.

Input: `NextHash` — the next hop's RouterIdentity hash; `FwdBody` — the full
1028-byte tunnel message body (`tunnel_id ‖ iv ‖ encrypted`). Output: `ok`;
when no RouterInfo for `NextHash` is in the NetDb the frame is dropped
silently (the peer manager owns reconnection).
""".
-spec send_tunnel_data(i2p_crypto:hash(), <<_:32, _:_*8>>) -> ok.
send_tunnel_data(NextHash, FwdBody) ->
    case i2p_netdb_srv:find(NextHash) of
        {ok, _RI} ->
            Fwd = #{
                type => 18,
                msg_id => i2p_i2np:fresh_msg_id(),
                expiration => erlang:system_time(second) + 60,
                body => FwdBody
            },
            i2p_peer:send_when_ready(NextHash, Fwd);
        not_found ->
            ok
    end.

%%%%%%% %%% Internal %%%%%%%

-spec handle_stb(map(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
handle_stb(Msg, #{local := Local} = State) ->
    case i2p_i2np:decode_short_tunnel_build(maps:get(body, Msg)) of
        {ok, #{records := Records}} ->
            StaticPriv = maps:get(static_priv, Local),
            StaticPub = maps:get(static_pub, Local),
            OurHash = maps:get(hash, Local),
            case
                i2p_tunnel:process_short_tunnel_build(
                    StaticPriv, StaticPub, OurHash, Records
                )
            of
                error ->
                    State;
                {ok, HopInfo} ->
                    seal_and_forward(Msg, HopInfo, Records, State)
            end;
        error ->
            State
    end.

%% seal_and_forward/4 — decide accept/reject, seal our reply into the record
%% list, then either forward the modified STB onward (transit/gateway roles)
%% or — when we accepted the outbound-endpoint role — assemble the OTBRM and
%% deliver it down the reply path named in our own record. Rejected records
%% still seal ret 30 and participate in forwarding.
-spec seal_and_forward(map(), i2p_tunnel:hop_info(), [binary()], i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
seal_and_forward(Msg, HopInfo, Records, State) ->
    {Ret, State2} = decide_ret(HopInfo, State),
    Records1 = i2p_tunnel:apply_build_reply(HopInfo, Ret, Records),
    State3 =
        case Ret of
            0 ->
                RecvID = maps:get(recv_tunnel_id, HopInfo),
                Entry = #{info => HopInfo, created_at => erlang:system_time(second)},
                State2#{
                    transit :=
                        maps:put(RecvID, Entry, maps:get(transit, State2))
                };
            _ ->
                State2
        end,
    case Ret =:= 0 andalso maps:get(role, HopInfo) =:= endpoint of
        true -> deliver_otbrm(Msg, HopInfo, Records1, State3);
        false -> forward_stb(Msg, HopInfo, Records1, State3)
    end.

%% forward_stb/4 — relay the sealed STB to our record's next hop with the
%% same message ID. Rejected records still participate in forwarding.
-spec forward_stb(map(), i2p_tunnel:hop_info(), [binary()], i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
forward_stb(Msg, HopInfo, Records1, State) ->
    Num = length(Records1),
    ForwardMsg = Msg#{
        body := <<Num:8, (iolist_to_binary(Records1))/binary>>
    },
    NextHash = maps:get(next_hash, HopInfo),
    case i2p_netdb_srv:find(NextHash) of
        {ok, _RI} ->
            i2p_peer:send_when_ready(NextHash, ForwardMsg);
        not_found ->
            %% Cannot route onward; the build reply dies here and the
            %% creator will time out. Nothing to clean up.
            ok
    end,
    State.

%% deliver_otbrm/4 — outbound-endpoint role: convert the sealed records into
%% an OTBRM (same message ID) and send it down the reply path named in OUR
%% record. next-ID zero means direct router delivery; otherwise the reply is
%% RGarlic-wrapped and injected as a TunnelGateway into the creator's inbound
%% tunnel at the named gateway router.
-spec deliver_otbrm(map(), i2p_tunnel:hop_info(), [binary()], i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
deliver_otbrm(Msg, HopInfo, Records1, State) ->
    Num = length(Records1),
    MsgID = maps:get(msg_id, Msg, i2p_i2np:fresh_msg_id()),
    Body = <<Num:8, (iolist_to_binary(Records1))/binary>>,
    OTBRM = #{
        type => 26,
        msg_id => MsgID,
        expiration => erlang:system_time(second) + 60,
        body => Body
    },
    ReplyTunID = maps:get(next_tunnel_id, HopInfo),
    NextHash = maps:get(next_hash, HopInfo),
    case ReplyTunID of
        0 ->
            i2p_peer:send_when_ready(NextHash, OTBRM),
            State;
        _ ->
            RKey = maps:get(rgarlic_key, HopInfo),
            RTag = maps:get(rgarlic_tag, HopInfo),
            Clove = #{
                delivery => local,
                type => 26,
                msg_id => MsgID,
                expiration => erlang:system_time(second) + 60,
                data => Body
            },
            GarlicMsg = i2p_garlic:wrap_existing_session([Clove], RKey, RTag),
            StdMsg =
                i2p_i2np:encode_std(#{
                    type => 11,
                    msg_id => maps:get(msg_id, GarlicMsg),
                    expiration_ms => 60000,
                    body => maps:get(body, GarlicMsg)
                }),
            TGMsg = i2p_i2np:tunnel_gateway(ReplyTunID, StdMsg),
            i2p_peer:send_when_ready(NextHash, TGMsg),
            State
    end.

%% decide_ret/2 — 0 accepts any role (transit, gateway, or outbound
%% endpoint); 30 rejects on capacity, duplicate receive ID, or a drained
%% build-pacing bucket. Rejections are still sealed into the record list so
%% the creator learns immediately.
-spec decide_ret(i2p_tunnel:hop_info(), i2p_tunnel_srv:tunnel_srv_state()) ->
    {0 | 30, i2p_tunnel_srv:tunnel_srv_state()}.
decide_ret(#{recv_tunnel_id := RecvID}, #{transit := Transit} = State) ->
    MaxTransit = application:get_env(i2per, transit_max_tunnels, ?DEFAULT_MAX_TRANSIT),
    Duplicate = maps:is_key(RecvID, Transit) orelse map_size(Transit) >= MaxTransit,
    case Duplicate of
        true -> {30, State};
        false -> pace_build(State)
    end.

%% pace_build/1 — charge one build-decision token against the build-accept
%% bucket. When the bucket is drained the acceptance becomes ret 30; a
%% denial charges nothing, so the refused build rolls into the next refill.
-spec pace_build(i2p_tunnel_srv:tunnel_srv_state()) ->
    {0 | 30, i2p_tunnel_srv:tunnel_srv_state()}.
pace_build(#{build_bucket := none} = State) ->
    {0, State};
pace_build(#{build_bucket := Bucket} = State) ->
    NowMs = erlang:system_time(millisecond),
    case i2p_token_bucket:consume(Bucket, 1, NowMs) of
        {allow, Bucket1} -> {0, State#{build_bucket := Bucket1}};
        deny -> {30, State}
    end.

-spec handle_tunnel_data(map(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
handle_tunnel_data(Msg, #{transit := Transit} = State) ->
    Body = maps:get(body, Msg),
    <<TunnelID:32/big, _/binary>> = Body,
    case maps:find(TunnelID, Transit) of
        {ok, #{info := Info}} ->
            relay_transit_data(Body, Info, State);
        error ->
            case find_endpoint(State, TunnelID) of
                {ok, Entry, Pool} ->
                    deliver_local_data(Msg, TunnelID, Entry, Pool, State);
                error ->
                    State
            end
    end.

%% find_endpoint/2 — resolve a TunnelID to a local inbound tunnel we
%% terminate, naming which pool map it lives in: the client `inbound` map
%% or the lookup pool's `exploratory_in`.
-spec find_endpoint(i2p_tunnel_srv:tunnel_srv_state(), 0..16#FFFFFFFF) ->
    {ok, i2p_tunnel_srv:inbound_entry(), inbound | exploratory_in} | error.
find_endpoint(#{inbound := Inbound, exploratory_in := ExploratoryIn}, TunnelID) ->
    case maps:find(TunnelID, Inbound) of
        {ok, Entry} ->
            {ok, Entry, inbound};
        error ->
            case maps:find(TunnelID, ExploratoryIn) of
                {ok, Entry1} ->
                    {ok, Entry1, exploratory_in};
                error ->
                    error
            end
    end.

%% relay_transit_data/3 — participant step on a transit tunnel we serve.
%% Gateway-role entries only accept TunnelGateway injections, not relayed
%% tunnel data; such frames are dropped silently. Relay volume is charged
%% against the transit bandwidth bucket (`none` = unlimited) BEFORE any
%% crypto, so a denied frame is dropped at the lowest cost.
-spec relay_transit_data(binary(), i2p_tunnel:hop_info(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
relay_transit_data(_Body, #{is_gateway := true}, State) ->
    State;
relay_transit_data(Body, Info, State) ->
    case allow_transit_data(State) of
        deny ->
            State;
        {allow, State1} ->
            %% Charged on acceptance, not on arrival and not on forwarding. A
            %% frame the token bucket refused was never carried, so charging it
            %% would let a router under pressure report the traffic it turned
            %% away as traffic it did — and the bucket is consulted before the
            %% crypto precisely because that is the cheapest place to stop.
            ok = i2p_stats:add(transit_bytes_in, byte_size(Body)),
            NextID = maps:get(next_tunnel_id, Info),
            NextHash = maps:get(next_hash, Info),
            case i2p_tunnel:process_tunnel_data(Body, Info, NextID, i2p_i2np:fresh_msg_id()) of
                {ok, FwdBody} ->
                    %% Charged here rather than inside `f:send_tunnel_data/2`,
                    %% which is also the gateway's own path for injecting local
                    %% client data. Counting there would report another router's
                    %% traffic and our own as the same figure.
                    ok = i2p_stats:add(transit_bytes_out, byte_size(FwdBody)),
                    send_tunnel_data(NextHash, FwdBody),
                    State1;
                error ->
                    %% Accepted and received, but not forwarded — so counted
                    %% once, in the inbound figure, and that asymmetry is the
                    %% honest one.
                    State1
            end
    end.

%% allow_transit_data/1 — charge one 1028-byte frame against the transit
%% relay bandwidth bucket. A denied frame consumes nothing, so the refused
%% bytes roll into the next refill.
-spec allow_transit_data(i2p_tunnel_srv:tunnel_srv_state()) ->
    {allow, i2p_tunnel_srv:tunnel_srv_state()} | deny.
allow_transit_data(#{transit_bucket := none} = State) ->
    {allow, State};
allow_transit_data(#{transit_bucket := Bucket} = State) ->
    NowMs = erlang:system_time(millisecond),
    case i2p_token_bucket:consume(Bucket, ?TRANSIT_FRAME_BYTES, NowMs) of
        {allow, Bucket1} -> {allow, State#{transit_bucket := Bucket1}};
        deny -> deny
    end.

%% deliver_local_data/5 — we are the endpoint of one of our own inbound
%% tunnels (client `inbound` or the lookup pool's `exploratory_in`):
%% unwrap every hop's layer, validate the checksum, parse the fragments,
%% and dispatch complete messages locally. `Pool` names the state map that
%% holds the entry so its fragment map is updated in place.
-spec deliver_local_data(
    map(),
    0..16#FFFFFFFF,
    i2p_tunnel_srv:inbound_entry(),
    inbound | exploratory_in,
    i2p_tunnel_srv:tunnel_srv_state()
) ->
    i2p_tunnel_srv:tunnel_srv_state().
deliver_local_data(Msg, TunnelID, Entry0, Pool, State) ->
    #{layers := Layers, frag_map := FragMap} = Entry0,
    Body = maps:get(body, Msg),
    case unwrap_and_parse(Body, Layers, FragMap) of
        {ok, Msgs, FragMap1} ->
            Entry = Entry0#{frag_map := FragMap1},
            State1 =
                State#{
                    Pool :=
                        maps:update(TunnelID, Entry, maps:get(Pool, State))
                },
            lists:foldl(fun dispatch_local_message/2, State1, Msgs);
        error ->
            State
    end.

%% unwrap_and_parse/3 — peel the endpoint layers off one tunnel frame and
%% parse its fragments. Any checksum or framing failure drops the frame.
-spec unwrap_and_parse(
    binary(),
    [i2p_tunnel:layer_keys()],
    #{i2p_i2np:message_id() := #{non_neg_integer() := binary()}}
) ->
    {ok, [binary()], #{i2p_i2np:message_id() := #{non_neg_integer() := binary()}}} | error.
%% dialyzer: nowarn because i2p_tunnel:ibep_unwrap/2's inferred success
%% typing pins Body to one exact binary size, which would argue for an
%% absurdly over-narrow spec on the input side.
-dialyzer({nowarn_function, unwrap_and_parse/3}).
unwrap_and_parse(Body, Layers, FragMap) ->
    case i2p_tunnel:ibep_unwrap(Body, Layers) of
        {ok, <<_TunID:32/big, IV:16/binary, Payload:1008/binary>>} ->
            case i2p_tunnel:parse_tunnel_data(Payload, IV, FragMap) of
                {ok, Fragments, FragMap1} ->
                    {Msgs, FragMap2} = reassemble(Fragments, FragMap1),
                    {ok, Msgs, FragMap2};
                error ->
                    error
            end;
        _ ->
            error
    end.

%% dispatch_local_message/2 — a fully reassembled standard-header I2NP
%% message arrived for us out of an inbound tunnel. Garlic messages go
%% through the clove dispatcher; anything our router key cannot open is
%% offered to the SAM sessions (end-to-end client payloads).
-spec dispatch_local_message(binary(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
dispatch_local_message(StdMsg, State) ->
    case i2p_i2np:decode_std(StdMsg) of
        {ok, #{type := 11, body := GarlicBody}} ->
            dispatch_inbound_garlic(GarlicBody, State);
        {ok, #{type := T} = Msg} when T =:= 1; T =:= 3 ->
            %% End of the lookup flow: a responder pushed its DatabaseStore
            %% or DatabaseSearchReply into our inbound tunnel as a bare message.
            DbMsg = #{type => maps:get(type, Msg), body => maps:get(body, Msg)},
            case i2p_garlic:dispatch_db_message(DbMsg, 0) of
                {store, lease, Key, LsBin, _Ts} ->
                    _ = i2p_netdb_srv:store_ls_binary(LsBin, erlang:system_time(second)),
                    notify_lookup(Key, lease);
                {store, router, Key, RiBin, _Ts} ->
                    _ = i2p_netdb_srv:store_binary(RiBin, erlang:system_time(millisecond)),
                    notify_lookup(Key, router);
                {search_reply, #{key := Key, peers := Peers}} ->
                    notify_search_reply(Key, Peers);
                _OtherOutcome ->
                    ok
            end,
            State;
        {ok, _Other} ->
            State;
        error ->
            State
    end.

%% dispatch_inbound_garlic/2 — garlic that arrived out of our own inbound
%% tunnel: open it under our router key (or a pending build's reply key) and
%% handle its cloves; anything we cannot open is offered to the SAM sessions
%% as an end-to-end client payload.
-spec dispatch_inbound_garlic(binary(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
dispatch_inbound_garlic(GarlicBody, State) ->
    OurHash = maps:get(hash, maps:get(local, State)),
    case unwrap_garlic_cloves(GarlicBody, State) of
        {ok, Cloves, State1} ->
            dispatch_garlic_cloves(self(), OurHash, Cloves, State1);
        error ->
            try_stream_delivery(GarlicBody),
            State
    end.

%% notify_lookup/2 — wake pending remote lookups (m:i2p_lookup_srv). The
%% orchestrator is an optional subscriber: standalone tunnel servers (tests,
%% tooling) run without it.
-spec notify_lookup(i2p_crypto:hash(), router | lease) -> ok.
notify_lookup(Key, Kind) ->
    maybe_notify({db_stored, Key, Kind}).

%% notify_search_reply/2 — hand a search reply's closer-peer list to the
%% pending lookup so it can chase the responders' suggestions.
-spec notify_search_reply(i2p_crypto:hash(), [i2p_crypto:hash()]) -> ok.
notify_search_reply(Key, Peers) ->
    maybe_notify({search_reply, Key, Peers}).

-spec maybe_notify(
    {db_stored, i2p_crypto:hash(), router | lease}
    | {search_reply, i2p_crypto:hash(), [i2p_crypto:hash()]}
) -> ok.
maybe_notify(Msg) ->
    case whereis(i2p_lookup_srv) of
        undefined ->
            ok;
        Pid ->
            Pid ! Msg,
            ok
    end.

%% try_stream_delivery/1 — offer an undecryptable garlic body to every
%% registered session: the first destination whose ECIES private key
%% opens it receives the payload as {stream_data, Payload}. The owning
%% session dispatches by style (streaming packets vs datagrams).
-spec try_stream_delivery(binary()) -> ok.
try_stream_delivery(GarlicBody) ->
    lists:foreach(
        fun({_DestHash, Pid, CryptoPriv}) ->
            case i2p_client:unwrap_payload(CryptoPriv, GarlicBody) of
                {ok, Payload} -> Pid ! {stream_data, Payload};
                error -> ok
            end
        end,
        i2p_sam_sup:client_sessions() ++
            i2p_addressbook_subs:client_destinations() ++
            i2p_server_tunnel:client_destinations()
    ),
    ok.

%% handle_tunnel_gateway/2 — inject a TunnelGateway payload into a tunnel
%% whose inbound gateway is our transit entry: fragment into plaintext
%% frames, encrypt one layer with OUR keys, and forward as TunnelData.
-spec handle_tunnel_gateway(map(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
handle_tunnel_gateway(Msg, #{transit := Transit} = State) ->
    case i2p_i2np:decode_tunnel_gateway(maps:get(body, Msg)) of
        {ok, #{tunnel_id := TunnelID, body := StdMsg}} ->
            case maps:find(TunnelID, Transit) of
                {ok, #{info := Info} = Entry} ->
                    inject_at_gateway(StdMsg, Info, Entry, State);
                error ->
                    State
            end;
        error ->
            State
    end.

%% inject_at_gateway/4 — fragment the payload and push each frame inward.
%% Fragmentation state lives in the transit entry so multi-frame messages
%% continue correctly across successive injections.
-spec inject_at_gateway(
    binary(),
    i2p_tunnel:hop_info(),
    i2p_tunnel_srv:transit_entry(),
    i2p_tunnel_srv:tunnel_srv_state()
) ->
    i2p_tunnel_srv:tunnel_srv_state().
inject_at_gateway(StdMsg, Info, Entry, State) ->
    TunnelID = maps:get(recv_tunnel_id, Info),
    NextID = maps:get(next_tunnel_id, Info),
    NextHash = maps:get(next_hash, Info),
    LayerKey = maps:get(layer_key, Info),
    IVKey = maps:get(iv_key, Info),
    {Frames, GwState} = i2p_tunnel:gateway_all(TunnelID, local, undefined, StdMsg),
    lists:foreach(
        fun(Frame) ->
            <<_:32/big, Rest/binary>> = Frame,
            EncFrame =
                i2p_tunnel:encrypt_layer(<<NextID:32/big, Rest/binary>>, LayerKey, IVKey),
            send_tunnel_data(NextHash, EncFrame)
        end,
        Frames
    ),
    Entry1 = Entry#{gw_state => GwState},
    State#{transit := maps:update(TunnelID, Entry1, maps:get(transit, State))}.

%% reassemble/2 — turn parsed fragments into complete standard-header I2NP
%% messages. Single-frame messages pass straight through; fragmented ones
%% are concatenated from the fragment map once their last piece arrives.
-spec reassemble(
    [map()], #{i2p_i2np:message_id() => #{non_neg_integer() => binary()}}
) ->
    {[binary()], #{i2p_i2np:message_id() => #{non_neg_integer() => binary()}}}.
reassemble(Fragments, FragMap0) ->
    lists:foldl(
        fun(F, {Acc, Map}) ->
            case complete_fragment(F, Map) of
                {ok, Msg, Map1} -> {[Msg | Acc], Map1};
                none -> {Acc, Map}
            end
        end,
        {[], FragMap0},
        Fragments
    ).

%% complete_fragment/2 — emit a message when this fragment completes it.
complete_fragment(#{type := first, msg_id := MsgID, last := true, data := Data}, Map) ->
    {ok, Data, maps:remove(MsgID, Map)};
complete_fragment(#{type := follow_on, msg_id := MsgID, last := true}, Map) ->
    case maps:find(MsgID, Map) of
        {ok, Pieces} when map_size(Pieces) > 0 ->
            Num = maps:size(Pieces),
            Msg =
                <<<<(maps:get(I, Pieces))/binary>> || I <- lists:seq(0, Num - 1)>>,
            {ok, Msg, maps:remove(MsgID, Map)};
        _ ->
            none
    end;
complete_fragment(_, _) ->
    none.

%% unwrap_garlic_cloves/2 — unwrap a garlic message body and return all
%% cloves. Two forms are recognised: Noise N one-shot wraps (direct garlic)
%% and Existing Session (RGarlic) frames whose 8-byte leading tag matches a
%% pending outbound build's OBEP reply material. The body is the garlic
%% I2NP payload `<<Length:32, Data/binary>>`.
-spec unwrap_garlic_cloves(binary(), i2p_tunnel_srv:tunnel_srv_state()) ->
    {ok, [i2p_garlic:clove()], i2p_tunnel_srv:tunnel_srv_state()} | error.
unwrap_garlic_cloves(GarlicBody, #{local := Local, pending := Pending} = State) ->
    case unwrap_blocks(GarlicBody, Local, Pending) of
        {ok, Blocks} -> {ok, i2p_garlic:extract_cloves(Blocks), State};
        error -> error
    end.

%% unwrap_blocks/3 — the encrypted garlic payload opens one of two ways: an
%% Existing Session (RGarlic) frame whose 8-byte leading tag matches a
%% pending build's OBEP reply material, or a Noise N one-shot wrap under our
%% router static key.
-spec unwrap_blocks(binary(), map(), map()) -> {ok, [i2p_garlic:block()]} | error.
unwrap_blocks(GarlicBody, Local, Pending) ->
    case i2p_i2np:decode_garlic(GarlicBody) of
        {ok, #{data := Encrypted}} ->
            case try_existing_session(Encrypted, Pending) of
                {ok, EsBlocks} -> {ok, EsBlocks};
                error -> i2p_garlic:unwrap_router(Encrypted, maps:get(static_priv, Local))
            end;
        error ->
            error
    end.

%% try_existing_session/2 — if the leading 8 bytes match a pending build's
%% OBEP RGarlic tag, decrypt with that build's reply key.
-spec try_existing_session(binary(), map()) -> {ok, [i2p_garlic:block()]} | error.
try_existing_session(<<Tag:8/binary, _/binary>> = Data, Pending) ->
    case find_rgarlic_key(Tag, Pending) of
        {ok, Key} -> i2p_garlic:unwrap_existing_session(Data, Key, Tag);
        error -> error
    end;
try_existing_session(_, _) ->
    error.

-spec find_rgarlic_key(binary(), map()) -> {ok, i2p_crypto:key()} | error.
find_rgarlic_key(_Tag, Pending) when map_size(Pending) =:= 0 ->
    error;
find_rgarlic_key(Tag, Pending) ->
    maps:fold(
        fun(_MsgID, #{hop_keys := HopKeys}, Acc) ->
            case Acc of
                {ok, _Key} ->
                    Acc;
                error ->
                    case
                        [
                            K
                         || K <- HopKeys,
                            maps:get(rgarlic_tag, K, undefined) =:= Tag,
                            maps:get(rgarlic_key, K, undefined) =/= undefined
                        ]
                    of
                        [#{rgarlic_key := Key}] -> {ok, Key};
                        _ -> error
                    end
            end
        end,
        error,
        Pending
    ).

%% dispatch_garlic_cloves/4 — iterate cloves and handle each type.
-spec dispatch_garlic_cloves(
    pid(), i2p_crypto:hash(), [i2p_garlic:clove()], i2p_tunnel_srv:tunnel_srv_state()
) ->
    i2p_tunnel_srv:tunnel_srv_state().
dispatch_garlic_cloves(ConnPid, PeerHash, [Clove | Rest], State) ->
    State1 = dispatch_one_clove(ConnPid, PeerHash, Clove, State),
    dispatch_garlic_cloves(ConnPid, PeerHash, Rest, State1);
dispatch_garlic_cloves(_ConnPid, _PeerHash, [], State) ->
    State.

-spec dispatch_one_clove(
    pid(), i2p_crypto:hash(), i2p_garlic:clove(), i2p_tunnel_srv:tunnel_srv_state()
) ->
    i2p_tunnel_srv:tunnel_srv_state().
dispatch_one_clove(_ConnPid, _PeerHash, #{type := 26, data := Data, msg_id := MsgID}, State) ->
    i2p_tunnel_build:handle_otbrm(#{type => 26, body => Data, msg_id => MsgID}, State);
dispatch_one_clove(_ConnPid, _PeerHash, #{type := 25, data := Data, msg_id := MsgID}, State) ->
    handle_stb(#{type => 25, body => Data, msg_id => MsgID}, State);
dispatch_one_clove(_ConnPid, PeerHash, #{type := T, data := Data}, State) when
    T =:= 1; T =:= 2; T =:= 3
->
    Msg = #{
        type => T,
        msg_id => i2p_i2np:fresh_msg_id(),
        expiration => erlang:system_time(second),
        body => Data
    },
    DbMsg = #{type => maps:get(type, Msg), body => maps:get(body, Msg)},
    case i2p_garlic:dispatch_db_message(DbMsg, 0) of
        {store, router, Key, RiBin, _Ts} ->
            %% RouterInfo clocks are milliseconds; LeaseSet clocks are
            %% seconds (matching the m:i2p_netdb store APIs).
            _ = i2p_netdb_srv:store_binary(RiBin, erlang:system_time(millisecond)),
            replicate_clove_store(0, Key, RiBin, PeerHash, State),
            notify_lookup(Key, router),
            State;
        {store, lease, Key, LsBin, _Ts} ->
            _ = i2p_netdb_srv:store_ls_binary(LsBin, erlang:system_time(second)),
            replicate_clove_store(1, Key, LsBin, PeerHash, State),
            notify_lookup(Key, lease),
            State;
        {lookup, Parsed} ->
            OurHash = maps:get(hash, maps:get(local, State)),
            i2p_peer:tunnel_lookup_reply(Parsed, OurHash),
            State;
        {search_reply, #{key := Key, peers := Peers}} ->
            notify_search_reply(Key, Peers),
            State;
        ignore ->
            State
    end;
dispatch_one_clove(_ConnPid, _PeerHash, _Clove, State) ->
    State.

%% Floodfill replication for DB stores arriving via garlic cloves.
%% Forwards to the 3 closest eligible floodfills (excluding self and sender).
replicate_clove_store(StoreType, Key, Data, PeerHash, #{local := Local}) ->
    %% Stays a case: the scrutinee is an i2p_floodfill:is_floodfill() call,
    %% not guard-expressible.
    case i2p_floodfill:is_floodfill() of
        false ->
            ok;
        true ->
            OurHash = maps:get(hash, Local),
            Outbox = i2p_floodfill:replication_outbox(StoreType, Key, Data, OurHash, PeerHash),
            lists:foreach(
                fun({Target, Msg}) ->
                    i2p_peer:send_when_ready(Target, Msg)
                end,
                Outbox
            ),
            ok
    end.
