-module(i2p_tunnel_tests).

-include_lib("eunit/include/eunit.hrl").

%%%%%%%%% Build request record %%%%%%%%%

build_request_record_basic_test() ->
    RecvID = 1234,
    NextID = 5678,
    NextHash = crypto:strong_rand_bytes(32),
    Rec = i2p_tunnel:build_request_record(RecvID, NextID, NextHash, #{}),
    ?assertEqual(154, byte_size(Rec)),
    <<R:32/big, N:32/big, HHash:32/binary, _Flag:8, _Rest/binary>> = Rec,
    ?assertEqual(RecvID, R),
    ?assertEqual(NextID, N),
    ?assertEqual(NextHash, HHash).

build_request_record_gateway_endpoint_test() ->
    Rec = i2p_tunnel:build_request_record(
        1,
        2,
        crypto:strong_rand_bytes(32),
        #{gateway => true, endpoint => true}
    ),
    <<_:64/big, _H:32/binary, Flag:8, _/binary>> = Rec,
    ?assertEqual(16#C0, Flag band 16#C0).

%%%%%%%%% Single-hop layer encrypt/decrypt roundtrip %%%%%%%%%

single_hop_layer_roundtrip_test() ->
    LK = crypto:strong_rand_bytes(32),
    IVK = crypto:strong_rand_bytes(32),
    TunnelID = 42,
    Payload = crypto:strong_rand_bytes(1024),
    Msg = <<TunnelID:32/big, Payload/binary>>,
    Enc = i2p_tunnel:encrypt_layer(Msg, LK, IVK),
    ?assertEqual(1028, byte_size(Enc)),
    Dec = i2p_tunnel:decrypt_layer(Enc, LK, IVK),
    ?assertEqual(Msg, Dec).

single_hop_layer_different_keys_test() ->
    LK = crypto:strong_rand_bytes(32),
    IVK = crypto:strong_rand_bytes(32),
    LK2 = crypto:strong_rand_bytes(32),
    IVK2 = crypto:strong_rand_bytes(32),
    Body = crypto:strong_rand_bytes(1024),
    Msg = <<1:32, Body/binary>>,
    Enc = i2p_tunnel:encrypt_layer(Msg, LK, IVK),
    Dec = i2p_tunnel:decrypt_layer(Enc, LK2, IVK2),
    ?assertNotEqual(Msg, Dec).

%%%%%%%%% Outbound gateway prep + participant-encrypt chain %%%%%%%%%

%%
%% Spec semantics (tunnel-message spec, "Participant Processing"): every
%% transit participant ENCRYPTS one layer; the outbound gateway pre-applies
%% the inverse (iterative CBC decreptions, endpoint's key first), so the
%% plaintext pops out exactly at the endpoint after its own encryption.
%%

multi_hop_obgw_participant_roundtrip_test() ->
    NHops = 3,
    Hops = [
        #{
            layer_key => crypto:strong_rand_bytes(32),
            iv_key => crypto:strong_rand_bytes(32)
        }
     || _ <- lists:seq(1, NHops)
    ],
    Body = crypto:strong_rand_bytes(1024),
    PlainFrame = <<77:32, Body/binary>>,
    Wire0 = i2p_tunnel:obgw_prep(PlainFrame, Hops),
    ?assertEqual(1028, byte_size(Wire0)),
    %% Each participant encrypts one layer in forward order
    Final = lists:foldl(
        fun(Hop, M) ->
            {ok, M1} = i2p_tunnel:process_tunnel_data(M, Hop, 77, <<0, 0, 0, 0>>),
            M1
        end,
        Wire0,
        Hops
    ),
    %% After the endpoint's own encryption the gateway's plaintext is back
    %% (the tunnel ID field was rewritten by the last participant)
    <<_:32/big, FinalIV:16/binary, FinalData:1008/binary>> = Final,
    <<_:32/big, OrigIV:16/binary, OrigData:1008/binary>> = PlainFrame,
    ?assertEqual({OrigIV, OrigData}, {FinalIV, FinalData}).

%%%%%%%%% Inbound gateway single layer + endpoint unwrap roundtrip %%%%%%%%%

multi_hop_ibgw_ibep_roundtrip_test() ->
    NHops = 3,
    Hops = [
        #{
            layer_key => crypto:strong_rand_bytes(32),
            iv_key => crypto:strong_rand_bytes(32)
        }
     || _ <- lists:seq(1, NHops)
    ],
    IV = crypto:strong_rand_bytes(16),
    Body = crypto:strong_rand_bytes(1008),
    PlainFrame = <<88:32, IV/binary, Body/binary>>,
    %% The inbound gateway applies ONE layer (its own keys) and forwards
    [#{layer_key := LK1, iv_key := IVK1} | Rest] = Hops,
    Wire1 = i2p_tunnel:encrypt_layer(PlainFrame, LK1, IVK1),
    %% Intermediate participants each add their layer
    Final =
        lists:foldl(
            fun(Hop, M) ->
                {ok, M1} = i2p_tunnel:process_tunnel_data(M, Hop, 88, <<0, 0, 0, 0>>),
                M1
            end,
            Wire1,
            Rest
        ),
    %% The creator-endpoint unwinds everything in reverse order
    {ok, Plain} = i2p_tunnel:ibep_unwrap(Final, Hops),
    ?assertEqual(PlainFrame, Plain).

%%%%%%%%% process_tunnel_data (participant encrypts one layer) %%%%%%%%%

process_tunnel_data_roundtrip_test() ->
    LK = crypto:strong_rand_bytes(32),
    IVK = crypto:strong_rand_bytes(32),
    HopConfig = #{layer_key => LK, iv_key => IVK},
    NextID = 9999,
    MsgID = crypto:strong_rand_bytes(4),
    Body = crypto:strong_rand_bytes(1024),
    Msg = <<123:32, Body/binary>>,
    {ok, Forward} = i2p_tunnel:process_tunnel_data(Msg, HopConfig, NextID, MsgID),
    ?assertEqual(1028, byte_size(Forward)),
    <<FwdID:32/big, _/binary>> = Forward,
    ?assertEqual(NextID, FwdID),
    %% decrypt_layer is the exact inverse of the participant step: the
    %% original IV and payload come back, only the tunnel ID stays rewritten
    Dec = i2p_tunnel:decrypt_layer(Forward, LK, IVK),
    <<_:32/big, DecIV:16/binary, DecData:1008/binary>> = Dec,
    <<_:32/big, OrigIV:16/binary, OrigData:1008/binary>> = Msg,
    ?assertEqual({OrigIV, OrigData}, {DecIV, DecData}).

process_tunnel_data_wrong_size_test() ->
    HopConfig = #{layer_key => <<0:256>>, iv_key => <<0:256>>},
    ?assertEqual(error, i2p_tunnel:process_tunnel_data(<<0:100>>, HopConfig, 1, <<0, 0, 0, 0>>)).

%%%%%%%%% Gateway fragmentation roundtrip (local delivery) %%%%%%%%%

gateway_local_single_fragment_test() ->
    TunnelID = 42,
    Msg = crypto:strong_rand_bytes(100),
    FragMap0 = #{},
    {ok, WireMsg, _State1} = i2p_tunnel:gateway(TunnelID, local, undefined, Msg, #{
        frag_map => FragMap0
    }),
    ?assertEqual(1028, byte_size(WireMsg)),
    <<GotTID:32/big, IV:16/binary, EncPayload:1008/binary>> = WireMsg,
    ?assertEqual(TunnelID, GotTID),
    %% Verify checksum: EncPayload = checksum(4) + rest(1004)
    <<Cksum:4/binary, Rest:1004/binary>> = EncPayload,
    Hash = crypto:hash(sha256, <<Rest/binary, IV/binary>>),
    <<CksumExpected:4/binary, _/binary>> = Hash,
    ?assertEqual(CksumExpected, Cksum).

gateway_local_empty_msg_test() ->
    ?assertEqual(done, i2p_tunnel:gateway(1, local, undefined, <<>>, #{})).

gateway_local_multi_fragment_test() ->
    TunnelID = 42,
    %% A message larger than one fragment can hold for local delivery
    %% MaxDataNoID = 1003 - 1(flag) - 0(base) - 2(size) = 1000
    %% First fragmented: MaxData = 1000 - 4(msgID) = 996
    %% Follow-on: MaxData = 1000 - 4(msgID) = 996
    %% 2000 bytes needs 3 fragments: 996 + 996 + 8
    Msg = crypto:strong_rand_bytes(2000),
    FragMap0 = #{},
    {ok, Wire1, State1} = i2p_tunnel:gateway(TunnelID, local, undefined, Msg, #{
        frag_map => FragMap0
    }),
    ?assertEqual(1028, byte_size(Wire1)),
    %% Second fragment
    {ok, Wire2, State2} = i2p_tunnel:gateway(TunnelID, local, undefined, <<>>, State1),
    ?assertEqual(1028, byte_size(Wire2)),
    %% Third fragment
    {ok, Wire3, State3} = i2p_tunnel:gateway(TunnelID, local, undefined, <<>>, State2),
    ?assertEqual(1028, byte_size(Wire3)),
    %% Fourth call should be done
    ?assertEqual(done, i2p_tunnel:gateway(TunnelID, local, undefined, <<>>, State3)).

%%%%%%%%% Gateway tunnel delivery %%%%%%%%%

gateway_tunnel_first_fragment_test() ->
    TunnelID = 42,
    TargetHash = crypto:strong_rand_bytes(32),
    Target = {9999, TargetHash},
    Msg = crypto:strong_rand_bytes(100),
    FragMap0 = #{},
    {ok, Wire, _State} = i2p_tunnel:gateway(TunnelID, tunnel, Target, Msg, #{frag_map => FragMap0}),
    ?assertEqual(1028, byte_size(Wire)),
    <<GotTID:32/big, _/binary>> = Wire,
    ?assertEqual(TunnelID, GotTID).

%%%%%%%%% Gateway router delivery %%%%%%%%%

gateway_router_first_fragment_test() ->
    TunnelID = 42,
    TargetHash = crypto:strong_rand_bytes(32),
    Msg = crypto:strong_rand_bytes(100),
    FragMap0 = #{},
    {ok, Wire, _State} = i2p_tunnel:gateway(TunnelID, router, TargetHash, Msg, #{
        frag_map => FragMap0
    }),
    ?assertEqual(1028, byte_size(Wire)).

%%%%%%%%% parse_tunnel_data roundtrip with gateway output %%%%%%%%%

parse_tunnel_data_local_roundtrip_test() ->
    TunnelID = 42,
    Msg = crypto:strong_rand_bytes(50),
    FragMap0 = #{},
    {ok, WireMsg, _State} = i2p_tunnel:gateway(TunnelID, local, undefined, Msg, #{
        frag_map => FragMap0
    }),
    %% Extract IV and EncPayload from the 1028-byte wire message
    <<_:32/big, IV:16/binary, EncPayload:1008/binary>> = WireMsg,
    FragMap1 = #{},
    case i2p_tunnel:parse_tunnel_data(EncPayload, IV, FragMap1) of
        {ok, Fragments, _FragMap2} ->
            ?assert(length(Fragments) >= 1),
            First = hd(Fragments),
            ?assertEqual(Msg, maps:get(data, First));
        error ->
            ?assert(false)
    end.

parse_tunnel_data_checksum_error_test() ->
    Payload = crypto:strong_rand_bytes(1004),
    IV = crypto:strong_rand_bytes(16),
    ?assertEqual(error, i2p_tunnel:parse_tunnel_data(Payload, IV, #{})).

parse_tunnel_data_wrong_size_test() ->
    ?assertEqual(error, i2p_tunnel:parse_tunnel_data(<<0:800>>, crypto:strong_rand_bytes(16), #{})).

%%%%%%%%% Gateway + parse roundtrip (tunnel delivery, multi-fragment) %%%%%%%%%

gateway_tunnel_multi_fragment_roundtrip_test() ->
    TunnelID = 42,
    TargetHash = crypto:strong_rand_bytes(32),
    Target = {9999, TargetHash},
    %% Tunnel first fragment header = 1(flag) + 4(tunID) + 32(hash) + 4(msgID) + 2(size) = 43
    %% MaxDataNoID first = 1003 - 43 = 960; follow-on MaxDataNoID = 1003 - 7 = 996
    %% 2000 bytes needs 3 fragments: 960 + 996 + 44
    Msg = crypto:strong_rand_bytes(2000),
    FragMap0 = #{},
    {ok, Wire1, State1} = i2p_tunnel:gateway(TunnelID, tunnel, Target, Msg, #{frag_map => FragMap0}),
    {ok, Wire2, State2} = i2p_tunnel:gateway(TunnelID, tunnel, Target, <<>>, State1),
    {ok, Wire3, State3} = i2p_tunnel:gateway(TunnelID, tunnel, Target, <<>>, State2),
    ?assertEqual(done, i2p_tunnel:gateway(TunnelID, tunnel, Target, <<>>, State3)),
    %% Parse all fragments
    <<_:32/big, IV1:16/binary, Payload1:1008/binary>> = Wire1,
    <<_:32/big, IV2:16/binary, Payload2:1008/binary>> = Wire2,
    <<_:32/big, IV3:16/binary, Payload3:1008/binary>> = Wire3,
    {ok, Frag1, FragMap1} = i2p_tunnel:parse_tunnel_data(Payload1, IV1, FragMap0),
    {ok, Frag2, FragMap2} = i2p_tunnel:parse_tunnel_data(Payload2, IV2, FragMap1),
    {ok, Frag3, _FragMap3} = i2p_tunnel:parse_tunnel_data(Payload3, IV3, FragMap2),
    %% Frag1 should be first, Frag2/Frag3 follow-on
    First = hd(Frag1),
    ?assertEqual(first, maps:get(type, First)),
    %% Reassemble
    AllData = [maps:get(data, F) || F <- Frag1 ++ Frag2 ++ Frag3],
    Reassembled = list_to_binary(AllData),
    ?assertEqual(Msg, Reassembled).

%%%%%%%%% parse_tunnel_data + reassemble multi-fragment %%%%%%%%%

parse_tunnel_data_reassemble_multi_fragment_test() ->
    TunnelID = 42,
    TargetHash = crypto:strong_rand_bytes(32),
    Target = {9999, TargetHash},
    Msg = crypto:strong_rand_bytes(2000),
    FragMap0 = #{},
    {ok, Wire1, State1} = i2p_tunnel:gateway(TunnelID, tunnel, Target, Msg, #{frag_map => FragMap0}),
    {ok, Wire2, State2} = i2p_tunnel:gateway(TunnelID, tunnel, Target, <<>>, State1),
    {ok, Wire3, State3} = i2p_tunnel:gateway(TunnelID, tunnel, Target, <<>>, State2),
    ?assertEqual(done, i2p_tunnel:gateway(TunnelID, tunnel, Target, <<>>, State3)),
    <<_:32/big, IV1:16/binary, Payload1:1008/binary>> = Wire1,
    <<_:32/big, IV2:16/binary, Payload2:1008/binary>> = Wire2,
    <<_:32/big, IV3:16/binary, Payload3:1008/binary>> = Wire3,
    {ok, Frag1, FragMap1} = i2p_tunnel:parse_tunnel_data(Payload1, IV1, FragMap0),
    {ok, Frag2, FragMap2} = i2p_tunnel:parse_tunnel_data(Payload2, IV2, FragMap1),
    {ok, Frag3, FragMap3} = i2p_tunnel:parse_tunnel_data(Payload3, IV3, FragMap2),
    {Msgs, _FragMap4} = i2p_tunnel_relay:reassemble(Frag1 ++ Frag2 ++ Frag3, FragMap3),
    ?assertEqual([Msg], Msgs).

%%%%%%%%% process_otbrm rejects mismatched lengths %%%%%%%%%

process_otbrm_mismatched_lengths_test() ->
    ?assertEqual(error, i2p_tunnel:process_otbrm([<<0:218>>, <<0:218>>], [#{record_index => 0}])).

%%%%%%%%% encrypt_layer rejects wrong size %%%%%%%%%

encrypt_layer_wrong_size_test() ->
    ?assertError(badarg, i2p_tunnel:encrypt_layer(<<0:100>>, <<0:32>>, <<0:32>>)).

%%%%%%%%% decrypt_layer rejects wrong size %%%%%%%%%

decrypt_layer_wrong_size_test() ->
    ?assertError(badarg, i2p_tunnel:decrypt_layer(<<0:100>>, <<0:32>>, <<0:32>>)).
