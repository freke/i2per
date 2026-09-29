-module(i2p_garlic_tests).

-include_lib("eunit/include/eunit.hrl").

%%%%%%%%% Delivery Instructions %%%%%%%%%

delivery_local_test() ->
    Enc = i2p_garlic:encode_delivery(local),
    ?assertEqual(<<0>>, Enc),
    {local, <<"rest">>} = i2p_garlic:decode_delivery(<<0, "rest">>).

delivery_destination_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Enc = i2p_garlic:encode_delivery({destination, Hash}),
    ?assertEqual(33, byte_size(Enc)),
    <<32:8, EncHash:32/binary>> = Enc,
    ?assertEqual(Hash, EncHash),
    {{destination, Hash}, <<"rest">>} =
        i2p_garlic:decode_delivery(<<Enc/binary, "rest">>).

delivery_router_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Enc = i2p_garlic:encode_delivery({router, Hash}),
    ?assertEqual(33, byte_size(Enc)),
    <<64:8, EncHash:32/binary>> = Enc,
    ?assertEqual(Hash, EncHash),
    {{router, Hash}, <<"rest">>} =
        i2p_garlic:decode_delivery(<<Enc/binary, "rest">>).

delivery_tunnel_test() ->
    Hash = crypto:strong_rand_bytes(32),
    TunnelID = 12345,
    Enc = i2p_garlic:encode_delivery({tunnel, Hash, TunnelID}),
    ?assertEqual(37, byte_size(Enc)),
    <<96:8, EncHash:32/binary, TunnelIDEnc:32/big>> = Enc,
    ?assertEqual(Hash, EncHash),
    ?assertEqual(TunnelID, TunnelIDEnc),
    {{tunnel, Hash, TunnelID}, <<"rest">>} =
        i2p_garlic:decode_delivery(<<Enc/binary, "rest">>).

delivery_roundtrip_all_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Types = [
        local,
        {destination, Hash},
        {router, Hash},
        {tunnel, Hash, 42}
    ],
    lists:foreach(
        fun(D) ->
            Enc = i2p_garlic:encode_delivery(D),
            {D, <<>>} = i2p_garlic:decode_delivery(Enc)
        end,
        Types
    ).

delivery_decode_error_test() ->
    ?assertEqual(error, i2p_garlic:decode_delivery(<<>>)),
    ?assertEqual(error, i2p_garlic:decode_delivery(<<32:8>>)).

%%%%%%%%% Short ECIES Clove %%%%%%%%%

clove_local_roundtrip_test() ->
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration => 1800000000,
        data => <<"hello">>
    },
    Enc = i2p_garlic:encode_clove(Clove),
    ?assertEqual({ok, Clove}, i2p_garlic:decode_clove(Enc)).

clove_router_roundtrip_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Clove = #{
        delivery => {router, Hash},
        type => 11,
        msg_id => <<5, 6, 7, 8>>,
        expiration => 1700000000,
        data => <<"router payload">>
    },
    Enc = i2p_garlic:encode_clove(Clove),
    ?assertEqual({ok, Clove}, i2p_garlic:decode_clove(Enc)).

clove_tunnel_roundtrip_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Clove = #{
        delivery => {tunnel, Hash, 9999},
        type => 17,
        msg_id => <<10, 11, 12, 13>>,
        expiration => 1600000000,
        data => <<"tunnel payload">>
    },
    Enc = i2p_garlic:encode_clove(Clove),
    ?assertEqual({ok, Clove}, i2p_garlic:decode_clove(Enc)).

clove_wire_layout_local_test() ->
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<0, 0, 0, 1>>,
        expiration => 0,
        data => <<>>
    },
    Enc = i2p_garlic:encode_clove(Clove),
    %% flag(1) || type(1) || msg_id(4) || exp(4) || data(0) = 10 bytes
    ?assertEqual(10, byte_size(Enc)),
    <<0:8, 11:8, 0, 0, 0, 1, 0:32/big>> = Enc.

clove_wire_layout_router_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Clove = #{
        delivery => {router, Hash},
        type => 11,
        msg_id => <<0, 0, 0, 2>>,
        expiration => 42,
        data => <<"X">>
    },
    Enc = i2p_garlic:encode_clove(Clove),
    %% flag(1) || hash(32) || type(1) || msg_id(4) || exp(4) || data(1) = 43 bytes
    ?assertEqual(43, byte_size(Enc)),
    <<64:8, EncHash:32/binary, 11:8, 0, 0, 0, 2, 42:32/big, "X">> = Enc,
    ?assertEqual(Hash, EncHash).

clove_decode_error_test() ->
    ?assertEqual(error, i2p_garlic:decode_clove(<<>>)),
    ?assertEqual(error, i2p_garlic:decode_clove(<<0, 11:8, 0, 0, 0>>)).

%%%%%%%%% TLV Payload Blocks %%%%%%%%%

payload_roundtrip_test() ->
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration => 1800000000,
        data => <<"test">>
    },
    Payload = i2p_garlic:encode_payload([Clove]),
    {ok, Blocks} = i2p_garlic:decode_payload(Payload),
    ?assert(length(Blocks) >= 2),
    [DTBlock | Rest] = Blocks,
    ?assertEqual(datetime, maps:get(type, DTBlock)),
    ?assert(maps:is_key(timestamp, DTBlock)),
    CloveBlocks = i2p_garlic:extract_cloves(Rest),
    ?assertEqual(1, length(CloveBlocks)),
    ?assertEqual(Clove, hd(CloveBlocks)).

payload_datetime_wire_test() ->
    Payload = i2p_garlic:encode_payload([], #{datetime => 1700000000}),
    {ok, [#{type := datetime, timestamp := 1700000000}]} =
        i2p_garlic:decode_payload(Payload).

payload_padding_test() ->
    Payload = i2p_garlic:encode_payload([], #{datetime => 0, pad_to => 100}),
    ?assert(byte_size(Payload) >= 100),
    {ok, Blocks} = i2p_garlic:decode_payload(Payload),
    PaddingBlocks = [B || #{type := padding} = B <- Blocks],
    ?assert(length(PaddingBlocks) >= 1).

payload_unknown_block_test() ->
    %% type 255, size 3, data [1,2,3] — then a datetime block
    Payload = <<255:8, 3:16/big, 1, 2, 3, 0:8, 4:16/big, 0, 0, 6, 64>>,
    {ok, Blocks} = i2p_garlic:decode_payload(Payload),
    UnknownBlocks = [B || #{type := {unknown, 255}} = B <- Blocks],
    ?assertEqual(1, length(UnknownBlocks)).

payload_empty_test() ->
    {ok, []} = i2p_garlic:decode_payload(<<>>).

%%%%%%%%% Block Type Constants %%%%%%%%%

block_constants_test() ->
    ?assertEqual(datetime, i2p_garlic:block_datetime()),
    ?assertEqual(session_id, i2p_garlic:block_session_id()),
    ?assertEqual(termination, i2p_garlic:block_termination()),
    ?assertEqual(options, i2p_garlic:block_options()),
    ?assertEqual(next_key, i2p_garlic:block_next_key()),
    ?assertEqual(ack, i2p_garlic:block_ack()),
    ?assertEqual(ack_request, i2p_garlic:block_ack_request()),
    ?assertEqual(garlic_clove, i2p_garlic:block_garlic_clove()),
    ?assertEqual(padding, i2p_garlic:block_padding()).

%%%%%%%%% Wrap/Unwrap Router ECIES %%%%%%%%%

wrap_unwrap_roundtrip_test() ->
    {RouterPub, RouterPriv} = i2p_crypto:x25519_keygen(),
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration => 1800000000,
        data => <<"garlic payload">>
    },
    Msg = i2p_garlic:wrap_router([Clove], RouterPub),
    ?assertEqual(i2p_i2np:type_garlic(), maps:get(type, Msg)),
    {ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    {ok, Blocks} = i2p_garlic:unwrap_router(Encrypted, RouterPriv),
    ResultCloves = i2p_garlic:extract_cloves(Blocks),
    ?assertEqual(1, length(ResultCloves)),
    ?assertEqual(Clove, hd(ResultCloves)).

wrap_unwrap_deterministic_test() ->
    {RouterPub, RouterPriv} = i2p_crypto:x25519_keygen(),
    {_EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration => 1800000000,
        data => <<"deterministic">>
    },
    Msg = i2p_garlic:wrap_router([Clove], RouterPub, EphPriv),
    {ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    <<EphPubGot:32/binary, _/binary>> = Encrypted,
    ?assertEqual(i2p_crypto:x25519_public_key(EphPriv), EphPubGot),
    {ok, Blocks} = i2p_garlic:unwrap_router(Encrypted, RouterPriv),
    [GotClove] = i2p_garlic:extract_cloves(Blocks),
    ?assertEqual(Clove, GotClove).

wrap_unwrap_multiple_cloves_test() ->
    {RouterPub, RouterPriv} = i2p_crypto:x25519_keygen(),
    Hash = crypto:strong_rand_bytes(32),
    Cloves = [
        #{
            delivery => local,
            type => 11,
            msg_id => <<1, 2, 3, 4>>,
            expiration => 1800000000,
            data => <<"primary">>
        },
        #{
            delivery => {router, Hash},
            type => 6,
            msg_id => <<5, 6, 7, 8>>,
            expiration => 1700000000,
            data => <<"secondary">>
        }
    ],
    Msg = i2p_garlic:wrap_router(Cloves, RouterPub),
    {ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    {ok, Blocks} = i2p_garlic:unwrap_router(Encrypted, RouterPriv),
    GotCloves = i2p_garlic:extract_cloves(Blocks),
    ?assertEqual(2, length(GotCloves)),
    ?assertEqual(lists:nth(1, Cloves), lists:nth(1, GotCloves)),
    ?assertEqual(lists:nth(2, Cloves), lists:nth(2, GotCloves)).

wrap_wrong_key_test() ->
    {RouterPub, _RouterPriv} = i2p_crypto:x25519_keygen(),
    {_WrongPub, WrongPriv} = i2p_crypto:x25519_keygen(),
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration => 1800000000,
        data => <<"secret">>
    },
    Msg = i2p_garlic:wrap_router([Clove], RouterPub),
    {ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    ?assertEqual(error, i2p_garlic:unwrap_router(Encrypted, WrongPriv)).

wrap_tamper_test() ->
    {RouterPub, RouterPriv} = i2p_crypto:x25519_keygen(),
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration => 1800000000,
        data => <<"integrity">>
    },
    Msg = i2p_garlic:wrap_router([Clove], RouterPub),
    {ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    <<First:8, Rest/binary>> = Encrypted,
    Tampered = <<(First bxor 16#FF):8, Rest/binary>>,
    ?assertEqual(error, i2p_garlic:unwrap_router(Tampered, RouterPriv)).

wrap_empty_payload_test() ->
    {RouterPub, RouterPriv} = i2p_crypto:x25519_keygen(),
    Msg = i2p_garlic:wrap_router([], RouterPub),
    {ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    {ok, Blocks} = i2p_garlic:unwrap_router(Encrypted, RouterPriv),
    ?assertEqual([], i2p_garlic:extract_cloves(Blocks)).

%%%%%%%%% Helpers %%%%%%%%%

extract_cloves_skips_non_clove_test() ->
    Blocks = [
        #{type => datetime, data => <<>>, timestamp => 0},
        #{type => padding, data => <<0, 0, 0>>},
        #{
            type => garlic_clove,
            data => <<>>,
            clove => #{
                delivery => local,
                type => 11,
                msg_id => <<1, 2, 3, 4>>,
                expiration => 0,
                data => <<>>
            }
        }
    ],
    ?assertEqual(1, length(i2p_garlic:extract_cloves(Blocks))).

clove_message_test() ->
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration => 1800000000,
        data => <<"body">>
    },
    Msg = i2p_garlic:clove_message(Clove),
    ?assertEqual(11, maps:get(type, Msg)),
    ?assertEqual(<<1, 2, 3, 4>>, maps:get(msg_id, Msg)),
    ?assertEqual(1800000000, maps:get(expiration, Msg)),
    ?assertEqual(<<"body">>, maps:get(body, Msg)).

%%%%%%%%% Encrypted Structure %%%%%%%%%

encrypted_structure_test() ->
    {RouterPub, _RouterPriv} = i2p_crypto:x25519_keygen(),
    {_EphPub, EphPriv} = i2p_crypto:x25519_keygen(),
    Clove = #{
        delivery => local,
        type => 11,
        msg_id => <<1, 2, 3, 4>>,
        expiration => 1800000000,
        data => <<"check structure">>
    },
    Msg = i2p_garlic:wrap_router([Clove], RouterPub, EphPriv),
    {ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    %% Encrypted = ephPub(32) || CT || tag(16)
    ?assert(byte_size(Encrypted) >= 48),
    <<_EphPub32:32/binary, CTAndTag/binary>> = Encrypted,
    %% CTAndTag = CT || Tag(16); CT is variable length
    CTLen = byte_size(CTAndTag) - 16,
    <<_CT:CTLen/binary, _Tag:16/binary>> = CTAndTag.

%%%%%%%%% DB Message Dispatch %%%%%%%%%

dispatch_db_store_router_test() ->
    Key = crypto:strong_rand_bytes(32),
    RiData = crypto:strong_rand_bytes(256),
    Body = <<Key/binary, 0:8, 0:32/big, RiData/binary>>,
    Msg = #{type => 1, msg_id => <<1, 2, 3, 4>>, expiration => 1800000000, body => Body},
    NowMs = 1700000000000,
    ?assertEqual(
        {store, router, Key, RiData, NowMs},
        i2p_garlic:dispatch_db_message(Msg, NowMs)
    ).

dispatch_db_store_lease_test() ->
    Key = crypto:strong_rand_bytes(32),
    LsData = crypto:strong_rand_bytes(128),
    Body = <<Key/binary, 1:8, 0:32/big, LsData/binary>>,
    Msg = #{type => 1, msg_id => <<1, 2, 3, 4>>, expiration => 1800000000, body => Body},
    NowMs = 1700000000000,
    ?assertEqual(
        {store, lease, Key, LsData, NowMs},
        i2p_garlic:dispatch_db_message(Msg, NowMs)
    ).

dispatch_db_store_with_reply_token_test() ->
    Key = crypto:strong_rand_bytes(32),
    RiData = crypto:strong_rand_bytes(64),
    Gateway = crypto:strong_rand_bytes(32),
    Body = <<Key/binary, 0:8, 42:32/big, 777:32/big, Gateway/binary, RiData/binary>>,
    Msg = #{type => 1, msg_id => <<1, 2, 3, 4>>, expiration => 1800000000, body => Body},
    NowMs = 1700000000000,
    ?assertEqual(
        {store, router, Key, RiData, NowMs},
        i2p_garlic:dispatch_db_message(Msg, NowMs)
    ).

dispatch_db_store_malformed_test() ->
    Msg = #{type => 1, msg_id => <<1, 2, 3, 4>>, expiration => 1800000000, body => <<>>},
    ?assertEqual(
        {ignored, undecodable_store}, i2p_garlic:dispatch_db_message(Msg, 0)
    ).

%% Store types 5 (EncryptedLeaseSet) and 7 (MetaLeaseSet) decode successfully
%% — `f:i2p_i2np:decode_db_store/1` reports every byte on the wire — so before
%% the catch-all clause they matched no clause here and raised `case_clause`,
%% taking the tunnel manager down with them. Both reference routers can emit 5.
dispatch_db_store_unimplemented_type_test_() ->
    [
        ?_assertEqual(
            {ignored, {unsupported_type, Type}}, dispatch_unimplemented_db_store(Type)
        )
     || Type <- [5, 7]
    ].

dispatch_db_store_unknown_byte_test_() ->
    %% Any other store type this router does not implement, not just the two
    %% the references are known to emit.
    [
        ?_assertEqual(
            {ignored, {unsupported_type, Type}}, dispatch_unimplemented_db_store(Type)
        )
     || Type <- [2, 4, 6, 8, 255]
    ].

dispatch_unimplemented_db_store(Type) ->
    Key = crypto:strong_rand_bytes(32),
    Data = crypto:strong_rand_bytes(64),
    Body = <<Key/binary, Type:8, 0:32/big, Data/binary>>,
    Msg = #{type => 1, msg_id => <<1, 2, 3, 4>>, expiration => 1800000000, body => Body},
    i2p_garlic:dispatch_db_message(Msg, 0).

dispatch_db_lookup_test() ->
    Key = crypto:strong_rand_bytes(32),
    From = crypto:strong_rand_bytes(32),
    Body = <<Key/binary, From/binary, 0:8, 0:16/big>>,
    Msg = #{type => 2, msg_id => <<1, 2, 3, 4>>, expiration => 1800000000, body => Body},
    ?assertMatch(
        {lookup, #{key := Key, from := From}},
        i2p_garlic:dispatch_db_message(Msg, 0)
    ).

dispatch_db_search_reply_test() ->
    Key = crypto:strong_rand_bytes(32),
    From = crypto:strong_rand_bytes(32),
    Body = <<Key/binary, 0:8, From/binary>>,
    Msg = #{type => 3, msg_id => <<1, 2, 3, 4>>, expiration => 1800000000, body => Body},
    ?assertMatch(
        {search_reply, #{key := Key, peers := [], from := From}},
        i2p_garlic:dispatch_db_message(Msg, 0)
    ).

dispatch_unknown_type_test() ->
    Msg = #{type => 42, msg_id => <<1, 2, 3, 4>>, expiration => 1800000000, body => <<"data">>},
    ?assertEqual(
        {ignored, not_a_db_message}, i2p_garlic:dispatch_db_message(Msg, 0)
    ).

%% The three store-shaped ways a message can be declined are kept apart, because the
%% ticket this came from needs the difference: a store whose *type* has no parser here
%% means a peer answered and the record arrived intact, while `undecodable_store` means
%% the bytes did not parse. One is a gap in this implementation, the other is a fault
%% on the wire, and an operator cannot act on either until they know which.
ignored_store_reasons_are_distinct_test() ->
    Key = crypto:strong_rand_bytes(32),
    Unimplemented = <<Key/binary, 5:8, 0:32/big, (crypto:strong_rand_bytes(64))/binary>>,
    Undecodable = #{type => 1, body => <<>>},
    NotAStore = #{type => 42, body => <<"data">>},
    ?assertEqual(
        [
            {ignored, {unsupported_type, 5}},
            {ignored, undecodable_store},
            {ignored, not_a_db_message}
        ],
        [
            i2p_garlic:dispatch_db_message(
                #{
                    type => 1,
                    msg_id => <<1, 2, 3, 4>>,
                    expiration => 0,
                    body => Unimplemented
                },
                0
            ),
            i2p_garlic:dispatch_db_message(Undecodable, 0),
            i2p_garlic:dispatch_db_message(NotAStore, 0)
        ]
    ).

%%%%%%%%% Existing Session (RGarlic) %%%%%%%%%

existing_session_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(32),
    Tag = crypto:strong_rand_bytes(8),
    Clove = #{
        delivery => local,
        type => 26,
        msg_id => crypto:strong_rand_bytes(4),
        expiration => erlang:system_time(second) + 60,
        data => crypto:strong_rand_bytes(100)
    },
    Msg = i2p_garlic:wrap_existing_session([Clove], Key, Tag),
    {ok, #{data := Data}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    %% Leading 8 bytes are the raw tag
    ?assertEqual(Tag, binary:part(Data, 0, 8)),
    {ok, Blocks} = i2p_garlic:unwrap_existing_session(Data, Key, Tag),
    Cloves = i2p_garlic:extract_cloves(Blocks),
    ?assertMatch([#{type := 26}], Cloves).

existing_session_wrong_key_test() ->
    Key = crypto:strong_rand_bytes(32),
    OtherKey = crypto:strong_rand_bytes(32),
    Tag = crypto:strong_rand_bytes(8),
    Clove = #{
        delivery => local,
        type => 26,
        msg_id => <<0, 0, 0, 1>>,
        expiration => 1800000000,
        data => <<"payload">>
    },
    Msg = i2p_garlic:wrap_existing_session([Clove], Key, Tag),
    {ok, #{data := Data}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    ?assertEqual(error, i2p_garlic:unwrap_existing_session(Data, OtherKey, Tag)).

existing_session_wrong_tag_test() ->
    Key = crypto:strong_rand_bytes(32),
    Tag = crypto:strong_rand_bytes(8),
    OtherTag = crypto:strong_rand_bytes(8),
    Clove = #{
        delivery => local,
        type => 26,
        msg_id => <<0, 0, 0, 1>>,
        expiration => 1800000000,
        data => <<"payload">>
    },
    Msg = i2p_garlic:wrap_existing_session([Clove], Key, Tag),
    {ok, #{data := Data}} = i2p_i2np:decode_garlic(maps:get(body, Msg)),
    ?assertEqual(error, i2p_garlic:unwrap_existing_session(Data, Key, OtherTag)).
