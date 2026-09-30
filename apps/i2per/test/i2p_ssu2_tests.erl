%% Structural and round-trip tests for the SSU2 codec: headers, header
%% obfuscation, payload blocks, the full XK handshake (both roles derive
%% identical data-phase keys), TokenRequest/Retry, data phase, and the
%% rejection paths (tampering, wrong IDs, wrong version/net ID).

-module(i2p_ssu2_tests).

-include_lib("eunit/include/eunit.hrl").

%%% --------------------------------------------------------------------------
%%% Noise initialization
%%% --------------------------------------------------------------------------

init_kdf_test() ->
    {Bpk, _Bik} = bob_keys(),
    {Ck, H} = i2p_ssu2:initialize(Bpk),
    ?assertEqual(
        <<16#B13722817423A8FDF42DF2E60ED1EDF41B93071DB1EC24A367F784EC270D8132:256>>,
        Ck
    ),
    %% h after init: null-prologue MixHash folds one more SHA256 before the
    %% responder static key.
    ?assertEqual(
        i2p_crypto:mixhash(crypto:hash(sha256, Ck), Bpk),
        H
    ).

%%% --------------------------------------------------------------------------
%%% Headers
%%% --------------------------------------------------------------------------

long_header_layout_test() ->
    %% dst(8) num(4) type(1) ver(1) netid(1) flag(1) src(8) token(8)
    H = i2p_ssu2:long_header(
        16#0102030405060708,
        16#AABBCCDD,
        0,
        16#1112131415161718,
        16#99
    ),
    <<Dst:64/big, Num:32/big, 0:8, 2:8, 2:8, 0:8, Src:64/big, Tok:64/big>> = H,
    ?assertEqual(16#0102030405060708, Dst),
    ?assertEqual(16#AABBCCDD, Num),
    ?assertEqual(16#1112131415161718, Src),
    ?assertEqual(16#99, Tok).

short_header_data_layout_test() ->
    H = i2p_ssu2:short_header_data(7, 42, 1),
    <<7:64/big, 42:32/big, 6:8, 1:8, 0:16>> = H.

short_header_confirmed_layout_test() ->
    H = i2p_ssu2:short_header_confirmed(9, 3, 5),
    <<9:64/big, 0:32, 2:8, 3:4, 5:4, 0:16>> = H.

seal_open_ephemeral_roundtrip_test() ->
    Packet = crypto:strong_rand_bytes(200),
    {_Bpk, Bik} = bob_keys(),
    Sealed = i2p_ssu2:seal_ephemeral(Packet, Bik, Bik),
    ?assertNotEqual(Packet, Sealed),
    {ok, Packet} = i2p_ssu2:open_ephemeral(Sealed, Bik, Bik).

seal_open_long_roundtrip_test() ->
    Packet = crypto:strong_rand_bytes(80),
    {_Bpk, Bik} = bob_keys(),
    Sealed = i2p_ssu2:seal_long(Packet, Bik, Bik),
    {ok, Packet} = i2p_ssu2:open_long(Sealed, Bik, Bik).

%% The long-header third section (source id + token, bytes 16..31) must be
%% ChaCha20-obfuscated under the intro key with a zero nonce, per the spec,
%% not left plaintext (only bytes 0..15 carry XOR masks).
seal_long_obfuscates_headerx_test() ->
    Packet = crypto:strong_rand_bytes(80),
    {_Bpk, Bik} = bob_keys(),
    Sealed = i2p_ssu2:seal_long(Packet, Bik, Bik),
    <<_A:16/binary, HeaderX:16/binary, _/binary>> = Packet,
    <<_B:16/binary, SealedX:16/binary, _/binary>> = Sealed,
    ?assertNotEqual(HeaderX, SealedX).

seal_open_short_roundtrip_test() ->
    Packet = crypto:strong_rand_bytes(60),
    {_Bpk, Bik} = bob_keys(),
    Sealed = i2p_ssu2:seal_short(Packet, Bik, Bik),
    {ok, Packet} = i2p_ssu2:open_short(Sealed, Bik, Bik).

open_rejects_undersized_test() ->
    {_Bpk, Bik} = bob_keys(),
    ?assertEqual(error, i2p_ssu2:open_long(<<1, 2, 3>>, Bik, Bik)),
    ?assertEqual(error, i2p_ssu2:open_ephemeral(<<1, 2, 3>>, Bik, Bik)).

%%% --------------------------------------------------------------------------
%%% Payload blocks
%%% --------------------------------------------------------------------------

block_roundtrips_test() ->
    Blocks =
        [
            {datetime, 1700000000},
            {options, crypto:strong_rand_bytes(12)},
            {router_info, 2, crypto:strong_rand_bytes(64)},
            {i2np, 6, 1234, 1700000001, crypto:strong_rand_bytes(32)},
            {first_fragment, 6, 5678, 1700000002, crypto:strong_rand_bytes(16)},
            {follow_on_fragment, 2, true, 5678, crypto:strong_rand_bytes(16)},
            {ack, 10, 2, [{1, 2}, {2, 3}]},
            {termination, 77, 3, <<"bye">>},
            {address, 8888, <<192, 0, 2, 1>>},
            relay_tag_request,
            {relay_tag, 42},
            {new_token, 1700000099, 16#DEADBEEF},
            {path_challenge, <<"challenge">>},
            {path_response, <<"challenge">>},
            {first_packet_number, 5},
            {congestion, 1},
            {padding, <<1, 2, 3>>}
        ],
    Encoded = i2p_ssu2:encode_blocks(Blocks),
    {ok, Decoded} = i2p_ssu2:decode_blocks(Encoded),
    %% padding decodes as ignored, everything else round-trips exactly.
    Expected = lists:delete({padding, <<1, 2, 3>>}, Blocks),
    ?assertEqual(Expected, Decoded).

unknown_block_is_skipped_test() ->
    Payload = <<16#7F:8, 4:16, "abcd", 0:8, 4:16, 1700000000:32>>,
    {ok, [{datetime, 1700000000}]} = i2p_ssu2:decode_blocks(Payload).

%% PeerTest block (type 10) round-trips: messages 2/4 carry the 32-byte router
%% hash, messages 1/3/5/6/7 do not. Endpoint size is 6 (IPv4) or 18 (IPv6).
peertest_block_roundtrips_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Sig = crypto:strong_rand_bytes(64),
    Blocks =
        [
            {peertest, 1, 0, 0, <<0:256>>, 2, 16#12345678, 1700000000, 9150, <<192, 0, 2, 1>>, Sig},
            {peertest, 2, 0, 0, Hash, 2, 16#12345678, 1700000000, 9150, <<192, 0, 2, 1>>, Sig},
            {peertest, 3, 0, 0, <<0:256>>, 2, 16#12345678, 1700000000, 9150, <<192, 0, 2, 1>>, Sig},
            {peertest, 4, 0, 0, Hash, 2, 16#12345678, 1700000000, 9150, <<192, 0, 2, 1>>, Sig},
            {peertest, 5, 0, 0, <<0:256>>, 2, 16#12345678, 1700000000, 9150, <<192, 0, 2, 1>>,
                <<>>},
            {peertest, 6, 0, 0, <<0:256>>, 2, 16#12345678, 1700000000, 9150, <<192, 0, 2, 1>>,
                <<>>},
            {peertest, 7, 0, 0, <<0:256>>, 2, 16#12345678, 1700000000, 9150, <<192, 0, 2, 1>>, <<>>}
        ],
    Encoded = i2p_ssu2:encode_blocks(Blocks),
    {ok, Decoded} = i2p_ssu2:decode_blocks(Encoded),
    ?assertEqual(Blocks, Decoded).

peertest_block_ipv6_roundtrip_test() ->
    Ip6 = <<16#2001:16, 16#0DB8:16, 0:16, 0:16, 0:16, 0:16, 16#ABCD:16, 16#EF01:16>>,
    Block = {peertest, 1, 0, 0, <<0:256>>, 2, 11, 12, 13873, Ip6, <<>>},
    {ok, [Block]} = i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([Block])).

peertest_block_reject_code_roundtrip_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Reject = {peertest, 4, 1, 0, <<0:256>>, 2, 16#01020304, 13, 9150, <<192, 0, 2, 1>>, <<>>},
    ?assertEqual(
        Reject,
        hd(element(2, i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([Reject]))))
    ),
    %% messages 2/4 always carry a 32-byte hash in the wire encoding.
    Enc = i2p_ssu2:encode_blocks([{peertest, 4, 0, 0, Hash, 2, 1, 2, 3, <<192, 0, 2, 1>>, <<>>}]),
    <<_:8, _Len:16, Msg:8, Code:8, Flags:8, HashEnc:32/binary, _/binary>> = Enc,
    ?assertEqual(4, Msg),
    ?assertEqual(0, Code),
    ?assertEqual(0, Flags),
    ?assertEqual(Hash, HashEnc).

%% Relay blocks (7 = RelayRequest, 8 = RelayResponse, 9 = RelayIntro)
%% round-trip exactly, IPv4 and IPv6 endpoints.
relay_block_roundtrips_test() ->
    Sig = crypto:strong_rand_bytes(64),
    AliceHash = crypto:strong_rand_bytes(32),
    Blocks =
        [
            %% block 7: flag, nonce, relay tag, timestamp, ver, asz, port, ip, sig
            {relay_request, 0, 16#12345678, 16#DEADBEEF, 1700000000, 2, 9150, <<192, 0, 2, 1>>,
                Sig},
            %% block 8 accept with token: flag, code 0, nonce, ts, ver, csz, port, ip, sig, token
            {relay_response, 0, 0, 16#12345678, 1700000000, 2, 9151, <<192, 0, 2, 2>>, Sig, 99},
            %% block 9: flag, Alice hash, nonce, relay tag, ts, ver, asz, port, ip, sig
            {relay_intro, 0, AliceHash, 16#12345678, 16#DEADBEEF, 1700000000, 2, 9152,
                <<192, 0, 2, 3>>, Sig}
        ],
    Encoded = i2p_ssu2:encode_blocks(Blocks),
    {ok, Decoded} = i2p_ssu2:decode_blocks(Encoded),
    ?assertEqual(Blocks, Decoded).

relay_block_ipv6_roundtrip_test() ->
    Ip6 = <<16#2001:16, 16#0DB8:16, 0:16, 0:16, 0:16, 0:16, 16#ABCD:16, 16#EF01:16>>,
    Sig = crypto:strong_rand_bytes(64),
    Req = {relay_request, 0, 1, 2, 3, 2, 13873, Ip6, Sig},
    {ok, [Req]} = i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([Req])),
    AliceHash = crypto:strong_rand_bytes(32),
    Intro = {relay_intro, 0, AliceHash, 1, 2, 3, 2, 13873, Ip6, Sig},
    {ok, [Intro]} = i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([Intro])),
    Resp = {relay_response, 0, 0, 1, 3, 2, 13873, Ip6, Sig, 42},
    {ok, [Resp]} = i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([Resp])).

%% Every relay reject code round-trips: Bob 1-6, Charlie 64-70, and the
%% catch-all 128. Rejects carry the signature but no token.
relay_response_reject_codes_roundtrip_test() ->
    Sig = crypto:strong_rand_bytes(64),
    Codes = [1, 2, 3, 4, 5, 6, 64, 65, 66, 67, 68, 69, 70, 128],
    lists:foreach(
        fun(Code) ->
            Reject =
                {relay_response, 0, Code, 16#01020304, 1700000000, 2, 9150, <<192, 0, 2, 1>>, Sig,
                    undefined},
            ?assertEqual(
                Reject,
                hd(element(2, i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([Reject]))))
            )
        end,
        Codes
    ).

%% A relay reject with no endpoint (csz 0) round-trips: Bob/Charlie reject
%% codes where no Charlie endpoint is available.
relay_response_empty_endpoint_roundtrip_test() ->
    Sig = crypto:strong_rand_bytes(64),
    Reject = {relay_response, 0, 3, 16#01020304, 1700000000, 2, 0, <<>>, Sig, undefined},
    ?assertEqual(
        Reject,
        hd(element(2, i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([Reject]))))
    ).

%% An accept (code 0) with no token round-trips as `undefined` token.
relay_response_accept_no_token_roundtrip_test() ->
    Sig = crypto:strong_rand_bytes(64),
    Accept =
        {relay_response, 0, 0, 16#01020304, 1700000000, 2, 9150, <<192, 0, 2, 1>>, Sig, undefined},
    ?assertEqual(
        Accept,
        hd(element(2, i2p_ssu2:decode_blocks(i2p_ssu2:encode_blocks([Accept]))))
    ).

%% Malformed relay blocks fail closed: bad endpoint size, token on a reject,
%% truncated data.
relay_block_malformed_errors_test() ->
    %% asz 7 is not a valid endpoint size (must be 6 or 18).
    BadAsz = <<7:8, 5:16, 0:8, 1:32, 2:32, 3:32, 2:8, 7:8, 0:8, 0:8, 1, 2, 3, 4, 0:512>>,
    ?assertEqual(error, i2p_ssu2:decode_blocks(BadAsz)),
    %% a token trailing a reject (code 3) is malformed.
    Sig = crypto:strong_rand_bytes(64),
    TokenOnReject =
        <<8:8, 66:16, 0:8, 3:8, 1:32, 3:32, 2:8, 6:8, 0:8, 0:8, 192, 0, 2, 1, Sig/binary, 42:64>>,
    ?assertEqual(error, i2p_ssu2:decode_blocks(TokenOnReject)),
    %% truncated RelayRequest data.
    ?assertEqual(error, i2p_ssu2:decode_blocks(<<7:8, 84:16, 0:8>>)).

truncated_block_errors_test() ->
    ?assertEqual(error, i2p_ssu2:decode_blocks(<<0:8, 9:16, 1, 2>>)),
    ?assertEqual(error, i2p_ssu2:decode_blocks(<<0:8>>)).

ensure_min_payload_test() ->
    Short = i2p_ssu2:encode_blocks([{datetime, 1}]),
    ?assert(byte_size(Short) < 8),
    Padded = i2p_ssu2:ensure_min_payload(Short),
    ?assert(byte_size(Padded) >= 8),
    AlreadyBig = crypto:strong_rand_bytes(20),
    ?assertEqual(AlreadyBig, i2p_ssu2:ensure_min_payload(AlreadyBig)).

% ---------------------------------------------------------------------------
% ACK block construction / expansion
% ---------------------------------------------------------------------------

%% Fold a list of received packet numbers into a receive window, the way a
%% session does, and encode it. The numbers go in as a list because that is how
%% the SSU2 spec states its cases, but the window is what the session actually
%% holds and what the encoder actually walks -- so this drives the production
%% path rather than a test-only one. See #7GP4A4K.
ack_of(ReceivedNums, MaxRanges) ->
    i2p_ssu2:build_ack(window(ReceivedNums, MaxRanges), MaxRanges).

window(ReceivedNums, MaxRanges) ->
    lists:foldl(
        fun
            (Num, _W) when Num < 0 ->
                error;
            (Num, W) ->
                case i2p_ssu2_recv:add(Num, W, MaxRanges) of
                    {new, W1} -> W1;
                    duplicate -> W
                end
        end,
        i2p_ssu2_recv:new(),
        ReceivedNums
    ).

ack_single_packet_test() ->
    %% "we want to ACK packet 10 only"
    {ack, 10, 0, []} = ack_of([10], 100),
    ?assertEqual({[10], []}, i2p_ssu2:ack_expand({ack, 10, 0, []})).

ack_contiguous_run_test() ->
    %% "we want to ACK packets 8-10 only": AckThrough 10, acnt 2, no ranges.
    {ack, 10, 2, []} = ack_of([8, 9, 10], 100),
    ?assertEqual({[8, 9, 10], []}, i2p_ssu2:ack_expand({ack, 10, 2, []})).

ack_spec_worked_example_test() ->
    %% "we want to ACK 10 9 8 6 5 2 1 0, and NACK 7 4 3"
    Recv = [10, 9, 8, 6, 5, 2, 1, 0],
    {ack, 10, 2, [{1, 2}, {2, 3}]} = ack_of(Recv, 100),
    {Acked, Nacked} = i2p_ssu2:ack_expand({ack, 10, 2, [{1, 2}, {2, 3}]}),
    ?assertEqual([0, 1, 2, 5, 6, 8, 9, 10], Acked),
    ?assertEqual([3, 4, 7], Nacked).

ack_bounded_ranges_test() ->
    %% MaxRanges=1 drops the older range (packets 2 1 0 / nack 4 3).
    {ack, 10, 2, [{1, 2}]} = ack_of([10, 9, 8, 6, 5, 2, 1, 0], 1),
    %% MaxRanges=0 emits no ranges at all.
    {ack, 10, 2, []} = ack_of([10, 9, 8, 6, 5, 2, 1, 0], 0).

ack_literal_bytes_kat_test() ->
    %% Known-answer test for the happy-path ACK block (the follow-up to the
    %% removed `ack_wire_layout_test`): nothing asserts the literal wire bytes
    %% of an ACK. The spec's worked example [10 9 8 6 5 2 1 0] must encode as
    %% tag 12, length 9, AckThrough=10 (32-bit BE), Acnt=2 (8-bit), then the
    %% {Nack,Ack} range bytes {1,2} then {2,3} — every byte pinned by hand.
    Ack = ack_of([10, 9, 8, 6, 5, 2, 1, 0], 100),
    ?assertEqual({ack, 10, 2, [{1, 2}, {2, 3}]}, Ack),
    Wire = <<12:8, 9:16, 10:32, 2:8, 1:8, 2:8, 2:8, 3:8>>,
    ?assertEqual(Wire, i2p_ssu2:encode_blocks([Ack])),
    {ok, [Ack]} = i2p_ssu2:decode_blocks(Wire),
    %% The empty ACK: no gaps, AckThrough 0, Acnt 0 — 5 data bytes, no ranges.
    ?assertEqual(
        <<12:8, 5:16, 0:32, 0:8>>,
        i2p_ssu2:encode_blocks([ack_of([], 100)])
    ).

ack_empty_test() ->
    {ack, 0, 0, []} = ack_of([], 100).

ack_expand_roundtrip_test() ->
    %% Random received sets must round-trip through build_ack -> ack_expand.
    lists:foreach(
        fun({Recv, Max}) ->
            {ack, AT, Acnt, Ranges} = ack_of(Recv, Max),
            {Acked, _Nacked} = i2p_ssu2:ack_expand({ack, AT, Acnt, Ranges}),
            ?assertEqual(lists:usort(Recv), Acked)
        end,
        [
            {[0], 8},
            {[0, 1, 2, 3, 4, 5], 8},
            {[0, 2, 4, 6, 8, 10], 8},
            {[0, 1, 2, 5, 6, 9, 10], 8},
            {[1, 3, 5, 7, 9], 8},
            {lists:seq(0, 300), 100},
            {lists:seq(0, 40) -- [3, 15, 22, 29, 31], 20},
            {lists:seq(50, 70) -- lists:seq(55, 60), 10}
        ]
    ).

ack_zero_zero_range_rejected_test() ->
    %% A range where both nack and ack count are zero is forbidden.
    ?assertEqual(error, i2p_ssu2:decode_blocks(<<12:8, 9:16, 10:32, 2:8, 0:8, 0:8, 2:8, 3:8>>)).

ack_truncated_rejected_test() ->
    %% Trailing half-range byte fails closed.
    ?assertEqual(error, i2p_ssu2:decode_blocks(<<12:8, 8:16, 10:32, 2:8, 1:8, 2:8, 1>>)).

% ---------------------------------------------------------------------------
% I2NP fragmentation
% ---------------------------------------------------------------------------

fragment_i2np_single_test() ->
    Body = crypto:strong_rand_bytes(100),
    [First] = i2p_ssu2:fragment_i2np(6, 1234, 1700000000, Body, 200),
    ?assertMatch({first_fragment, 6, 1234, 1700000000, _}, First),
    {first_fragment, 6, 1234, _, FragBody} = First,
    ?assertEqual(Body, FragBody).

fragment_i2np_multi_test() ->
    Body = crypto:strong_rand_bytes(100),
    Frags = i2p_ssu2:fragment_i2np(6, 1234, 1700000000, Body, 30),
    ?assert(length(Frags) >= 4),
    {first_fragment, 6, 1234, _, F0} = lists:nth(1, Frags),
    Follows = lists:nthtail(1, Frags),
    ?assertEqual(byte_size(F0), 30),
    Combined =
        lists:foldl(
            fun({follow_on_fragment, _, _, _, B}, Acc) -> <<Acc/binary, B/binary>> end,
            F0,
            Follows
        ),
    ?assertEqual(Body, Combined),
    %% FragNum ascends and exactly the last follow-on is flagged IsLast.
    FragNums = [N || {follow_on_fragment, N, _, _, _} <- Follows],
    ?assertEqual(lists:seq(1, length(Follows)), FragNums),
    ?assertMatch(
        {follow_on_fragment, _N, true, _, _},
        lists:last(Frags)
    ).

fragment_i2np_exact_split_test() ->
    %% Body splitting exactly on the max size: one first + one last follow-on.
    Body = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Frags = i2p_ssu2:fragment_i2np(6, 9, 1700000000, Body, 4),
    ?assertEqual(
        [
            {first_fragment, 6, 9, 1700000000, <<1, 2, 3, 4>>},
            {follow_on_fragment, 1, true, 9, <<5, 6, 7, 8>>}
        ],
        Frags
    ).

%%% --------------------------------------------------------------------------
%%% Full handshake
%%% --------------------------------------------------------------------------

handshake_roundtrip_test() ->
    {Packets, KeysA, InfoB, Apk, _BlocksSent} = run_handshake(1200),
    ?assert(length(Packets) == 1),
    ?assertMatch(
        #{
            static_key := Apk,
            blocks := [{router_info, _, _} | _],
            keys := KeysA
        },
        InfoB
    ),
    ok.

fragmented_handshake_test() ->
    %% A tiny MTU forces the SessionConfirmed to split over many packets.
    {Packets, KeysA, InfoB, _Apk, _RI} = run_handshake(300),
    ?assert(length(Packets) > 1),
    #{keys := KeysB} = InfoB,
    ?assertEqual(KeysA, KeysB),
    ok.

tampered_session_request_rejected_test() ->
    {AlicePub, AlicePriv} = alice_keys(),
    {Bpk, Bik, BskPriv} = bob_full(),
    S0 = i2p_ssu2:alice_init(Bpk, Bik, AlicePriv, AlicePub),
    {ok, SR, _S1} =
        i2p_ssu2:create_session_request(
            S0,
            ephemeral(),
            16#AAAA,
            16#BBBB,
            0,
            1,
            [{datetime, 1700000000}]
        ),
    B0 = i2p_ssu2:bob_init(BskPriv, Bpk, Bik),
    Pos = byte_size(SR) - 20,
    <<Head:Pos/binary, Byte:8, Tail/binary>> = SR,
    BadSR = <<Head/binary, (Byte bxor 16#FF):8, Tail/binary>>,
    ?assertEqual(error, i2p_ssu2:receive_session_request(B0, BadSR)).

wrong_net_id_rejected_test() ->
    {AlicePub, AlicePriv} = alice_keys(),
    {Bpk, Bik, BskPriv} = bob_full(),
    S0 = i2p_ssu2:alice_init(Bpk, Bik, AlicePriv, AlicePub),
    {ok, SR, _S1} =
        i2p_ssu2:create_session_request(
            S0,
            ephemeral(),
            16#AAAA,
            16#BBBB,
            0,
            1,
            [{datetime, 1700000000}]
        ),
    %% Flip the net ID byte (offset 14 of the plaintext header; it is not
    %% covered by any mask-independent check, so re-seal via the codec by
    %% tampering after de-obfuscation is equivalent to crafting a packet).
    B0 = i2p_ssu2:bob_init(BskPriv, Bpk, Bik),
    Opened = open_with(Bik, SR),
    <<Head:15/binary, _BadNetId:8, Rest/binary>> = Opened,
    Forged = i2p_ssu2:seal_ephemeral(
        <<Head/binary, 9:8, Rest/binary>>,
        Bik,
        Bik
    ),
    ?assertEqual(error, i2p_ssu2:receive_session_request(B0, Forged)).

identical_conn_ids_rejected_test() ->
    %% The encoder refuses to build a datagram whose connection IDs match.
    {AlicePub, AlicePriv} = alice_keys(),
    {Bpk, Bik, _BskPriv} = bob_full(),
    S0 = i2p_ssu2:alice_init(Bpk, Bik, AlicePriv, AlicePub),
    Same = 16#ABCD,
    ?assertEqual(
        error,
        i2p_ssu2:create_session_request(S0, ephemeral(), Same, Same, 0, 1, [
            {datetime, 1700000000}
        ])
    ).

mirrored_conn_ids_enforced_via_real_handshake_test() ->
    {AlicePub, AlicePriv} = alice_keys(),
    {Bpk, Bik, BskPriv} = bob_full(),
    SA0 = i2p_ssu2:alice_init(Bpk, Bik, AlicePriv, AlicePub),
    {ok, SR, SA1} =
        i2p_ssu2:create_session_request(
            SA0,
            ephemeral(),
            16#AAAA,
            16#BBBB,
            0,
            1,
            [{datetime, 1700000000}]
        ),
    SB0 = i2p_ssu2:bob_init(BskPriv, Bpk, Bik),
    {ok, _Info, SB1} = i2p_ssu2:receive_session_request(SB0, SR),
    {ok, SC, _SB2} =
        i2p_ssu2:create_session_created(
            SB1,
            ephemeral(),
            2,
            [{datetime, 1700000000}]
        ),
    %% Corrupt the connection-ID fields of the opened datagram, then
    %% re-obfuscate with the SAME derived keys captured by intercepting:
    %% instead of intercepting, decode then verify the codec rejects a
    %% hand-made datagram carrying wrong IDs under the right keys.
    {ok, Open} = open_created(SC, SB1),
    <<_Hdr:32/binary, Y:32/binary, Rest/binary>> = Open,
    BadHeader = i2p_ssu2:long_header(16#FEED, 2, 1, 16#C0DE, 0),
    KH2 = maps:get(sess_create_header_key, SB1),
    Forged = i2p_ssu2:seal_ephemeral(
        <<BadHeader/binary, Y/binary, Rest/binary>>,
        Bik,
        KH2
    ),
    ?assertEqual(error, i2p_ssu2:receive_session_created(SA1, Forged)).

open_created(Packet, SB1) ->
    i2p_ssu2:open_ephemeral(
        Packet,
        maps:get(bik, SB1),
        maps:get(sess_create_header_key, SB1)
    ).

%%% --------------------------------------------------------------------------
%%% TokenRequest / Retry
%%% --------------------------------------------------------------------------

token_request_retry_test() ->
    {_Bpk, Bik} = bob_keys(),
    {ok, TR} =
        i2p_ssu2:encode_token_request(
            Bik,
            16#01020304,
            16#AAAA,
            16#BBBB,
            [{datetime, 1700000000}, {padding, <<0, 0>>}]
        ),
    {ok, #{src_conn_id := 16#BBBB, dst_conn_id := 16#AAAA}} =
        i2p_ssu2:decode_token_request(Bik, TR),
    {ok, Retry} =
        i2p_ssu2:encode_retry(
            Bik,
            16#05060708,
            16#BBBB,
            16#AAAA,
            16#CAFEBABE,
            [{datetime, 1700000001}, {address, 9150, <<127, 0, 0, 1>>}]
        ),
    {ok, #{token := 16#CAFEBABE, blocks := Blocks}} =
        i2p_ssu2:decode_retry(Bik, Retry),
    ?assertMatch(
        [{datetime, 1700000001}, {address, 9150, <<127, 0, 0, 1>>}],
        Blocks
    ).

token_request_wrong_key_rejected_test() ->
    {_Bpk, Bik} = bob_keys(),
    {ok, TR} =
        i2p_ssu2:encode_token_request(
            Bik,
            1,
            16#AAAA,
            16#BBBB,
            [{datetime, 1700000000}, {padding, <<0>>}]
        ),
    Sz = byte_size(TR) - 1,
    <<Head:Sz/binary, LastByte:8>> = TR,
    Flipped = <<Head/binary, (LastByte bxor 1):8>>,
    ?assertEqual(error, i2p_ssu2:decode_token_request(Bik, Flipped)).

%% Out-of-session PeerTest message (type 7): same symmetric framing as
%% TokenRequest/Retry, addressed straight at the recipient's intro key.
peertest_message_roundtrip_test() ->
    {_Bpk, Bik} = bob_keys(),
    Sig = crypto:strong_rand_bytes(64),
    PeerTest =
        {peertest, 5, 0, 0, <<0:256>>, 2, 16#12345678, 1700000000, 13873, <<192, 0, 2, 1>>, Sig},
    {ok, Msg} =
        i2p_ssu2:encode_peertest(
            Bik,
            16#01020304,
            16#AAAA,
            16#BBBB,
            [
                {peertest, 5, 0, 0, <<0:256>>, 2, 16#12345678, 1700000000, 13873, <<192, 0, 2, 1>>,
                    Sig}
            ]
        ),
    {ok, #{blocks := Blocks, dst_conn_id := 16#AAAA}} =
        i2p_ssu2:decode_peertest(Bik, Msg),
    ?assertEqual([PeerTest], Blocks).

peertest_message_wrong_key_rejected_test() ->
    {_Bpk, Bik} = bob_keys(),
    {ok, Msg} =
        i2p_ssu2:encode_peertest(Bik, 1, 16#AAAA, 16#BBBB, [
            {peertest, 5, 0, 0, <<0:256>>, 2, 1, 2, 3, <<192, 0, 2, 1>>, <<>>}
        ]),
    Sz = byte_size(Msg) - 1,
    <<Head:Sz/binary, LastByte:8>> = Msg,
    Flipped = <<Head/binary, (LastByte bxor 1):8>>,
    ?assertEqual(error, i2p_ssu2:decode_peertest(Bik, Flipped)).

%% A symmetric long-header datagram that stops inside its own Poly1305 tag is
%% short, not malformed, and the answer is `error` (#YNBT5ZD).
%%
%% The 32-byte long header leaves `Size - 32` bytes for ciphertext-plus-tag, so
%% every length from ?MIN_PACKET (40) up to 47 arrives with fewer than the 16
%% tag bytes. That used to reach `finish_symmetric/7`, where the split is a hard
%% match: `Sz` goes negative and the whole process died. On the listener this was
%% remote and unauthenticated, because the only thing standing between a
%% stranger's datagram and this code is the introduction key, which every
%% RouterInfo publishes.
%%
%% So it is asserted on all three symmetric decoders, at every short length, and
%% not merely that they answer: an assert that only catches `error` would still
%% pass if the function raised, since eunit reports a raise as a badmatch in the
%% test rather than a mismatch between two values.
truncated_symmetric_datagram_is_error_not_raise_test() ->
    {_Bpk, Bik} = bob_keys(),
    Decoders = [
        {"token_request", 10, fun(Dgram) -> i2p_ssu2:decode_token_request(Bik, Dgram) end},
        {"retry", 9, fun(Dgram) -> i2p_ssu2:decode_retry(Bik, Dgram) end},
        {"peertest", 7, fun(Dgram) -> i2p_ssu2:decode_peertest(Bik, Dgram) end},
        {"holepunch", 11, fun(Dgram) -> i2p_ssu2:decode_holepunch(Bik, Dgram) end}
    ],
    %% The whole table as one value, so a failure prints every case rather than
    %% whichever one the generator happened to reach first.
    ?assertEqual(
        [
            {Name, Size, error}
         || {Name, _Type, _Decode} <- Decoders, Size <- lists:seq(40, 47)
        ],
        [
            {Name, Size, outcome(Decode, build_short_symmetric(Bik, Type, Size))}
         || {Name, Type, Decode} <- Decoders, Size <- lists:seq(40, 47)
        ]
    ).

%% `error`, and specifically not a raise. A raise is turned into a value that
%% cannot be mistaken for an answer, so the assertion is about the outcome rather
%% than about there not having been one.
outcome(Decode, Dgram) ->
    try
        Decode(Dgram)
    catch
        Class:Reason -> {raised, Class, Reason}
    end.

%% A well-formed header carrying the decoder's own type, sealed for real and then
%% cut short. The masks are tail-derived, so the truncated bytes still unmask
%% correctly and the header really does present as the expected type -- which is
%% what leaves the length as the only thing wrong with it.
build_short_symmetric(Bik, Type, Size) ->
    Trailing = Size - 32,
    Plain = <<16#AABBCCDDEEFF0011:64, 1:32, Type:8, 2:8, 2:8, 0:8, 0:64, 0:64, 0:(Trailing * 8)>>,
    Sealed = i2p_ssu2:seal_long(Plain, Bik, Bik),
    ?assertEqual(Size, byte_size(Sealed)),
    Sealed.

%% Out-of-session HolePunch message (type 11): Charlie answers Alice with a
%% DateTime + Address + RelayResponse payload under her intro key. The
%% connection IDs are the relay-nonce pair (see relay_*_conn_id helpers).
holepunch_message_roundtrip_test() ->
    {_Bpk, Bik} = bob_keys(),
    Sig = crypto:strong_rand_bytes(64),
    Nonce = 16#12345678,
    Response =
        {relay_response, 0, 0, Nonce, 1700000000, 2, 13873, <<192, 0, 2, 1>>, Sig, 99},
    {ok, Msg} =
        i2p_ssu2:encode_holepunch(
            Bik,
            16#01020304,
            16#AAAA,
            16#BBBB,
            [
                {datetime, 1700000000},
                {address, 13873, <<192, 0, 2, 1>>},
                Response
            ]
        ),
    {ok, #{dst_conn_id := 16#AAAA, blocks := Blocks}} =
        i2p_ssu2:decode_holepunch(Bik, Msg),
    ?assertEqual(
        [
            {datetime, 1700000000},
            {address, 13873, <<192, 0, 2, 1>>},
            Response
        ],
        Blocks
    ).

holepunch_message_wrong_key_rejected_test() ->
    {_Bpk, Bik} = bob_keys(),
    {ok, Msg} =
        i2p_ssu2:encode_holepunch(Bik, 1, 16#AAAA, 16#BBBB, [
            {relay_response, 0, 0, 1, 2, 2, 3, <<192, 0, 2, 1>>, crypto:strong_rand_bytes(64), 9}
        ]),
    Sz = byte_size(Msg) - 1,
    <<Head:Sz/binary, LastByte:8>> = Msg,
    Flipped = <<Head/binary, (LastByte bxor 1):8>>,
    ?assertEqual(error, i2p_ssu2:decode_holepunch(Bik, Flipped)).

%%% --------------------------------------------------------------------------
%%% Data phase
%%% --------------------------------------------------------------------------

data_phase_roundtrip_test() ->
    Keys = sample_data_keys(),
    {_Bpk, Bik} = bob_keys(),
    Blocks = [{i2np, 6, 99, 1700000000, crypto:strong_rand_bytes(48)}],
    %% Alice -> Bob: receiver (Bob) masks with his own intro key... no:
    %% mask 1 uses the RECEIVER's intro key, so the sender passes the
    %% remote peer's intro key.
    {ok, PktAB} = i2p_ssu2:encode_data(Keys, ab, Bik, 0, 16#AAAA, Blocks),
    {ok, #{pkt_num := 0, blocks := Blocks}} =
        i2p_ssu2:decode_data(Keys, ab, Bik, PktAB),
    {ok, PktBA} = i2p_ssu2:encode_data(
        Keys,
        ba,
        Bik,
        7,
        16#BBBB,
        [{padding, <<1, 2, 3, 4, 5, 6>>}, {datetime, 1}]
    ),
    {ok, #{pkt_num := 7}} = i2p_ssu2:decode_data(Keys, ba, Bik, PktBA).

data_phase_tamper_rejected_test() ->
    Keys = sample_data_keys(),
    {_Bpk, Bik} = bob_keys(),
    {ok, Pkt} =
        i2p_ssu2:encode_data(
            Keys,
            ab,
            Bik,
            3,
            16#AAAA,
            [{datetime, 1700000000}]
        ),
    Pos = byte_size(Pkt) - 30,
    <<Head:Pos/binary, Byte:8, Tail/binary>> = Pkt,
    ?assertEqual(
        error,
        i2p_ssu2:decode_data(
            Keys,
            ab,
            Bik,
            <<Head/binary, (Byte bxor 16#80):8, Tail/binary>>
        )
    ).

data_phase_non_data_header_rejected_test() ->
    Keys = sample_data_keys(),
    {_Bpk, Bik} = bob_keys(),
    {ok, Pkt} =
        i2p_ssu2:encode_data(
            Keys,
            ab,
            Bik,
            0,
            16#AAAA,
            [{datetime, 1}]
        ),
    %% The data-phase header is conn_id(8) + pkt_num(4) + type(1) +
    %% immediate_ack(1) + reserved(2), so the type byte is at offset 12 -- and
    %% it reaches us header-masked, because seal_data/3 masks bytes 8..15. Its
    %% on-wire value therefore depends on the freshly generated keys.
    %%
    %% So do not write a fixed literal here: this used to overwrite the byte
    %% with 7, which is a no-op whenever the masked byte happens to BE 7, and
    %% decode_data/4 then accepted the packet. Measured over 3000 fresh key
    %% sets that collision hit 14 times, 0.467%, so the test failed roughly one
    %% run in 214 and looked perfectly stable in short streaks. Xor-ing a bit
    %% guarantees a different byte, which is what the intent actually needs.
    <<Pre:12/binary, Type:8, Post/binary>> = Pkt,
    ?assertEqual(
        error,
        i2p_ssu2:decode_data(
            Keys,
            ab,
            Bik,
            <<Pre/binary, (Type bxor 16#80):8, Post/binary>>
        )
    ).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

alice_keys() ->
    {KPub, KPriv} = i2p_crypto:x25519_keygen(),
    {KPriv, KPub}.

bob_keys() ->
    {Bpk, Bik, _BskPriv} = bob_full(),
    {Bpk, Bik}.

bob_full() ->
    {KPub, KPriv} = i2p_crypto:x25519_keygen(),
    {KPub, crypto:strong_rand_bytes(32), KPriv}.

ephemeral() ->
    {_Pub, Priv} = i2p_crypto:x25519_keygen(),
    Priv.

sample_data_keys() ->
    i2p_ssu2:data_keys(crypto:strong_rand_bytes(32)).

run_handshake(MaxPacketSize) ->
    {AlicePriv, AlicePub} = alice_keys(),
    {Bpk, Bik, BskPriv} = bob_full(),
    RI = crypto:strong_rand_bytes(400),
    %% -- Alice: SessionRequest
    SA0 = i2p_ssu2:alice_init(Bpk, Bik, AlicePriv, AlicePub),
    {ok, SR, SA1} =
        i2p_ssu2:create_session_request(
            SA0,
            ephemeral(),
            16#AAAA,
            16#BBBB,
            0,
            1,
            [{datetime, 1700000000}, {padding, crypto:strong_rand_bytes(11)}]
        ),
    %% -- Bob: receive, answer SessionCreated
    SB0 = i2p_ssu2:bob_init(BskPriv, Bpk, Bik),
    {ok, SRInfo, SB1} = i2p_ssu2:receive_session_request(SB0, SR),
    ?assertEqual(16#AAAA, maps:get(dst_conn_id, SRInfo)),
    ?assertEqual(16#BBBB, maps:get(src_conn_id, SRInfo)),
    {ok, SC, SB2} =
        i2p_ssu2:create_session_created(
            SB1,
            ephemeral(),
            2,
            [
                {datetime, 1700000001},
                {address, 9150, <<192, 0, 2, 9>>},
                {padding, crypto:strong_rand_bytes(13)}
            ]
        ),
    %% -- Alice: receive SessionCreated, send SessionConfirmed
    {ok, SCInfo, SA2} = i2p_ssu2:receive_session_created(SA1, SC),
    ?assertEqual(
        [
            {datetime, 1700000001},
            {address, 9150, <<192, 0, 2, 9>>}
        ],
        proplibs_delete_padding(maps:get(blocks, SCInfo))
    ),
    {ok, SCPackets, KeysA, _SA3} =
        i2p_ssu2:create_session_confirmed(
            SA2,
            [{router_info, 0, RI}, {padding, crypto:strong_rand_bytes(7)}],
            MaxPacketSize
        ),
    %% -- Bob: reassemble and confirm
    {ok, #{static_key := AlicePub, keys := _KeysB} = InfoB, _SB3} =
        i2p_ssu2:receive_session_confirmed(SB2, SCPackets),
    {SCPackets, KeysA, InfoB, AlicePub, RI}.

proplibs_delete_padding(Blocks) ->
    [B || B <- Blocks, element(1, B) =/= padding].

open_with(Bik, Packet) ->
    {ok, Opened} = i2p_ssu2:open_ephemeral(Packet, Bik, Bik),
    Opened.
