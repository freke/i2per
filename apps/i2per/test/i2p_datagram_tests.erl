%% Repliable (Datagram1) datagram codec. Round-trip preserves sender
%% destination and payload; the Ed25519 signature binds the payload, so any
%% tampering, foreign sender, truncation, or bad destination length fails
%% closed (error).

-module(i2p_datagram_tests).

-include_lib("eunit/include/eunit.hrl").

datagram_codec_test_() ->
    [
        {"round-trip keeps sender destination and payload", fun roundtrip/0},
        {"tampered payload fails authentication", fun tampered/0},
        {"signature by another key fails", fun foreign_signer/0},
        {"malformed frames fail closed", fun malformed/0}
    ].

roundtrip() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    Payload = <<"ping over tunnels">>,
    {ok, Wire} = i2p_datagram:encode(FromBin, Seed, Payload),
    ?assertEqual(391 + 64 + byte_size(Payload), byte_size(Wire)),
    {ok, #{from := FromBin, payload := Payload}} = i2p_datagram:decode(Wire).

tampered() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    {ok, Wire} = i2p_datagram:encode(i2p_keys:to_binary(Id), Seed, <<"attack at dawn">>),
    HeadSize = 391 + 64,
    <<Head:HeadSize/binary, P, Rest/binary>> = Wire,
    ?assertEqual(error, i2p_datagram:decode(<<Head/binary, (P bxor 16#FF), Rest/binary>>)).

foreign_signer() ->
    #{sign_priv := SeedA} = i2p_keys:generate_with_privkeys(),
    #{identity := IdB} = i2p_keys:generate_with_privkeys(),
    %% Signed by A but claims B as sender: the embedded signature does not
    %% verify against B's public signing key.
    {ok, Wire} = i2p_datagram:encode(i2p_keys:to_binary(IdB), SeedA, <<"spoof">>),
    ?assertEqual(error, i2p_datagram:decode(Wire)).

malformed() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    {ok, Wire} = i2p_datagram:encode(FromBin, Seed, <<"payload">>),
    %% Truncated below from+signature minimum
    ?assertEqual(error, i2p_datagram:decode(binary:part(Wire, 0, 400))),
    ?assertEqual(error, i2p_datagram:decode(<<>>)),
    ?assertEqual(error, i2p_datagram:decode(<<0, 1, 2, 3>>)),
    %% Non-binary input
    ?assertEqual(error, i2p_datagram:decode(wrong)),
    %% Sender destination must be a full 391-byte binary
    ?assertEqual(error, i2p_datagram:encode(<<0:16/unit:8>>, Seed, <<"x">>)),
    %% Target hash must be 32 bytes
    ?assertEqual(error, i2p_datagram:encode2(FromBin, Seed, <<0:16/unit:8>>, <<"x">>)),
    %% Payload must be a binary
    ?assertEqual(
        error, i2p_datagram:encode2(FromBin, Seed, crypto:hash(sha256, <<"t">>), not_a_binary)
    ).

datagram2_codec_test_() ->
    [
        {"round-trip keeps sender destination and payload", fun roundtrip2/0},
        {"tampered payload fails authentication", fun tampered2/0},
        {"signature by another key fails", fun foreign_signer2/0},
        {"malformed frames fail closed", fun malformed2/0},
        {"unsupported flag bits fail closed", fun flag_bits2/0}
    ].

roundtrip2() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Payload = <<"ping over datagram2">>,
    {ok, Wire} = i2p_datagram:encode2(FromBin, Seed, TargetHash, Payload),
    ?assertEqual(391 + 2 + byte_size(Payload) + 64, byte_size(Wire)),
    {ok, #{from := FromBin, payload := Payload, flags := 16#0002}} =
        i2p_datagram:decode2(Wire, TargetHash).

tampered2() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    {ok, Wire} = i2p_datagram:encode2(
        i2p_keys:to_binary(Id), Seed, TargetHash, <<"attack at dawn">>
    ),
    HeadSize = 391 + 2,
    <<Head:HeadSize/binary, P, Rest/binary>> = Wire,
    ?assertEqual(
        error, i2p_datagram:decode2(<<Head/binary, (P bxor 16#FF), Rest/binary>>, TargetHash)
    ).

foreign_signer2() ->
    #{sign_priv := SeedA} = i2p_keys:generate_with_privkeys(),
    #{identity := IdB} = i2p_keys:generate_with_privkeys(),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    {ok, Wire} = i2p_datagram:encode2(i2p_keys:to_binary(IdB), SeedA, TargetHash, <<"spoof">>),
    ?assertEqual(error, i2p_datagram:decode2(Wire, TargetHash)).

malformed2() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    {ok, Wire} = i2p_datagram:encode2(FromBin, Seed, TargetHash, <<"payload">>),
    ?assertEqual(error, i2p_datagram:decode2(binary:part(Wire, 0, 400), TargetHash)),
    ?assertEqual(error, i2p_datagram:decode2(<<>>, TargetHash)),
    ?assertEqual(error, i2p_datagram:decode2(<<0, 1, 2, 3>>, TargetHash)),
    ?assertEqual(error, i2p_datagram:decode2(Wire, wrong)),
    ?assertEqual(error, i2p_datagram:decode2(Wire, <<0:16/unit:8>>)),
    ?assertEqual(error, i2p_datagram:decode2(not_a_binary, TargetHash)).

flag_bits2() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Payload = <<"payload">>,
    lists:foreach(
        fun(Flags) ->
            ToSign = <<TargetHash:32/binary, Flags:16/big, Payload/binary>>,
            Sig = i2p_crypto:ed25519_sign(ToSign, Seed),
            Wire = <<FromBin:391/binary, Flags:16/big, Payload/binary, Sig:64/binary>>,
            ?assertEqual(error, i2p_datagram:decode2(Wire, TargetHash))
        end,
        [16#0012, 16#0022]
    ).
