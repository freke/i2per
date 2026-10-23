%% Repliable (Datagram1) datagram codec. Round-trip preserves sender
%% destination and payload; the Ed25519 signature binds the payload, so any
%% tampering, foreign sender, truncation, or bad destination length fails
%% closed (error).
%%
%% Datagram2 (Proposal 163) adds the options Mapping (flag bit 4) and the
%% offline-signature section (flag bit 5) to the same framing. The options
%% and the offline section are covered by the signature, and an offline
%% section is only accepted when the sender's own key vouches
%% for it.

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
        {"unsupported flag bits fail closed", fun flag_bits2/0},
        {"options round-trip through the Mapping", fun options_roundtrip/0},
        {"options absent when the bit is clear", fun options_absent/0},
        {"options are covered by the signature", fun options_signed/0},
        {"malformed options fail closed", fun options_malformed/0},
        {"duplicate option keys are refused", fun options_duplicate/0},
        {"offline-signed datagrams verify against the sender key", fun offline_roundtrip/0},
        {"offline signature by a key other than from fails", fun offline_wrong_signer/0},
        {"tampered offline signature fails", fun offline_tampered/0},
        {"expired offline blocks fail closed", fun offline_expired/0},
        {"unsupported offline signature types fail closed", fun offline_sigtype/0},
        {"the transient key signs the payload", fun offline_transient_signs/0},
        {"options and offline section travel together", fun options_and_offline/0}
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
    %% A wrong version nibble, a reserved bit, and the two section bits
    %% without the sections they announce: all refused.
    lists:foreach(
        fun(Flags) ->
            ToSign = <<TargetHash:32/binary, Flags:16/big, Payload/binary>>,
            Sig = i2p_crypto:ed25519_sign(ToSign, Seed),
            Wire = <<FromBin:391/binary, Flags:16/big, Payload/binary, Sig:64/binary>>,
            ?assertEqual(error, i2p_datagram:decode2(Wire, TargetHash))
        end,
        [16#0001, 16#0003, 16#0040, 16#0012, 16#0022]
    ).

options_roundtrip() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Payload = <<"with options">>,
    Options = [{<<"b">>, <<"2">>}, {<<"a">>, <<"1">>}],
    {ok, Wire} = i2p_datagram:encode2(FromBin, Seed, TargetHash, Payload, #{options => Options}),
    %% The Mapping is a 2-byte size and the pairs that follow it: each pair
    %% is len + key + '=' + len + value + ';'.
    PairSize = 1 + 1 + 1 + 1 + 1 + 1,
    ?assertEqual(391 + 2 + 2 + 2 * PairSize + byte_size(Payload) + 64, byte_size(Wire)),
    {ok, Decoded} = i2p_datagram:decode2(Wire, TargetHash),
    ?assertEqual(16#0012, maps:get(flags, Decoded)),
    %% The keys come back sorted, as the spec wants for a signed mapping.
    ?assertEqual([{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}], maps:get(options, Decoded)),
    ?assertEqual(Payload, maps:get(payload, Decoded)).

options_absent() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    {ok, Wire} = i2p_datagram:encode2(FromBin, Seed, TargetHash, <<"plain">>),
    {ok, Decoded} = i2p_datagram:decode2(Wire, TargetHash),
    ?assertEqual(16#0002, maps:get(flags, Decoded)),
    ?assertNot(maps:is_key(options, Decoded)),
    ?assertNot(maps:is_key(offline, Decoded)).

options_signed() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    {ok, Wire} = i2p_datagram:encode2(
        FromBin, Seed, TargetHash, <<"payload">>, #{options => [{<<"k">>, <<"v">>}]}
    ),
    %% Change a byte inside the options. The mapping still parses, so the
    %% frame is only refused because the signature covers the section.
    <<Head:391/binary, Flags:16/big, Size:16/big, Body:Size/binary, Rest/binary>> = Wire,
    ?assertEqual(16#0012, Flags),
    Last = byte_size(Body) - 1,
    Tampered =
        <<Head/binary, Flags:16/big, Size:16/big, (binary:part(Body, 0, Last))/binary,
            (binary:at(Body, Last) bxor 16#FF), Rest/binary>>,
    ?assertEqual(error, i2p_datagram:decode2(Tampered, TargetHash)).

options_malformed() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Payload = <<"payload">>,
    %% Flag bit 4 set, but the section is not a Mapping: the frame cannot be
    %% parsed, so it is refused.
    lists:foreach(
        fun(Body) ->
            Flags = 16#0012,
            ToSign = <<TargetHash:32/binary, Flags:16/big, Body/binary, Payload/binary>>,
            Sig = i2p_crypto:ed25519_sign(ToSign, Seed),
            Wire = <<FromBin:391/binary, Flags:16/big, Body/binary, Payload/binary, Sig:64/binary>>,
            ?assertEqual(error, i2p_datagram:decode2(Wire, TargetHash))
        end,
        [
            %% a pair without the trailing ';'
            <<5:16/big, 1:8, "k", $=, 1:8, "v">>,
            %% a pair without the '='
            <<4:16/big, 1:8, "k", 1:8, "v">>,
            %% a length that runs past the section
            <<2:16/big, 9:8, "k">>
        ]
    ).

options_duplicate() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Duplicate = [{<<"k">>, <<"1">>}, {<<"k">>, <<"2">>}],
    ?assertEqual(
        error,
        i2p_datagram:encode2(FromBin, Seed, TargetHash, <<"x">>, #{options => Duplicate})
    ),
    %% An unknown option key is refused too.
    ?assertEqual(
        error,
        i2p_datagram:encode2(FromBin, Seed, TargetHash, <<"x">>, #{nonsense => [a]})
    ).

offline_roundtrip() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Payload = <<"offline signed">>,
    Block = offline_block(Seed),
    {ok, Wire} = i2p_datagram:encode2(
        FromBin, Seed, TargetHash, Payload, #{offline => Block}
    ),
    %% from + flags + expires + sigtype + pubkey + offsig + payload + sig
    ?assertEqual(391 + 2 + 4 + 2 + 32 + 64 + byte_size(Payload) + 64, byte_size(Wire)),
    {ok, Decoded} = i2p_datagram:decode2(Wire, TargetHash),
    ?assertEqual(16#0022, maps:get(flags, Decoded)),
    ?assertEqual(Payload, maps:get(payload, Decoded)),
    #{expires := Expires, sigtype := 7, pubkey := PubKey, offsig := OffSig} =
        maps:get(offline, Decoded),
    ?assertEqual(maps:get(expires, Block), Expires),
    ?assertEqual(maps:get(pubkey, Block), PubKey),
    ?assertEqual(maps:get(offsig, Block), OffSig).

offline_wrong_signer() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    #{identity := _OtherId, sign_priv := OtherSeed} = i2p_keys:generate_with_privkeys(),
    Block = offline_block(OtherSeed),
    {ok, Wire} = i2p_datagram:encode2(
        FromBin, Seed, TargetHash, <<"offline signed">>, #{offline => Block}
    ),
    %% The offline block is signed by a key other than `from`, so it is rejected.
    ?assertEqual(error, i2p_datagram:decode2(Wire, TargetHash)).

offline_tampered() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Block = offline_block(Seed),
    {ok, Wire} = i2p_datagram:encode2(
        FromBin, Seed, TargetHash, <<"offline signed">>, #{offline => Block}
    ),
    %% Flip a byte of the offline signature.
    <<Head:391/binary, Flags:16/big, Expires:32/big, SigType:16/big, PubKey:32/binary,
        OffSig:64/binary, Rest/binary>> = Wire,
    Broken =
        <<Head/binary, Flags:16/big, Expires:32/big, SigType:16/big, PubKey/binary,
            (binary:at(OffSig, 0) bxor 16#FF), (binary:part(OffSig, 1, 63))/binary, Rest/binary>>,
    ?assertEqual(error, i2p_datagram:decode2(Broken, TargetHash)).

offline_expired() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Block = offline_block(Seed, erlang:system_time(second) - 60),
    {ok, Wire} = i2p_datagram:encode2(
        FromBin, Seed, TargetHash, <<"offline signed">>, #{offline => Block}
    ),
    ?assertEqual(error, i2p_datagram:decode2(Wire, TargetHash)).

offline_sigtype() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Payload = <<"x">>,
    Block = offline_block(Seed),
    %% A signature type this codec does not sign with is refused on the
    %% way out and on the way in.
    ?assertEqual(
        error,
        i2p_datagram:encode2(
            FromBin, Seed, TargetHash, Payload, #{offline => Block#{sigtype => 3}}
        )
    ),
    Wire = offline_wire(FromBin, Seed, TargetHash, Payload, Block#{sigtype => 3}),
    ?assertEqual(error, i2p_datagram:decode2(Wire, TargetHash)).

offline_transient_signs() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Payload = <<"offline signed">>,
    Block = offline_block(Seed),
    %% The same frame, but the payload signed by the sender's own key
    %% instead of the transient one: the transient key is the only one the
    %% receiver accepts.
    Wire = offline_wire(FromBin, Seed, TargetHash, Payload, Block),
    ?assertEqual(error, i2p_datagram:decode2(Wire, TargetHash)),
    %% Signed by the transient key, it verifies.
    Wire2 = offline_wire(FromBin, maps:get(seed, Block), TargetHash, Payload, Block),
    ?assertMatch({ok, _}, i2p_datagram:decode2(Wire2, TargetHash)).

options_and_offline() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    FromBin = i2p_keys:to_binary(Id),
    TargetHash = crypto:hash(sha256, <<"target destination">>),
    Payload = <<"both">>,
    Block = offline_block(Seed),
    {ok, Wire} = i2p_datagram:encode2(
        FromBin,
        Seed,
        TargetHash,
        Payload,
        #{options => [{<<"k">>, <<"v">>}], offline => Block}
    ),
    {ok, Decoded} = i2p_datagram:decode2(Wire, TargetHash),
    ?assertEqual(16#0032, maps:get(flags, Decoded)),
    ?assertEqual([{<<"k">>, <<"v">>}], maps:get(options, Decoded)),
    ?assertEqual(Payload, maps:get(payload, Decoded)),
    ?assertMatch(#{pubkey := _}, maps:get(offline, Decoded)).

%%%%%%% %%% Internal %%%%%%%

%% offline_block/1 — the block the *sender* mints: a transient keypair, plus
%% the sender's own signature over the expiry, the transient signature type
%% and the transient public key. `SignerSeed` is the sender's signing seed.
offline_block(SignerSeed) ->
    offline_block(SignerSeed, erlang:system_time(second) + 3600).

offline_block(SignerSeed, Expires) ->
    {PubKey, Seed} = i2p_crypto:ed25519_keygen(),
    Signed = <<Expires:32/big, 7:16/big, PubKey/binary>>,
    OffSig = i2p_crypto:ed25519_sign(Signed, SignerSeed),
    #{
        expires => Expires,
        sigtype => 7,
        pubkey => PubKey,
        offsig => OffSig,
        seed => Seed
    }.

%% offline_wire/5 — the frame a sender builds by hand: the offline section
%% followed by the payload, signed by `SignSeed`.
offline_wire(FromBin, SignSeed, TargetHash, Payload, Block) ->
    #{expires := Expires, sigtype := SigType, pubkey := PubKey, offsig := OffSig} = Block,
    Section = <<Expires:32/big, SigType:16/big, PubKey/binary, OffSig/binary>>,
    Flags = 16#0022,
    ToSign = <<TargetHash:32/binary, Flags:16/big, Section/binary, Payload/binary>>,
    Sig = i2p_crypto:ed25519_sign(ToSign, SignSeed),
    <<FromBin:391/binary, Flags:16/big, Section/binary, Payload/binary, Sig:64/binary>>.
