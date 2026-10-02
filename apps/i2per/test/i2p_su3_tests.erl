%% SU3 container codec. Round-trips are built with an in-test
%% RSA-4096 key and self-signed certificate; negative tests mutate single
%% header fields and expect precise rejections.

-module(i2p_su3_tests).

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% Round-trip
%% --------------------------------------------------------------------------

round_trip_test_() ->
    {timeout, 60, fun round_trip/0}.

round_trip() ->
    {Priv, Cert} = keypair(),
    Content = crypto:strong_rand_bytes(1024),
    Bin = i2p_su3:encode(<<"1789000000">>, <<"alice@mail.i2p">>, Content, Priv),
    {ok, Su3} = i2p_su3:decode(Bin),
    ?assertEqual(<<"1789000000">>, i2p_su3:version(Su3)),
    ?assertEqual(<<"alice@mail.i2p">>, i2p_su3:signer_id(Su3)),
    ?assertEqual(0, i2p_su3:file_type(Su3)),
    ?assertEqual(3, i2p_su3:content_type(Su3)),
    ?assertEqual(Content, i2p_su3:content(Su3)),
    ?assertEqual(ok, i2p_su3:verify(Su3, Cert)).

long_version_not_padded_test_() ->
    {timeout, 60, fun long_version_not_padded/0}.

long_version_not_padded() ->
    %% A version already >= 16 bytes must be carried verbatim.
    {Priv, Cert} = keypair(),
    Version = binary:copy(<<"v">>, 20),
    Bin = i2p_su3:encode(Version, <<"s">>, <<>>, Priv),
    {ok, Su3} = i2p_su3:decode(Bin),
    ?assertEqual(Version, i2p_su3:version(Su3)),
    ?assertEqual(ok, i2p_su3:verify(Su3, Cert)).

%% --------------------------------------------------------------------------
%% Left-padding of short signatures
%% --------------------------------------------------------------------------

%% A raw RSA signature shorter than the declared 512 bytes must be left-padded
%% with exactly the missing bytes. Roughly 0.5% of RSA-4096 signatures come
%% back 511 bytes, so an encode/decode round-trip is not a reliable regression
%% guard. A 1024-bit key always yields a signature of at most 128 bytes, which
%% makes the short-signature path deterministic.

short_signature_padded_to_declared_length_test_() ->
    {timeout, 60, fun short_signature_padded_to_declared_length/0}.

short_signature_padded_to_declared_length() ->
    Priv = public_key:generate_key({rsa, 1024, 65537}),
    Content = crypto:strong_rand_bytes(1024),
    Bin = i2p_su3:encode(<<"1789000000">>, <<"alice@mail.i2p">>, Content, Priv),
    ?assertEqual(40 + 16 + 14 + byte_size(Content) + 512, byte_size(Bin)),
    {ok, Su3} = i2p_su3:decode(Bin),
    ?assertEqual(Content, i2p_su3:content(Su3)).

short_signature_verifies_test_() ->
    {timeout, 60, fun short_signature_verifies/0}.

short_signature_verifies() ->
    Priv = public_key:generate_key({rsa, 1024, 65537}),
    #{cert := Cert} = public_key:pkix_test_root_cert("su3-short", [{key, Priv}]),
    Content = crypto:strong_rand_bytes(1024),
    Bin = i2p_su3:encode(<<"1789000000">>, <<"alice@mail.i2p">>, Content, Priv),
    {ok, Su3} = i2p_su3:decode(Bin),
    ?assertEqual(Content, i2p_su3:content(Su3)),
    ?assertEqual(ok, i2p_su3:verify(Su3, Cert)).

%% --------------------------------------------------------------------------
%% Signature failures
%% --------------------------------------------------------------------------

tampered_content_rejected_test_() ->
    {timeout, 60, fun tampered_content_rejected/0}.

tampered_content_rejected() ->
    {Priv, Cert} = keypair(),
    Bin0 = i2p_su3:encode(<<"1789000000">>, <<"s">>, <<"payload">>, Priv),
    BodyLen = byte_size(Bin0) - 512,
    <<Body:BodyLen/binary, Sig:512/binary>> = Bin0,
    TamperedBody = flip_last_byte(Body),
    Tampered = <<TamperedBody/binary, Sig/binary>>,
    {ok, Su3} = i2p_su3:decode(Tampered),
    ?assertEqual({error, bad_signature}, i2p_su3:verify(Su3, Cert)).

tampered_signature_rejected_test_() ->
    {timeout, 60, fun tampered_signature_rejected/0}.

tampered_signature_rejected() ->
    {Priv, Cert} = keypair(),
    Bin0 = i2p_su3:encode(<<"1789000000">>, <<"s">>, <<"payload">>, Priv),
    BodyLen = byte_size(Bin0) - 512,
    <<Body:BodyLen/binary, Sig:512/binary>> = Bin0,
    Tampered = <<Body:BodyLen/binary, (flip_last_byte(Sig))/binary>>,
    {ok, Su3} = i2p_su3:decode(Tampered),
    ?assertEqual({error, bad_signature}, i2p_su3:verify(Su3, Cert)).

wrong_certificate_rejected_test_() ->
    {timeout, 60, fun wrong_certificate_rejected/0}.

wrong_certificate_rejected() ->
    {Priv, _Cert} = keypair(),
    {_OtherPriv, OtherCert} = other_keypair(),
    Bin = i2p_su3:encode(<<"1789000000">>, <<"s">>, <<"x">>, Priv),
    {ok, Su3} = i2p_su3:decode(Bin),
    ?assertEqual({error, bad_signature}, i2p_su3:verify(Su3, OtherCert)).

%% --------------------------------------------------------------------------
%% Header rejections
%% --------------------------------------------------------------------------

truncated_header_rejected_test_() ->
    {timeout, 60, fun truncated_header_rejected/0}.

truncated_header_rejected() ->
    ?assertEqual({error, truncated_header}, i2p_su3:decode(binary:part(i2psu3(), 39, 1))).

bad_magic_rejected_test_() ->
    {timeout, 60, fun bad_magic_rejected/0}.

bad_magic_rejected() ->
    BadMagic = <<"SU3!">>,
    ?assertEqual(
        {error, bad_magic},
        i2p_su3:decode(<<BadMagic/binary, 0:288>>)
    ).

bad_format_version_rejected_test_() ->
    {timeout, 60, fun bad_format_version_rejected/0}.

bad_format_version_rejected() ->
    Bin = set_header_byte(i2psu3(), 7, 1),
    ?assertEqual({error, bad_format_version}, i2p_su3:decode(Bin)).

unsupported_signature_type_rejected_test_() ->
    {timeout, 60, fun unsupported_signature_type_rejected/0}.

unsupported_signature_type_rejected() ->
    %% Type 7 (EdDSA-SHA512-Ed25519ph) exists on the wire but is not supported.
    TypeBin = set_header_bytes(i2psu3(), 8, <<7:16/big>>),
    ?assertEqual(
        {error, {unsupported_signature_type, 7}},
        i2p_su3:decode(TypeBin)
    ).

bad_signature_length_rejected_test_() ->
    {timeout, 60, fun bad_signature_length_rejected/0}.

bad_signature_length_rejected() ->
    Bin = set_header_bytes(i2psu3(), 10, <<256:16/big>>),
    ?assertEqual({error, bad_signature_length}, i2p_su3:decode(Bin)).

short_version_rejected_test_() ->
    {timeout, 60, fun short_version_rejected/0}.

short_version_rejected() ->
    Bin = set_header_byte(i2psu3(), 13, 15),
    ?assertEqual({error, short_version}, i2p_su3:decode(Bin)).

trailing_data_rejected_test_() ->
    {timeout, 60, fun trailing_data_rejected/0}.

trailing_data_rejected() ->
    Bin = i2psu3(),
    ?assertEqual({error, trailing_data}, i2p_su3:decode(<<Bin/binary, 0:8>>)).

truncated_body_rejected_test_() ->
    {timeout, 60, fun truncated_body_rejected/0}.

truncated_body_rejected() ->
    Bin = i2psu3(),
    ?assertEqual({error, truncated}, i2p_su3:decode(binary:part(Bin, 0, byte_size(Bin) - 1))).

%% --------------------------------------------------------------------------
%% Certificate helpers
%% --------------------------------------------------------------------------

cert_valid_at_now_test_() ->
    {timeout, 60, fun cert_valid_at_now/0}.

cert_valid_at_now() ->
    {_Priv, Cert} = keypair(),
    ?assert(i2p_su3:cert_valid_at(Cert, calendar:universal_time())).

cert_expired_test_() ->
    {timeout, 60, fun cert_expired/0}.

cert_expired() ->
    {_Priv, Cert} = keypair(),
    ?assertNot(i2p_su3:cert_valid_at(Cert, {{2100, 1, 1}, {0, 0, 0}})).

%% --------------------------------------------------------------------------
%% Fixtures
%% --------------------------------------------------------------------------

%% i2psu3/0 — one valid container, memoised so the encoding is done once. The
%% signing key is shared per run; see `i2p_ct_helpers:su3_keypair/0`.
i2psu3() ->
    {Priv, _Cert} = keypair(),
    case persistent_term:get({?MODULE, su3}, undefined) of
        undefined ->
            Bin = i2p_su3:encode(<<"1789000000">>, <<"memo">>, <<"content">>, Priv),
            persistent_term:put({?MODULE, su3}, Bin),
            Bin;
        Bin ->
            Bin
    end.

keypair() -> i2p_ct_helpers:su3_keypair().

other_keypair() -> i2p_ct_helpers:su3_other_keypair().

%% The signing identity is generated once per run by
%% `i2p_ct_helpers:su3_keypair/0`, which is also why this module keeps no keygen
%% of its own.

flip_last_byte(Bin) ->
    Len = byte_size(Bin),
    <<Prefix:(Len - 1)/binary, B:8>> = Bin,
    <<Prefix:(Len - 1)/binary, (B bxor 1):8>>.

set_header_byte(Bin, Offset, Byte) when is_integer(Byte) ->
    set_header_bytes(Bin, Offset, <<Byte:8>>).

set_header_bytes(Bin, Offset, Bytes) ->
    Size = byte_size(Bytes),
    <<Head:Offset/binary, _Old:Size/binary, Tail/binary>> = Bin,
    <<Head:Offset/binary, Bytes/binary, Tail/binary>>.
