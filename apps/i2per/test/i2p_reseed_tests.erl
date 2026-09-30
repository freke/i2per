%% Reseed pipeline. A localhost HTTP server (one gen_tcp accept per
%% request) serves SU3 files built in-test with a dedicated RSA-4096 key, so
%% the whole fetch -> verify -> unpack path runs offline.

-module(i2p_reseed_tests).

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% Pipeline
%% --------------------------------------------------------------------------

fetch_and_process_test() ->
    Ris = [router_info(4700), router_info(4701)],
    Port = serve_su3(sign(Ris)),
    {ok, Body} = i2p_reseed:fetch(url(Port)),
    {ok, Decoded} = i2p_reseed:process(Body, trust()),
    ?assertEqual(
        [i2p_router_info:hash(RI) || RI <- Ris],
        [i2p_router_info:hash(RI) || RI <- Decoded]
    ).

%% Fallback across hosts: a dead one first, then a live one.
%%
%% **Order matters here and it is load-bearing.** `f:serve_su3/1` binds an ephemeral
%% port and `f:dead_port/0` binds one and releases it, so asking for the dead port
%% *first* leaves the OS free to hand that same number straight back to
%% `f:serve_su3/1`. When it does, both URLs address the one-shot server: the first
%% fetch consumes its single accept and the second gets nothing, so the case fails
%% with `{error, no_router_infos}`.
%%
%% That is a flake, not a bug, and it is how this case failed roughly one run in
%% three -- with a report naming reseed and pointing at the reseed parser. Starting
%% the live server first and only then releasing a dead port removes it at the root:
%% a port held by a live listener cannot be allocated again, so the two are
%% guaranteed distinct.
run_falls_back_to_next_host_test() ->
    Ris = [router_info(4702)],
    LivePort = serve_su3(sign(Ris)),
    DeadPort = dead_port(),
    ?assertNotEqual(LivePort, DeadPort),
    {ok, [RI]} = i2p_reseed:run([url(DeadPort), url(LivePort)], trust()),
    ?assertEqual(i2p_router_info:hash(hd(Ris)), i2p_router_info:hash(RI)).

all_hosts_dead_test() ->
    ?assertMatch({error, _}, i2p_reseed:run([url(dead_port()), url(dead_port())])).

%% --------------------------------------------------------------------------
%% Rejections
%% --------------------------------------------------------------------------

unknown_signer_rejected_test() ->
    Su3 = sign([router_info(4703)]),
    ?assertEqual(
        {error, {unknown_signer, <<"test-signer">>}},
        i2p_reseed:process(Su3, #{})
    ).

tampered_file_rejected_test() ->
    Su3 = flip_last_byte(sign([router_info(4704)])),
    ?assertEqual({error, bad_signature}, i2p_reseed:process(Su3, trust())).

signer_cert_expired_rejected_test() ->
    {_Priv, _Cert} = keypair(),
    %% A trust anchor whose validity window closed in 2021 is refused before
    %% any signature work happens.
    #{cert := Expired} = public_key:pkix_test_root_cert(
        "expired-reseed",
        [{key, element(1, keypair())}, {validity, {{2020, 1, 1}, {2021, 1, 1}}}]
    ),
    Su3 = sign([router_info(4706)]),
    ?assertEqual(
        {error, {signer_cert_expired, <<"test-signer">>}},
        i2p_reseed:process(Su3, #{<<"test-signer">> => Expired})
    ).

not_a_reseed_file_rejected_test() ->
    %% Same signer and key as the happy path, but the container declares
    %% content type 1 (router update) instead of 3 (reseed).
    Bin = su3_with_content_type(1),
    ?assertEqual({error, not_a_reseed_file}, i2p_reseed:process(Bin, trust())).

bundled_trust_store_loads_test() ->
    %% The committed reseed anchors parse as RSA certificates. No time
    %% assertion here — expiry is enforced against live files at runtime.
    Store = i2p_reseed:load_trust_store(),
    ?assert(17 =< maps:size(Store)),
    maps:foreach(
        fun(SignerId, Der) ->
            _ = i2p_su3:cert_public_key(Der),
            ?assert(is_binary(SignerId))
        end,
        Store
    ).

real_live_su3_bundle_test() ->
    %% Captured from the current live reseed service. This is the public
    %% process/2 seam: the complete fetch, trust lookup, signature check,
    %% archive decode, and RouterInfo decode path must work against real data.
    Path = filename:join(["apps", "i2per", "test", "fixtures", "live_reseed.su3"]),
    {ok, Bin} = file:read_file(Path),
    {ok, Ris} = i2p_reseed:process(Bin, i2p_reseed:load_trust_store()),
    ?assertEqual(75, length(Ris)).

%% --------------------------------------------------------------------------
%% Fixtures
%% --------------------------------------------------------------------------

%% Shared with the other reseed-shaped suites and generated once per run. See
%% `i2p_ct_helpers:su3_keypair/0` for why the key is 4096 bits.
keypair() ->
    i2p_ct_helpers:su3_keypair().

trust() ->
    #{<<"test-signer">> => element(2, keypair())}.

sign(Ris) ->
    {Priv, _Cert} = keypair(),
    Zip = zip_ris(Ris),
    i2p_su3:encode(<<"1789000000">>, <<"test-signer">>, Zip, Priv).

su3_with_content_type(ContentType) ->
    {Priv, _Cert} = keypair(),
    Zip = zip_ris([router_info(4705)]),
    %% The spec pads the version to at least 16 bytes with trailing zeroes.
    Version0 = <<"1789000000">>,
    Pad = 16 - byte_size(Version0),
    Version = <<Version0/binary, 0:Pad/unit:8>>,
    SignerId = <<"test-signer">>,
    VLen = byte_size(Version),
    SignerLen = byte_size(SignerId),
    ContentLen = byte_size(Zip),
    Header =
        <<
            "I2Psu3",
            0:8,
            0:8,
            16#0006:16/big,
            512:16/big,
            0:8,
            VLen:8,
            0:8,
            SignerLen:8,
            ContentLen:64/big,
            0:8,
            0:8,
            0:8,
            ContentType:8,
            0:96
        >>,
    Signed = <<Header/binary, Version/binary, SignerId/binary, Zip/binary>>,
    Digest = crypto:hash(sha512, Signed),
    Signature = public_key:sign(Digest, sha512, Priv),
    <<Signed/binary, Signature/binary>>.

zip_ris(Ris) ->
    %% Entry names are strings: OTP 28's zip rejects binary names with einval.
    Entries = [
        {
            "routerInfo-" ++ binary_to_list(i2p_router_info:hash(RI)) ++ ".dat",
            i2p_router_info:to_binary(RI)
        }
     || RI <- Ris
    ],
    {ok, {_ArchiveName, ZipBin}} = zip:create("i2pseeds.zip", Entries, [memory]),
    ZipBin.

router_info(Port) ->
    {StaticPub, _StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed).

%% serve_su3/1 — start a one-shot HTTP server answering a single request with
%% Su3; returns its port.
serve_su3(Su3) ->
    {ok, Listen} = gen_tcp:listen(0, [
        {ip, {127, 0, 0, 1}},
        binary,
        {active, false},
        {reuseaddr, true}
    ]),
    {ok, Port} = inet:port(Listen),
    spawn_link(fun() -> serve_once(Listen, Su3) end),
    Port.

serve_once(Listen, Su3) ->
    {ok, Sock} = gen_tcp:accept(Listen, 10_000),
    {ok, _Request} = gen_tcp:recv(Sock, 0, 10_000),
    Response = [
        <<"HTTP/1.1 200 OK\r\n">>,
        <<"Content-Type: application/octet-stream\r\n">>,
        <<"Content-Length: ">>,
        integer_to_binary(byte_size(Su3)),
        <<"\r\n">>,
        <<"Connection: close\r\n\r\n">>,
        Su3
    ],
    ok = gen_tcp:send(Sock, Response),
    gen_tcp:close(Sock),
    gen_tcp:close(Listen).

dead_port() ->
    %% Bind and release an ephemeral port; nothing listens there now.
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    gen_tcp:close(L),
    Port.

url(Port) ->
    lists:flatten(io_lib:format("http://127.0.0.1:~b/", [Port])).

flip_last_byte(Bin) ->
    Len = byte_size(Bin),
    <<Prefix:(Len - 1)/binary, B:8>> = Bin,
    <<Prefix:(Len - 1)/binary, (B bxor 1):8>>.
