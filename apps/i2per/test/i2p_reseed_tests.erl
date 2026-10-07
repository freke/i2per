%% Reseed pipeline. A localhost HTTP server (i2p_ct_helpers:serve_su3/1 —
%% every request in the case, kept up until teardown) serves SU3 files built
%% in-test with a dedicated RSA-4096 key, so the whole fetch -> verify ->
%% unpack path runs offline.

-module(i2p_reseed_tests).

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% Pipeline
%% --------------------------------------------------------------------------

fetch_and_process_test_() ->
    {timeout, 60, fun fetch_and_process/0}.

fetch_and_process() ->
    Ris = [router_info(4700), router_info(4701)],
    {Port, Srv} = i2p_ct_helpers:serve_su3(sign(Ris)),
    try
        {ok, Body} = i2p_reseed:fetch(url(Port)),
        {ok, Decoded} = i2p_reseed:process(Body, trust()),
        ?assertEqual(
            [i2p_router_info:hash(RI) || RI <- Ris],
            [i2p_router_info:hash(RI) || RI <- Decoded]
        )
    after
        i2p_ct_helpers:stop_su3_server(Srv)
    end.

%% Fallback across hosts: a dead one first, then a live one.
%%
%% **Order matters here and it is load-bearing.** `f:dead_port/0` binds a port
%% and releases it because a refused connection needs nothing listening;
%% `f:serve_su3/1` holds the live port for the whole case, so asking for the
%% dead port cannot shadow the live one — a held port cannot be allocated to
%% two paths at once. Binding the dead port first would leave the OS free to
%% hand that same number to a later bind, so the live server comes up first.
run_falls_back_to_next_host_test_() ->
    {timeout, 60, fun run_falls_back_to_next_host/0}.

run_falls_back_to_next_host() ->
    Ris = [router_info(4702)],
    {LivePort, Srv} = i2p_ct_helpers:serve_su3(sign(Ris)),
    try
        DeadPort = dead_port(),
        ?assertNotEqual(LivePort, DeadPort),
        {ok, [RI]} = i2p_reseed:run([url(DeadPort), url(LivePort)], trust()),
        ?assertEqual(i2p_router_info:hash(hd(Ris)), i2p_router_info:hash(RI))
    after
        i2p_ct_helpers:stop_su3_server(Srv)
    end.

all_hosts_dead_test() ->
    ?assertMatch({error, _}, i2p_reseed:run([url(dead_port()), url(dead_port())])).

%% --------------------------------------------------------------------------
%% Rejections
%% --------------------------------------------------------------------------

unknown_signer_rejected_test_() ->
    {timeout, 60, fun unknown_signer_rejected/0}.

unknown_signer_rejected() ->
    Su3 = sign([router_info(4703)]),
    ?assertEqual(
        {error, {unknown_signer, <<"test-signer">>}},
        i2p_reseed:process(Su3, #{})
    ).

tampered_file_rejected_test_() ->
    {timeout, 60, fun tampered_file_rejected/0}.

tampered_file_rejected() ->
    Su3 = flip_last_byte(sign([router_info(4704)])),
    ?assertEqual({error, bad_signature}, i2p_reseed:process(Su3, trust())).

signer_cert_expired_rejected_test_() ->
    {timeout, 60, fun signer_cert_expired_rejected/0}.

signer_cert_expired_rejected() ->
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

not_a_reseed_file_rejected_test_() ->
    {timeout, 60, fun not_a_reseed_file_rejected/0}.

not_a_reseed_file_rejected() ->
    %% Same signer and key as the happy path, but the container declares
    %% content type 1 (router update) instead of 3 (reseed).
    Bin = su3_with_content_type(1),
    ?assertEqual({error, not_a_reseed_file}, i2p_reseed:process(Bin, trust())).

bundled_trust_store_loads_test_() ->
    {timeout, 60, fun bundled_trust_store_loads/0}.

bundled_trust_store_loads() ->
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

real_live_su3_bundle_test_() ->
    {timeout, 60, fun real_live_su3_bundle/0}.

real_live_su3_bundle() ->
    %% Captured from the current live reseed service. This is the public
    %% process/2 seam: the complete fetch, trust lookup, signature check,
    %% archive decode, and RouterInfo decode path must work against real data.
    Path = filename:join(["apps", "i2per", "test", "fixtures", "live_reseed.su3"]),
    {ok, Bin} = file:read_file(Path),
    {ok, Ris} = i2p_reseed:process(Bin, i2p_reseed:load_trust_store()),
    ?assertEqual(75, length(Ris)).

%% --------------------------------------------------------------------------
%% Entry names
%% --------------------------------------------------------------------------

%% #Q6NKB9P. The entry-name filter asked `filename:extension/1`, which reads `/`
%% as a directory separator -- so an entry named `routerInfo-<31 bytes>/.dat`
%% reported no extension, the filter said no, and the RouterInfo behind it was
%% dropped. Silently, because the filter was a comprehension clause: a bundle of
%% two came back as one, the NetDb stayed a router short, and nothing anywhere
%% said so. Observed once in roughly 128 reseeds from the three suites that built
%% their entry names out of raw hash bytes rather than the spec's Base64.
entry_name_with_a_slash_is_still_taken_test_() ->
    {timeout, 60, fun entry_name_with_a_slash_is_still_taken/0}.

entry_name_with_a_slash_is_still_taken() ->
    RI = router_info(4707),
    Hash = i2p_router_info:hash(RI),
    %% The last hash byte replaced by a `/`, so the name ends `/.dat` exactly as
    %% the fixtures' raw-byte names did one time in 256.
    Name = "routerInfo-" ++ binary_to_list(binary:part(Hash, 0, 31)) ++ "/.dat",
    ?assertEqual(<<>>, filename:extension(list_to_binary(Name))),
    Su3 = sign_named([{Name, i2p_router_info:to_binary(RI)}]),
    ?assertMatch({ok, [RI]}, i2p_reseed:process(Su3, trust())).

%% A name is a name: `routerInfo-<hash>.dat` with anything in between, and the
%% `.dat` suffix matched wherever it falls.
entry_name_matching_is_not_a_path_query_test_() ->
    {timeout, 60, fun entry_name_matching_is_not_a_path_query/0}.

entry_name_matching_is_not_a_path_query() ->
    RI = router_info(4708),
    Hash = i2p_router_info:hash(RI),
    Taken = [
        {"routerInfo-" ++ binary_to_list(Hash) ++ ".dat", i2p_router_info:to_binary(RI)},
        {"routerInfo-" ++ binary_to_list(Hash) ++ "/sub.dat", i2p_router_info:to_binary(RI)},
        {"routerInfo-.dat", i2p_router_info:to_binary(RI)}
    ],
    NotTaken = [
        {"routerInfo-" ++ binary_to_list(Hash), i2p_router_info:to_binary(RI)},
        {"routerInfo-" ++ binary_to_list(Hash) ++ ".dat.bak", i2p_router_info:to_binary(RI)},
        {"leaset-" ++ binary_to_list(Hash) ++ ".dat", i2p_router_info:to_binary(RI)},
        {"README", i2p_router_info:to_binary(RI)}
    ],
    {ok, Ris} = i2p_reseed:process(sign_named(Taken), trust()),
    ?assertEqual(3, length(Ris)),
    %% Nothing left, so the bundle is refused rather than half-accepted: the
    %% name filter is what decides this, and it decides all four.
    ?assertEqual({error, no_router_infos}, i2p_reseed:process(sign_named(NotTaken), trust())).

%% An entry this module cannot take is recorded, not dropped. `reseed_failed`
%% covers the bundle; nothing covered the entries, which is how a NetDb ended up
%% one router short with every other line saying the reseed had worked.
skipped_entries_are_recorded_test_() ->
    {timeout, 60, fun skipped_entries_are_recorded/0}.

skipped_entries_are_recorded() ->
    Good = router_info(4709),
    %% Two entries this module will not take: one whose name is not one it
    %% recognises, and one whose name is fine but whose bytes are not a
    %% RouterInfo.
    Names = [
        {"README", <<"not a router info">>},
        {"routerInfo-broken.dat", <<"not a router info either">>}
    ],
    Entries = [{"routerInfo-good.dat", i2p_router_info:to_binary(Good)} | Names],
    Events = i2p_ct_helpers:log_events_from(
        fun() ->
            {ok, [Good]} = i2p_reseed:process(sign_named(Entries), trust())
        end
    ),
    Lines = [i2p_ct_helpers:render_log_event(E) || E <- Events],
    %% **Both reasons, and both at `warning`.** The checklist row says
    %% `warning`, and this is the assertion that the row and the call site
    %% agree -- text alone would pass for the same line recorded at any level.
    Skipped = [E || #{msg := {Format, Args}} = E <- Events, is_skip(Format, Args)],
    ?assertEqual(2, length(Skipped)),
    lists:foreach(fun(#{level := L}) -> ?assertEqual(warning, L) end, Skipped),
    ?assert(lists:any(fun(L) -> string:find(L, "README") =/= nomatch end, Lines)),
    ?assert(
        lists:any(fun(L) -> string:find(L, "routerInfo-broken.dat") =/= nomatch end, Lines)
    ).

%% The one line this module writes about an entry it did not take. Matched on
%% the reason argument so the two entries above cannot both be counted by one
%% line.
is_skip("reseed bundle entry ~0p skipped: ~0p", [_Name, Reason]) ->
    Reason =/= undefined;
is_skip(_, _) ->
    false.

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

%% A bundle whose entry names are chosen here rather than by `f:zip_ris/1`, for
%% the cases that are about the names. Entry names are strings: OTP 28's zip
%% rejects binary names with einval.
sign_named(Entries) ->
    {Priv, _Cert} = keypair(),
    {ok, {_Name, ZipBin}} = zip:create("i2pseeds.zip", Entries, [memory]),
    i2p_su3:encode(<<"1789000000">>, <<"test-signer">>, ZipBin, Priv).

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
    i2p_ct_helpers:reseed_zip(Ris).

router_info(Port) ->
    {StaticPub, _StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed).

dead_port() ->
    %% Bind and release an ephemeral port; nothing listens there now. The
    %% release is the point — a refused connection needs closed, and a held
    %% listening socket would instead stall the client until its read
    %% timeout. A port in this state cannot be promised by the OS not to
    %% reappear as a later bind, which is why callers bind their live
    %% server first and hold it for the case: the held port cannot alias.
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
