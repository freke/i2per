-module(i2p_client_tests).

-moduledoc """
Tests for `m:i2p_client`: lease selection and end-to-end payload wrapping.
""".
-include_lib("eunit/include/eunit.hrl").

%% End-to-end payload round trip: the destination that wraps can be opened
%% only by the matching private key, and yields the original bytes.
wrap_unwrap_roundtrip_test() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    Payload = <<"stream bytes \0 with NULs">>,
    {ok, Body} = i2p_client:wrap_payload(Pub, Payload),
    ?assertEqual({ok, Payload}, i2p_client:unwrap_payload(Priv, Body)).

unwrap_with_wrong_key_test() ->
    {Pub, _Priv} = i2p_crypto:x25519_keygen(),
    {_OtherPub, OtherPriv} = i2p_crypto:x25519_keygen(),
    {ok, Body} = i2p_client:wrap_payload(Pub, <<"secret">>),
    ?assertEqual(error, i2p_client:unwrap_payload(OtherPriv, Body)).

%% The freshest unexpired lease wins; fully expired sets select nothing.
pick_lease_freshest_test() ->
    LS = fixture_ls([60_000, 120_000, 30_000]),
    NowMs = erlang:system_time(millisecond),
    {ok, {_Gateway, TunnelID}} = i2p_client:pick_lease(LS, NowMs),
    %% fixture assigns tunnel_id = index + 1; the 120s lease is second
    ?assertEqual(2, TunnelID).

pick_lease_all_expired_test() ->
    LS = fixture_ls([-60_000, -120_000]),
    NowMs = erlang:system_time(millisecond),
    ?assertEqual(error, i2p_client:pick_lease(LS, NowMs)).

%% A wrapped payload survives a standard-header type-11 round trip, the
%% shape it travels in inside tunnel frames.
std_message_roundtrip_test() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    Payload = crypto:strong_rand_bytes(500),
    {ok, Body} = i2p_client:wrap_payload(Pub, Payload),
    StdMsg =
        i2p_i2np:encode_std(#{
            type => 11,
            msg_id => <<1, 2, 3, 4>>,
            expiration_ms => 60000,
            body => Body
        }),
    {ok, #{type := 11, body := Body}} = i2p_i2np:decode_std(StdMsg),
    ?assertEqual({ok, Payload}, i2p_client:unwrap_payload(Priv, Body)).

%%%%%%%%% Helpers %%%%%%%%%

fixture_ls(OffsetMsList) ->
    Identity = i2p_keys:from_keys(
        element(1, i2p_crypto:x25519_keygen()),
        element(1, i2p_crypto:ed25519_keygen())
    ),
    Seed = element(2, i2p_crypto:ed25519_keygen()),
    NowMs = erlang:system_time(millisecond),
    {Leases, _} =
        lists:mapfoldl(
            fun(OffsetMs, I) ->
                {
                    [
                        #{
                            gateway => crypto:strong_rand_bytes(32),
                            tunnel_id => I,
                            end_date => NowMs + OffsetMs
                        }
                    ],
                    I + 1
                }
            end,
            1,
            OffsetMsList
        ),
    i2p_leaset:build(Identity, erlang:system_time(second), 1, lists:flatten(Leases), Seed).
