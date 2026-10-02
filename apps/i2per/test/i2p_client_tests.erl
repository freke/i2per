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

%%%%%%%%% A send whose tunnel has gone %%%%%%%%%
%%
%% `f:send_wire/2` used to match the injection answer and drop it on the floor:
%%
%%     case i2p_tunnel_srv:send_via_outbound(...) of
%%         ok -> ok;
%%         error -> ok
%%     end.
%%
%% Two branches with the same body, which reads as a considered distinction that
%% was not there, and left a message this router routed and could not deliver
%% indistinguishable from one it never routed -- the opposite of what
%% `transit_frames_dropped_no_route` reports. Not propagating is still right
%% (the connection's resend machinery recovers, and four call sites are spec'd
%% `-> ok`), so the fix counts rather than propagates.

%% The drop is counted. Reverting the call site to `error -> ok` leaves this at
%% zero, which is the only thing that makes it a test rather than a smoke check.
send_to_a_vanished_tunnel_is_counted_test() ->
    with_client(fun() ->
        ?assertEqual(0, counter()),
        ?assertEqual(ok, i2p_client:send_wire(fixture_route(4242), <<"payload">>)),
        ?assertEqual(1, counter())
    end).

%% The contract four call sites depend on: a vanished tunnel is not an error the
%% caller sees. This is the assertion that stops the count being "fixed" by
%% propagating instead -- which would compile, pass the case above, and break
%% `i2p_addressbook_subs`, `i2p_server_tunnel` and both `i2p_sam_session` sites.
send_wire_reports_ok_when_the_tunnel_is_gone_test() ->
    with_client(fun() ->
        ?assertEqual(ok, i2p_client:send_wire(fixture_route(4242), <<"payload">>)),
        ?assertEqual(ok, i2p_client:send_wire(fixture_route(4243), <<"payload">>)),
        ?assertEqual(2, counter())
    end).

%% Counted, not merely present. `f:snapshot/0` reports every declared counter
%% whether or not it has moved, so "measured and zero" is distinguishable from
%% "not measured yet" -- which is the property that lets a consumer trust the
%% zero it sees before the first drop. Without the declaration this key would be
%% absent, and a consumer would have to treat absent and zero as the same thing.
counter_is_in_the_read_api_before_anything_moves_test() ->
    with_client(fun() ->
        ?assertMatch(#{client_messages_dropped_no_tunnel := 0}, i2p_stats:snapshot())
    end).

%%%%%%%%% Helpers %%%%%%%%%

counter() ->
    maps:get(client_messages_dropped_no_tunnel, i2p_stats:snapshot()).

%% A route naming an outbound tunnel the manager does not hold, so
%% `f:find_outbound/2` answers `error`. The tunnel manager starts with empty
%% `tunnels` and `exploratory`, so any id will do -- no tunnel has to be built,
%% and nothing here depends on a race to reproduce.
fixture_route(OutTid) ->
    {DestPub, _Priv} = i2p_crypto:x25519_keygen(),
    #{
        out_tid => OutTid,
        gw => crypto:strong_rand_bytes(32),
        tid => 1,
        dest_pub => DestPub
    }.

with_client(Fun) ->
    ok = stop(i2p_stats),
    ok = stop(i2p_tunnel_srv),
    {ok, _} = i2p_stats:start_link(),
    {ok, _} = i2p_tunnel_srv:start_link(fixture_local()),
    try
        Fun()
    after
        ok = stop(i2p_tunnel_srv),
        ok = stop(i2p_stats)
    end.

%% `i2p_peer:local_keys()` is a real RouterInfo, and the tunnel manager's `local`
%% field is never read on the injection path -- `f:find_outbound/2` consults
%% `tunnels` and `exploratory`, both empty at start. Built anyway rather than
%% passed as `undefined`, so the fixture satisfies the spec it is handed to.
%%
%% The port is fixed rather than probed for a free one, for the same reason: this
%% process never binds it, and a `free_port/0` here would be a second way for
%% this case to fail for a reason that has nothing to do with what it asserts.
fixture_local() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, 1, StaticPub, IV),
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], #{}, Seed),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        hash => i2p_router_info:hash(RI),
        iv => IV,
        ri => RI
    }.

stop(Module) ->
    case whereis(Module) of
        undefined ->
            ok;
        Pid ->
            ok = gen_server:stop(Pid)
    end.

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
