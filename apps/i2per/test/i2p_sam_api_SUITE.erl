%% System-level tests for the public Erlang API (`m:i2p_sam_api`).
%%
%% Companion apps (i2per_proxy, i2per_tun) reach the core over the Erlang
%% network through this API instead of the SAM wire protocol (E1CHFWF). This
%% suite proves the API is usable against a running router: a session can be
%% created, a destination resolved, and the failure modes (no route, bad target)
%% are reported as values rather than crashes.

-module(i2p_sam_api_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-export([all/0, suite/0]).

-export([
    create_session_returns_destination/1,
    session_dest_b64_roundtrips/1,
    naming_lookup_passthrough/1,
    stream_connect_no_route_is_clean/1,
    raw_send_no_route_is_clean/1
]).

-define(APP, i2per).

all() ->
    [
        create_session_returns_destination,
        session_dest_b64_roundtrips,
        naming_lookup_passthrough,
        stream_connect_no_route_is_clean,
        raw_send_no_route_is_clean
    ].

suite() ->
    [{timetrap, 60000}].

create_session_returns_destination(_Config) ->
    ok = with_router(fun() ->
        {ok, Pid, DestB64} = i2p_sam_api:create_session(),
        ?assert(is_pid(Pid)),
        ?assert(is_binary(DestB64)),
        ?assertEqual(1, i2p_sam_api:version())
    end).

session_dest_b64_roundtrips(_Config) ->
    ok = with_router(fun() ->
        {ok, Pid, DestB64} = i2p_sam_api:create_session(),
        ?assertEqual(DestB64, i2p_sam_api:session_dest_b64(Pid))
    end).

naming_lookup_passthrough(_Config) ->
    ok = with_router(fun() ->
        Dest = i2p_sam_api:create_destination(),
        B64 = maps:get(dest_b64, Dest),
        ?assertEqual({ok, B64}, i2p_sam_api:naming_lookup(B64))
    end).

stream_connect_no_route_is_clean(_Config) ->
    ok = with_router(fun() ->
        {ok, Pid, _DestB64} = i2p_sam_api:create_session(),
        Result = i2p_sam_api:stream_connect(Pid, <<"not-a-destination">>, self()),
        ?assertMatch({error, _}, Result)
    end).

raw_send_no_route_is_clean(_Config) ->
    ok = with_router(fun() ->
        Result = i2p_sam_api:raw_send(<<"not-a-destination">>, <<"payload">>),
        %% raw_send returns ok (fire-and-forget) or {error, _}; never crashes.
        ?assert(Result =:= ok orelse element(1, Result) =:= error)
    end).

%% ---- helpers (mirrored from i2p_read_api_SUITE) ----

with_router(Fun) ->
    ok = start_readable_router(),
    try
        Fun()
    after
        ok = stop_readable_router()
    end.

start_readable_router() ->
    {ok, _} = application:ensure_all_started(?APP),
    Local = local_identity(),
    unlinked(fun() -> i2p_peer:start_link(Local, []) end),
    unlinked(fun() -> i2p_tunnel_srv:start_link(Local) end),
    unlinked(fun() -> i2p_sam_sup:start_link() end),
    ok.

stop_readable_router() ->
    _ = catch gen_server:stop(i2p_sam_sup),
    _ = catch i2p_tunnel_srv:stop(),
    _ = catch i2p_peer:stop(),
    ok = i2p_ct_helpers:stop_app(),
    ok.

unlinked(Start) ->
    {ok, Pid} = Start(),
    unlink(Pid),
    ok.

local_identity() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(
        <<"127.0.0.1">>, i2p_ct_helpers:free_port(), StaticPub, IV
    ),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        sign_priv => Seed,
        sign_pub => SignPub,
        hash => i2p_keys:hash(Identity),
        iv => IV,
        ri => RI
    }.
