-module(i2per_tun_core_router).

-export([start/0, stop/0]).

start() ->
    {ok, _} = application:ensure_all_started(i2per),
    Local = local_identity(),
    unlinked(fun() -> i2p_peer:start_link(Local, []) end),
    unlinked(fun() -> i2p_tunnel_srv:start_link(Local) end),
    unlinked(fun() -> i2p_sam_sup:start_link() end),
    ok.

stop() ->
    _ = catch gen_server:stop(i2p_sam_sup),
    _ = catch i2p_tunnel_srv:stop(),
    _ = catch i2p_peer:stop(),
    _ = application:stop(i2per),
    wait_stopped(5000),
    ok.

wait_stopped(0) ->
    timeout;
wait_stopped(Budget) ->
    case lists:keymember(i2per, 1, application:which_applications()) of
        true ->
            timer:sleep(20),
            wait_stopped(Budget - 20);
        false ->
            ok
    end.

local_identity() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(
        <<"127.0.0.1">>, free_port(), StaticPub, IV
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

free_port() ->
    {ok, Sock} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Sock),
    gen_tcp:close(Sock),
    Port.

unlinked(Start) ->
    {ok, Pid} = Start(),
    unlink(Pid),
    ok.