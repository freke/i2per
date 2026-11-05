-module(i2per_tun_core_router).

-moduledoc """
Start a core on the local node for the tests that reach it over `erpc`.

The companion apps call the core through `f:erpc:call/5`, so these cases need a
real router on the node rather than a mock: the `i2per` application and the peer,
tunnel and SAM managers the client-facing API calls into.

**Start only what is missing, and stop only what you started.** The full eunit
run shares one node, so another module may already have started one of those
managers. Taking it over and stopping it afterwards pulls the router out from
under the test that owns it, and the next `f:start/0` then dies on
`{error, {already_started, _}}` -- one leak turning every later core case red.

The record of what this call started lives in the process dictionary, written as
each manager comes up rather than once at the end, so a case that dies partway
through `f:start/0` still leaves `f:stop/0` able to undo it. Both run in the same
eunit process, so the record cannot outlive the case.

## Usage

```erlang
try
    i2per_tun_core_router:start(),
    %% ... drive the app against the local core ...
after
    i2per_tun_core_router:stop()
end.
```
""".

-export([start/0, stop/0]).

%% What this call had to start, so `stop/0` can put the node back as it found it.
-define(STARTED, {?MODULE, started}).

-doc """
Start the core managers this node does not already have.

Input: none. Output: `ok`. The `i2per` application is started when it is not
already running, and `i2p_peer`, `i2p_tunnel_srv` and `i2p_sam_sup` are started
unlinked when they are not already registered.
""".
-spec start() -> ok.
start() ->
    put(?STARTED, #{app => false, children => []}),
    start_app(),
    Local = local_identity(),
    ensure_child(i2p_peer, fun() -> i2p_peer:start_link(Local, []) end),
    ensure_child(i2p_tunnel_srv, fun() -> i2p_tunnel_srv:start_link(Local) end),
    ensure_child(i2p_sam_sup, fun() -> i2p_sam_sup:start_link() end),
    ok.

-doc """
Undo `f:start/0`, and nothing else.

Input: none. Output: `ok`. Managers that were already running are left alone, and
so is an `i2per` application this helper did not start. Safe to call when
`f:start/0` was never reached, or after it raised.
""".
-spec stop() -> ok.
stop() ->
    case erase(?STARTED) of
        undefined ->
            ok;
        #{app := AppStarted, children := Children} ->
            lists:foreach(fun stop_child/1, lists:reverse(Children)),
            stop_app(AppStarted)
    end.

%%%%%%% %%% Internal %%%%%%%

%% `which_applications/0` rather than the started list `ensure_all_started/1`
%% returns: that list also carries dependencies, and a call that started only a
%% dependency must not license stopping the application later.
start_app() ->
    case lists:keymember(i2per, 1, application:which_applications()) of
        true ->
            ok;
        false ->
            {ok, _} = application:ensure_all_started(i2per),
            record_app_started()
    end.

stop_app(true) ->
    _ = application:stop(i2per),
    wait_stopped(5000);
stop_app(false) ->
    ok.

ensure_child(Module, Start) ->
    case whereis(Module) of
        undefined ->
            unlinked(Start),
            record_child(Module);
        _Pid ->
            ok
    end.

record_app_started() ->
    Started = get(?STARTED),
    put(?STARTED, Started#{app := true}).

record_child(Module) ->
    #{children := Children} = Started = get(?STARTED),
    put(?STARTED, Started#{children := Children ++ [Module]}).

stop_child(i2p_sam_sup) ->
    _ = catch gen_server:stop(i2p_sam_sup),
    ok;
stop_child(i2p_tunnel_srv) ->
    _ = catch i2p_tunnel_srv:stop(),
    wait_unregistered(i2p_tunnel_srv, 5000);
stop_child(i2p_peer) ->
    _ = catch i2p_peer:stop(),
    wait_unregistered(i2p_peer, 5000).

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

%% `i2p_peer:stop/0` and `i2p_tunnel_srv:stop/0` are casts, so the name is still
%% registered when they return. Waiting for it to go is what makes the next
%% `f:start/0` see the node as it was rather than as this call left it.
wait_unregistered(_Module, 0) ->
    timeout;
wait_unregistered(Module, Budget) ->
    case whereis(Module) of
        undefined ->
            ok;
        _Pid ->
            timer:sleep(20),
            wait_unregistered(Module, Budget - 20)
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
