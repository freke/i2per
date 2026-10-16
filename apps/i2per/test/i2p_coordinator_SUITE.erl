%% The introducer coordinators' lifecycle. Each case boots the `i2per`
%% application and checks one part of the wiring: the boot gate (the
%% coordinators are children of `m:i2per_sup` only when enabled), the hot
%% switch (`m:i2p_config_srv:set/2` starts and stops them without a restart),
%% the `live_network` requirement on the relay coordinator, and — the case the
%% whole ticket exists for — the relay coordinator serving a relay-tag request
%% through the running router's own SSU2 listener.
%%
%% The router is booted in the persistent mode (`data_dir` + `seeds`), with SSU2
%% serving UDP so the listener binds and spawns sessions owned by
%% `m:i2p_peer`. `live_network` is set only alongside `reseed` disabled,
%% because a live-network boot enables the reseed worker and an unpopulated
%% NetDb is exactly what makes it reach for the network.

-module(i2p_coordinator_SUITE).
-include_lib("eunit/include/eunit.hrl").
-export([all/0, suite/0, init_per_testcase/2, end_per_testcase/2]).
-export([
    disabled_by_default/1,
    coordinators_start_when_enabled/1,
    hot_stop_and_start/1,
    relay_coord_requires_live_network/1,
    relay_coord_serves_a_tag_through_the_router/1
]).

-define(APP, i2per).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        disabled_by_default,
        coordinators_start_when_enabled,
        hot_stop_and_start,
        relay_coord_requires_live_network,
        relay_coord_serves_a_tag_through_the_router
    ].

%% ---------------------------------------------------------------------------
%% Per-case lifecycle
%% ---------------------------------------------------------------------------

init_per_testcase(Case, Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Port = i2p_ct_helpers:free_port(),
    Ssu2Port = i2p_ct_helpers:free_port(),
    ok = application:set_env(?APP, data_dir, Dir),
    ok = application:set_env(?APP, seeds, [dummy_seed()]),
    ok = application:set_env(?APP, port, Port),
    ok = application:set_env(?APP, ssu2_port, Ssu2Port),
    ok = application:set_env(?APP, allow_private_host, true),
    case Case of
        relay_coord_requires_live_network ->
            ok = application:set_env(?APP, relay_coord, true);
        disabled_by_default ->
            ok;
        _ ->
            ok = application:set_env(?APP, ssu2, enable_udp),
            ok = application:set_env(?APP, live_network, true),
            ok = application:set_env(?APP, reseed, #{enabled => false}),
            ok = application:set_env(?APP, relay_coord, true),
            ok = application:set_env(?APP, peertest_coord, true)
    end,
    {ok, _} = application:ensure_all_started(?APP),
    [{data_dir, Dir} | Config].

end_per_testcase(_Case, Config) ->
    application:stop(?APP),
    Dir = proplists:get_value(data_dir, Config),
    lists:foreach(
        fun(K) -> application:unset_env(?APP, K) end,
        [
            data_dir,
            seeds,
            port,
            ssu2_port,
            allow_private_host,
            ssu2,
            live_network,
            reseed,
            relay_coord,
            peertest_coord
        ]
    ),
    case Dir of
        undefined -> ok;
        _ -> file:del_dir_r(Dir)
    end,
    ok.

%% ---------------------------------------------------------------------------
%% The boot gate
%% ---------------------------------------------------------------------------

%% Both coordinators default off: the shipped profile is a local client, and
%% the keys are unset, so neither coordinator is a child of `m:i2per_sup`.
disabled_by_default(_Config) ->
    [] = coordinator_children(),
    false = i2p_relay_coord:enabled(),
    false = i2p_peertest_coord:enabled().

%% With the keys set (and `live_network` for the relay one), both coordinators
%% start under `m:i2per_sup` as children, in attach mode: alive, and with no
%% listener of their own — the running router's SSU2 listener is the one this
%% boot binds.
coordinators_start_when_enabled(_Config) ->
    [i2p_peertest_coord, i2p_relay_coord] = lists:sort(coordinator_children()),
    true = is_process_alive(whereis(i2p_relay_coord)),
    true = is_process_alive(whereis(i2p_peertest_coord)),
    %% Attach mode: the router's listener is up, so the port an operator asks
    %% for is the router's own SSU2 port, not a coordinator-owned one.
    {ok, Ssu2Port} = application:get_env(?APP, ssu2_port),
    Ssu2Port = i2p_relay_coord:port(i2p_relay_coord),
    Ssu2Port = i2p_peertest_coord:port(i2p_peertest_coord).

%% ---------------------------------------------------------------------------
%% The hot switch
%% ---------------------------------------------------------------------------

%% An accepted `false` stops the coordinator and removes the child; an accepted
%% `true` starts it again — no restart. The registry and the app env follow, so
%% a following set does not find a stopped-but-present child.
hot_stop_and_start(_Config) ->
    [i2p_peertest_coord, i2p_relay_coord] = lists:sort(coordinator_children()),
    ok = i2p_config_srv:set(relay_coord, false),
    ct:pal(
        "DEBUG after stop relay: which_children=~0p env=~0p",
        [supervisor:which_children(i2per_sup), application:get_env(?APP, relay_coord)]
    ),
    false = i2p_relay_coord:enabled(),
    [i2p_peertest_coord] = lists:sort(coordinator_children()),
    ok = i2p_config_srv:set(peertest_coord, false),
    {ok, false} = application:get_env(?APP, peertest_coord),
    [] = coordinator_children(),
    ok = i2p_config_srv:set(relay_coord, true),
    {ok, true} = application:get_env(?APP, relay_coord),
    true = is_process_alive(whereis(i2p_relay_coord)),
    ok = i2p_config_srv:set(peertest_coord, true),
    true = is_process_alive(whereis(i2p_peertest_coord)),
    [i2p_peertest_coord, i2p_relay_coord] = lists:sort(coordinator_children()).

%% ---------------------------------------------------------------------------
%% The `live_network` requirement
%% ---------------------------------------------------------------------------

%% `relay_coord = true` without `live_network` is refused at the door, and the
%% boot gate does not start the coordinator either: the two agree. A hot set
%% from that state changes nothing — the environment holds the init's `true`,
%% the coordinator is still not started, and `live_network` is a
%% restart-required key, so there is no hot path to it, which is the point.
relay_coord_requires_live_network(_Config) ->
    [] = coordinator_children(),
    false = i2p_relay_coord:enabled(),
    {error, {requires_live_network, relay_coord}} = i2p_config_srv:set(relay_coord, true),
    {ok, true} = application:get_env(?APP, relay_coord),
    [] = coordinator_children(),
    %% The peer-test coordinator has no such requirement — but this boot has the
    %% key unset, so it is off too.
    false = i2p_peertest_coord:enabled().

%% ---------------------------------------------------------------------------
%% The forwarding, end to end
%% ---------------------------------------------------------------------------

%% A dialing peer connects to the running router's SSU2 listener, asks for a
%% relay tag (block 15), and the attached relay coordinator answers with a
%% RelayTag block (16) registered in the listener-owned registry against the
%% Bob-side session. This is the whole chain the ticket wires: the session
%% forwards the block to `m:i2p_peer`, which forwards it to the coordinator,
%% which answers through the same session.
relay_coord_serves_a_tag_through_the_router(Config) ->
    Dir = proplists:get_value(data_dir, Config),
    {ok, Id} = i2p_identity:ensure_identity(Dir),
    Host = application:get_env(?APP, host, <<"127.0.0.1">>),
    TcpPort = application:get_env(?APP, port, 9150),
    RouterLocal = i2p_identity:build_local(Id, Host, TcpPort, maps:get(sign_seed, Id)),
    {ok, Ssu2Opts} = i2p_router_info:ssu2_address_options(maps:get(ri, RouterLocal)),

    {PeerListener, PeerLocal, PeerRIBinary} = peer_with_listener(<<"127.0.0.1">>),
    RemoteOpts =
        #{
            host => maps:get(host, Ssu2Opts),
            port => maps:get(port, Ssu2Opts),
            static_key => maps:get(static_key, Ssu2Opts),
            intro_key => maps:get(intro_key, Ssu2Opts)
        },
    {ok, PeerPid, _Keys} =
        i2p_ssu2_conn:connect(PeerLocal, RemoteOpts, PeerRIBinary, PeerListener),
    erlang:unlink(PeerPid),
    try
        ok = i2p_ssu2_conn:send_relay(PeerPid, relay_tag_request),
        %% `f:i2p_ct_helpers:wait_msg/2` returns the awaited value itself.
        Tag =
            i2p_ct_helpers:wait_msg(
                fun
                    ({ssu2_data, P, Blocks}) when P =:= PeerPid ->
                        case lists:keyfind(relay_tag, 1, Blocks) of
                            {relay_tag, T} -> {true, T};
                            false -> false
                        end;
                    (_) ->
                        false
                end,
                20000
            ),
        true = Tag > 0,
        %% The registry maps the tag to the Bob-side session the coordinator
        %% routed, with a usable lifetime.
        TaggedSess = i2p_relay_coord:tagged_sess(i2p_relay_coord),
        [{Tag, RegPid, Expires}] = ets:lookup(i2p_ssu2_relay_tags, Tag),
        true = RegPid =:= TaggedSess,
        true = is_process_alive(RegPid),
        true = RegPid =/= PeerPid,
        true = Expires > erlang:system_time(second)
    after
        catch i2p_ssu2_conn:terminate_session(PeerPid, normal),
        catch i2p_ssu2_listener:stop(PeerListener)
    end.

%% ---------------------------------------------------------------------------
%% Fixtures and helpers
%% ---------------------------------------------------------------------------

coordinator_children() ->
    [
        Id
     || {Id, Pid, worker, _Modules} <- supervisor:which_children(i2per_sup),
        is_pid(Pid),
        Id =:= i2p_relay_coord orelse Id =:= i2p_peertest_coord
    ].

%% A listener-bound dialing peer, in the shape the relay suite's
%% `listen_full_local/1` provides: its own SSU2 listener, and a local map whose
%% RouterInfo advertises that listener's real port.
peer_with_listener(Host) ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Base =
        #{
            static_priv => Priv,
            static_pub => Pub,
            intro_key => IntroKey,
            sign_seed => Seed,
            sign_pub => SignPub
        },
    {ok, Listener} = i2p_ssu2_listener:listen(Host, 0, Base, self()),
    PeerPort = i2p_ssu2_listener:port(Listener),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(Host, PeerPort, Pub, IntroKey),
    RI =
        i2p_router_info:build(
            Identity,
            erlang:system_time(millisecond),
            [Addr],
            #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
            Seed
        ),
    Local = Base#{hash => i2p_router_info:hash(RI), ri => RI},
    {Listener, Local, maps:get(binary, RI)}.

%% A bootstrap RouterInfo for the persistent boot, in the shape the boot suite's
%% `dummy_seed/0` provides.
dummy_seed() ->
    {StaticPub, _} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [
            i2p_router_info:ntcp2_address(
                <<"127.0.0.1">>, 4668, StaticPub, crypto:strong_rand_bytes(16)
            )
        ],
        Opts,
        Seed
    ).
