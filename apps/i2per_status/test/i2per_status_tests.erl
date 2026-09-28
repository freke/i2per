-module(i2per_status_tests).

-moduledoc """
End-to-end tests for the `i2per_status` web service: standalone boot with an
unreachable router (offline rendering), live snapshot once the router runs on
the same node, realtime bus counters, and the two HTTP endpoints.
""".

-include_lib("eunit/include/eunit.hrl").

%% Start the status service bound to a dead router node.
start_status(Port) ->
    application:set_env(i2per_status, port, Port),
    {ok, _} = application:ensure_all_started(i2per_status),
    ok.

%% The status code is returned rather than asserted, because it is part of what
%% these tests check: the endpoints answer 200 only when the router is online and
%% 503 when it is not, so a test that only wanted a body should say so.
http_get(Path) ->
    {ok, {{_, Status, _}, Headers, Body}} =
        httpc:request(
            get, {"http://127.0.0.1:" ++ integer_to_list(cfg_port()) ++ Path, []}, [], []
        ),
    {Status, proplists:get_value("content-type", Headers), iolist_to_binary(Body)}.

cfg_port() ->
    {ok, P} = application:get_env(i2per_status, port),
    P.

free_port() ->
    {ok, L} = gen_tcp:listen(0, []),
    {ok, P} = inet:port(L),
    ok = gen_tcp:close(L),
    P.

offline_snapshot_test_() ->
    {timeout, 30, fun offline_snapshot_body/0}.

offline_snapshot_body() ->
    Port = free_port(),
    application:set_env(i2per_status, router_node, 'ghost@nowhere'),
    start_status(Port),
    try
        Snap = i2per_status_state:snapshot(),
        ?assertEqual(false, maps:get(online, Snap)),
        %% 503, not 200: a monitoring consumer must be able to tell a
        %% dead router from a healthy one by the status code. `online` in
        %% the body is no substitute for a consumer that only reads the code.
        {Status, CT, Body} = http_get("/status.json"),
        ?assertEqual(503, Status),
        ?assert(lists:prefix("application/json", CT)),
        #{<<"online">> := false} = json:decode(Body)
    after
        application:stop(i2per_status)
    end.

offline_page_test_() ->
    {timeout, 30, fun offline_page_body/0}.

offline_page_body() ->
    Port = free_port(),
    application:set_env(i2per_status, router_node, 'ghost@nowhere'),
    start_status(Port),
    try
        {Status, CT, Body} = http_get("/"),
        ?assertEqual(503, Status),
        ?assert(lists:prefix("text/html", CT)),
        ?assertNotEqual(nomatch, binary:match(Body, <<"router offline">>))
    after
        application:stop(i2per_status)
    end.

live_router_online_test_() ->
    {timeout, 30, fun live_router_online_body/0}.

live_router_online_body() ->
    boot_live_router(),
    Port = free_port(),
    %% router_node defaults to this node when unset.
    application:unset_env(i2per_status, router_node),
    start_status(Port),
    try
        wait_online(),
        {Status, _CT, Body} = http_get("/status.json"),
        ?assertEqual(200, Status),
        Json = json:decode(Body),
        ?assertEqual(true, maps:get(<<"online">>, Json)),
        ?assert(maps:is_key(<<"identity">>, Json)),
        ?assert(maps:is_key(<<"tunnels">>, Json))
    after
        application:stop(i2per_status),
        teardown_live_router()
    end.

bus_event_counter_test_() ->
    {timeout, 30, fun bus_event_counter_body/0}.

bus_event_counter_body() ->
    boot_live_router(),
    Port = free_port(),
    application:unset_env(i2per_status, router_node),
    start_status(Port),
    try
        Before =
            case maps:find(events, i2per_status_state:snapshot()) of
                {ok, M} -> maps:get(tunnel_built, M, 0);
                error -> 0
            end,
        ok = i2p_events:notify({tunnel_built, outbound, 3}),
        wait_counter(tunnel_built, Before + 1)
    after
        application:stop(i2per_status),
        teardown_live_router()
    end.

%% Boot exactly what `m:i2p_status_data:view/0` reads: peer manager,
%% tunnel manager, SAM supervisor — NetDb/events/config come with the app.
boot_live_router() ->
    {ok, _} = application:ensure_all_started(i2per),
    Router = mock_router(),
    Local = #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => maps:get(hash, Router),
        iv => maps:get(iv, Router),
        ri => maps:get(ri, Router)
    },
    {ok, _} = i2p_peer:start_link(Local, []),
    {ok, _} = i2p_tunnel_srv:start_link(Local),
    {ok, _} = i2p_sam_sup:start_link(),
    ok.

teardown_live_router() ->
    catch gen_server:stop(i2p_sam_sup),
    catch i2p_tunnel_srv:stop(),
    catch i2p_peer:stop(),
    ok.

%% Minimal router identity (same recipe as the SAM e2e suites).
mock_router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, free_port(), StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        iv => IV,
        ri => RI,
        hash => i2p_router_info:hash(RI)
    }.

wait_online() ->
    wait_online(20).

wait_online(0) ->
    erlang:error(router_never_came_online);
wait_online(N) ->
    case maps:get(online, i2per_status_state:snapshot()) of
        true ->
            ok;
        false ->
            timer:sleep(500),
            wait_online(N - 1)
    end.

wait_counter(Key, Want) ->
    wait_counter(Key, Want, 20).

wait_counter(_Key, _Want, 0) ->
    erlang:error(counter_never_reached);
wait_counter(Key, Want, N) ->
    Snap = i2per_status_state:snapshot(),
    Got =
        case maps:find(events, Snap) of
            {ok, Ev} -> maps:get(Key, Ev, 0);
            error -> 0
        end,
    case Got >= Want of
        true ->
            ok;
        false ->
            timer:sleep(300),
            wait_counter(Key, Want, N - 1)
    end.

%% Distributed end-to-end coverage lives in `m:i2per_status_SUITE` because
%% Common Test starts with distribution enabled; it never renames this EUnit VM.
