-module(i2per_proxy_http_core_tests).

-include_lib("eunit/include/eunit.hrl").

http_proxy_direct_path_test_() ->
    {"HTTP proxy exercises the core (erpc) path against a running router",
        {timeout, 60, fun() ->
            i2per_proxy_core_router:start(),
            try
                application:set_env(i2per_proxy, sam_port, closed_sam_port()),
                application:set_env(i2per_proxy, sam_host, <<"127.0.0.1">>),
                application:set_env(i2per_proxy, router_node, node()),
                {ok, Pid} = i2per_proxy_listener:start_link(#{protocol => http, port => 0}),
                try
                    BoundPort = i2per_proxy_listener:port(Pid),
                    {ok, ClientSock} = gen_tcp:connect(
                        "127.0.0.1", BoundPort, [binary, {packet, raw}, {active, false}], 5000
                    ),
                    ok = gen_tcp:send(
                        ClientSock, <<"GET http://peer.i2p/ HTTP/1.1\r\nHost: peer.i2p\r\n\r\n">>
                    ),
                    {ok, Resp} = gen_tcp:recv(ClientSock, 0, 10000),
                    %% The direct path cannot reach a destination on a bare
                    %% router, so it falls through to the SAM path, which is
                    %% also down here: the handler reports 503 rather than
                    %% crashing or hanging.
                    ?assertNotEqual(nomatch, binary:match(Resp, <<"503">>)),
                    gen_tcp:close(ClientSock)
                after
                    i2per_proxy_listener:stop(Pid)
                end
            after
                application:unset_env(i2per_proxy, sam_port),
                application:unset_env(i2per_proxy, sam_host),
                application:unset_env(i2per_proxy, router_node),
                i2per_proxy_core_router:stop()
            end
        end}}.

closed_sam_port() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}]),
    {ok, {_, Port}} = inet:sockname(LSock),
    gen_tcp:close(LSock),
    Port.