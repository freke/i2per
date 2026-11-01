-module(i2per_proxy_socks_core_tests).

-include_lib("eunit/include/eunit.hrl").

socks5_direct_path_test_() ->
    {"SOCKS5 CONNECT exercises the core (erpc) path against a running router",
        {timeout, 60, fun() ->
            try
                i2per_proxy_core_router:start(),
                application:set_env(i2per_proxy, sam_port, closed_sam_port()),
                application:set_env(i2per_proxy, sam_host, <<"127.0.0.1">>),
                application:set_env(i2per_proxy, router_node, node()),
                {ok, Pid} = i2per_proxy_listener:start_link(#{protocol => socks, port => 0}),
                try
                    BoundPort = i2per_proxy_listener:port(Pid),
                    {ok, ClientSock} = gen_tcp:connect(
                        "127.0.0.1", BoundPort, [binary, {packet, raw}, {active, false}], 5000
                    ),
                    ok = gen_tcp:send(ClientSock, <<5, 1, 0>>),
                    {ok, <<5, 0>>} = gen_tcp:recv(ClientSock, 2, 5000),
                    Host = <<"peer.i2p">>,
                    Port = 80,
                    Req = <<5, 1, 0, 3, (byte_size(Host)):8, Host/binary, Port:16>>,
                    ok = gen_tcp:send(ClientSock, Req),
                    {ok, Reply} = gen_tcp:recv(ClientSock, 10, 5000),
                    %% Direct path fails to reach the destination and the SAM
                    %% fallback is also down, so the handler reports a SOCKS
                    %% failure (reply code 4) rather than crashing.
                    ?assertEqual(<<5, 4, 0, 1, 0, 0, 0, 0, 0, 0>>, Reply),
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
