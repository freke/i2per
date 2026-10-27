-module(i2per_proxy_socks_tests).

-include_lib("eunit/include/eunit.hrl").

%% See `i2per_proxy_http_tests`: force the SAM fallback instead of allowing the
%% handler to reach a local core node first.
-define(DEAD_NODE, 'i2per_proxy_socks_test@host-invalid').

socks5_handshake_test_() ->
    {"SOCKS5 CONNECT completes against a mock SAM server",
        {timeout, 30, fun() ->
            Mock = i2per_proxy_mock_sam:start(fun(_StreamSock) -> ok end),
            {_, SamPort, _} = Mock,
            application:set_env(i2per_proxy, sam_port, SamPort),
            application:set_env(i2per_proxy, sam_host, <<"127.0.0.1">>),
            application:set_env(i2per_proxy, router_node, ?DEAD_NODE),
            {ok, Pid} = i2per_proxy_listener:start_link(#{protocol => socks, port => 0}),
            try
                BoundPort = i2per_proxy_listener:port(Pid),
                {ok, ClientSock} = gen_tcp:connect(
                    "127.0.0.1", BoundPort, [binary, {packet, raw}, {active, false}], 5000
                ),
                %% greeting: VER=5, NMETHODS=1, method 0
                ok = gen_tcp:send(ClientSock, <<5, 1, 0>>),
                {ok, <<5, 0>>} = gen_tcp:recv(ClientSock, 2, 5000),
                %% request: VER=5, CMD=1(CONNECT), RSV=0, ATYP=3(domain), len, host, port
                Host = <<"peer.i2p">>,
                Port = 80,
                Req = <<5, 1, 0, 3, (byte_size(Host)):8, Host/binary, Port:16>>,
                ok = gen_tcp:send(ClientSock, Req),
                {ok, Reply} = gen_tcp:recv(ClientSock, 10, 5000),
                ?assertEqual(<<5, 0, 0, 1, 0, 0, 0, 0, 0, 0>>, Reply),
                gen_tcp:close(ClientSock)
            after
                i2per_proxy_listener:stop(Pid),
                i2per_proxy_mock_sam:stop(Mock),
                application:unset_env(i2per_proxy, sam_port),
                application:unset_env(i2per_proxy, sam_host),
                application:unset_env(i2per_proxy, router_node)
            end
        end}}.

socks4a_handshake_test_() ->
    {"SOCKS4a CONNECT completes against a mock SAM server",
        {timeout, 30, fun() ->
            Mock = i2per_proxy_mock_sam:start(fun(_StreamSock) -> ok end),
            {_, SamPort, _} = Mock,
            application:set_env(i2per_proxy, sam_port, SamPort),
            application:set_env(i2per_proxy, sam_host, <<"127.0.0.1">>),
            application:set_env(i2per_proxy, router_node, ?DEAD_NODE),
            {ok, Pid} = i2per_proxy_listener:start_link(#{protocol => socks, port => 0}),
            try
                BoundPort = i2per_proxy_listener:port(Pid),
                {ok, ClientSock} = gen_tcp:connect(
                    "127.0.0.1", BoundPort, [binary, {packet, raw}, {active, false}], 5000
                ),
                %% VER=4, CMD=1(CONNECT), port, IP=0.0.0.1 (SOCKS4a), user id, host
                ok = gen_tcp:send(ClientSock, <<4, 1, 80:16, 0, 0, 0, 1, 0, "peer.i2p", 0>>),
                {ok, Reply} = gen_tcp:recv(ClientSock, 8, 5000),
                ?assertEqual(<<0, 90, 80:16, 0, 0, 0, 1>>, Reply),
                gen_tcp:close(ClientSock)
            after
                i2per_proxy_listener:stop(Pid),
                i2per_proxy_mock_sam:stop(Mock),
                application:unset_env(i2per_proxy, sam_port),
                application:unset_env(i2per_proxy, sam_host),
                application:unset_env(i2per_proxy, router_node)
            end
        end}}.
