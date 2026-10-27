-module(i2per_proxy_http_tests).

-include_lib("eunit/include/eunit.hrl").

%% Pin the core-node lookup to an unreachable node so the handler takes the
%% SAM path deterministically. Without this, `router_node/0` defaults to
%% `node()` and the handler may call the local `i2p_sam_api` first, which in a
%% shared eunit VM can block until the test itself times out.
-define(DEAD_NODE, 'i2per_proxy_http_test@host-invalid').

http_proxy_test_() ->
    {"HTTP proxy fetches through a mock SAM server",
        {timeout, 30, fun() ->
            Mock = i2per_proxy_mock_sam:start(fun(StreamSock) ->
                {ok, Request} = gen_tcp:recv(StreamSock, 0, 5000),
                ?assertMatch(<<"GET / HTTP/1.1\r\n", _/binary>>, Request),
                ok = gen_tcp:send(
                    StreamSock, <<"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nhello from i2p">>
                )
            end),
            {_, SamPort, _} = Mock,
            application:set_env(i2per_proxy, sam_port, SamPort),
            application:set_env(i2per_proxy, sam_host, <<"127.0.0.1">>),
            application:set_env(i2per_proxy, router_node, ?DEAD_NODE),
            {ok, Pid} = i2per_proxy_listener:start_link(#{protocol => http, port => 0}),
            try
                BoundPort = i2per_proxy_listener:port(Pid),
                {ok, ClientSock} = gen_tcp:connect(
                    "127.0.0.1", BoundPort, [binary, {packet, raw}, {active, false}], 5000
                ),
                ok = gen_tcp:send(
                    ClientSock, <<"GET http://peer.i2p/ HTTP/1.1\r\nHost: peer.i2p\r\n\r\n">>
                ),
                {ok, Resp} = gen_tcp:recv(ClientSock, 0, 5000),
                ?assertNotEqual(nomatch, binary:match(Resp, <<"hello from i2p">>)),
                gen_tcp:close(ClientSock)
            after
                i2per_proxy_listener:stop(Pid),
                i2per_proxy_mock_sam:stop(Mock),
                application:unset_env(i2per_proxy, sam_port),
                application:unset_env(i2per_proxy, sam_host),
                application:unset_env(i2per_proxy, router_node)
            end
        end}}.
