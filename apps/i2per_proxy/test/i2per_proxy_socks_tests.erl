-module(i2per_proxy_socks_tests).

-include_lib("eunit/include/eunit.hrl").

%% See `i2per_proxy_http_tests`: force the SAM fallback instead of allowing the
%% handler to reach a local core node first.
-define(DEAD_NODE, 'i2per_proxy_socks_test@host-invalid').

socks5_handshake_test_() ->
    {"SOCKS5 CONNECT completes against a mock SAM server",
        {timeout, 30, fun() ->
            {ok, LSock} =
                gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
            {ok, {_, SamPort}} = inet:sockname(LSock),
            application:set_env(i2per_proxy, sam_port, SamPort),
            application:set_env(i2per_proxy, sam_host, <<"127.0.0.1">>),
            application:set_env(i2per_proxy, router_node, ?DEAD_NODE),
            Server = spawn(fun() -> mock_sam(LSock) end),
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
                Server ! stop,
                i2per_proxy_listener:stop(Pid),
                gen_tcp:close(LSock),
                application:unset_env(i2per_proxy, sam_port),
                application:unset_env(i2per_proxy, sam_host),
                application:unset_env(i2per_proxy, router_node)
            end
        end}}.

mock_sam(LSock) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            gen_tcp:send(Sock, <<"HELLO REPLY RESULT=OK VERSION=3.1\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"SESSION STATUS RESULT=OK DESTINATION=mydest\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"NAMING REPLY RESULT=OK NAME=peer.i2p VALUE=targetdest\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"STREAM STATUS RESULT=OK\n">>),
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            ok
    end.
