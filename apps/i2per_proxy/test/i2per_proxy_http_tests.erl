-module(i2per_proxy_http_tests).

-include_lib("eunit/include/eunit.hrl").

http_proxy_test_() ->
    {"HTTP proxy fetches through a mock SAM server", fun() ->
        {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
        {ok, {_, SamPort}} = inet:sockname(LSock),
        application:set_env(i2per_proxy, sam_port, SamPort),
        application:set_env(i2per_proxy, sam_host, <<"127.0.0.1">>),
        Server = spawn(fun() -> mock_sam(LSock) end),
        {ok, Pid} = i2per_proxy_listener:start_link(#{protocol => http, port => 0}),
        BoundPort = i2per_proxy_listener:port(Pid),
        {ok, ClientSock} = gen_tcp:connect(
            "127.0.0.1", BoundPort, [binary, {packet, raw}, {active, false}], 5000
        ),
        ok = gen_tcp:send(
            ClientSock, <<"GET http://peer.i2p/ HTTP/1.1\r\nHost: peer.i2p\r\n\r\n">>
        ),
        {ok, Resp} = gen_tcp:recv(ClientSock, 0, 5000),
        ?assertNotEqual(nomatch, binary:match(Resp, <<"hello from i2p">>)),
        gen_tcp:close(ClientSock),
        Server ! stop,
        i2per_proxy_listener:stop(Pid),
        gen_tcp:close(LSock),
        application:unset_env(i2per_proxy, sam_port)
    end}.

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
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nhello from i2p">>),
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            ok
    end.
