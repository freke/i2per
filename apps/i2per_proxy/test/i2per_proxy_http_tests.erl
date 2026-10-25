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
            {ok, LSock} =
                gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
            {ok, {_, SamPort}} = inet:sockname(LSock),
            application:set_env(i2per_proxy, sam_port, SamPort),
            application:set_env(i2per_proxy, sam_host, <<"127.0.0.1">>),
            application:set_env(i2per_proxy, router_node, ?DEAD_NODE),
            Server = spawn(fun() -> mock_sam(LSock) end),
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
                Server ! stop,
                i2per_proxy_listener:stop(Pid),
                gen_tcp:close(LSock),
                application:unset_env(i2per_proxy, sam_port),
                application:unset_env(i2per_proxy, sam_host),
                application:unset_env(i2per_proxy, router_node)
            end
        end}}.

%% Every reply here follows the request it answers, one recv per protocol line.
%% Sending `HELLO REPLY` before reading HELLO lets the client reach SESSION CREATE
%% unprompted; the two requests then arrive in one buffer, every later recv is a
%% message ahead, and both sides time out at the fifth (WD5N85Y).
mock_sam(LSock) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"HELLO REPLY RESULT=OK VERSION=3.1\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"SESSION STATUS RESULT=OK DESTINATION=mydest\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"NAMING REPLY RESULT=OK NAME=peer.i2p VALUE=targetdest\n">>),
            {ok, _StreamConnect} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"STREAM STATUS RESULT=OK\n">>),
            {ok, Request} = gen_tcp:recv(Sock, 0, 5000),
            ?assertMatch(<<"GET / HTTP/1.1\r\n", _/binary>>, Request),
            gen_tcp:send(Sock, <<"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nhello from i2p">>),
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            ok
    end.
