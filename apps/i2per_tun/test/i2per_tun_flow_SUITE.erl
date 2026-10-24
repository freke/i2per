-module(i2per_tun_flow_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([flow_relays_bytes/1]).

all() ->
    [flow_relays_bytes].

init_per_testcase(_TC, Config) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, {_, SamPort}} = inet:sockname(LSock),
    Server = spawn_link(fun() -> mock_sam(LSock) end),
    [{sam_lsock, LSock}, {sam_port, SamPort}, {sam_server, Server} | Config].

end_per_testcase(_TC, Config) ->
    catch gen_tcp:close(proplists:get_value(sam_lsock, Config)),
    catch exit(proplists:get_value(sam_server, Config), kill),
    ok.

flow_relays_bytes(Config) ->
    SamPort = proplists:get_value(sam_port, Config),
    {ok, HostLSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, {_, HostPort}} = inet:sockname(HostLSock),
    {ok, ClientSock} = gen_tcp:connect(
        "127.0.0.1", HostPort, [binary, {packet, raw}, {active, false}], 5000
    ),
    {ok, HostSock} = gen_tcp:accept(HostLSock, 5000),
    ok = gen_tcp:send(ClientSock, <<"ping">>),
    Pid = spawn(fun() ->
        i2per_tun_flow:run(HostSock, <<"peer.i2p">>, <<"127.0.0.1">>, SamPort)
    end),
    {ok, <<"pong">>} = gen_tcp:recv(ClientSock, 4, 5000),
    gen_tcp:close(ClientSock),
    _ = Pid,
    gen_tcp:close(HostLSock),
    ok.

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
            ok = wait_for_ping(Sock, <<>>),
            ok = gen_tcp:send(Sock, <<"pong">>),
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            ok
    end.

wait_for_ping(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data} ->
            Combined = <<Acc/binary, Data/binary>>,
            case binary:match(Combined, <<"ping">>) of
                {_, _} -> ok;
                nomatch -> wait_for_ping(Sock, Combined)
            end;
        {error, _} ->
            {error, timeout}
    end.
