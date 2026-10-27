-module(i2per_tun_flow_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([flow_relays_bytes/1]).

all() ->
    [flow_relays_bytes].

init_per_testcase(_TC, Config) ->
    Mock = i2per_tun_mock_sam:start(fun(StreamSock) ->
        ok = wait_for_ping(StreamSock, <<>>),
        ok = gen_tcp:send(StreamSock, <<"pong">>)
    end),
    [{sam_mock, Mock}, {sam_port, element(2, Mock)} | Config].

end_per_testcase(_TC, Config) ->
    i2per_tun_mock_sam:stop(proplists:get_value(sam_mock, Config)),
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
