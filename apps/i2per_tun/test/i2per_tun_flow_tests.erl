-module(i2per_tun_flow_tests).

-include_lib("eunit/include/eunit.hrl").

run_session_test_() ->
    {"run_session opens and holds a SAM session", fun() ->
        {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
        {ok, {_, SamPort}} = inet:sockname(LSock),
        Server = spawn(fun() -> mock_sam(LSock) end),
        {ok, _SessionId, Pid} = i2per_tun_flow:run_session(
            <<"peer.i2p">>, <<"127.0.0.1">>, SamPort
        ),
        ?assert(is_pid(Pid)),
        Pid ! stop,
        Server ! stop,
        gen_tcp:close(LSock)
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
            receive
                stop -> ok
            after 5000 -> ok
            end,
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            ok
    end.
