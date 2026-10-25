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

%% A core session carries exactly one flow, so both core helpers must close
%% it when the flow ends. The failure path is the one that used to drop the
%% only reference to the session and leave it running for the router's life.
failed_core_connect_closes_the_session_test_() ->
    {"a failed core connect closes the session it created",
        {timeout, 30, fun failed_core_connect_closes_the_session/0}}.

failed_core_connect_closes_the_session() ->
    Before = core_sessions(),
    Port = closed_port(),
    ?assertMatch(
        {error, _},
        i2per_tun_flow:run_session(<<"nonexistent.i2p">>, <<"127.0.0.1">>, Port)
    ),
    ?assertEqual(Before, core_sessions()).

failed_core_connect_closes_the_session_of_a_run_test_() ->
    {"a failed core connect closes the session a run created",
        {timeout, 30, fun failed_core_connect_closes_the_session_of_a_run/0}}.

failed_core_connect_closes_the_session_of_a_run() ->
    Before = core_sessions(),
    {Client, Host} = tcp_pair(),
    Result = i2per_tun_flow:run(Host, <<"nonexistent.i2p">>, <<"127.0.0.1">>, closed_port()),
    ?assertMatch({error, _}, Result),
    ?assertEqual(Before, core_sessions()),
    gen_tcp:close(Client),
    gen_tcp:close(Host).

%% Every process started through `i2p_sam_api:create_session/1` runs this
%% callback, so the dictionary entry identifies a session wherever it lives.
core_sessions() ->
    [Pid || Pid <- processes(), initial_call(Pid) =:= {i2p_client_session, init, 1}].

initial_call(Pid) ->
    case erlang:process_info(Pid, dictionary) of
        {dictionary, Dict} -> proplists:get_value('$initial_call', Dict);
        undefined -> undefined
    end.

%% A port nothing listens on: the core path has no route to the target, and
%% the SAM fallback fails to connect, so `run_session` returns an error.
closed_port() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}]),
    {ok, {_, Port}} = inet:sockname(LSock),
    ok = gen_tcp:close(LSock),
    Port.

tcp_pair() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}]),
    {ok, {_, Port}} = inet:sockname(LSock),
    {ok, Client} = gen_tcp:connect(
        "127.0.0.1", Port, [binary, {packet, raw}, {active, false}], 5000
    ),
    {ok, Host} = gen_tcp:accept(LSock, 5000),
    gen_tcp:close(LSock),
    {Client, Host}.

mock_sam(LSock) ->
    case gen_tcp:accept(LSock, 10000) of
        {ok, Sock} ->
            gen_tcp:send(Sock, <<"HELLO REPLY RESULT=OK VERSION=3.1\n">>),
            {ok, _} = recv_line(Sock, 10000),
            gen_tcp:send(Sock, <<"SESSION STATUS RESULT=OK DESTINATION=mydest\n">>),
            {ok, _} = recv_line(Sock, 10000),
            gen_tcp:send(Sock, <<"NAMING REPLY RESULT=OK NAME=peer.i2p VALUE=targetdest\n">>),
            {ok, _} = recv_line(Sock, 10000),
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

recv_line(Sock, Timeout) when is_integer(Timeout) ->
    recv_line(Sock, <<>>, Timeout).

recv_line(Sock, Acc, Timeout) ->
    case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Data} ->
            Combined = <<Acc/binary, Data/binary>>,
            case binary:match(Combined, <<"\n">>) of
                {Pos, _} -> {ok, binary:part(Combined, 0, Pos + 1)};
                nomatch -> recv_line(Sock, Combined, Timeout)
            end;
        {error, _} = Err ->
            Err
    end.
