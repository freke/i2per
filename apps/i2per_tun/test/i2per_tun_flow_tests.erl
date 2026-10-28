-module(i2per_tun_flow_tests).

-include_lib("eunit/include/eunit.hrl").

run_session_holds_both_sockets_test_() ->
    {"run_session opens and holds the session and stream sockets",
        {timeout, 30, fun() ->
            Self = self(),
            Mock = i2per_tun_mock_sam:start(fun(StreamSock) ->
                %% The holder must keep the stream open until it is stopped.
                Self ! {stream_closed, gen_tcp:recv(StreamSock, 0, 5000)}
            end),
            {_, SamPort, _} = Mock,
            try
                {ok, _SessionId, Pid} = i2per_tun_flow:run_session(
                    <<"peer.i2p">>, <<"127.0.0.1">>, SamPort
                ),
                ?assert(is_pid(Pid)),
                i2per_tun_flow:stop_session(Pid),
                receive
                    {stream_closed, Result} -> ?assertEqual({error, closed}, Result)
                after 5000 ->
                    ?assert(false)
                end
            after
                i2per_tun_mock_sam:stop(Mock)
            end
        end}}.

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
