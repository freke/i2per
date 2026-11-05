-module(i2per_tun_flow_core_tests).

-include_lib("eunit/include/eunit.hrl").

core_sessions() ->
    [Pid || Pid <- processes(), initial_call(Pid) =:= {i2p_client_session, init, 1}].

initial_call(Pid) ->
    case erlang:process_info(Pid, dictionary) of
        {dictionary, Dict} -> proplists:get_value('$initial_call', Dict);
        undefined -> undefined
    end.

closed_port() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}]),
    {ok, {_, Port}} = inet:sockname(LSock),
    gen_tcp:close(LSock),
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

run_direct_path_test_() ->
    {"run/4 exercises the core (erpc) path against a running router",
        {timeout, 60, fun() ->
            try
                i2per_tun_core_router:start(),
                Before = core_sessions(),
                Port = closed_port(),
                {Client, Host} = tcp_pair(),
                Result = i2per_tun_flow:run(Host, <<"peer.i2p">>, <<"127.0.0.1">>, Port),
                ?assertMatch({error, _}, Result),
                ?assertEqual(Before, core_sessions()),
                gen_tcp:close(Client),
                gen_tcp:close(Host)
            after
                i2per_tun_core_router:stop()
            end
        end}}.

run_session_direct_path_test_() ->
    {"run_session/3 exercises the core (erpc) path against a running router",
        {timeout, 60, fun() ->
            try
                i2per_tun_core_router:start(),
                Before = core_sessions(),
                Port = closed_port(),
                Result = i2per_tun_flow:run_session(<<"peer.i2p">>, <<"127.0.0.1">>, Port),
                ?assertMatch({error, _}, Result),
                ?assertEqual(Before, core_sessions())
            after
                i2per_tun_core_router:stop()
            end
        end}}.

run_raw_session_direct_path_test_() ->
    {"run_raw_session/3 exercises the core (erpc) path against a running router",
        {timeout, 60, fun() ->
            try
                i2per_tun_core_router:start(),
                {ok, _SessionId, Pid} = i2per_tun_flow:run_raw_session(
                    <<"peer.i2p">>, <<"127.0.0.1">>, 7656
                ),
                ?assert(is_pid(Pid)),
                Result = i2per_tun_flow:send_raw(Pid, <<"payload">>),
                ?assertMatch({error, _}, Result),
                i2per_tun_flow:stop_session(Pid)
            after
                i2per_tun_core_router:stop()
            end
        end}}.
