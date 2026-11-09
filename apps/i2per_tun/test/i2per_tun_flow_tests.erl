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

%% The flow relay's timeout is idle, not absolute: six ticks 100 ms apart span
%% 600 ms, longer than the 200 ms timeout, so an absolute timer would cut it.
relay_idle_timeout_is_reset_by_traffic_test_() ->
    {"the flow relay outlives its idle timeout while bytes keep flowing",
        {timeout, 30, fun relay_idle_timeout_is_reset_by_traffic/0}}.

relay_idle_timeout_is_reset_by_traffic() ->
    Saved = application:get_env(i2per_tun, relay_idle_timeout_ms),
    application:set_env(i2per_tun, relay_idle_timeout_ms, 200),
    {RelayA, PeerA} = tcp_pair(),
    {RelayB, PeerB} = tcp_pair(),
    Relay = spawn(fun() -> i2per_tun_flow:relay(RelayA, RelayB) end),
    try
        lists:foreach(
            fun(N) ->
                timer:sleep(100),
                ok = gen_tcp:send(PeerA, <<N:8>>),
                {ok, <<N:8>>} = gen_tcp:recv(PeerB, 1, 2000)
            end,
            lists:seq(1, 6)
        ),
        ?assert(is_process_alive(Relay))
    after
        exit(Relay, kill),
        close_all([PeerA, PeerB, RelayA, RelayB]),
        restore_env(relay_idle_timeout_ms, Saved)
    end.

relay_survives_silence_when_idle_timeout_is_disabled_test_() ->
    {"the flow relay survives silence and resumes when traffic returns",
        {timeout, 30, fun relay_survives_silence/0}}.

relay_survives_silence() ->
    Saved = application:get_env(i2per_tun, relay_idle_timeout_ms),
    application:unset_env(i2per_tun, relay_idle_timeout_ms),
    ?assertEqual(infinity, i2per_tun_config:relay_idle_timeout()),
    {RelayA, PeerA} = tcp_pair(),
    {RelayB, PeerB} = tcp_pair(),
    Relay = spawn(fun() -> i2per_tun_flow:relay(RelayA, RelayB) end),
    try
        timer:sleep(300),
        ?assert(is_process_alive(Relay)),
        ok = gen_tcp:send(PeerA, <<"after-silence">>),
        {ok, <<"after-silence">>} = gen_tcp:recv(PeerB, 13, 2000)
    after
        exit(Relay, kill),
        close_all([PeerA, PeerB, RelayA, RelayB]),
        restore_env(relay_idle_timeout_ms, Saved)
    end.

close_all(Socks) ->
    lists:foreach(fun(S) -> _ = gen_tcp:close(S) end, Socks).

restore_env(Key, {ok, Value}) ->
    application:set_env(i2per_tun, Key, Value);
restore_env(Key, undefined) ->
    application:unset_env(i2per_tun, Key).

dev_collect_loop(Parent) ->
    dev_collect_loop(Parent, <<>>).

dev_collect_loop(Parent, Acc) ->
    receive
        {tun_write, Bytes} ->
            Parent ! {dev_received, Bytes},
            dev_collect_loop(Parent, <<Acc/binary, Bytes/binary>>);
        stop ->
            ok
    end.

held_session_devpid_forwards_and_retains_nothing_test_() ->
    {"a held SAM session with a DevPid forwards bytes and retains nothing",
        {timeout, 30, fun() ->
            Self = self(),
            DevPid = spawn(fun() -> dev_collect_loop(Self) end),
            Mock = i2per_tun_mock_sam:start(fun(StreamSock) ->
                gen_tcp:send(StreamSock, <<"hello-bytes">>),
                timer:sleep(200)
            end),
            {_, SamPort, _} = Mock,
            try
                {ok, _SessionId, Pid} = i2per_tun_flow:run_session(
                    <<"peer.i2p">>, <<"127.0.0.1">>, SamPort, 5000, DevPid
                ),
                receive
                    {dev_received, Bytes} ->
                        ?assertEqual(<<"hello-bytes">>, Bytes)
                after 5000 ->
                    ?assert(false)
                end,
                ?assertEqual(<<>>, i2per_tun_flow:received(Pid)),
                i2per_tun_flow:stop_session(Pid)
            after
                i2per_tun_mock_sam:stop(Mock),
                exit(DevPid, kill)
            end
        end}}.
