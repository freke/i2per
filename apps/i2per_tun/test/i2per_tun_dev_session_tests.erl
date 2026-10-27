-module(i2per_tun_dev_session_tests).

-moduledoc """
Hermetic tests for `i2per_tun_dev` session spawning (epiq 091VYQC).

No privileges and no real TUN device are required: the device owner is
started with the fake TUN facade (`i2per_tun_tun_fake`) and packets are
fed through `i2per_tun_dev:inject/1`. A mock SAM server on an ephemeral
port stands in for the core.
""".

-include_lib("eunit/include/eunit.hrl").

%% ---------------------------------------------------------------- helpers

fake_opts(SamPort, Destinations) ->
    #{
        tun_mod => i2per_tun_tun_fake,
        sam_host => <<"127.0.0.1">>,
        sam_port => SamPort,
        destinations => Destinations,
        spawn_sessions => true
    }.

destinations() ->
    #{<<"10.0.0.2">> => <<"peer.i2p">>}.

tcp_packet() ->
    <<4:4, 5:4, 0:8, 40:16, 0:16, 0:16, 64:8, 6:8, 0:16, 10, 0, 0, 1, 10, 0, 0, 2, 1234:16, 80:16,
        0:32, 0:32, 5:4, 0:4, 0:8, 1000:16, 0:16, 0:16, "x">>.

udp_packet() ->
    <<4:4, 5:4, 0:8, 28:16, 0:16, 0:16, 64:8, 17:8, 0:16, 10, 0, 0, 1, 10, 0, 0, 2, 53:16, 5353:16,
        8:16, 0:16, "hi">>.

start_dev(SamPort) ->
    {ok, Pid} = i2per_tun_dev:start_link(fake_opts(SamPort, destinations())),
    Pid.

start_dev_disabled(SamPort) ->
    {ok, Pid} = i2per_tun_dev:start_link(#{
        tun_mod => i2per_tun_tun_fake,
        sam_host => <<"127.0.0.1">>,
        sam_port => SamPort,
        destinations => destinations(),
        spawn_sessions => false
    }),
    Pid.

stop_dev(Pid) ->
    catch gen_server:stop(Pid),
    ok.

start_tcp_mock() ->
    Mock = i2per_tun_mock_sam:start(fun(StreamSock) ->
        %% The device holds the flow for the life of the session; return when
        %% the device closes it.
        _ = gen_tcp:recv(StreamSock, 0, 5000),
        ok
    end),
    {_, Port, _} = Mock,
    {Mock, Port}.

stop_tcp_mock(Mock) ->
    i2per_tun_mock_sam:stop(Mock),
    ok.

start_raw_mock() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, {_, Port}} = inet:sockname(LSock),
    Server = spawn(fun() -> mock_sam_raw(LSock) end),
    {LSock, Port, Server}.

stop_mock({LSock, _Port, Server}) ->
    Server ! stop,
    catch gen_tcp:close(LSock),
    ok.

mock_sam_raw(LSock) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            gen_tcp:send(Sock, <<"HELLO REPLY RESULT=OK VERSION=3.1\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"SESSION STATUS RESULT=OK DESTINATION=mydest\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"NAMING REPLY RESULT=OK NAME=peer.i2p VALUE=targetdest\n">>),
            _ = gen_tcp:recv(Sock, 0, 1000),
            receive
                stop -> ok
            after 5000 -> ok
            end,
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            ok
    end.

%% ---------------------------------------------------------------- tests

session_spawning_test() ->
    {Mock, Port} = start_tcp_mock(),
    Pid = start_dev(Port),
    try
        ?assertEqual(ok, i2per_tun_dev:inject(Pid, tcp_packet())),
        ?assertEqual(1, maps:size(i2per_tun_dev:sessions(Pid))),
        ?assertEqual(1, maps:size(i2per_tun_dev:flows(Pid))),
        ?assertEqual(ok, i2per_tun_dev:inject(Pid, tcp_packet())),
        ?assertEqual(1, maps:size(i2per_tun_dev:sessions(Pid))),
        ?assertEqual(
            2,
            maps:get(
                {tcp, {10, 0, 0, 1}, {10, 0, 0, 2}, 1234, 80},
                i2per_tun_dev:flows(Pid)
            )
        )
    after
        stop_dev(Pid),
        stop_tcp_mock(Mock)
    end.

monitor_teardown_test() ->
    {Mock, Port} = start_tcp_mock(),
    Pid = start_dev(Port),
    i2per_tun_dev:inject(Pid, tcp_packet()),
    SessPid = hd(maps:values(i2per_tun_dev:sessions(Pid))),
    try
        exit(SessPid, kill),
        timer:sleep(100),
        ?assertEqual(0, maps:size(i2per_tun_dev:sessions(Pid)))
    after
        stop_dev(Pid),
        stop_tcp_mock(Mock)
    end.

stats_test() ->
    {Mock, Port} = start_tcp_mock(),
    Pid = start_dev(Port),
    try
        i2per_tun_dev:inject(Pid, tcp_packet()),
        i2per_tun_dev:inject(Pid, tcp_packet()),
        S = i2per_tun_dev:stats(Pid),
        ?assertEqual(2, maps:get(packets, S)),
        ?assertEqual(1, maps:get(sessions, S)),
        ?assert(maps:get(bytes, S) > 0)
    after
        stop_dev(Pid),
        stop_tcp_mock(Mock)
    end.

spawn_disabled_test() ->
    {Mock, Port} = start_tcp_mock(),
    Pid = start_dev_disabled(Port),
    try
        i2per_tun_dev:inject(Pid, tcp_packet()),
        ?assertEqual(0, maps:size(i2per_tun_dev:sessions(Pid))),
        ?assertEqual(1, maps:size(i2per_tun_dev:flows(Pid)))
    after
        stop_dev(Pid),
        stop_tcp_mock(Mock)
    end.

udp_wiring_test() ->
    Mock = start_raw_mock(),
    Port = element(2, Mock),
    Pid = start_dev(Port),
    try
        ?assertEqual(ok, i2per_tun_dev:inject(Pid, udp_packet())),
        ?assertEqual(1, maps:size(i2per_tun_dev:sessions(Pid))),
        ?assertEqual(1, maps:size(i2per_tun_dev:flows(Pid)))
    after
        stop_dev(Pid),
        stop_mock(Mock)
    end.
