-module(i2per_tun_datapath_e2e_SUITE).

-moduledoc """
Hermetic end-to-end TUN datapath test (epiq B0BGEZJ).

No privileges and no real TUN device: the device owner runs on the fake
recording TUN facade and a mock SAM v3 server stands in for the core.
Bytes are checked in both directions and the holder's retained state is
asserted to stay empty (bounded).
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([end_to_end_byte_delivery/1]).

all() -> [end_to_end_byte_delivery].

init_per_testcase(_TC, Config) ->
    i2per_tun_tun_record:register_sink(self()),
    Config.

end_per_testcase(_TC, _Config) ->
    i2per_tun_tun_record:unregister_sink(),
    ok.

tcp_packet() ->
    <<4:4, 5:4, 0:8, 40:16, 0:16, 0:16, 64:8, 6:8, 0:16, 10, 0, 0, 1, 10, 0, 0, 2, 1234:16, 80:16,
        0:32, 0:32, 5:4, 0:4, 0:8, 1000:16, 0:16, 0:16, "x">>.

destinations() ->
    #{<<"10.0.0.2">> => <<"peer.i2p">>}.

fake_opts(Port) ->
    #{
        tun_mod => i2per_tun_tun_record,
        sam_host => <<"127.0.0.1">>,
        sam_port => Port,
        destinations => destinations(),
        spawn_sessions => true
    }.

end_to_end_byte_delivery(_Config) ->
    Parent = self(),
    OnStream = fun(StreamSock) ->
        gen_tcp:send(StreamSock, <<"from-peer">>),
        %% Wait for the client's bytes (or a timeout) before closing.
        case gen_tcp:recv(StreamSock, 0, 2000) of
            {ok, Data} -> Parent ! {mock_received, Data};
            {error, _} -> Parent ! {mock_received, <<>>}
        end,
        ok
    end,
    Mock = i2per_tun_mock_sam:start(OnStream),
    {_LSock, Port, _Pid} = Mock,
    {ok, DevPid} = i2per_tun_dev:start_link(fake_opts(Port)),
    try
        ?assertEqual(ok, i2per_tun_dev:inject(DevPid, tcp_packet())),
        wait_for_sessions(DevPid, 1, 5000),
        ?assertEqual(1, maps:size(i2per_tun_dev:sessions(DevPid))),
        SessPid = hd(maps:values(i2per_tun_dev:sessions(DevPid))),
        ?assertEqual(ok, i2per_tun_dev:inject(DevPid, tcp_packet())),
        TunWrites = i2per_tun_tun_record:collect(1, 2000),
        ?assertEqual([<<"from-peer">>], TunWrites),
        receive
            {mock_received, <<"x">>} -> ok;
            {mock_received, Other} -> ct:fail({unexpected_mock_received, Other})
        after 5000 ->
            ct:fail(mock_did_not_receive)
        end,
        ?assertEqual(<<>>, i2per_tun_flow:held_bytes(SessPid))
    after
        catch gen_server:stop(DevPid),
        i2per_tun_mock_sam:stop(Mock),
        ok
    end.

wait_for_sessions(_Pid, 0, _Timeout) -> ok;
wait_for_sessions(Pid, N, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_for_sessions_loop(Pid, N, Deadline).

wait_for_sessions_loop(Pid, N, Deadline) ->
    case maps:size(i2per_tun_dev:sessions(Pid)) >= N of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> ct:fail(session_timeout);
                false -> timer:sleep(10), wait_for_sessions_loop(Pid, N, Deadline)
            end
    end.