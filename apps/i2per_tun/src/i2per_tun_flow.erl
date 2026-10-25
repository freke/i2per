-module(i2per_tun_flow).

-moduledoc """
One TCP flow -> one SAM STREAM session (shape (a) spike).

Opens a SAM connection, runs the conversation, then relays bytes in both
directions until either side closes. Runs in the caller's process.

`f:run_session/3` opens and holds a SAM STREAM session for a flow without a
host TCP socket attached yet — used by the TUN packet path to establish a
session up front; the relay is attached later.
""".

-export([
    run/4,
    run_session/3, run_session/4,
    run_raw_session/3, run_raw_session/4,
    send_raw/2,
    stop_session/1
]).

-spec run(gen_tcp:socket(), binary(), binary(), inet:port_number()) -> ok | {error, term()}.
run(TcpSock, DestHost, SamHost, SamPort) ->
    %% Prefer the Erlang-network path (E1CHFWF); fall back to SAM TCP.
    case try_core_run(TcpSock, DestHost) of
        ok ->
            ok;
        {fallback, _} ->
            run_sam(TcpSock, DestHost, SamHost, SamPort)
    end.

try_core_run(TcpSock, DestHost) ->
    Node = i2per_tun_config:router_node(),
    case catch erpc:call(Node, i2p_sam_api, create_session, [#{}], 5000) of
        {ok, SessionPid, _DestB64} ->
            case
                catch erpc:call(
                    Node, i2p_sam_api, stream_connect, [SessionPid, DestHost, self()], 15000
                )
            of
                {ok, ConnPid} ->
                    relay_core(TcpSock, ConnPid),
                    i2p_sam_api:stream_close(ConnPid),
                    ok;
                Other ->
                    {fallback, Other}
            end;
        Other ->
            {fallback, Other}
    end.

relay_core(TcpSock, ConnPid) ->
    _ = inet:setopts(TcpSock, [{active, once}]),
    relay_core_loop(TcpSock, ConnPid).

relay_core_loop(TcpSock, ConnPid) ->
    receive
        {tcp, TcpSock, Data} ->
            _ = i2p_sam_api:stream_send(ConnPid, Data),
            _ = inet:setopts(TcpSock, [{active, once}]),
            relay_core_loop(TcpSock, ConnPid);
        {tcp_closed, TcpSock} ->
            i2p_sam_api:stream_close(ConnPid),
            ok;
        {tcp_error, TcpSock, _} ->
            i2p_sam_api:stream_close(ConnPid),
            ok;
        {stream_data, ConnPid, Bytes} ->
            _ = gen_tcp:send(TcpSock, Bytes),
            relay_core_loop(TcpSock, ConnPid);
        {stream_closed, ConnPid} ->
            ok;
        {stream_reset, ConnPid} ->
            ok
    after 300000 ->
        i2p_sam_api:stream_close(ConnPid),
        ok
    end.

run_sam(TcpSock, DestHost, SamHost, SamPort) ->
    case
        gen_tcp:connect(
            binary_to_list(SamHost), SamPort, [binary, {packet, raw}, {active, false}], 5000
        )
    of
        {ok, SamSock} ->
            Result = do_flow(SamSock, DestHost, TcpSock),
            gen_tcp:close(SamSock),
            Result;
        {error, _} = Err ->
            Err
    end.

do_flow(SamSock, DestHost, TcpSock) ->
    case i2per_tun_sam:hello(SamSock) of
        ok ->
            case i2per_tun_sam:session_create(SamSock) of
                {ok, SessionId, _DestB64} ->
                    case i2per_tun_sam:naming_lookup(SamSock, DestHost) of
                        {ok, TargetB64} ->
                            case i2per_tun_sam:stream_connect(SamSock, SessionId, TargetB64) of
                                ok ->
                                    relay(TcpSock, SamSock);
                                {error, _} = Err ->
                                    Err
                            end;
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

relay(TcpSock, SamSock) ->
    %% Put both sockets in active mode? Simpler: spawn a forwarder each direction.
    Parent = self(),
    P1 = spawn_link(fun() -> forward(TcpSock, SamSock, Parent) end),
    P2 = spawn_link(fun() -> forward(SamSock, TcpSock, Parent) end),
    receive
        {done, P1} ->
            receive
                {done, P2} -> ok
            after 5000 -> ok
            end;
        {done, P2} ->
            receive
                {done, P1} -> ok
            after 5000 -> ok
            end
    after 300000 ->
        exit(P1, kill),
        exit(P2, kill),
        ok
    end.

forward(Src, Dst, Parent) ->
    case gen_tcp:recv(Src, 0, 30000) of
        {ok, Data} ->
            case gen_tcp:send(Dst, Data) of
                ok -> forward(Src, Dst, Parent);
                {error, _} -> Parent ! {done, self()}
            end;
        {error, _} ->
            Parent ! {done, self()}
    end.

-doc "Open and hold a SAM STREAM session for a flow, without a host socket.".
run_session(DestHost, SamHost, SamPort) ->
    run_session(DestHost, SamHost, SamPort, 5000).

run_session(DestHost, SamHost, SamPort, Timeout) ->
    _ = Timeout,
    case try_core_run_session(DestHost) of
        {ok, SessionId, HoldPid} ->
            {ok, SessionId, HoldPid};
        {fallback, _} ->
            run_session_sam(DestHost, SamHost, SamPort, Timeout)
    end.

try_core_run_session(DestHost) ->
    Node = i2per_tun_config:router_node(),
    case catch erpc:call(Node, i2p_sam_api, create_session, [#{}], 5000) of
        {ok, SessionPid, _DestB64} ->
            case
                catch erpc:call(
                    Node, i2p_sam_api, stream_connect, [SessionPid, DestHost, self()], 15000
                )
            of
                {ok, ConnPid} ->
                    HoldPid = spawn(fun() -> hold_core_session(ConnPid) end),
                    SessionId = erlang:unique_integer([positive, monotonic]),
                    {ok, SessionId, HoldPid};
                Other ->
                    {fallback, Other}
            end;
        Other ->
            {fallback, Other}
    end.

hold_core_session(ConnPid) ->
    receive
        stop ->
            i2p_sam_api:stream_close(ConnPid),
            ok;
        {stop, From, Ref} ->
            i2p_sam_api:stream_close(ConnPid),
            From ! {stopped, Ref},
            ok
    end.

run_session_sam(DestHost, SamHost, SamPort, Timeout) ->
    case
        gen_tcp:connect(
            binary_to_list(SamHost), SamPort, [binary, {packet, raw}, {active, false}], Timeout
        )
    of
        {ok, SamSock} ->
            case i2per_tun_sam:hello(SamSock) of
                ok ->
                    case i2per_tun_sam:session_create(SamSock) of
                        {ok, SessionId, _DestB64} ->
                            case i2per_tun_sam:naming_lookup(SamSock, DestHost) of
                                {ok, TargetB64} ->
                                    case
                                        i2per_tun_sam:stream_connect(SamSock, SessionId, TargetB64)
                                    of
                                        ok ->
                                            Pid = spawn(fun() -> hold_session(SamSock) end),
                                            {ok, SessionId, Pid};
                                        {error, _} = Err ->
                                            gen_tcp:close(SamSock),
                                            Err
                                    end;
                                {error, _} = Err ->
                                    gen_tcp:close(SamSock),
                                    Err
                            end;
                        {error, _} = Err ->
                            gen_tcp:close(SamSock),
                            Err
                    end;
                {error, _} = Err ->
                    gen_tcp:close(SamSock),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

-doc "Open and hold a SAM RAW session for a UDP flow, without a host socket.".
run_raw_session(DestHost, SamHost, SamPort) ->
    run_raw_session(DestHost, SamHost, SamPort, 5000).

run_raw_session(DestHost, SamHost, SamPort, Timeout) ->
    _ = {SamHost, SamPort, Timeout},
    %% Prefer the Erlang-network path: raw sends go through i2p_sam_api.
    %% No SAM fallback is needed because the holder forwards send_raw to
    %% the core and surfaces failures there.
    HoldPid = spawn(fun() -> hold_core_raw_session(DestHost) end),
    SessionId = erlang:unique_integer([positive, monotonic]),
    {ok, SessionId, HoldPid}.

hold_core_raw_session(DestHost) ->
    hold_core_raw_session(DestHost, i2per_tun_config:router_node()).

hold_core_raw_session(DestHost, Node) ->
    receive
        {send, Payload, From, Ref} ->
            Result =
                try
                    erpc:call(Node, i2p_sam_api, raw_send, [DestHost, Payload], 5000)
                catch
                    Class:Reason -> {error, {Class, Reason}}
                end,
            From ! {sent, Ref, Result},
            hold_core_raw_session(DestHost, Node);
        stop ->
            ok;
        {stop, From, Ref} ->
            From ! {stopped, Ref},
            ok
    end.

-spec send_raw(pid(), binary()) -> ok | {error, term()}.
send_raw(Pid, Payload) when is_pid(Pid), is_binary(Payload) ->
    Ref = make_ref(),
    Pid ! {send, Payload, self(), Ref},
    receive
        {sent, Ref} -> ok;
        {sent, Ref, ok} -> ok;
        {sent, Ref, {error, _} = Err} -> Err;
        {sent, Ref, Other} -> {error, Other}
    after 5000 -> {error, timeout}
    end.

hold_session(SamSock) ->
    receive
        stop ->
            gen_tcp:close(SamSock),
            ok;
        {stop, From, Ref} ->
            gen_tcp:close(SamSock),
            From ! {stopped, Ref},
            ok
    end.

-spec stop_session(pid()) -> ok.
stop_session(Pid) when is_pid(Pid) ->
    Pid ! stop,
    ok.
