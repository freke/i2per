-module(i2per_tun_flow).

-moduledoc """
One TCP flow -> one SAM STREAM session (shape (a) spike).

Opens a SAM connection, runs the conversation, then relays bytes in both
directions until either side closes. Runs in the caller's process.

`f:run_session/3` opens and holds a SAM STREAM session for a flow without a
host TCP socket attached yet — used by the TUN packet path to establish a
session up front; the relay is attached later.
""".

-export([run/4, run_session/3, run_session/4, stop_session/1]).

-spec run(gen_tcp:socket(), binary(), binary(), inet:port_number()) -> ok | {error, term()}.
run(TcpSock, DestHost, SamHost, SamPort) ->
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
