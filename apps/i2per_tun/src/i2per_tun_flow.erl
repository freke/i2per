-module(i2per_tun_flow).

-moduledoc """
One TCP flow -> one SAM STREAM session (shape (a) spike).

Opens the two sockets SAM v3 requires: a session socket that carries the
handshake (`HELLO`, `SESSION CREATE`, `NAMING LOOKUP`) and stays open for the
life of the session, and a stream socket that carries `HELLO` and
`STREAM CONNECT` and then relays bytes in both directions until either side
closes. Runs in the caller's process.

`f:run_session/3` opens and holds a SAM STREAM session for a flow without a
host TCP socket attached yet — used by the TUN packet path to establish a
session up front; the relay is attached later.

A core session is per flow, so it must not outlive the flow: both core
helpers close the session on every exit path, including the one where the
session was created and the connect that followed failed.
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
                    close_core_session(Node, SessionPid),
                    ok;
                Other ->
                    close_core_session(Node, SessionPid),
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
    case i2per_tun_sam:open_stream(SamHost, SamPort, DestHost) of
        {ok, SessionSock, StreamSock} ->
            %% The stream socket carries the bytes; the session socket has to
            %% stay open for as long as the flow does, or the session ends.
            Result = relay(TcpSock, StreamSock),
            gen_tcp:close(StreamSock),
            gen_tcp:close(SessionSock),
            Result;
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
            Holder = spawn(fun() -> hold_core_session_wait(Node, SessionPid) end),
            case
                catch erpc:call(
                    Node, i2p_sam_api, stream_connect, [SessionPid, DestHost, Holder], 15000
                )
            of
                {ok, ConnPid} ->
                    Holder ! {conn, ConnPid},
                    SessionId = erlang:unique_integer([positive, monotonic]),
                    {ok, SessionId, Holder};
                Other ->
                    exit(Holder, kill),
                    close_core_session(Node, SessionPid),
                    {fallback, Other}
            end;
        Other ->
            {fallback, Other}
    end.

%% The holder is the only reference to this session, so every way it can end
%% has to close the session: otherwise the session, its conns and its published
%% LeaseSet outlive the flow.
hold_core_session_wait(Node, SessionPid) ->
    receive
        {conn, ConnPid} -> hold_core_session(Node, SessionPid, ConnPid)
    end.

hold_core_session(Node, SessionPid, ConnPid) ->
    receive
        {stream_data, ConnPid, _Bytes} ->
            hold_core_session(Node, SessionPid, ConnPid);
        {stream_closed, ConnPid} ->
            stop_core_flow(Node, SessionPid, ConnPid);
        {stream_reset, ConnPid} ->
            stop_core_flow(Node, SessionPid, ConnPid);
        stop ->
            stop_core_flow(Node, SessionPid, ConnPid);
        {stop, From, Ref} ->
            stop_core_flow(Node, SessionPid, ConnPid),
            From ! {stopped, Ref},
            ok
    end.

stop_core_flow(Node, SessionPid, ConnPid) ->
    catch i2p_sam_api:stream_close(ConnPid),
    close_core_session(Node, SessionPid).

close_core_session(Node, SessionPid) ->
    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid], 5000),
    ok.

run_session_sam(DestHost, SamHost, SamPort, Timeout) ->
    case i2per_tun_sam:open_stream(SamHost, SamPort, DestHost, Timeout) of
        {ok, SessionSock, StreamSock} ->
            Pid = spawn(fun() -> hold_session(SessionSock, StreamSock) end),
            %% The session id is a client-side handle, as on the core path; the
            %% holder pid is what keeps the session alive.
            {ok, erlang:unique_integer([positive, monotonic]), Pid};
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

%% Both sockets belong to the flow: the session socket is the session, and the
%% stream socket is the data path. Closing either one on `stop` is what ends
%% the flow and releases the session.
hold_session(SessionSock, StreamSock) ->
    receive
        stop ->
            close_sam(SessionSock, StreamSock),
            ok;
        {stop, From, Ref} ->
            close_sam(SessionSock, StreamSock),
            From ! {stopped, Ref},
            ok
    end.

close_sam(SessionSock, StreamSock) ->
    gen_tcp:close(StreamSock),
    gen_tcp:close(SessionSock),
    ok.

-spec stop_session(pid()) -> ok.
stop_session(Pid) when is_pid(Pid) ->
    Pid ! stop,
    ok.
