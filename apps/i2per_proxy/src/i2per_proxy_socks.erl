-module(i2per_proxy_socks).

-moduledoc """
SOCKS proxy handler for `i2per_proxy`.

Supports SOCKS5 CONNECT (no authentication, domain-name targets) and
SOCKS4a CONNECT. After a successful CONNECT the handler relays bytes in
both directions.
""".

-export([handle/1]).

handle(ClientSock) ->
    Result =
        case gen_tcp:recv(ClientSock, 1, 5000) of
            {ok, <<5>>} ->
                socks5(ClientSock);
            {ok, <<4>>} ->
                socks4a(ClientSock);
            {ok, _} ->
                gen_tcp:close(ClientSock),
                ok;
            {error, _} ->
                ok
        end,
    gen_tcp:close(ClientSock),
    Result.

%% ---- SOCKS5 ----

socks5(ClientSock) ->
    case gen_tcp:recv(ClientSock, 1, 5000) of
        {ok, <<NMethods>>} ->
            case gen_tcp:recv(ClientSock, NMethods, 5000) of
                {ok, _Methods} ->
                    gen_tcp:send(ClientSock, <<5, 0>>),
                    socks5_request(ClientSock);
                _ ->
                    ok
            end;
        _ ->
            ok
    end.

socks5_request(ClientSock) ->
    case gen_tcp:recv(ClientSock, 4, 5000) of
        {ok, <<5, 1, 0, 3>>} ->
            case gen_tcp:recv(ClientSock, 1, 5000) of
                {ok, <<Len>>} ->
                    case gen_tcp:recv(ClientSock, Len + 2, 5000) of
                        {ok, <<Host:Len/binary, Port:16>>} ->
                            socks5_connect(ClientSock, Host, Port);
                        _ ->
                            ok
                    end;
                _ ->
                    ok
            end;
        {ok, <<5, 1, 0, 1>>} ->
            case gen_tcp:recv(ClientSock, 6, 5000) of
                {ok, <<A, B, C, D, Port:16>>} ->
                    Host = iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D])),
                    socks5_connect(ClientSock, Host, Port);
                _ ->
                    ok
            end;
        _ ->
            %% unsupported request
            gen_tcp:send(ClientSock, <<5, 7, 0, 1, 0, 0, 0, 0, 0, 0>>),
            ok
    end.

socks5_connect(ClientSock, Host, Port) ->
    _ = Port,
    %% Prefer the Erlang-network path (ADR 0001/0004, E1CHFWF): talk to the
    %% core over distribution instead of SAM on TCP. Fall back to SAM when the
    %% core is unreachable, so non-Erlang/legacy deployments keep working.
    case try_core_connect(ClientSock, Host) of
        ok ->
            ok;
        {fallback, Reason} ->
            _ = Reason,
            socks5_connect_sam(ClientSock, Host)
    end.

try_core_connect(ClientSock, Host) ->
    Node = i2per_proxy_config:router_node(),
    case catch erpc:call(Node, i2p_sam_api, create_session, [#{}], 5000) of
        {ok, SessionPid, _DestB64} ->
            case
                catch erpc:call(
                    Node, i2p_sam_api, stream_connect, [SessionPid, Host, self()], 15000
                )
            of
                {ok, ConnPid} ->
                    gen_tcp:send(ClientSock, <<5, 0, 0, 1, 0, 0, 0, 0, 0, 0>>),
                    relay_core(ClientSock, ConnPid),
                    i2p_sam_api:stream_close(ConnPid),
                    ok;
                Other ->
                    {fallback, Other}
            end;
        Other ->
            {fallback, Other}
    end.

relay_core(ClientSock, ConnPid) ->
    _ = inet:setopts(ClientSock, [{active, once}]),
    relay_core_loop(ClientSock, ConnPid).

relay_core_loop(ClientSock, ConnPid) ->
    receive
        {tcp, ClientSock, Data} ->
            _ = i2p_sam_api:stream_send(ConnPid, Data),
            _ = inet:setopts(ClientSock, [{active, once}]),
            relay_core_loop(ClientSock, ConnPid);
        {tcp_closed, ClientSock} ->
            i2p_sam_api:stream_close(ConnPid),
            ok;
        {tcp_error, ClientSock, _} ->
            i2p_sam_api:stream_close(ConnPid),
            ok;
        {stream_data, ConnPid, Bytes} ->
            _ = gen_tcp:send(ClientSock, Bytes),
            relay_core_loop(ClientSock, ConnPid);
        {stream_closed, ConnPid} ->
            ok;
        {stream_reset, ConnPid} ->
            ok
    after 300000 ->
        i2p_sam_api:stream_close(ConnPid),
        ok
    end.

socks5_connect_sam(ClientSock, Host) ->
    SamHost = i2per_proxy_config:sam_host(),
    SamPort = i2per_proxy_config:sam_port(),
    case
        gen_tcp:connect(
            binary_to_list(SamHost), SamPort, [binary, {packet, raw}, {active, false}], 5000
        )
    of
        {ok, SamSock} ->
            case open_sam(SamSock, Host) of
                ok ->
                    gen_tcp:send(ClientSock, <<5, 0, 0, 1, 0, 0, 0, 0, 0, 0>>),
                    i2per_proxy_relay:relay(ClientSock, SamSock),
                    gen_tcp:close(SamSock),
                    ok;
                {error, _} ->
                    gen_tcp:close(SamSock),
                    gen_tcp:send(ClientSock, <<5, 4, 0, 1, 0, 0, 0, 0, 0, 0>>),
                    ok
            end;
        {error, _} ->
            gen_tcp:send(ClientSock, <<5, 4, 0, 1, 0, 0, 0, 0, 0, 0>>),
            ok
    end.

open_sam(SamSock, Host) ->
    case i2per_proxy_sam:hello(SamSock) of
        ok ->
            case i2per_proxy_sam:session_create(SamSock) of
                {ok, SessionId, _DestB64} ->
                    case i2per_proxy_sam:naming_lookup(SamSock, Host) of
                        {ok, TargetB64} ->
                            i2per_proxy_sam:stream_connect(SamSock, SessionId, TargetB64);
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% ---- SOCKS4a ----

socks4a(ClientSock) ->
    case gen_tcp:recv(ClientSock, 7, 5000) of
        {ok, <<_Cmd:8, Port:16, 0, 0, 0, _NonZero:8>>} ->
            case recv_until(ClientSock, 0) of
                {ok, _User} ->
                    case recv_until(ClientSock, 0) of
                        {ok, Host} when byte_size(Host) > 0 ->
                            socks4a_connect(ClientSock, Host, Port);
                        _ ->
                            gen_tcp:send(ClientSock, <<0, 91, 0, 0, 0, 0, 0, 0>>),
                            ok
                    end;
                _ ->
                    gen_tcp:send(ClientSock, <<0, 91, 0, 0, 0, 0, 0, 0>>),
                    ok
            end;
        _ ->
            ok
    end.

socks4a_connect(ClientSock, Host, Port) ->
    SamHost = i2per_proxy_config:sam_host(),
    SamPort = i2per_proxy_config:sam_port(),
    case
        gen_tcp:connect(
            binary_to_list(SamHost), SamPort, [binary, {packet, raw}, {active, false}], 5000
        )
    of
        {ok, SamSock} ->
            case open_sam(SamSock, Host) of
                ok ->
                    gen_tcp:send(ClientSock, <<0, 90, Port:16, 0, 0, 0, 1>>),
                    i2per_proxy_relay:relay(ClientSock, SamSock),
                    gen_tcp:close(SamSock),
                    ok;
                {error, _} ->
                    gen_tcp:close(SamSock),
                    gen_tcp:send(ClientSock, <<0, 91, 0, 0, 0, 0, 0, 0>>),
                    ok
            end;
        {error, _} ->
            gen_tcp:send(ClientSock, <<0, 91, 0, 0, 0, 0, 0, 0>>),
            ok
    end.

recv_until(Sock, Term) ->
    recv_until(Sock, Term, <<>>).

recv_until(Sock, Term, Acc) ->
    case gen_tcp:recv(Sock, 1, 5000) of
        {ok, <<B>>} when B =:= Term ->
            {ok, Acc};
        {ok, <<B>>} ->
            recv_until(Sock, Term, <<Acc/binary, B>>);
        {error, _} ->
            {error, eof}
    end.
