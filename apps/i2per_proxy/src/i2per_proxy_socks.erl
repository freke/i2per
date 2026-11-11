-module(i2per_proxy_socks).

-moduledoc """
SOCKS proxy handler for `i2per_proxy`.

Supports SOCKS5 CONNECT (no authentication, IPv4, IPv6 and domain-name
targets) and SOCKS4a CONNECT. After a successful CONNECT the handler
relays bytes in both directions.

BIND (0x02) and UDP ASSOCIATE (0x03) are not supported and are rejected
with a 0x07 reply, as is any ATYP other than 1 (IPv4), 3 (domain) and
4 (IPv6).
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
                    _ = gen_tcp:send(ClientSock, <<5, 0>>),
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
                            socks5_connect(ClientSock, Host, Port, 3);
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
                    socks5_connect(ClientSock, Host, Port, 1);
                _ ->
                    ok
            end;
        {ok, <<5, 1, 0, 4>>} ->
            case gen_tcp:recv(ClientSock, 18, 5000) of
                {ok, <<IpBin:16/binary, Port:16>>} ->
                    Host = ipv6_to_binary(IpBin),
                    socks5_connect(ClientSock, Host, Port, 4);
                _ ->
                    ok
            end;
        _ ->
            %% unsupported request (BIND, UDP ASSOCIATE, unknown ATYP)
            _ = gen_tcp:send(ClientSock, <<5, 7, 0, 1, 0, 0, 0, 0, 0, 0>>),
            ok
    end.

ipv6_to_binary(IpBin) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> = IpBin,
    list_to_binary(inet:ntoa({A, B, C, D, E, F, G, H})).

socks5_reply(4) ->
    <<5, 0, 0, 4, 0:128, 0:16>>;
socks5_reply(_) ->
    <<5, 0, 0, 1, 0, 0, 0, 0, 0, 0>>.

socks5_error_reply(4) ->
    <<5, 4, 0, 4, 0:128, 0:16>>;
socks5_error_reply(_) ->
    <<5, 4, 0, 1, 0, 0, 0, 0, 0, 0>>.

socks5_connect(ClientSock, Host, Port, Atyp) ->
    _ = Port,
    %% Prefer the Erlang-network path (ADR 0001/0004, E1CHFWF): talk to the
    %% core over distribution instead of SAM on TCP. Fall back to SAM when the
    %% core is unreachable, so non-Erlang/legacy deployments keep working.
    case try_core_connect(ClientSock, Host, Atyp) of
        ok ->
            ok;
        {fallback, Reason} ->
            _ = Reason,
            socks5_connect_sam(ClientSock, Host, Atyp)
    end.

try_core_connect(ClientSock, Host, Atyp) ->
    Node = i2per_proxy_config:router_node(),
    case catch erpc:call(Node, i2p_sam_api, create_session, [#{}], 5000) of
        {ok, SessionPid, _DestB64} ->
            case
                catch erpc:call(
                    Node, i2p_sam_api, stream_connect, [SessionPid, Host, self()], 15000
                )
            of
                {ok, ConnPid} ->
                    _ = gen_tcp:send(ClientSock, socks5_reply(Atyp)),
                    relay_core(ClientSock, ConnPid, Node),
                    _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
                    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid]),
                    ok;
                Other ->
                    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid]),
                    {fallback, Other}
            end;
        Other ->
            {fallback, Other}
    end.

relay_core(ClientSock, ConnPid, Node) ->
    Idle = i2per_proxy_config:relay_idle_timeout(),
    _ = inet:setopts(ClientSock, [{active, once}, {keepalive, true}]),
    relay_core_loop(ClientSock, ConnPid, Node, Idle).

relay_core_loop(ClientSock, ConnPid, Node, Idle) ->
    receive
        {tcp, ClientSock, Data} ->
            _ = catch erpc:call(Node, i2p_sam_api, stream_send, [ConnPid, Data]),
            _ = inet:setopts(ClientSock, [{active, once}]),
            relay_core_loop(ClientSock, ConnPid, Node, Idle);
        {tcp_closed, ClientSock} ->
            _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
            ok;
        {tcp_error, ClientSock, _} ->
            _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
            ok;
        {stream_data, ConnPid, Bytes} ->
            _ = gen_tcp:send(ClientSock, Bytes),
            relay_core_loop(ClientSock, ConnPid, Node, Idle);
        {stream_closed, ConnPid} ->
            ok;
        {stream_reset, ConnPid} ->
            ok
    after Idle ->
        _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
        ok
    end.

socks5_connect_sam(ClientSock, Host, Atyp) ->
    case open_sam(Host) of
        {ok, SessionSock, StreamSock} ->
            _ = gen_tcp:send(ClientSock, socks5_reply(Atyp)),
            i2per_proxy_relay:relay(ClientSock, StreamSock),
            close_sam(SessionSock, StreamSock),
            ok;
        {error, _} ->
            _ = gen_tcp:send(ClientSock, socks5_error_reply(Atyp)),
            ok
    end.

open_sam(Host) ->
    i2per_proxy_sam:open_stream(
        i2per_proxy_config:sam_host(), i2per_proxy_config:sam_port(), Host
    ).

close_sam(SessionSock, StreamSock) ->
    gen_tcp:close(StreamSock),
    gen_tcp:close(SessionSock),
    ok.

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
                            _ = gen_tcp:send(ClientSock, <<0, 91, 0, 0, 0, 0, 0, 0>>),
                            ok
                    end;
                _ ->
                    _ = gen_tcp:send(ClientSock, <<0, 91, 0, 0, 0, 0, 0, 0>>),
                    ok
            end;
        _ ->
            ok
    end.

socks4a_connect(ClientSock, Host, Port) ->
    case open_sam(Host) of
        {ok, SessionSock, StreamSock} ->
            _ = gen_tcp:send(ClientSock, <<0, 90, Port:16, 0, 0, 0, 1>>),
            i2per_proxy_relay:relay(ClientSock, StreamSock),
            close_sam(SessionSock, StreamSock),
            ok;
        {error, _} ->
            _ = gen_tcp:send(ClientSock, <<0, 91, 0, 0, 0, 0, 0, 0>>),
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
