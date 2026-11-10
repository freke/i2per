-module(i2per_proxy_http).

-moduledoc """
HTTP proxy handler for `i2per_proxy`.

Accepts a plain HTTP request on a client socket, extracts the target host,
opens a SAM STREAM session to it, forwards the request, and relays the
response back.

Unlike a request-line rewriter, this forwards the full header block and
request body verbatim (Content-Length and chunked transfer encodings are
both consumed so the request boundary is known), supports the standard
HTTP methods, and tunnels CONNECT.
""".

-export([handle/1]).

-spec handle(gen_tcp:socket()) -> ok.

handle(ClientSock) ->
    Result =
        case recv_request(ClientSock) of
            {ok, Info} ->
                case maps:get(method, Info) of
                    <<"CONNECT">> -> handle_connect(ClientSock, Info);
                    _Method -> handle_request(ClientSock, Info)
                end;
            error ->
                _ = send_http(ClientSock, 400, <<"Bad Request">>),
                ok
        end,
    gen_tcp:close(ClientSock),
    Result.

handle_request(ClientSock, Info) ->
    Method = maps:get(method, Info),
    Host = maps:get(host, Info),
    Path = maps:get(path, Info),
    Version = maps:get(version, Info),
    HeadersBin = maps:get(headers, Info),
    BodyBin = maps:get(body, Info),
    _ = Method,
    Request = build_request(Method, Path, Version, HeadersBin, BodyBin),
    case try_core_fetch(Host, Request, ClientSock) of
        ok ->
            ok;
        {fallback, Reason} ->
            _ = Reason,
            handle_request_sam(ClientSock, Host, Request);
        {error, _Reason, 0} ->
            _ = send_http(ClientSock, 502, <<"Bad Gateway">>),
            ok;
        {error, _Reason, _Total} ->
            ok
    end.

try_core_fetch(Host, Request, ClientSock) ->
    Node = i2per_proxy_config:router_node(),
    case catch erpc:call(Node, i2p_sam_api, create_session, [#{}], 5000) of
        {ok, SessionPid, _DestB64} ->
            Target = Host,
            case
                catch erpc:call(
                    Node, i2p_sam_api, stream_connect, [SessionPid, Target, self()], 15000
                )
            of
                {ok, ConnPid} ->
                    _ = catch erpc:call(Node, i2p_sam_api, stream_send, [ConnPid, Request]),
                    Result = core_recv_and_stream(ConnPid, ClientSock, 0),
                    _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
                    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid]),
                    case Result of
                        {ok, _Total} -> ok;
                        {error, Reason, Total} -> {error, Reason, Total}
                    end;
                _Other ->
                    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid]),
                    {fallback, _Other}
            end;
        _Other ->
            {fallback, _Other}
    end.

core_recv_and_stream(ConnPid, ClientSock, Total) ->
    receive
        {stream_data, ConnPid, Bytes} ->
            case stream_to_client(ClientSock, Bytes, Total) of
                {ok, NewTotal} ->
                    core_recv_and_stream(ConnPid, ClientSock, NewTotal);
                {error, cap_exceeded, NewTotal} ->
                    {error, response_too_large, NewTotal}
            end;
        {stream_closed, ConnPid} ->
            {ok, Total};
        {stream_reset, ConnPid} ->
            {error, reset, Total}
    after 30000 ->
        {error, timeout, Total}
    end.

handle_request_sam(ClientSock, Host, Request) ->
    case open_sam(Host) of
        {ok, SessionSock, StreamSock} ->
            Result = fetch_via_sam(StreamSock, ClientSock, Request),
            gen_tcp:close(StreamSock),
            gen_tcp:close(SessionSock),
            case Result of
                {ok, _Total} ->
                    ok;
                {error, _Reason, 0} ->
                    _ = send_http(ClientSock, 502, <<"Bad Gateway">>),
                    ok;
                {error, _Reason, _Total} ->
                    ok
            end;
        {error, Reason} ->
            _ = send_http(ClientSock, 503, iolist_to_binary(io_lib:format("~p", [Reason]))),
            ok
    end.

open_sam(Host) ->
    i2per_proxy_sam:open_stream(
        i2per_proxy_config:sam_host(), i2per_proxy_config:sam_port(), Host
    ).

fetch_via_sam(StreamSock, ClientSock, Request) ->
    Runner = self(),
    {Worker, Mon} =
        spawn_monitor(fun() ->
            Runner ! {proxy_fetch, self(), fetch_over_sam(StreamSock, ClientSock, Request)}
        end),
    receive
        {proxy_fetch, Worker, Result} ->
            erlang:demonitor(Mon, [flush]),
            Result;
        {'DOWN', Mon, process, Worker, Reason} ->
            {error, Reason, 0}
    after 30000 ->
        exit(Worker, kill),
        erlang:demonitor(Mon, [flush]),
        {error, fetch_timeout, 0}
    end.

fetch_over_sam(StreamSock, ClientSock, Request) ->
    ok = gen_tcp:send(StreamSock, Request),
    recv_stream_sam(StreamSock, ClientSock, 0).

%% ---- CONNECT tunneling ----

handle_connect(ClientSock, Info) ->
    Target = maps:get(url, Info),
    Host = strip_port(Target),
    Node = i2per_proxy_config:router_node(),
    case catch erpc:call(Node, i2p_sam_api, create_session, [#{}], 5000) of
        {ok, SessionPid, _DestB64} ->
            case
                catch erpc:call(
                    Node, i2p_sam_api, stream_connect, [SessionPid, Host, self()], 15000
                )
            of
                {ok, ConnPid} ->
                    _ = gen_tcp:send(ClientSock, <<"HTTP/1.1 200 Connection Established\r\n\r\n">>),
                    relay_core(ClientSock, ConnPid, Node),
                    _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
                    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid]),
                    ok;
                _Other ->
                    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid]),
                    connect_sam_http(ClientSock, Host)
            end;
        _ ->
            connect_sam_http(ClientSock, Host)
    end.

connect_sam_http(ClientSock, Host) ->
    case open_sam(Host) of
        {ok, SessionSock, StreamSock} ->
            _ = gen_tcp:send(ClientSock, <<"HTTP/1.1 200 Connection Established\r\n\r\n">>),
            i2per_proxy_relay:relay(ClientSock, StreamSock),
            close_sam(SessionSock, StreamSock),
            ok;
        {error, _} ->
            _ = send_http(ClientSock, 502, <<"Bad Gateway">>),
            ok
    end.

relay_core(ClientSock, ConnPid, Node) ->
    _ = inet:setopts(ClientSock, [{active, once}, {keepalive, true}]),
    relay_core_loop(ClientSock, ConnPid, Node).

relay_core_loop(ClientSock, ConnPid, Node) ->
    receive
        {tcp, ClientSock, Data} ->
            _ = catch erpc:call(Node, i2p_sam_api, stream_send, [ConnPid, Data]),
            _ = inet:setopts(ClientSock, [{active, once}]),
            relay_core_loop(ClientSock, ConnPid, Node);
        {tcp_closed, ClientSock} ->
            _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
            ok;
        {tcp_error, ClientSock, _} ->
            _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
            ok;
        {stream_data, ConnPid, Bytes} ->
            _ = gen_tcp:send(ClientSock, Bytes),
            relay_core_loop(ClientSock, ConnPid, Node);
        {stream_closed, ConnPid} ->
            ok;
        {stream_reset, ConnPid} ->
            ok
    after 30000 ->
        _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
        ok
    end.

close_sam(SessionSock, StreamSock) ->
    gen_tcp:close(StreamSock),
    gen_tcp:close(SessionSock),
    ok.

strip_port(Target) ->
    case binary:split(Target, <<":">>) of
        [Host, _Port] -> Host;
        [Host] -> Host
    end.

%% ---- request parsing ----

recv_request(Sock) ->
    case recv_until_headers(Sock, <<>>) of
        {ok, Raw, Leftover} ->
            case binary:split(Raw, <<"\r\n">>) of
                [ReqLine, Rest] ->
                    case parse_request_line(ReqLine) of
                        {ok, Method, Url, Version} ->
                            {Host, Path} = parse_url(Url),
                            case recv_body(Sock, Rest, Leftover) of
                                {ok, Body} ->
                                    {ok, #{
                                        method => Method,
                                        url => Url,
                                        host => Host,
                                        path => Path,
                                        version => Version,
                                        headers => Rest,
                                        body => Body
                                    }};
                                error ->
                                    error
                            end;
                        error ->
                            error
                    end;
                _ ->
                    error
            end;
        error ->
            error
    end.

parse_request_line(ReqLine) ->
    case binary:split(ReqLine, <<" ">>, [global]) of
        [Method, Url, Version] -> {ok, Method, Url, Version};
        [Method, Url] -> {ok, Method, Url, <<"HTTP/1.1">>};
        _ -> error
    end.

recv_until_headers(Sock, Acc) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        {Pos, _Len} ->
            Headers = binary:part(Acc, 0, Pos + 4),
            Leftover = binary:part(Acc, Pos + 4, byte_size(Acc) - (Pos + 4)),
            {ok, Headers, Leftover};
        nomatch ->
            case gen_tcp:recv(Sock, 0, 5000) of
                {ok, Data} when byte_size(Data) > 0 ->
                    recv_until_headers(Sock, <<Acc/binary, Data/binary>>);
                {ok, <<>>} ->
                    error;
                {error, _} ->
                    error
            end
    end.

recv_body(Sock, HeadersBin, Leftover) ->
    case content_length(HeadersBin) of
        N when is_integer(N), N >= 0 ->
            recv_exact(Sock, N, Leftover);
        _ ->
            case transfer_encoding_chunked(HeadersBin) of
                true -> recv_chunked(Sock, Leftover);
                false -> {ok, <<>>}
            end
    end.

recv_exact(_Sock, N, Acc) when byte_size(Acc) >= N ->
    {ok, binary:part(Acc, 0, N)};
recv_exact(_Sock, 0, Acc) ->
    {ok, Acc};
recv_exact(Sock, N, Acc) when N > 0 ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data} when byte_size(Data) > 0 ->
            recv_exact(Sock, N, <<Acc/binary, Data/binary>>);
        {ok, <<>>} ->
            error;
        {error, _} ->
            error
    end.

recv_chunked(Sock, Acc) ->
    case binary:match(Acc, <<"\r\n0\r\n\r\n">>) of
        {Pos, _Len} ->
            {ok, binary:part(Acc, 0, Pos + 7)};
        nomatch ->
            case gen_tcp:recv(Sock, 0, 5000) of
                {ok, Data} when byte_size(Data) > 0 ->
                    recv_chunked(Sock, <<Acc/binary, Data/binary>>);
                {ok, <<>>} ->
                    case binary:match(Acc, <<"\r\n0\r\n">>) of
                        {_, _} -> {ok, Acc};
                        nomatch -> error
                    end;
                {error, timeout} ->
                    case binary:match(Acc, <<"\r\n0\r\n">>) of
                        {_, _} -> {ok, Acc};
                        nomatch -> error
                    end;
                {error, _} ->
                    error
            end
    end.

content_length(HeadersBin) ->
    case re:run(HeadersBin, <<"Content-Length:\\s*(\\d+)">>, [caseless, {capture, [1], binary}]) of
        {match, [N]} ->
            try
                binary_to_integer(N)
            catch
                _:_ -> undefined
            end;
        _ ->
            undefined
    end.

transfer_encoding_chunked(HeadersBin) ->
    case re:run(HeadersBin, <<"Transfer-Encoding:">>, [caseless]) of
        {match, _} ->
            case re:run(HeadersBin, <<"chunked">>, [caseless]) of
                {match, _} -> true;
                _ -> false
            end;
        _ ->
            false
    end.

build_request(Method, Path, Version, HeadersBin, BodyBin) ->
    ReqLine = <<Method/binary, " ", Path/binary, " ", Version/binary, "\r\n">>,
    <<ReqLine/binary, HeadersBin/binary, BodyBin/binary>>.

parse_url(<<"http://", Rest/binary>>) ->
    case binary:split(Rest, <<"/">>) of
        [Host, RestPath] -> {Host, <<"/", RestPath/binary>>};
        [Host] -> {Host, <<"/">>}
    end;
parse_url(Url) ->
    case binary:split(Url, <<"/">>) of
        [Host, RestPath] -> {Host, <<"/", RestPath/binary>>};
        [Host] -> {Host, <<"/">>}
    end.

send_http(ClientSock, Code, Body) ->
    StatusText = status_text(Code),
    Resp = [
        <<"HTTP/1.1 ">>,
        integer_to_binary(Code),
        <<" ">>,
        StatusText,
        <<"\r\n">>,
        <<"Content-Length: ">>,
        integer_to_binary(byte_size(Body)),
        <<"\r\n">>,
        <<"\r\n">>,
        Body
    ],
    gen_tcp:send(ClientSock, Resp).

status_text(400) -> <<"Bad Request">>;
status_text(502) -> <<"Bad Gateway">>;
status_text(503) -> <<"Service Unavailable">>.

recv_stream_sam(Sock, ClientSock, Total) ->
    case gen_tcp:recv(Sock, 0, 2000) of
        {ok, Data} when byte_size(Data) > 0 ->
            case stream_to_client(ClientSock, Data, Total) of
                {ok, NewTotal} ->
                    recv_stream_sam(Sock, ClientSock, NewTotal);
                {error, cap_exceeded, NewTotal} ->
                    {error, response_too_large, NewTotal}
            end;
        {ok, <<>>} ->
            {ok, Total};
        {error, closed} ->
            {ok, Total};
        {error, timeout} ->
            {error, timeout, Total};
        {error, Reason} ->
            {error, Reason, Total}
    end.

stream_to_client(ClientSock, Data, Total) ->
    Cap = i2per_proxy_config:max_http_response_bytes(),
    Remaining = Cap - Total,
    Allowed =
        case Remaining > 0 of
            true -> erlang:min(byte_size(Data), Remaining);
            false -> 0
        end,
    if
        Allowed >= byte_size(Data) ->
            _ = gen_tcp:send(ClientSock, Data),
            {ok, Total + byte_size(Data)};
        Allowed > 0 ->
            Chunk = binary:part(Data, 0, Allowed),
            _ = gen_tcp:send(ClientSock, Chunk),
            {error, cap_exceeded, Total + Allowed};
        true ->
            {error, cap_exceeded, Total}
    end.
