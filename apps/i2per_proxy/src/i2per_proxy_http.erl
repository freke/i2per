-module(i2per_proxy_http).

-moduledoc """
HTTP proxy handler for `i2per_proxy`.

Accepts a plain HTTP request on a client socket, extracts the target host,
opens a SAM STREAM session to it, forwards the request, and relays the
response back.
""".

-export([handle/1]).

handle(ClientSock) ->
    Result =
        case recv_request(ClientSock) of
            {ok, Method, Url} when
                Method =:= <<"GET">>; Method =:= <<"HEAD">>
            ->
                handle_request(ClientSock, Method, Url);
            {ok, _Method, _Url} ->
                _ = send_http(ClientSock, 405, <<"Method Not Allowed">>),
                ok;
            error ->
                _ = send_http(ClientSock, 400, <<"Bad Request">>),
                ok
        end,
    gen_tcp:close(ClientSock),
    Result.

handle_request(ClientSock, Method, Url) ->
    {Host, Path} = parse_url(Url),
    case try_core_fetch(Host, Path, Method) of
        {ok, Response} ->
            _ = gen_tcp:send(ClientSock, Response),
            ok;
        {fallback, Reason} ->
            _ = Reason,
            handle_request_sam(ClientSock, Host, Path, Method)
    end.

try_core_fetch(Host, Path, Method) ->
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
                    Request = [
                        Method,
                        <<" ">>,
                        Path,
                        <<" HTTP/1.1\r\n">>,
                        <<"Host: ">>,
                        Host,
                        <<"\r\n">>,
                        <<"Connection: close\r\n">>,
                        <<"\r\n">>
                    ],
                    _ = catch erpc:call(Node, i2p_sam_api, stream_send, [ConnPid, Request]),
                    %% Collect the response until the stream closes.
                    Response = core_recv_all(ConnPid, <<>>),
                    _ = catch erpc:call(Node, i2p_sam_api, stream_close, [ConnPid]),
                    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid]),
                    {ok, Response};
                Other ->
                    _ = catch erpc:call(Node, i2p_sam_api, close_session, [SessionPid]),
                    {fallback, Other}
            end;
        Other ->
            {fallback, Other}
    end.

core_recv_all(ConnPid, Acc) ->
    receive
        {stream_data, ConnPid, Bytes} ->
            core_recv_all(ConnPid, <<Acc/binary, Bytes/binary>>);
        {stream_closed, ConnPid} ->
            Acc;
        {stream_reset, ConnPid} ->
            Acc
    after 30000 ->
        Acc
    end.

handle_request_sam(ClientSock, Host, Path, Method) ->
    case open_sam(Host) of
        {ok, SessionSock, StreamSock} ->
            Result = fetch_via_sam(StreamSock, Host, Path, ClientSock, Method),
            gen_tcp:close(StreamSock),
            gen_tcp:close(SessionSock),
            case Result of
                {ok, Response} ->
                    _ = gen_tcp:send(ClientSock, Response),
                    ok;
                {error, Reason} ->
                    _ = send_http(ClientSock, 502, iolist_to_binary(io_lib:format("~p", [Reason]))),
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

fetch_via_sam(StreamSock, Host, Path, _ClientSock, Method) ->
    Runner = self(),
    {Worker, Mon} =
        spawn_monitor(fun() ->
            Runner ! {proxy_fetch, self(), fetch_over_sam(StreamSock, Host, Path, Method)}
        end),
    receive
        {proxy_fetch, Worker, Response} ->
            erlang:demonitor(Mon, [flush]),
            {ok, Response};
        {'DOWN', Mon, process, Worker, Reason} ->
            {error, Reason}
    after 30000 ->
        exit(Worker, kill),
        erlang:demonitor(Mon, [flush]),
        {error, fetch_timeout}
    end.

fetch_over_sam(StreamSock, Host, Path, Method) ->
    Request = [
        Method,
        <<" ">>,
        Path,
        <<" HTTP/1.1\r\n">>,
        <<"Host: ">>,
        Host,
        <<"\r\n">>,
        <<"Connection: close\r\n">>,
        <<"\r\n">>
    ],
    ok = gen_tcp:send(StreamSock, Request),
    case recv_all(StreamSock) of
        {ok, Response} -> Response;
        {error, Reason} -> throw({recv_failed, Reason})
    end.

recv_request(Sock) ->
    recv_request(Sock, <<>>).

recv_request(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data} ->
            Combined = <<Acc/binary, Data/binary>>,
            case binary:match(Combined, <<"\r\n">>) of
                {Pos, _} ->
                    Line = binary:part(Combined, 0, Pos),
                    case binary:split(Line, <<" ">>, [global]) of
                        [Method, Url | _] -> {ok, Method, Url};
                        _ -> error
                    end;
                nomatch ->
                    recv_request(Sock, Combined)
            end;
        {error, _} ->
            error
    end.

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
status_text(405) -> <<"Method Not Allowed">>;
status_text(502) -> <<"Bad Gateway">>;
status_text(503) -> <<"Service Unavailable">>.

recv_all(Sock) ->
    recv_all(Sock, <<>>).

recv_all(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 2000) of
        {ok, Data} -> recv_all(Sock, <<Acc/binary, Data/binary>>);
        {error, closed} -> {ok, Acc};
        {error, timeout} -> recv_all(Sock, Acc);
        {error, Reason} -> {error, Reason}
    end.
