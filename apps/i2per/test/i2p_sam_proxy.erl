-module(i2p_sam_proxy).

-moduledoc """
HTTP GET proxy that fetches URLs through the I2P SAM v3 STREAM interface.

**A test fixture, not a feature.** It lives in the test tree because
`i2p_sam_SUITE` is the only thing in the repository that calls it. It was in
`apps/i2per/src/` until #EK2KTKP moved it, which meant the operator's release
tarball carried it and the generated API reference listed it among the modules
with a one-line description reading as a capability — which would have had
whoever wrote the release notes conclude the router has an HTTP proxy. It does
not. It has a fixture. `i2p_shipped_modules_tests` now fails `just check` if the
next one lands in `src/`.

Listens on a local TCP port (default 7657), bound to `listen_host` (default
`127.0.0.1`), and accepts plain HTTP GET
requests. For each request the proxy opens a SAM STREAM session to the
target destination, sends the HTTP request over the I2P stream, and
returns the response to the caller.

## Usage

```erlang
{ok, Pid} = i2p_sam_proxy:start_link(#{
    port => 7657,
    sam_port => 7656
}).
```
""".

-export([start_link/1, port/1, address/1, stop/1]).
-export([init/1]).

-doc "Start the HTTP proxy.".
-spec start_link(map()) -> {ok, pid()}.
start_link(Opts) ->
    proc_lib:start_link(?MODULE, init, [Opts]).

-doc "Return the bound port.".
-spec port(pid()) -> inet:port_number().
port(Pid) ->
    Ref = make_ref(),
    Pid ! {port, self(), Ref},
    receive
        {port, Ref, P} -> P
    end.

-doc "Return the bound local address of the proxy.".
-spec address(pid()) -> inet:ip_address().
address(Pid) ->
    Ref = make_ref(),
    Pid ! {address, self(), Ref},
    receive
        {address, Ref, Address} -> Address
    end.

-doc "Stop the proxy.".
-spec stop(pid()) -> ok.
stop(Pid) ->
    Ref = make_ref(),
    Pid ! {stop, self(), Ref},
    receive
        {stopped, Ref} -> ok
    end.

-dialyzer({no_underspecs, init/1}).

-doc false.
-spec init(map()) -> no_return().
init(#{port := Port, sam_port := SamPort} = Opts) ->
    ListenIP = maps:get(listen_host, Opts, {127, 0, 0, 1}),
    {ok, LSock} = gen_tcp:listen(Port, [
        {ip, ListenIP},
        binary,
        {packet, raw},
        {active, false},
        {reuseaddr, true},
        {nodelay, true}
    ]),
    {ok, {BoundIP, BoundPort}} = inet:sockname(LSock),
    proc_lib:init_ack({ok, self()}),
    accept_loop(LSock, BoundIP, BoundPort, SamPort).

accept_loop(LSock, BoundIP, BoundPort, SamPort) ->
    receive
        {port, From, Ref} ->
            From ! {port, Ref, BoundPort},
            accept_loop(LSock, BoundIP, BoundPort, SamPort);
        {address, From, Ref} ->
            From ! {address, Ref, BoundIP},
            accept_loop(LSock, BoundIP, BoundPort, SamPort);
        {stop, From, Ref} ->
            From ! {stopped, Ref},
            gen_tcp:close(LSock),
            exit(normal)
    after 0 ->
        case gen_tcp:accept(LSock, 1000) of
            {ok, ClientSock} ->
                spawn_link(fun() -> handle_http(ClientSock, SamPort) end),
                accept_loop(LSock, BoundIP, BoundPort, SamPort);
            {error, timeout} ->
                accept_loop(LSock, BoundIP, BoundPort, SamPort);
            {error, closed} ->
                exit(normal)
        end
    end.

%%%%%%% %%% HTTP handler %%%%%%%

handle_http(ClientSock, SamPort) ->
    _ =
        case recv_request(ClientSock) of
            {ok, <<"GET">>, Url} ->
                handle_get(ClientSock, Url, SamPort);
            {ok, _, _} ->
                send_http(ClientSock, 405, <<"Method Not Allowed">>);
            error ->
                send_http(ClientSock, 400, <<"Bad Request">>)
        end,
    gen_tcp:close(ClientSock).

handle_get(ClientSock, Url, SamPort) ->
    {Host, Path} = parse_url(Url),
    case
        gen_tcp:connect(
            "127.0.0.1",
            SamPort,
            [binary, {packet, raw}, {active, false}],
            5000
        )
    of
        {ok, SamSock} ->
            case fetch_via_sam(SamSock, Host, Path) of
                {ok, Response} ->
                    gen_tcp:send(ClientSock, Response);
                {error, Reason} ->
                    send_http(
                        ClientSock,
                        502,
                        iolist_to_binary(io_lib:format("~p", [Reason]))
                    )
            end;
        {error, _} ->
            send_http(ClientSock, 503, <<"SAM bridge unavailable">>)
    end.

%% fetch_via_sam/3 — run the whole SAM conversation in a throwaway worker so a
%% failed step crashes only the worker (taking its socket with it); recovery
%% lives here, above the conversation.
fetch_via_sam(SamSock, Host, Path) ->
    Runner = self(),
    {Worker, Mon} =
        spawn_monitor(fun() ->
            Runner ! {proxy_fetch, self(), fetch_over_sam(SamSock, Host, Path)}
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

fetch_over_sam(SamSock, Host, Path) ->
    ok = sam_hello(SamSock),
    {ok, SessionId, _DestB64} = sam_session_create(SamSock),
    {ok, TargetB64} = sam_naming_lookup(SamSock, Host),
    {ok, StreamSock} = sam_stream_connect(SamSock, SessionId, TargetB64),
    HttpRequest = [
        <<"GET ">>,
        Path,
        <<" HTTP/1.1\r\n">>,
        <<"Host: ">>,
        Host,
        <<"\r\n">>,
        <<"Connection: close\r\n">>,
        <<"\r\n">>
    ],
    ok = gen_tcp:send(StreamSock, HttpRequest),
    {ok, Response} = recv_all(StreamSock),
    Response.

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

%%%%%%% %%% HTTP request parsing %%%%%%%

recv_request(Sock) ->
    recv_request(Sock, <<>>).

recv_request(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data} ->
            Combined = <<Acc/binary, Data/binary>>,
            case binary:match(Combined, <<"\r\n">>) of
                {Pos, _} ->
                    Line = binary:part(Combined, 0, Pos),
                    case binary:split(Line, <<" ">>) of
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

%%%%%%% %%% SAM v3 client protocol %%%%%%%

sam_hello(Sock) ->
    ok = gen_tcp:send(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1\n">>),
    case sam_recv_line(Sock) of
        {ok, <<"HELLO REPLY RESULT=OK", _/binary>>} -> ok;
        {ok, Other} -> error({sam_hello_failed, Other})
    end.

sam_session_create(Sock) ->
    Id = iolist_to_binary([
        <<"proxy-">>,
        integer_to_binary(erlang:unique_integer([positive, monotonic]))
    ]),
    ok = gen_tcp:send(Sock, [
        <<"SESSION CREATE STYLE=STREAM ID=">>, Id, <<"\n">>
    ]),
    case sam_recv_line(Sock) of
        {ok, <<"SESSION STATUS RESULT=OK DESTINATION=", DestB64/binary>>} ->
            {ok, Id, DestB64};
        {ok, Other} ->
            error({sam_session_create_failed, Other})
    end.

sam_naming_lookup(Sock, Host) ->
    ok = gen_tcp:send(Sock, [
        <<"NAMING LOOKUP NAME=">>, Host, <<"\n">>
    ]),
    case sam_recv_line(Sock) of
        {ok, Line} ->
            parse_naming_reply(Line);
        {error, _} = Err ->
            Err
    end.

parse_naming_reply(<<"NAMING REPLY RESULT=OK ", Rest/binary>>) ->
    case find_value(Rest) of
        {ok, DestB64} -> {ok, DestB64};
        error -> error({sam_naming_lookup_failed, bad_value})
    end;
parse_naming_reply(Other) ->
    error({sam_naming_lookup_failed, Other}).

find_value(<<"VALUE=", Rest/binary>>) ->
    {ok, Rest};
find_value(<<_, Rest/binary>>) ->
    find_value(Rest);
find_value(<<>>) ->
    error.

%% sam_stream_connect/3 — SAM v3 gives every stream its own client-to-SAM
%% socket, so this opens a second connection to the bridge and returns it for
%% the raw exchange. The session socket stays open in line mode, which is what
%% keeps the session alive; sending CONNECT on it is rejected as
%% "Socket already in use".
sam_stream_connect(SessionSock, SessionId, TargetB64) ->
    {ok, {Addr, Port}} = inet:peername(SessionSock),
    {ok, Sock} = gen_tcp:connect(Addr, Port, [binary, {packet, raw}, {active, false}], 5000),
    ok = sam_hello(Sock),
    ok = gen_tcp:send(Sock, [
        <<"STREAM CONNECT ID=">>,
        SessionId,
        <<" DESTINATION=">>,
        TargetB64,
        <<"\n">>
    ]),
    case sam_recv_line(Sock) of
        {ok, <<"STREAM STATUS RESULT=OK">>} ->
            {ok, Sock};
        {ok, Other} ->
            gen_tcp:close(Sock),
            error({sam_stream_connect_failed, Other})
    end.

sam_recv_line(Sock) ->
    sam_recv_line(Sock, <<>>).

sam_recv_line(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data} ->
            Combined = <<Acc/binary, Data/binary>>,
            case binary:match(Combined, <<"\n">>) of
                {Pos, _} ->
                    {ok, binary:part(Combined, 0, Pos)};
                nomatch ->
                    sam_recv_line(Sock, Combined)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

recv_all(Sock) ->
    recv_all(Sock, <<>>).

recv_all(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 2000) of
        {ok, Data} ->
            recv_all(Sock, <<Acc/binary, Data/binary>>);
        {error, closed} ->
            {ok, Acc};
        {error, timeout} ->
            {ok, Acc}
    end.
