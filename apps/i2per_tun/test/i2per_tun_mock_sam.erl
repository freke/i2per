-module(i2per_tun_mock_sam).

-moduledoc """
Mock SAM v3 bridge for the hermetic `i2per_tun` tests.

Serves the shape SAM v3 specifies rather than the shape the client used to
send: a session socket carrying `HELLO`, `SESSION CREATE` and `NAMING LOOKUP`
that stays open for the session's life, and a second connection carrying
`HELLO` and `STREAM CONNECT` that the client relays on.

The mock fails with `{sam_protocol_violation, _}` instead of accepting a client
that sends `STREAM CONNECT` on the session socket or closes the session socket
before opening the stream, so a regression cannot pass the gate.
""".

-export([start/1, stop/1]).
-export_type([server/0]).

-type server() :: {gen_tcp:socket(), inet:port_number(), pid()}.

-doc """
Listen on an ephemeral port and hand every established stream socket to
`OnStream`.

`OnStream` runs in the mock's process, owns the stream socket, and returns when
the exchange is over; the mock then closes both sockets.
""".
-spec start(fun((gen_tcp:socket()) -> term())) -> server().
start(OnStream) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, {_, Port}} = inet:sockname(LSock),
    Pid = spawn_link(fun() -> serve(LSock, OnStream) end),
    {LSock, Port, Pid}.

-doc "Close the listening socket and stop the mock.".
-spec stop(server()) -> ok.
stop({LSock, _Port, Pid}) ->
    %% Unlink first: a test that finishes mid-exchange must not have the kill
    %% land on its own process.
    unlink(Pid),
    gen_tcp:close(LSock),
    exit(Pid, kill),
    ok.

%%%%%%% %%%% Internal %%%%%%%

serve(LSock, OnStream) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, SessionSock} ->
            serve_session(LSock, SessionSock, OnStream);
        {error, closed} ->
            %% The test stopped the mock before a session connected.
            ok
    end.

serve_session(LSock, SessionSock, OnStream) ->
    ok = expect(SessionSock, <<"HELLO ">>),
    ok = gen_tcp:send(SessionSock, <<"HELLO REPLY RESULT=OK VERSION=3.1\n">>),
    ok = expect(SessionSock, <<"SESSION CREATE ">>),
    ok = gen_tcp:send(SessionSock, <<"SESSION STATUS RESULT=OK DESTINATION=mydest\n">>),
    ok = expect(SessionSock, <<"NAMING LOOKUP ">>),
    ok = gen_tcp:send(SessionSock, <<"NAMING REPLY RESULT=OK NAME=peer.i2p VALUE=targetdest\n">>),
    StreamSock = await_stream(LSock, SessionSock),
    ok = expect(StreamSock, <<"HELLO ">>),
    ok = gen_tcp:send(StreamSock, <<"HELLO REPLY RESULT=OK VERSION=3.1\n">>),
    ok = expect(StreamSock, <<"STREAM CONNECT ">>),
    ok = gen_tcp:send(StreamSock, <<"STREAM STATUS RESULT=OK\n">>),
    OnStream(StreamSock),
    gen_tcp:close(StreamSock),
    gen_tcp:close(SessionSock),
    ok.

%% The stream lives on a second connection. While waiting for it, anything the
%% client writes on the session socket is a violation, and so is a close: the
%% session dies with its socket.
await_stream(LSock, SessionSock) ->
    await_stream(LSock, SessionSock, erlang:monotonic_time(millisecond) + 5000).

await_stream(LSock, SessionSock, Deadline) ->
    case gen_tcp:accept(LSock, 20) of
        {ok, StreamSock} ->
            StreamSock;
        {error, timeout} ->
            case gen_tcp:recv(SessionSock, 0, 0) of
                {ok, Unexpected} ->
                    exit({sam_protocol_violation, {command_on_session_socket, Unexpected}});
                {error, timeout} ->
                    check_deadline(LSock, SessionSock, Deadline);
                {error, closed} ->
                    exit({sam_protocol_violation, session_socket_closed});
                {error, Reason} ->
                    exit({sam_protocol_violation, {session_socket, Reason}})
            end;
        {error, Reason} ->
            exit({sam_protocol_violation, {accept_failed, Reason}})
    end.

check_deadline(LSock, SessionSock, Deadline) ->
    case erlang:monotonic_time(millisecond) > Deadline of
        true -> exit({sam_protocol_violation, no_stream_socket});
        false -> await_stream(LSock, SessionSock, Deadline)
    end.

expect(Sock, Prefix) ->
    Line = recv_line(Sock, <<>>),
    Size = byte_size(Prefix),
    case Line of
        <<Prefix:Size/binary, _/binary>> ->
            ok;
        _ ->
            exit({sam_protocol_violation, {expected, Prefix, got, Line}})
    end.

%% One byte at a time so bytes after the newline stay in the socket buffer for
%% the stream data that follows the handshake.
recv_line(Sock, Acc) ->
    case gen_tcp:recv(Sock, 1, 5000) of
        {ok, <<"\n">>} ->
            Acc;
        {ok, Byte} ->
            recv_line(Sock, <<Acc/binary, Byte/binary>>);
        {error, Reason} ->
            exit({sam_protocol_violation, {recv_failed, Reason, Acc}})
    end.
