-module(i2per_tun_sam).

-moduledoc """
SAM v3 client conversation for `i2per_tun` (epiq `D3750BZ`, shape spike (a)).

SAM v3 puts the stream on a second socket: the session socket must stay open
for the session's life, and `STREAM CONNECT` arrives on a fresh connection.
Use `f:open_stream/3` rather than driving the individual commands, so both
sockets and their lifetimes stay together.
""".

-export([
    open_stream/3,
    open_stream/4,
    hello/1,
    hello/2,
    session_create/1,
    session_create/2,
    session_create_raw/1,
    session_create_raw/2,
    naming_lookup/2,
    naming_lookup/3,
    stream_connect/3,
    stream_connect/4,
    raw_send/3,
    raw_recv/1,
    raw_recv/2,
    parse_hello/1,
    parse_session_status/1,
    parse_naming_reply/1,
    parse_stream_status/1,
    parse_raw_received/1,
    sam_recv_line/1,
    sam_recv_line/2,
    sam_recv_line/3
]).

-doc """
Open a session and a stream to `Host` on the two sockets SAM v3 requires.

The session socket carries `HELLO`, `SESSION CREATE` and `NAMING LOOKUP`, and
must stay open for as long as the session is needed: closing it ends the
session. The stream socket is a second connection to the same bridge carrying
only `HELLO` and `STREAM CONNECT`; the caller relays stream bytes on it and
closes both sockets when the flow ends.

Input: the bridge host and port, and the host to resolve.
Output: `{ok, SessionSock, StreamSock}`, or `{error, Reason}` with every socket
this function opened closed.
""".
-spec open_stream(binary(), inet:port_number(), binary() | string()) ->
    {ok, gen_tcp:socket(), gen_tcp:socket()} | {error, term()}.
open_stream(SamHost, SamPort, Host) ->
    open_stream(SamHost, SamPort, Host, 5000).

-doc "As `f:open_stream/3`, with `Timeout` bounding each bridge connect.".
-spec open_stream(binary(), inet:port_number(), binary() | string(), timeout()) ->
    {ok, gen_tcp:socket(), gen_tcp:socket()} | {error, term()}.
open_stream(SamHost, SamPort, Host, Timeout) ->
    case connect(SamHost, SamPort, Timeout) of
        {ok, SessionSock} -> open_stream_on(SessionSock, SamHost, SamPort, Host, Timeout);
        {error, _} = Err -> Err
    end.

hello(Sock) ->
    hello(Sock, 5000).

hello(Sock, Timeout) ->
    case gen_tcp:send(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1\n">>) of
        ok ->
            case sam_recv_line(Sock, Timeout) of
                {ok, Line} -> parse_hello(Line);
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end.

session_create(Sock) ->
    session_create(Sock, 60000).

session_create(Sock, Timeout) ->
    Id = iolist_to_binary([
        <<"tun-">>, integer_to_binary(erlang:unique_integer([positive, monotonic]))
    ]),
    Cmd = [<<"SESSION CREATE STYLE=STREAM ID=">>, Id, <<" DESTINATION=TRANSIENT\n">>],
    case gen_tcp:send(Sock, Cmd) of
        ok ->
            case sam_recv_line(Sock, Timeout) of
                {ok, Line} ->
                    case parse_session_status(Line) of
                        {ok, DestB64} -> {ok, Id, DestB64};
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

naming_lookup(Sock, Host) when is_list(Host) ->
    naming_lookup(Sock, list_to_binary(Host));
naming_lookup(Sock, Host) when is_binary(Host) ->
    naming_lookup(Sock, Host, 15000).

naming_lookup(Sock, Host, Timeout) when is_list(Host) ->
    naming_lookup(Sock, list_to_binary(Host), Timeout);
naming_lookup(Sock, Host, Timeout) when is_binary(Host) ->
    case valid_host(Host) of
        true ->
            Cmd = [<<"NAMING LOOKUP NAME=">>, Host, <<"\n">>],
            case gen_tcp:send(Sock, Cmd) of
                ok ->
                    case sam_recv_line(Sock, Timeout) of
                        {ok, Line} -> parse_naming_reply(Line);
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        false ->
            {error, {sam_naming_lookup_failed, invalid_name}}
    end.

stream_connect(Sock, SessionId, TargetB64) ->
    stream_connect(Sock, SessionId, TargetB64, 60000).

stream_connect(Sock, SessionId, TargetB64, Timeout) ->
    Cmd = [<<"STREAM CONNECT ID=">>, SessionId, <<" DESTINATION=">>, TargetB64, <<"\n">>],
    case gen_tcp:send(Sock, Cmd) of
        ok ->
            case sam_recv_line(Sock, Timeout) of
                {ok, Line} -> parse_stream_status(Line);
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end.

session_create_raw(Sock) ->
    session_create_raw(Sock, 60000).

session_create_raw(Sock, Timeout) ->
    Id = iolist_to_binary([
        <<"tun-">>, integer_to_binary(erlang:unique_integer([positive, monotonic]))
    ]),
    Cmd = [<<"SESSION CREATE STYLE=RAW ID=">>, Id, <<" DESTINATION=TRANSIENT\n">>],
    case gen_tcp:send(Sock, Cmd) of
        ok ->
            case sam_recv_line(Sock, Timeout) of
                {ok, Line} ->
                    case parse_session_status(Line) of
                        {ok, DestB64} -> {ok, Id, DestB64};
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

raw_send(Sock, DestB64, Payload) when is_binary(Payload) ->
    Size = byte_size(Payload),
    Cmd = [<<"RAW SEND DESTINATION=">>, DestB64, <<" SIZE=">>, integer_to_binary(Size), <<"\n">>],
    gen_tcp:send(Sock, [Cmd, Payload]).

raw_recv(Sock) ->
    raw_recv(Sock, 5000).

raw_recv(Sock, Timeout) ->
    case sam_recv_line(Sock, Timeout) of
        {ok, Line} ->
            case parse_raw_received(Line) of
                {ok, Size, SrcB64} ->
                    case gen_tcp:recv(Sock, Size, Timeout) of
                        {ok, Payload} -> {ok, SrcB64, Payload};
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

-spec parse_raw_received(binary()) -> {ok, non_neg_integer(), binary()} | {error, term()}.
parse_raw_received(Line) ->
    case find_kv(Line, <<"SIZE=">>) of
        {ok, SizeBin} ->
            case find_kv(Line, <<"DESTINATION=">>) of
                {ok, DestBin} ->
                    case parse_int(SizeBin) of
                        {ok, Size} -> {ok, Size, trim(DestBin)};
                        error -> {error, {bad_size, Line}}
                    end;
                error ->
                    {error, {missing_destination, Line}}
            end;
        error ->
            {error, {missing_size, Line}}
    end.

find_kv(Bin, Key) ->
    case binary:match(Bin, Key) of
        {Pos, Len} ->
            Start = Pos + Len,
            Rest = binary:part(Bin, Start, byte_size(Bin) - Start),
            %% value runs until space or end
            case binary:match(Rest, <<" ">>) of
                {SPos, _} -> {ok, binary:part(Rest, 0, SPos)};
                nomatch -> {ok, Rest}
            end;
        nomatch ->
            error
    end.

parse_int(Bin) ->
    try
        {ok, binary_to_integer(trim(Bin))}
    catch
        _:_ -> error
    end.

-spec parse_hello(binary()) -> ok | {error, term()}.
parse_hello(<<"HELLO REPLY RESULT=OK", _/binary>>) -> ok;
parse_hello(Other) -> {error, {sam_hello_failed, Other}}.

-spec parse_session_status(binary()) -> {ok, binary()} | {error, term()}.
parse_session_status(<<"SESSION STATUS RESULT=OK DESTINATION=", DestB64/binary>>) ->
    {ok, trim(DestB64)};
parse_session_status(Other) ->
    {error, {sam_session_create_failed, Other}}.

-spec parse_naming_reply(binary()) -> {ok, binary()} | {error, term()}.
parse_naming_reply(<<"NAMING REPLY RESULT=OK ", Rest/binary>>) ->
    case find_value(Rest) of
        {ok, V} -> {ok, trim(V)};
        error -> {error, {sam_naming_lookup_failed, bad_value}}
    end;
parse_naming_reply(Other) ->
    {error, {sam_naming_lookup_failed, Other}}.

-spec parse_stream_status(binary()) -> ok | {error, term()}.
parse_stream_status(<<"STREAM STATUS RESULT=OK", _/binary>>) -> ok;
parse_stream_status(Other) -> {error, {sam_stream_connect_failed, Other}}.

find_value(<<"VALUE=", Rest/binary>>) -> {ok, Rest};
find_value(<<_, Rest/binary>>) -> find_value(Rest);
find_value(<<>>) -> error.

trim(Bin) -> string:trim(Bin, both, "\r\n\t ").

-spec valid_host(binary()) -> boolean().
valid_host(<<>>) ->
    false;
valid_host(Bin) ->
    lists:all(
        fun(C) ->
            (C >= $A andalso C =< $Z) orelse
                (C >= $a andalso C =< $z) orelse
                (C >= $0 andalso C =< $9) orelse
                C =:= $. orelse C =:= $_ orelse C =:= $~ orelse
                C =:= $= orelse C =:= $: orelse C =:= $- orelse
                C =:= $+
        end,
        binary_to_list(Bin)
    ).

sam_recv_line(Sock) -> sam_recv_line(Sock, 5000).

%% `Timeout` is in milliseconds (or `infinity`). It is threaded through
%% every call so no command shares one module-level ceiling: HELLO uses a
%% short bound (5 s), NAMING LOOKUP a medium one (15 s), and SESSION CREATE
%% and STREAM CONNECT a long one (60 s), because the latter wait on this
%% router's own tunnel work rather than a network round trip.

%% Read exactly one byte at a time so bytes after the newline stay in the
%% socket buffer for the raw stream that follows the handshake.
sam_recv_line(Sock, Timeout) when is_integer(Timeout); Timeout =:= infinity ->
    sam_recv_line(Sock, <<>>, Timeout);
sam_recv_line(Sock, Acc) when is_binary(Acc) ->
    sam_recv_line(Sock, Acc, 5000).

sam_recv_line(Sock, Acc, Timeout) ->
    Deadline =
        case Timeout of
            infinity -> infinity;
            _ -> erlang:monotonic_time(millisecond) + Timeout
        end,
    sam_recv_line_loop(Sock, Acc, Deadline).

sam_recv_line_loop(Sock, Acc, infinity) ->
    case gen_tcp:recv(Sock, 1, infinity) of
        {ok, <<"\n">>} ->
            {ok, Acc};
        {ok, Byte} when byte_size(Acc) < 8192 ->
            sam_recv_line_loop(Sock, <<Acc/binary, Byte/binary>>, infinity);
        {ok, _} ->
            {error, line_too_long};
        {error, Reason} ->
            {error, Reason}
    end;
sam_recv_line_loop(Sock, Acc, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining < 0 of
        true ->
            {error, timeout};
        false ->
            case gen_tcp:recv(Sock, 1, Remaining) of
                {ok, <<"\n">>} ->
                    {ok, Acc};
                {ok, Byte} when byte_size(Acc) < 8192 ->
                    sam_recv_line_loop(Sock, <<Acc/binary, Byte/binary>>, Deadline);
                {ok, _} ->
                    {error, line_too_long};
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% Internal

-spec connect(binary(), inet:port_number(), timeout()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
connect(SamHost, SamPort, Timeout) ->
    gen_tcp:connect(
        binary_to_list(SamHost), SamPort, [binary, {packet, raw}, {active, false}], Timeout
    ).

%% The session socket is opened by the caller; every failure after this point
%% has to close it, because a session socket nobody holds open is a session
%% nobody can use.
open_stream_on(SessionSock, SamHost, SamPort, Host, Timeout) ->
    case session_ready(SessionSock, Host) of
        {ok, SessionId, TargetB64} ->
            case stream_ready(SamHost, SamPort, SessionId, TargetB64, Timeout) of
                {ok, StreamSock} ->
                    {ok, SessionSock, StreamSock};
                {error, _} = Err ->
                    gen_tcp:close(SessionSock),
                    Err
            end;
        {error, _} = Err ->
            gen_tcp:close(SessionSock),
            Err
    end.

-spec session_ready(gen_tcp:socket(), binary() | string()) ->
    {ok, binary(), binary()} | {error, term()}.
session_ready(SessionSock, Host) ->
    case hello(SessionSock) of
        ok ->
            case session_create(SessionSock) of
                {ok, SessionId, _DestB64} ->
                    case naming_lookup(SessionSock, Host) of
                        {ok, TargetB64} -> {ok, SessionId, TargetB64};
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

-spec stream_ready(binary(), inet:port_number(), binary(), binary(), timeout()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
stream_ready(SamHost, SamPort, SessionId, TargetB64, Timeout) ->
    case connect(SamHost, SamPort, Timeout) of
        {ok, StreamSock} ->
            case hello(StreamSock) of
                ok ->
                    case stream_connect(StreamSock, SessionId, TargetB64) of
                        ok ->
                            {ok, StreamSock};
                        {error, _} = Err ->
                            gen_tcp:close(StreamSock),
                            Err
                    end;
                {error, _} = Err ->
                    gen_tcp:close(StreamSock),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.
