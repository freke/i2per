-module(i2per_proxy_sam).

-moduledoc """
SAM v3 client conversation for `i2per_proxy`.
""".

-export([
    hello/1,
    session_create/1,
    naming_lookup/2,
    stream_connect/3,
    sam_recv_line/1,
    sam_recv_line/2,
    parse_hello/1,
    parse_session_status/1,
    parse_naming_reply/1,
    parse_stream_status/1
]).

hello(Sock) ->
    case gen_tcp:send(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1\n">>) of
        ok ->
            case sam_recv_line(Sock) of
                {ok, Line} -> parse_hello(Line);
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end.

session_create(Sock) ->
    Id = iolist_to_binary([
        <<"proxy-">>, integer_to_binary(erlang:unique_integer([positive, monotonic]))
    ]),
    Cmd = [<<"SESSION CREATE STYLE=STREAM ID=">>, Id, <<"\n">>],
    case gen_tcp:send(Sock, Cmd) of
        ok ->
            case sam_recv_line(Sock) of
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

naming_lookup(Sock, Host) ->
    Cmd = [<<"NAMING LOOKUP NAME=">>, Host, <<"\n">>],
    case gen_tcp:send(Sock, Cmd) of
        ok ->
            case sam_recv_line(Sock) of
                {ok, Line} -> parse_naming_reply(Line);
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end.

stream_connect(Sock, SessionId, TargetB64) ->
    Cmd = [<<"STREAM CONNECT ID=">>, SessionId, <<" DESTINATION=">>, TargetB64, <<"\n">>],
    case gen_tcp:send(Sock, Cmd) of
        ok ->
            case sam_recv_line(Sock) of
                {ok, Line} -> parse_stream_status(Line);
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end.

parse_hello(<<"HELLO REPLY RESULT=OK", _/binary>>) -> ok;
parse_hello(Other) -> {error, {sam_hello_failed, Other}}.

parse_session_status(<<"SESSION STATUS RESULT=OK DESTINATION=", DestB64/binary>>) ->
    {ok, trim(DestB64)};
parse_session_status(Other) ->
    {error, {sam_session_create_failed, Other}}.

parse_naming_reply(<<"NAMING REPLY RESULT=OK ", Rest/binary>>) ->
    case find_value(Rest) of
        {ok, V} -> {ok, trim(V)};
        error -> {error, {sam_naming_lookup_failed, bad_value}}
    end;
parse_naming_reply(Other) ->
    {error, {sam_naming_lookup_failed, Other}}.

parse_stream_status(<<"STREAM STATUS RESULT=OK", _/binary>>) -> ok;
parse_stream_status(Other) -> {error, {sam_stream_connect_failed, Other}}.

find_value(<<"VALUE=", Rest/binary>>) -> {ok, Rest};
find_value(<<_, Rest/binary>>) -> find_value(Rest);
find_value(<<>>) -> error.

trim(Bin) -> string:trim(Bin, both, "\r\n\t ").

sam_recv_line(Sock) -> sam_recv_line(Sock, <<>>).

sam_recv_line(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data} ->
            Combined = <<Acc/binary, Data/binary>>,
            case binary:match(Combined, <<"\n">>) of
                {Pos, _} -> {ok, binary:part(Combined, 0, Pos)};
                nomatch -> sam_recv_line(Sock, Combined)
            end;
        {error, Reason} ->
            {error, Reason}
    end.
