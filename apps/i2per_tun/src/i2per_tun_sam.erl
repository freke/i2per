-module(i2per_tun_sam).

-moduledoc """
SAM v3 client conversation for `i2per_tun` (epiq `D3750BZ`, shape spike (a)).
""".

-export([
    hello/1,
    session_create/1,
    session_create_raw/1,
    naming_lookup/2,
    stream_connect/3,
    raw_send/3,
    raw_recv/1,
    parse_hello/1,
    parse_session_status/1,
    parse_naming_reply/1,
    parse_stream_status/1,
    parse_raw_received/1,
    sam_recv_line/1,
    sam_recv_line/2
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
        <<"tun-">>, integer_to_binary(erlang:unique_integer([positive, monotonic]))
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

session_create_raw(Sock) ->
    Id = iolist_to_binary([
        <<"tun-">>, integer_to_binary(erlang:unique_integer([positive, monotonic]))
    ]),
    Cmd = [<<"SESSION CREATE STYLE=RAW ID=">>, Id, <<"\n">>],
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

raw_send(Sock, DestB64, Payload) when is_binary(Payload) ->
    Size = byte_size(Payload),
    Cmd = [<<"RAW SEND DESTINATION=">>, DestB64, <<" SIZE=">>, integer_to_binary(Size), <<"\n">>],
    gen_tcp:send(Sock, [Cmd, Payload]).

raw_recv(Sock) ->
    case sam_recv_line(Sock) of
        {ok, Line} ->
            case parse_raw_received(Line) of
                {ok, Size, SrcB64} ->
                    case gen_tcp:recv(Sock, Size, 5000) of
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
