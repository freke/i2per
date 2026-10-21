-module(i2p_sam_parse).

-moduledoc """
Pure text parsers for the SAM v3 line protocol (`m:i2p_sam_session`): HELLO
negotiation, command tokens with `KEY=VALUE` options, tunnel-length options,
ports and hosts, and `.b32.i2p` address decoding.

Nothing here touches a socket or process state — every function maps binaries
to parsed terms or `error`, so malformed input is always an explicit return
value. Protocol violations that cannot be recovered from (a bad SIZE breaks
byte framing) are raised by the session handlers, not here.

## Usage

```erlang
ok = i2p_sam_parse:parse_hello(<<"HELLO VERSION MIN=3.1 MAX=3.1">>),
{stream_connect, <<"1">>, DestB64} =
    i2p_sam_parse:parse_command(<<"STREAM CONNECT ID=1 DESTINATION=", DestB64/binary>>),
{ok, 7656} = i2p_sam_parse:parse_port(<<"7656">>).
```
""".

-export([
    parse_hello/1,
    parse_command/1,
    parse_port/1,
    host_string/1,
    parse_b32_address/1
]).

%%%%%%% %%% Public API %%%%%%%

-doc """
Validate a HELLO line.

Input: `Line` — one SAM protocol line without its newline.
Output: `ok` for any `HELLO VERSION …` line; `{error, bad_hello}` otherwise
(the caller answers with a HELLO REPLY error and kills the session).
""".
-spec parse_hello(binary()) -> ok | {error, bad_hello}.
parse_hello(Line) ->
    case binary:split(Line, <<" ">>, [global]) of
        [<<"HELLO">>, <<"VERSION">> | _] -> ok;
        _ -> {error, bad_hello}
    end.

-doc """
Parse one SAM command line into a typed request tuple.

Input: `Line` — one command line without its newline.
Output: the command tuple (see the individual clauses), or
`{error, unknown_command}` for anything unrecognized.
""".
-spec parse_command(binary()) ->
    {dest_generate, non_neg_integer()}
    | {session_create, i2p_sam_session:style(), i2p_sam_session:session_id(), binary() | undefined,
        i2p_sam_session:tunnel_lengths() | {error, bad_length}}
    | {stream_connect, i2p_sam_session:session_id(), binary()}
    | {stream_accept, i2p_sam_session:session_id()}
    | {stream_forward, i2p_sam_session:session_id(), binary() | undefined, binary()}
    | {datagram_send, i2p_sam_session:send_kind(), binary(), binary()}
    | {naming_lookup, binary()}
    | {error, unknown_command}.
parse_command(Line) ->
    Tokens = binary:split(Line, <<" ">>, [global]),
    parse_command_tokens(Tokens).

-doc """
Parse a PORT option value.

Input: `Bin` — the raw option value.
Output: `{ok, Port}` for digit-only values in 1..65535; `error` otherwise
(a protocol violation at the caller — the byte stream stays frameable, but
the FORWARD request is dead).
""".
-spec parse_port(binary()) -> {ok, inet:port_number()} | error.
parse_port(Bin) when byte_size(Bin) > 0 ->
    case all_digits(Bin) of
        true ->
            Port = binary_to_integer(Bin),
            case Port >= 1 andalso Port =< 16#FFFF of
                true -> {ok, Port};
                false -> error
            end;
        false ->
            error
    end;
parse_port(_Bin) ->
    error.

-doc """
The HOST option as an Erlang string (dotted quad or resolvable name),
defaulting to loopback like the SAM spec.
""".
-spec host_string(binary() | undefined) -> [byte()].
host_string(undefined) ->
    "127.0.0.1";
host_string(HostBin) ->
    binary_to_list(HostBin).

-doc """
Decode a `<56-char>.b32.i2p` address to the destination hash it names.

Input: `Addr` — the full host string including the `.b32.i2p` suffix.
Output: `{ok, Hash}` when the base32 body decodes to exactly 32 bytes;
`error` for other shapes or undecodable bodies.
""".
-spec parse_b32_address(binary()) -> {ok, i2p_crypto:hash()} | error.
parse_b32_address(Addr) ->
    case binary:match(Addr, <<".b32.i2p">>) of
        {Pos, 8} ->
            B32 = binary:part(Addr, 0, Pos),
            case base32_to_bytes(B32) of
                <<Hash:32/binary>> -> {ok, Hash};
                _ -> error
            end;
        nomatch ->
            error
    end.

%%%%%%% %%% Internal %%%%%%%

-dialyzer({no_underspecs, parse_command_tokens/1}).
-spec parse_command_tokens([binary()]) ->
    {dest_generate, non_neg_integer()}
    | {session_create, i2p_sam_session:style(), i2p_sam_session:session_id(), binary() | undefined,
        i2p_sam_session:tunnel_lengths() | {error, bad_length}}
    | {stream_connect, i2p_sam_session:session_id(), binary()}
    | {stream_accept, i2p_sam_session:session_id()}
    | {stream_forward, i2p_sam_session:session_id(), binary() | undefined, binary()}
    | {datagram_send, i2p_sam_session:send_kind(), binary(), binary()}
    | {naming_lookup, binary()}
    | {error, unknown_command}.
parse_command_tokens([<<"DEST">>, <<"GENERATE">> | Rest]) ->
    SigTypeBin = parse_kv(<<"SIGNATURE_TYPE">>, Rest, <<"7">>),
    SigType = binary_to_integer(SigTypeBin),
    {dest_generate, SigType};
parse_command_tokens([<<"SESSION">>, <<"CREATE">> | Rest]) ->
    Style = parse_session_style(parse_kv(<<"STYLE">>, Rest, <<"STREAM">>)),
    Id = parse_kv(<<"ID">>, Rest, <<>>),
    Dest = parse_kv(<<"DESTINATION">>, Rest, undefined),
    {session_create, Style, Id, Dest, parse_tunnel_lengths(Rest)};
parse_command_tokens([<<"STREAM">>, <<"CONNECT">> | Rest]) ->
    Id = parse_kv(<<"ID">>, Rest, <<>>),
    Dest = parse_kv(<<"DESTINATION">>, Rest, <<>>),
    {stream_connect, Id, Dest};
parse_command_tokens([<<"STREAM">>, <<"ACCEPT">> | Rest]) ->
    Id = parse_kv(<<"ID">>, Rest, <<>>),
    {stream_accept, Id};
parse_command_tokens([<<"STREAM">>, <<"FORWARD">> | Rest]) ->
    Id = parse_kv(<<"ID">>, Rest, <<>>),
    Port = parse_kv(<<"PORT">>, Rest, <<>>),
    Host = parse_kv(<<"HOST">>, Rest, undefined),
    {stream_forward, Id, Host, Port};
parse_command_tokens([<<"DATAGRAM">>, <<"SEND">> | Rest]) ->
    Dest = parse_kv(<<"DESTINATION">>, Rest, <<>>),
    Size = parse_kv(<<"SIZE">>, Rest, <<>>),
    {datagram_send, repliable, Dest, Size};
parse_command_tokens([<<"RAW">>, <<"SEND">> | Rest]) ->
    Dest = parse_kv(<<"DESTINATION">>, Rest, <<>>),
    Size = parse_kv(<<"SIZE">>, Rest, <<>>),
    {datagram_send, raw, Dest, Size};
parse_command_tokens([<<"NAMING">>, <<"LOOKUP">> | Rest]) ->
    Name = parse_kv(<<"NAME">>, Rest, <<>>),
    {naming_lookup, Name};
parse_command_tokens(_) ->
    {error, unknown_command}.

-dialyzer({no_underspecs, parse_kv/3}).
-spec parse_kv(nonempty_binary(), [binary()], binary() | undefined) -> binary() | undefined.
parse_kv(_Key, [], Default) ->
    Default;
parse_kv(Key, [Elem | Rest], Default) ->
    Prefix = <<Key/binary, "=">>,
    case binary:match(Elem, Prefix) of
        {0, _} ->
            binary:part(Elem, byte_size(Prefix), byte_size(Elem) - byte_size(Prefix));
        _ ->
            parse_kv(Key, Rest, Default)
    end.

-spec parse_session_style(binary()) -> i2p_sam_session:style().
parse_session_style(<<"STREAM">>) -> stream;
parse_session_style(<<"DATAGRAM">>) -> datagram;
parse_session_style(<<"RAW">>) -> raw;
parse_session_style(_) -> stream.

%% parse_tunnel_lengths/1 — extract the tunnel-length options from a
%% SESSION CREATE token list: `inbound.length=N` / `outbound.length=N`,
%% integers clamped into 1..?MAX_HOPS. A non-integer value is reported as
%% `{error, bad_length}` (a protocol violation at the handler); unknown
%% options are ignored.
-spec parse_tunnel_lengths([binary()]) ->
    i2p_sam_session:tunnel_lengths() | {error, bad_length}.
parse_tunnel_lengths(Tokens) ->
    case length_opt(<<"inbound.length">>, Tokens) of
        {error, bad_length} = E ->
            E;
        In ->
            case length_opt(<<"outbound.length">>, Tokens) of
                {error, bad_length} = E ->
                    E;
                Out ->
                    Opts1 = maybe_put_len(in_len, In, #{}),
                    maybe_put_len(out_len, Out, Opts1)
            end
    end.

%% length_opt/2 — the parsed option: `none` when absent, `{ok, ClampedLen}`
%% when present and integral, `{error, bad_length}` otherwise.
-dialyzer({no_underspecs, length_opt/2}).
-spec length_opt(binary(), [binary()]) ->
    none | {ok, 1..7} | {error, bad_length}.
length_opt(Key, Tokens) ->
    case parse_kv(Key, Tokens, undefined) of
        undefined -> none;
        Bin -> parse_hops(Bin)
    end.

%% parse_hops/1 — digit-only integer clamped to 1..7; anything else
%% (empty, signed, non-digit) is bad_length.
-spec parse_hops(binary()) -> {ok, 1..7} | {error, bad_length}.
parse_hops(Bin) when byte_size(Bin) > 0 ->
    case all_digits(Bin) of
        true -> {ok, min(max(binary_to_integer(Bin), 1), 7)};
        false -> {error, bad_length}
    end;
parse_hops(_Bin) ->
    {error, bad_length}.

-spec maybe_put_len(in_len | out_len, none | {ok, 1..7}, i2p_sam_session:tunnel_lengths()) ->
    i2p_sam_session:tunnel_lengths().
maybe_put_len(_Key, none, Acc) ->
    Acc;
maybe_put_len(Key, {ok, Len}, Acc) ->
    maps:put(Key, Len, Acc).

%% all_digits/1 — every byte is an ASCII digit (shared by parse_port and
%% parse_hops).
-spec all_digits(binary()) -> boolean().
all_digits(Bin) ->
    lists:all(
        fun(C) -> C >= $0 andalso C =< $9 end,
        binary_to_list(Bin)
    ).

-spec base32_to_bytes(binary()) -> binary().
base32_to_bytes(B32) ->
    Alphabet = <<"abcdefghijklmnopqrstuvwxyz234567">>,
    Bits = base32_to_bits(B32, Alphabet, <<>>),
    %% Number of complete data bytes: N chars * 5 bits / 8.
    DataBytes = byte_size(B32) * 5 div 8,
    case Bits of
        <<Result:DataBytes/binary, _/bitstring>> ->
            Result;
        <<Result:DataBytes/binary>> ->
            Result;
        _ ->
            <<>>
    end.

base32_to_bits(<<>>, _Alphabet, Acc) ->
    Acc;
base32_to_bits(<<C, Rest/binary>>, Alphabet, Acc) ->
    case find_b32_index(Alphabet, C, 0) of
        error -> <<>>;
        Idx -> base32_to_bits(Rest, Alphabet, <<Acc/bitstring, Idx:5>>)
    end.

find_b32_index(_Alphabet, _C, Idx) when Idx > 31 ->
    error;
find_b32_index(Alphabet, C, Idx) ->
    case binary:at(Alphabet, Idx) of
        C -> Idx;
        _ -> find_b32_index(Alphabet, C, Idx + 1)
    end.
