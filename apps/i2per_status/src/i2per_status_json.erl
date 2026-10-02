-module(i2per_status_json).

-moduledoc """
Cowboy handler for `GET /status.json`: the current snapshot as JSON.

Answers 200 only when the snapshot says the router is online, and 503 when it
does not. A monitoring consumer can then tell a healthy router from a dead one
by status code alone; before, every response was 200 and `online` was the only
signal, which a consumer that only looked at the code could not see.

503 also covers the case where there is no snapshot at all — the collector is
down, or did not answer. That is the same operational fact as an offline router
(the service is up; the thing it reports on is not), and it is answerable, so
answering it beats letting the request crash into cowboy's 500.
""".

-export([init/2, to_jsonable/1]).

init(Req0, State) ->
    Req =
        case i2per_status_state:fetch() of
            {ok, #{online := true} = Snap} ->
                reply(200, Snap, Req0);
            {ok, _Offline} ->
                reply(503, offline(), Req0);
            {error, Reason} ->
                logger:warning("status.json: no snapshot available: ~0p", [Reason]),
                reply(503, offline(), Req0)
        end,
    {ok, Req, State}.

%% An offline answer still carries a JSON body saying so, so a consumer that
%% only reads the body learns what a consumer that reads the code learns. The
%% shape is `t:i2per_status_state:snapshot/0`'s, with the fields that describe
%% the observation rather than the router left out: there is no subscription and
%% no event count to report when the router is not there.
offline() ->
    #{online => false, events => #{}}.

reply(Status, Snap, Req0) ->
    cowboy_req:reply(
        Status,
        #{<<"content-type">> => <<"application/json">>},
        json(Snap),
        Req0
    ).

json(Snap) ->
    json:encode(to_jsonable(Snap)).

-doc """
Make a snapshot safe to hand to `json:encode/1`.

Input: any term from a snapshot. Output: the same shape with every value a JSON
encoder cannot take replaced by something it can.

The encoder is strict — it raises `unsupported_type` on a tuple and
`invalid_byte` on a binary that is not valid UTF-8 — so "pass everything else
through untouched" is a crash or a corrupt body waiting for the first value
outside the current view. Neither is acceptable for a public read API: the
snapshot is the thing a client is meant to be able to parse.

Two replacements, both lossless and both reversible by the reader:

  - a binary that is not valid UTF-8 becomes base64, which is how the router
    already encodes identity (`m:i2p_status_data:identity_b64/1`), so a raw
    32-byte hash reads the same here as it does there;
  - a tuple becomes a JSON array, since a tuple is an ordered sequence and the
    array preserves both the order and the arity.

A binary that *is* valid UTF-8 is left alone: it is a string, which is what the
caller meant. The `is_control` clause keeps JSON's own restriction — an encoded
control character is not a valid string in JSON either, so those go to base64
too rather than producing a body no parser will accept.
""".
-spec to_jsonable(term()) -> term().
to_jsonable(Map) when is_map(Map) ->
    maps:from_list([{jsonable_key(K), to_jsonable(V)} || {K, V} <- maps:to_list(Map)]);
to_jsonable(Node) when is_atom(Node), Node =/= true, Node =/= false ->
    atom_to_binary(Node, utf8);
to_jsonable(Bin) when is_binary(Bin) ->
    case printable_utf8(Bin) of
        true -> Bin;
        false -> base64:encode(Bin)
    end;
to_jsonable(Tuple) when is_tuple(Tuple) ->
    [to_jsonable(E) || E <- tuple_to_list(Tuple)];
to_jsonable(List) when is_list(List) ->
    [to_jsonable(E) || E <- List];
to_jsonable(Value) ->
    Value.

%% A map key has to be a string, and the same rule applies to it as to a value:
%% a snapshot keyed by peer hash would otherwise produce an unencodable object.
jsonable_key(Key) when is_binary(Key) ->
    to_jsonable(Key);
jsonable_key(Key) when is_atom(Key) ->
    to_jsonable(Key);
jsonable_key(Key) ->
    base64:encode(iolist_to_binary(io_lib:format("~0p", [Key]))).

%% Valid UTF-8 with no control characters. `unicode:characters_to_binary/3`
%% round-trips only well-formed input, so a lone continuation byte or a
%% truncated sequence fails here rather than reaching the encoder.
printable_utf8(Bin) ->
    case unicode:characters_to_binary(Bin, utf8, utf8) of
        Bin -> not has_control(Bin);
        _ -> false
    end.

has_control(Bin) ->
    lists:any(fun(C) when is_integer(C) -> C < 32 orelse C =:= 127 end, binary_to_list(Bin)).
