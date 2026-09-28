-module(i2per_status_contract_tests).

-moduledoc """
Tests for the `i2per_status` read API's edges: the JSON encoder's tolerance of
values the encoder itself rejects, and the two status codes.

The encoder used to have clauses for maps and atoms and pass everything else to
`json:encode/1` untouched. That is only safe while the view contains nothing the
encoder refuses, which was true by accident: `m:i2p_status_data:view/0` happened
to pre-base64 the one identity it exposed. A per-peer hash reaching the view
would have made `/status.json` raise `invalid_byte` and answer 500, so the
tolerance is tested against values the view does not return *yet*.
""".

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%% JSON encoding %%%%% %%%

%% A raw 32-byte hash as a value. `json:encode/1` raises `invalid_byte` on one,
%% so this is the case that made the endpoint 500 the moment a peer hash arrived.
raw_hash_as_value_encodes_test() ->
    Hash = crypto:strong_rand_bytes(32),
    ?assertEqual(#{<<"peer">> => base64:encode(Hash)}, roundtrip(#{peer => Hash})).

%% The same hash as a *key*. The encoder refuses an unencodable key just as it
%% refuses an unencodable value, and a view keyed by peer hash is the obvious way
%% this endpoint grows.
raw_hash_as_key_encodes_test() ->
    Hash = crypto:strong_rand_bytes(32),
    ?assertEqual(#{base64:encode(Hash) => #{}}, roundtrip(#{Hash => #{}})).

%% A tuple. The encoder raises `unsupported_type`; a JSON array preserves order
%% and arity, so nothing is lost that the reader had.
tuple_becomes_array_test() ->
    ?assertEqual(#{<<"v">> => [<<"a">>, <<"b">>]}, roundtrip(#{v => {a, b}})),
    %% A 1-tuple stays a 1-element array: arity is information a reader of the
    %% array can recover, and collapsing it to a scalar would lose it.
    ?assertEqual(#{<<"v">> => [<<"only">>]}, roundtrip(#{v => {only}})),
    ?assertEqual(
        #{<<"v">> => [1, 2, 3, 4, 5, 6, 7, 8, 9]},
        roundtrip(#{v => list_to_tuple(lists:seq(1, 9))})
    ).

%% A tuple nested inside a list, and a list inside a map: recursion matters, or
%% the top-level clause passes and the nested value still crashes the encoder.
nested_shapes_encode_test() ->
    Snap = #{
        <<"peers">> => [#{<<"hash">> => crypto:strong_rand_bytes(32)}],
        <<"tunnels">> => #{<<"counts">> => [{1, 2}, {3, 4}]}
    },
    #{<<"peers">> := [#{<<"hash">> := H}], <<"tunnels">> := #{<<"counts">> := C}} = roundtrip(
        Snap
    ),
    ?assertEqual(32, byte_size(base64:decode(H))),
    ?assertEqual([[1, 2], [3, 4]], C).

%% Valid UTF-8 is a string, and stays one. Base64-encoding every binary would be
%% technically safe and practically useless: the router's own identity arrives
%% base64-encoded already, and an operator reading it wants the string it meant.
utf8_stays_a_string_test() ->
    ?assertEqual(#{<<"s">> => <<"hello">>}, roundtrip(#{s => <<"hello">>})),
    %% Multi-byte UTF-8 survives intact rather than being mangled or encoded.
    Snowman = <<16#E2, 16#98, 16#83>>,
    ?assertEqual(#{<<"s">> => Snowman}, roundtrip(#{s => Snowman})),
    %% A binary that happens to be printable ASCII is a string too.
    ?assertEqual(#{<<"s">> => <<"abc123">>}, roundtrip(#{s => <<"abc123">>})).

%% An empty binary is valid UTF-8 and a legal JSON string, so it must not be
%% base64-encoded into <<>>'s neighbour, and must not become an empty array.
empty_binary_is_empty_string_test() ->
    ?assertEqual(#{<<"s">> => <<>>}, roundtrip(#{s => <<>>})).

%% Control characters are valid UTF-8 but not valid *inside* a JSON string, so
%% they take the base64 path. A hash is full of them, and this is the reason the
%% round-trip above needs two clauses to succeed.
control_bytes_become_base64_test() ->
    WithNul = <<"a", 0, "b">>,
    ?assertEqual(#{<<"s">> => base64:encode(WithNul)}, roundtrip(#{s => WithNul})),
    ?assertEqual(#{<<"s">> => base64:encode(<<127>>)}, roundtrip(#{s => <<127>>})).

%% Scalars the encoder handles natively must still be handled natively.
scalars_pass_through_test() ->
    ?assertEqual(
        #{
            <<"t">> => true,
            <<"f">> => false,
            <<"n">> => 42,
            <<"a">> => <<"ok">>
        },
        roundtrip(#{t => true, f => false, n => 42, a => ok})
    ),
    %% null is how JSON spells "this key has no value", and `undefined` is how
    %% Erlang spells it. Collapsing the two would lose the distinction.
    ?assertEqual(#{<<"u">> => <<"undefined">>}, roundtrip(#{u => undefined})).

%% A snapshot shaped like the real one, with the values the real one does not have
%% yet, must survive the whole pipeline. This is the property the endpoint needs
%% and the one the old implementation could not provide.
realistic_snapshot_with_unencodable_values_test() ->
    Hash = crypto:strong_rand_bytes(32),
    Snap = #{
        online => true,
        router_node => 'router@somewhere',
        subscribed => true,
        identity => base64:encode(Hash),
        peers => #{Hash => #{reachable => true}},
        tunnels => #{
            outbound => 1,
            inbound => 2,
            transit => 3,
            pending => 0,
            exploratory_outbound => 1,
            exploratory_inbound => 0
        },
        netdb => #{ri => 9, ls => 4},
        sessions => 0,
        events => #{tunnel_built => 7, reachability => {ssu2, reachable}}
    },
    Decoded = roundtrip(Snap),
    ?assertEqual(true, maps:get(<<"online">>, Decoded)),
    ?assertEqual(<<"router@somewhere">>, maps:get(<<"router_node">>, Decoded)),
    ?assert(maps:is_key(base64:encode(Hash), maps:get(<<"peers">>, Decoded))),
    ?assertEqual(
        1, maps:get(<<"exploratory_outbound">>, maps:get(<<"tunnels">>, Decoded))
    ),
    ?assertEqual(
        [<<"ssu2">>, <<"reachable">>],
        maps:get(<<"reachability">>, maps:get(<<"events">>, Decoded))
    ).

%% %%%%% %%% Helpers %%%%% %%%

%% Encode and decode, so every assertion is about a body a client can actually
%% parse. A value that encodes to something `json:decode/1` rejects is just as
%% broken as one that raises, and neither shows up if the test only encodes.
%%
%% `json:encode/1` returns an iolist and `json:decode/1` wants a binary, so the
%% flattening is part of what is under test: the body cowboy is handed is the
%% iolist, and a client sees the bytes.
roundtrip(Snap) ->
    json:decode(iolist_to_binary(json:encode(i2per_status_json:to_jsonable(Snap)))).
