-module(i2p_datagram_replay_tests).

-include_lib("eunit/include/eunit.hrl").

basic_test_() ->
    [
        {"fresh key is accepted", fun fresh/0},
        {"replayed key is detected", fun replay/0},
        {"capacity bound and eviction", fun capacity_eviction/0},
        {"counters track outcomes", fun counters/0}
    ].

fresh() ->
    W0 = i2p_datagram_replay:new(2),
    {accepted, W1} = i2p_datagram_replay:check(W0, key1),
    ?assertEqual(1, i2p_datagram_replay:size(W1)),
    ?assertEqual(2, i2p_datagram_replay:capacity(W1)).

replay() ->
    W0 = i2p_datagram_replay:new(2),
    {accepted, W1} = i2p_datagram_replay:check(W0, key1),
    {replay, _W2} = i2p_datagram_replay:check(W1, key1).

capacity_eviction() ->
    W0 = i2p_datagram_replay:new(2),
    {accepted, W1} = i2p_datagram_replay:check(W0, key1),
    {accepted, W2} = i2p_datagram_replay:check(W1, key2),
    %% Full: inserting key3 evicts key1.
    {accepted, W3} = i2p_datagram_replay:check(W2, key3),
    ?assertEqual(2, i2p_datagram_replay:size(W3)),
    %% key1 is gone -> accepted again.
    {accepted, _W4} = i2p_datagram_replay:check(W3, key1).

counters() ->
    W0 = i2p_datagram_replay:new(2),
    {accepted, W1} = i2p_datagram_replay:check(W0, key1),
    {replay, W2} = i2p_datagram_replay:check(W1, key1),
    {accepted, W3} = i2p_datagram_replay:check(W2, key2),
    {accepted, W4} = i2p_datagram_replay:check(W3, key3),
    ?assertEqual(
        #{accepted => 3, replayed => 1, evicted => 1},
        i2p_datagram_replay:stats(W4)
    ).
