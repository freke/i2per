-module(i2p_netdb_raw_tests).

-include_lib("eunit/include/eunit.hrl").

netdb_type5_store_and_find_test() ->
    Store0 = i2p_netdb:new(),
    Key = rand_hash(),
    Bin = crypto:strong_rand_bytes(64),
    {ok, Store1, added} = i2p_netdb:store_ls_5_binary_at(Store0, Key, Bin, now_sec()),
    ?assertMatch({ok, Bin}, i2p_netdb:find_ls_5(Store1, Key)),
    ?assertEqual(error, i2p_netdb:find_ls_5(Store0, Key)).

netdb_type7_store_and_find_test() ->
    Store0 = i2p_netdb:new(),
    Key = rand_hash(),
    Bin = crypto:strong_rand_bytes(64),
    {ok, Store1, added} = i2p_netdb:store_ls_7_binary_at(Store0, Key, Bin, now_sec()),
    ?assertMatch({ok, Bin}, i2p_netdb:find_ls_7(Store1, Key)).

now_sec() ->
    erlang:system_time(second).

rand_hash() ->
    crypto:strong_rand_bytes(32).
