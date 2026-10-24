-module(i2per_tun_config_tests).

-include_lib("eunit/include/eunit.hrl").

lookup_empty_test() ->
    application:unset_env(i2per_tun, destinations),
    ?assertEqual(error, i2per_tun_config:lookup(<<"10.0.0.2">>)).

lookup_found_test() ->
    application:set_env(i2per_tun, destinations, #{<<"10.0.0.2">> => <<"peer.i2p">>}),
    ?assertEqual({ok, <<"peer.i2p">>}, i2per_tun_config:lookup(<<"10.0.0.2">>)),
    application:unset_env(i2per_tun, destinations).

sam_defaults_test() ->
    application:unset_env(i2per_tun, sam_host),
    application:unset_env(i2per_tun, sam_port),
    ?assertEqual(<<"127.0.0.1">>, i2per_tun_config:sam_host()),
    ?assertEqual(7656, i2per_tun_config:sam_port()).
