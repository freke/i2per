-module(i2per_proxy_config_tests).

-include_lib("eunit/include/eunit.hrl").

defaults_test() ->
    application:unset_env(i2per_proxy, listen_host),
    application:unset_env(i2per_proxy, socks_port),
    application:unset_env(i2per_proxy, http_port),
    application:unset_env(i2per_proxy, sam_host),
    application:unset_env(i2per_proxy, sam_port),
    ?assertEqual(<<"127.0.0.1">>, i2per_proxy_config:listen_host()),
    ?assertEqual(4447, i2per_proxy_config:socks_port()),
    ?assertEqual(4444, i2per_proxy_config:http_port()),
    ?assertEqual(<<"127.0.0.1">>, i2per_proxy_config:sam_host()),
    ?assertEqual(7656, i2per_proxy_config:sam_port()).

overrides_test() ->
    application:set_env(i2per_proxy, listen_host, <<"0.0.0.0">>),
    application:set_env(i2per_proxy, socks_port, 1080),
    application:set_env(i2per_proxy, http_port, 8080),
    application:set_env(i2per_proxy, sam_host, <<"10.0.0.1">>),
    application:set_env(i2per_proxy, sam_port, 7657),
    ?assertEqual(<<"0.0.0.0">>, i2per_proxy_config:listen_host()),
    ?assertEqual(1080, i2per_proxy_config:socks_port()),
    ?assertEqual(8080, i2per_proxy_config:http_port()),
    ?assertEqual(<<"10.0.0.1">>, i2per_proxy_config:sam_host()),
    ?assertEqual(7657, i2per_proxy_config:sam_port()),
    application:unset_env(i2per_proxy, listen_host),
    application:unset_env(i2per_proxy, socks_port),
    application:unset_env(i2per_proxy, http_port),
    application:unset_env(i2per_proxy, sam_host),
    application:unset_env(i2per_proxy, sam_port).
