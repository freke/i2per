-module(i2p_upnp_srv_tests).

-moduledoc """
Unit tests for the UPnP service's switch and status surface. The protocol path
needs a gateway and is exercised by hand against a real router; these tests pin
the bounded, off-by-default contract.
""".

-include_lib("eunit/include/eunit.hrl").

enabled_reads_app_env_test() ->
    Old = application:get_env(i2per, upnp),
    try
        ok = application:unset_env(i2per, upnp),
        ?assertNot(i2p_upnp_srv:enabled()),
        ok = application:set_env(i2per, upnp, true),
        ?assert(i2p_upnp_srv:enabled()),
        ok = application:set_env(i2per, upnp, false),
        ?assertNot(i2p_upnp_srv:enabled())
    after
        restore(Old)
    end.

status_when_not_running_test() ->
    case whereis(i2p_upnp_srv) of
        undefined ->
            ?assertMatch(
                #{running := false},
                i2p_upnp_srv:status()
            );
        _Pid ->
            ok
    end.

parse_locations_case_insensitive_test() ->
    Bin = <<
        "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:49152/gateway.xml\r\n"
        "Location: http://192.168.1.2:49152/gateway.xml\r\n"
        "location: http://192.168.1.3:49152/gateway.xml\r\n"
    >>,
    ?assertEqual(
        [
            <<"http://192.168.1.1:49152/gateway.xml">>,
            <<"http://192.168.1.2:49152/gateway.xml">>,
            <<"http://192.168.1.3:49152/gateway.xml">>
        ],
        i2p_upnp_srv:parse_locations(Bin)
    ).

parse_locations_empty_test() ->
    ?assertEqual(
        [], i2p_upnp_srv:parse_locations(<<"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n">>)
    ).

restore(undefined) ->
    application:unset_env(i2per, upnp);
restore({ok, Value}) ->
    application:set_env(i2per, upnp, Value).
