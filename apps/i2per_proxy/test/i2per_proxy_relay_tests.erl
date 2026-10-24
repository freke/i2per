-module(i2per_proxy_relay_tests).

-include_lib("eunit/include/eunit.hrl").

relay_closes_cleanly_test() ->
    {ok, LSockA} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, {_, PortA}} = inet:sockname(LSockA),
    {ok, LSockB} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, {_, PortB}} = inet:sockname(LSockB),
    spawn(fun() -> accept_and_close(LSockA) end),
    spawn(fun() -> accept_and_close(LSockB) end),
    {ok, SA} = gen_tcp:connect("127.0.0.1", PortA, [binary, {packet, raw}, {active, false}], 5000),
    {ok, SB} = gen_tcp:connect("127.0.0.1", PortB, [binary, {packet, raw}, {active, false}], 5000),
    ok = i2per_proxy_relay:relay(SA, SB, 2000),
    gen_tcp:close(LSockA),
    gen_tcp:close(LSockB).

accept_and_close(LSock) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            gen_tcp:close(Sock);
        {error, _} ->
            ok
    end.
