-module(i2per_proxy_app).

-moduledoc """
The `i2per_proxy` OTP application callback.

Companion app (ADR 0001): SOCKS and HTTP proxying for the i2per router,
delivered as a separate application the operator starts and stops. It reaches
the router only over SAM on TCP, never through core modules, so it may run on
the router's own node or on a node the operator connects.
""".

-behaviour(application).

-export([start/2, stop/1]).

-spec start(application:start_type(), term()) -> {ok, pid()}.
start(_Type, _Args) ->
    i2per_proxy_sup:start_link().

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
