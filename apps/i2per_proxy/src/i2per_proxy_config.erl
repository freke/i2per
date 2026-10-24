-module(i2per_proxy_config).

-moduledoc """
Static configuration for `i2per_proxy`.

Reads app env of `i2per_proxy`. Defaults match i2pd's proxy ports.
""".

-export([listen_host/0, socks_port/0, http_port/0, sam_host/0, sam_port/0, router_node/0]).

-spec listen_host() -> binary() | inet:ip_address().
listen_host() ->
    case application:get_env(i2per_proxy, listen_host) of
        {ok, H} when is_binary(H), byte_size(H) > 0 -> H;
        {ok, IP} when is_tuple(IP) -> IP;
        _ -> <<"127.0.0.1">>
    end.

-spec socks_port() -> inet:port_number().
socks_port() ->
    case application:get_env(i2per_proxy, socks_port) of
        {ok, P} when is_integer(P), P > 0 -> P;
        _ -> 4447
    end.

-spec http_port() -> inet:port_number().
http_port() ->
    case application:get_env(i2per_proxy, http_port) of
        {ok, P} when is_integer(P), P > 0 -> P;
        _ -> 4444
    end.

-spec sam_host() -> binary().
sam_host() ->
    case application:get_env(i2per_proxy, sam_host) of
        {ok, H} when is_binary(H), byte_size(H) > 0 -> H;
        _ -> <<"127.0.0.1">>
    end.

-spec sam_port() -> inet:port_number().
sam_port() ->
    case application:get_env(i2per_proxy, sam_port) of
        {ok, P} when is_integer(P), P > 0 -> P;
        _ -> 7656
    end.

-spec router_node() -> node().
router_node() ->
    case application:get_env(i2per_proxy, router_node) of
        {ok, N} when is_atom(N) -> N;
        _ -> node()
    end.
