-module(i2per_proxy_config).

-moduledoc """
Static configuration for `i2per_proxy`.

Reads app env of `i2per_proxy`. Defaults match i2pd's proxy ports.
""".

-export([
    listen_host/0,
    socks_port/0,
    http_port/0,
    sam_host/0,
    sam_port/0,
    router_node/0,
    relay_idle_timeout/0
]).

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

-doc """
Idle timeout for the byte relays, in milliseconds.

The timeout is reset by any byte in either direction, so it closes a relay only
when both directions have been quiet for the whole interval. The default is
`infinity` (no idle cutoff), matching i2pd; `0` also disables it. A positive
value enables it. Set the `relay_idle_timeout_ms` key in the `i2per_proxy` app
env.
""".
-spec relay_idle_timeout() -> infinity | pos_integer().
relay_idle_timeout() ->
    case application:get_env(i2per_proxy, relay_idle_timeout_ms) of
        {ok, infinity} -> infinity;
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> infinity
    end.
