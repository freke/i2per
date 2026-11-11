-module(i2per_tun_config).

-moduledoc """
Static configuration for `i2per_tun` (epiq `D3750BZ`).

Destination mapping is a static IP -> destination map (research decision):
the protocol has no automatic IP<->I2P mapping. Configured via the
`destinations` app env of `i2per_tun`: a map from a binary IP string
(e.g. <<"10.0.0.2">>) to a destination hostname (e.g. <<"peer.i2p">>).
""".

-export([
    destinations/0,
    lookup/1,
    sam_host/0,
    sam_port/0,
    listen_port/0,
    router_node/0,
    relay_idle_timeout/0
]).

-spec destinations() -> #{binary() => binary()}.
destinations() ->
    case application:get_env(i2per_tun, destinations) of
        {ok, M} when is_map(M) -> M;
        _ -> #{}
    end.

-spec lookup(binary()) -> {ok, binary()} | error.
lookup(Ip) when is_binary(Ip) ->
    case maps:find(Ip, destinations()) of
        {ok, Dest} when is_binary(Dest) -> {ok, Dest};
        _ -> error
    end.

-spec sam_host() -> binary().
sam_host() ->
    case application:get_env(i2per_tun, sam_host) of
        {ok, H} when is_binary(H), byte_size(H) > 0 -> H;
        _ -> <<"127.0.0.1">>
    end.

-spec sam_port() -> inet:port_number().
sam_port() ->
    case application:get_env(i2per_tun, sam_port) of
        {ok, P} when is_integer(P), P > 0 -> P;
        _ -> 7656
    end.

-spec router_node() -> node().
router_node() ->
    case application:get_env(i2per_tun, router_node) of
        {ok, N} when is_atom(N) -> N;
        _ -> node()
    end.

-spec listen_port() -> inet:port_number().
listen_port() ->
    case application:get_env(i2per_tun, listen_port) of
        {ok, P} when is_integer(P), P > 0 -> P;
        _ -> 7657
    end.

-doc """
Idle timeout for the flow relays, in milliseconds.

The timeout is reset by any byte in either direction, so it closes a flow only
when both directions have been quiet for the whole interval. The default is
`infinity` (no idle cutoff), matching i2pd; `0` also disables it. A positive
value enables it. Set the `relay_idle_timeout_ms` key in the `i2per_tun` app
env.
""".
-spec relay_idle_timeout() -> infinity | pos_integer().
relay_idle_timeout() ->
    case application:get_env(i2per_tun, relay_idle_timeout_ms) of
        {ok, infinity} -> infinity;
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> infinity
    end.
