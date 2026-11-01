-module(i2p_transport_ntcp2).

-moduledoc "NTCP2 adapter for the i2p_transport behaviour.".

-behaviour(i2p_transport).

-export([name/0, listen/2, dial/2, published_address/1, reachability/0]).

-doc "Transport name atom.".
-spec name() -> ntcp2.
name() -> ntcp2.

-doc "Return the NTCP2 supervisor.".
-spec listen(map(), map()) -> {ok, pid()} | {error, term()}.
listen(_Local, _Opts) ->
    case whereis(i2p_ntcp2_sup) of
        Pid when is_pid(Pid) -> {ok, Pid};
        _ -> {error, not_started}
    end.

-doc "Start a NTCP2 connection via supervisor.".
-spec dial(map(), map()) -> {ok, pid()} | {error, term()} | {ok, pid(), term()}.
dial(_Peer, Opts) ->
    try
        i2p_ntcp2_sup:start_connection(maps:get(child_spec, Opts, maps:get(spec, Opts)))
    catch
        _:_ -> {error, not_available}
    end.

-doc "Build the published NTCP2 RouterAddress if applicable.".
-spec published_address(map()) -> map() | none.
published_address(Local) ->
    try
        Host =
            case maps:find(host, Local) of
                {ok, H} -> H;
                error -> maps:get(our_host, Local, undefined)
            end,
        Port = maps:get(port, Local),
        Pub = maps:get(static_pub, Local),
        IV = maps:get(iv, Local),
        case maps:get(published, Local, maps:get(ntcp2_published, Local, true)) of
            true -> i2p_router_info:ntcp2_address(Host, Port, Pub, IV);
            false -> i2p_router_info:ntcp2_nonpublished_address(ntcp2_address_family(Host), Pub)
        end
    catch
        _:_ -> none
    end.

-doc "NTCP2 has no separate peer-test reachability service.".
-spec reachability() -> not_applicable.
reachability() -> not_applicable.

-spec ntcp2_address_family(binary()) -> ipv4 | ipv6.
ntcp2_address_family(Host) ->
    case inet:parse_ipv4_address(binary_to_list(Host)) of
        {ok, _} -> ipv4;
        {error, _} -> ipv6
    end.
