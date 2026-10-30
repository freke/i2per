-module(i2p_transport_ssu2).

-moduledoc "SSU2 adapter for the i2p_transport behaviour.".

-behaviour(i2p_transport).

-export([name/0, listen/2, dial/2, published_address/1, reachability/0]).

-doc "Transport name atom.".
-spec name() -> atom().
name() -> ssu2.

-doc "Start the SSU2 supervisor/listener if requested.".
-spec listen(map(), map()) -> {ok, pid()} | {error, term()}.
listen(Local, Opts) ->
    try
        Host = maps:get(host, Opts, maps:get(host, Local, <<"127.0.0.1">>)),
        Port = maps:get(port, Opts),
        LocalKeys = maps:get(local_keys, Opts),
        Owner = maps:get(owner, Opts, i2p_peer),
        i2p_ssu2_sup:start_link(Host, Port, LocalKeys, Owner)
    catch
        _:_ -> {error, not_available}
    end.

-doc "Dial via SSU2 connection.".
-spec dial(map(), map()) -> {ok, pid(), term()} | {error, term()}.
dial(_Peer, Opts) ->
    try
        i2p_ssu2_conn:connect(
            maps:get(local_keys, Opts),
            maps:get(remote_opts, Opts),
            maps:get(ri_block, Opts),
            maps:get(listener, Opts)
        )
    catch
        _:_ -> {error, not_available}
    end.

-doc "Build the published SSU2 RouterAddress if SSU2 is available.".
-spec published_address(map()) -> map() | none.
published_address(Local) ->
    try
        case i2p_identity:ssu2_available() of
            true ->
                Host = maps:get(host, Local),
                Port = maps:get(ssu2_port, Local, maps:get(port, Local)),
                Pub = maps:get(static_pub, Local),
                Intro = maps:get(intro_key, Local),
                i2p_router_info:ssu2_address(Host, Port, Pub, Intro);
            false ->
                none
        end
    catch
        _:_ -> none
    end.

-doc "SSU2 reachability via the reachability service.".
-spec reachability() -> reachable | firewalled | unknown | not_applicable.
reachability() ->
    try
        i2p_ssu2_reachability:status()
    catch
        _:_ -> unknown
    end.
