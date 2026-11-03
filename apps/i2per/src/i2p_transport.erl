-module(i2p_transport).

-moduledoc """
Transport behaviour for i2per (Z2DRRT5).

A transport is a module implementing this behaviour. Adding a transport is
then a new module plus an entry in the configured transport list, with no
edits to identity, peer or reachability code required once those modules
iterate over the registry instead of naming transports.

The behaviour is intentionally minimal and mirrors the existing NTCP2/SSU2
supervision entry points.
""".

-callback name() -> atom().
-callback listen(Local :: map(), Opts :: map()) -> {ok, pid()} | {error, term()}.
-callback dial(Peer :: map(), Opts :: map()) -> {ok, pid()} | {error, term()} | {ok, pid(), term()}.
-callback published_address(Local :: map()) -> map() | none.
-callback reachability() -> reachable | firewalled | unknown | not_applicable.

-optional_callbacks([dial/2]).

-export([
    configured/0,
    all/0,
    modules/0,
    module_for/1,
    listen/3,
    dial/3,
    published_address/2,
    published_addresses/1,
    reachability/0,
    reachability/1
]).

-doc "The configured transport list, from app env `i2per` -> `transports` (default [ntcp2, ssu2]).".
-spec configured() -> [atom()].
configured() ->
    case application:get_env(i2per, transports) of
        {ok, List} when is_list(List), List =/= [] ->
            case lists:any(fun(T) -> T =:= ntcp2 orelse T =:= ssu2 end, List) of
                true -> List;
                false -> [ntcp2, ssu2]
            end;
        _ -> [ntcp2, ssu2]
    end.

-doc "Resolve configured transport atoms to their implementing modules.".
-spec all() -> [module()].
all() ->
    [module_for(T) || T <- configured()].

-doc "Alias for all/0.".
-spec modules() -> [module()].
modules() ->
    all().

-doc "Map a transport atom to its module.".
-spec module_for(atom()) -> module().
module_for(ntcp2) -> i2p_transport_ntcp2;
module_for(ssu2) -> i2p_transport_ssu2;
module_for(Other) -> Other.

-doc "Start listening for a named transport.".
-spec listen(atom(), map(), map()) -> {ok, pid()} | {error, term()}.
listen(Name, Local, Opts) ->
    Mod = module_for(Name),
    try
        Mod:listen(Local, Opts)
    catch
        _:_ -> {error, not_available}
    end.

-doc "Dial via a named transport.".
-spec dial(atom(), map(), map()) -> {ok, pid()} | {error, term()} | {ok, pid(), term()}.
dial(Name, Peer, Opts) ->
    Mod = module_for(Name),
    try
        Mod:dial(Peer, Opts)
    catch
        _:_ -> {error, not_available}
    end.

-doc "Get published address for a named transport.".
-spec published_address(atom(), map()) -> map() | none.
published_address(Name, Local) ->
    Mod = module_for(Name),
    try
        Mod:published_address(Local)
    catch
        Class:Reason:Stack ->
            logger:warning(
                "i2p_transport:published_address(~p) failed: ~p:~p ~p",
                [Name, Class, Reason, Stack]
            ),
            none
    end.

-doc "Collect published addresses from all configured transports.".
-spec published_addresses(map()) -> [map()].
published_addresses(Local) ->
    lists:filtermap(
        fun(Name) ->
            case published_address(Name, Local) of
                none -> false;
                Addr -> {true, Addr}
            end
        end,
        configured()
    ).

-doc "Get reachability for a named transport.".
-spec reachability(atom()) -> reachable | firewalled | unknown | not_applicable.
reachability(Name) ->
    case lists:member(Name, configured()) of
        false ->
            not_applicable;
        true ->
            Mod = module_for(Name),
            try
                Mod:reachability()
            catch
                _:_ -> unknown
            end
    end.

-doc "Aggregate reachability over configured transports (SSU2-oriented).".
-spec reachability() -> reachable | firewalled | unknown | not_applicable.
reachability() ->
    case lists:member(ssu2, configured()) of
        true ->
            try
                i2p_ssu2_reachability:status()
            catch
                _:_ -> unknown
            end;
        false ->
            not_applicable
    end.
