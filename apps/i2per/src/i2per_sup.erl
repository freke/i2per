-module(i2per_sup).

-moduledoc """
The top-level supervisor of the i2per application.

Holds the event bus, runtime configuration service, NetDb store, peer
reputation store, reachability decision, NTCP2 and SSU2 supervisors, peer
connection manager, tunnel manager, lookup service, address-book services, and
the SAM v3 bridge supervisor. The `i2per_status` web service is a separate
application and is not started here.

In persistent operator mode, app env `i2per` -> `data_dir` selects the identity
directory and `seeds` supplies bootstrap RouterInfos. The NTCP2 supervisor
starts with a boot listener bound on the configured local port (owner
`m:i2p_peer`), so the router can accept inbound connections when its RouterInfo
publishes that endpoint. A firewalled boot still binds the local listener for
outbound handshakes but publishes the cost-14 non-published RouterInfo form.
When app env `i2per` -> `ssu2_enabled` is also set, the SSU2 supervisor starts
with a UDP boot listener on the configured SSU2 port and the RouterInfo
advertises the SSU2 address. In explicit test mode, app env `i2per` ->
`i2p_peer` supplies the identity and seeds directly, and no listener is bound
because the test owns its listeners.

The published `host` (app env `i2per` -> `host`, default `127.0.0.1`) is
validated: a non-public literal (loopback, private, link-local, multicast,
unspecified) or a hostname resolving to only non-public addresses is a config
error and raises the process, so we never publish an undialable RouterInfo on
the live network. Set app env `i2per` -> `allow_private_host = true` to opt
out (tests and local-only boots).

Both the peer manager and tunnel manager are started in one of two modes:

* **Explicit** — app env `i2per` -> `i2p_peer` carries `#{local, seeds}`.
* **Persistent** — app env `i2per` -> `data_dir` names a directory where
  `m:i2p_identity` stores the identity file; `seeds` carries bootstrap
  RouterInfos.

The `Local` identity map is computed once and shared between all managers.
""".

-behaviour(supervisor).

-export([start_link/0, init/1]).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    LocalSeeds = resolve_local(),
    Children =
        [
            events_child(),
            stats_child(),
            config_srv_child(),
            netdb_child(),
            peer_rep_child(),
            reachability_child()
        ] ++
            ntcp2_sup_children(LocalSeeds) ++ ssu2_sup_children(LocalSeeds) ++
            manager_children(LocalSeeds),
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, Children}}.

%% First child: the status event bus every other component announces on.
events_child() ->
    #{
        id => i2p_events,
        start => {i2p_events, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_events]
    }.

%% Second child, and early on purpose: the counter home. Nothing here blocks on
%% it — `i2p_stats:add/2` is a no-op while it is absent — but the counters a
%% transport increments on its first packet should not be the ones lost to a
%% start order.
stats_child() ->
    #{
        id => i2p_stats,
        start => {i2p_stats, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_stats]
    }.

%% Validated runtime configuration front door (`m:i2p_config_srv`).
config_srv_child() ->
    #{
        id => i2p_config_srv,
        start => {i2p_config_srv, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_config_srv]
    }.

netdb_child() ->
    #{
        id => i2p_netdb_srv,
        start => {i2p_netdb_srv, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_netdb_srv]
    }.

%% The per-peer reliability store (`m:i2p_peer_rep`). Like the NetDb process it
%% is always up (memory-only without a data dir) so every component can query
%% `f:i2p_peer_rep:avoided/1` without registration races.
peer_rep_child() ->
    #{
        id => i2p_peer_rep,
        start => {i2p_peer_rep, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_peer_rep]
    }.

%% The SSU2 inbound-reachability decision (`m:i2p_ssu2_reachability`) starts
%% before peer tests so `status/0,1` is available from boot. Private-host boots
%% also publish their firewalled decision before handling peer-test results.
reachability_child() ->
    #{
        id => i2p_ssu2_reachability,
        start => {i2p_ssu2_reachability, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_ssu2_reachability]
    }.

ntcp2_sup_child() ->
    #{
        id => i2p_ntcp2_sup,
        start => {i2p_ntcp2_sup, start_link, []},
        restart => permanent,
        shutdown => infinity,
        type => supervisor,
        modules => [i2p_ntcp2_sup]
    }.

%% The NTCP2 supervisor: plain (no listener) except in the persistent boot,
%% where a boot listener bound on the configured local port accepts inbound
%% connections on behalf of the peer manager. The port is carried in the local
%% map so a non-published RouterInfo does not prevent the listener from starting.
ntcp2_sup_children({ok, Local, _Seeds, listen}) ->
    Port = maps:get(port, Local),
    [
        #{
            id => i2p_ntcp2_sup,
            start => {i2p_ntcp2_sup, start_link, [Port, Local, i2p_peer]},
            restart => permanent,
            shutdown => infinity,
            type => supervisor,
            modules => [i2p_ntcp2_sup]
        }
    ];
ntcp2_sup_children(_LocalSeeds) ->
    [ntcp2_sup_child()].

%% The SSU2 supervisor: a plain supervisor child unless transport wiring is
%% enabled (app env `i2per` -> `ssu2_enabled`), and in the persistent boot it
%% additionally binds a UDP listener on the published SSU2 port (owner
%% `m:i2p_peer`) that accepts inbound sessions. The supervisor remains a child
%% when SSU2 is disabled so the session registry ETS tables exist for code
%% paths that consult them. The listener and outbound selection come online
%% only when enabled.
ssu2_sup_children(_LocalSeeds = {ok, Local, _Seeds, listen}) ->
    case i2p_identity:ssu2_enabled() of
        true ->
            {ok, #{host := Host, port := Port}} =
                i2p_router_info:ssu2_address_options(maps:get(ri, Local)),
            [
                #{
                    id => i2p_ssu2_sup,
                    start =>
                        {i2p_ssu2_sup, start_link, [Host, Port, ssu2_local(Local), i2p_peer]},
                    restart => permanent,
                    shutdown => infinity,
                    type => supervisor,
                    modules => [i2p_ssu2_sup]
                }
            ];
        false ->
            [ssu2_sup_child()]
    end;
ssu2_sup_children(_LocalSeeds) ->
    [ssu2_sup_child()].

ssu2_sup_child() ->
    #{
        id => i2p_ssu2_sup,
        start => {i2p_ssu2_sup, start_link, []},
        restart => permanent,
        shutdown => infinity,
        type => supervisor,
        modules => [i2p_ssu2_sup]
    }.

%% The SSU2 session local map: static keys + intro key (from the peer local
%% map) plus the signing material and RouterInfo needed by the SSU2 peer-test
%% Charlie/Bob roles (message 2 -> 3 responder and introducer relay).
ssu2_local(Local) ->
    #{
        static_priv => maps:get(static_priv, Local),
        static_pub => maps:get(static_pub, Local),
        intro_key => maps:get(intro_key, Local),
        sign_seed => maps:get(sign_seed, Local),
        sign_pub => maps:get(sign_pub, Local),
        hash => maps:get(hash, Local),
        ri => maps:get(ri, Local)
    }.

%% Compute Local once; start peer + tunnel + SAM managers when configured.
manager_children({ok, Local, Seeds, Listen}) ->
    [
        peer_child_spec(Local, Seeds),
        tunnel_srv_child_spec(Local),
        sam_sup_child_spec(Local, Listen)
    ] ++
        [
            lookup_srv_child_spec(Local),
            addressbook_child_spec()
        ] ++
        subs_children() ++
        server_tunnels_children() ++ reseed_children();
manager_children(error) ->
    [].

%% reseed_children/0 — the one-shot bootstrap worker (`m:i2p_reseed_srv`)
%% when app env `i2per` -> `reseed` is enabled. The NetDb threshold is
%% checked by the worker itself: supervisor specs are built before any child
%% runs, so querying `f:i2p_netdb_srv:count/0` here would always fail.
lookup_srv_child_spec(Local) ->
    #{
        id => i2p_lookup_srv,
        start => {i2p_lookup_srv, start_link, [maps:get(hash, Local)]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_lookup_srv]
    }.

%% addressbook_child_spec/0 - the hostname book; persists to
%% <data_dir>/hosts.txt when a data dir is configured, memory-only otherwise.
addressbook_child_spec() ->
    DataDir =
        case application:get_env(i2per, data_dir) of
            {ok, Dir} -> Dir;
            undefined -> undefined
        end,
    #{
        id => i2p_addressbook,
        start => {i2p_addressbook, start_link, [i2p_addressbook:hosts_file_for(DataDir)]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_addressbook]
    }.

%% subs_children/0 - the hosts.txt subscription fetcher when subscriptions
%% are configured via app env `i2per` -> `addressbook`.
subs_children() ->
    case application:get_env(i2per, live_network) of
        {ok, false} ->
            [];
        _ ->
            Opts =
                case application:get_env(i2per, addressbook) of
                    {ok, Value = #{subscriptions := [_ | _]}} -> Value;
                    _ -> #{}
                end,
            [subs_child_spec(Opts) || maps:is_key(subscriptions, Opts)]
    end.

subs_child_spec(Opts) ->
    #{
        id => i2p_addressbook_subs,
        start => {i2p_addressbook_subs, start_link, [Opts]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_addressbook_subs]
    }.

%% server_tunnels_children/0 - one server-tunnel child per service declared
%% via app env `i2per` -> `server_tunnels` (programmatic) plus the parsed
%% `tunnels.conf` entries (`server_tunnels_file`, built by `m:i2p_config`);
%% both feed `m:i2p_server_tunnel`.
server_tunnels_children() ->
    [i2p_server_tunnel:child_spec(Decl) || Decl <- i2p_server_tunnel_decls()].

i2p_server_tunnel_decls() ->
    app_env_decls() ++ file_decls().

app_env_decls() ->
    case application:get_env(i2per, server_tunnels) of
        {ok, Decls} when is_list(Decls) ->
            Decls;
        _ ->
            []
    end.

file_decls() ->
    case application:get_env(i2per, server_tunnels_file) of
        {ok, Decls} when is_list(Decls) ->
            Decls;
        _ ->
            []
    end.

reseed_children() ->
    %% Live reseeding is opt-in. A normal local boot leaves it disabled unless
    %% `live_network = true` or `reseed.enabled = true` is selected. The NetDb
    %% threshold guard lives in the worker (`m:i2p_reseed_srv`), which checks
    %% `i2p_netdb_srv:count()` at run time after all children are up — it
    %% never re-reseeds a populated NetDb.
    case reseed_enabled() of
        true -> [reseed_child_spec(default_reseed_opts())];
        false -> []
    end.

reseed_enabled() ->
    case application:get_env(i2per, reseed) of
        {ok, #{enabled := false}} -> false;
        {ok, #{enabled := true}} -> true;
        _ -> live_network_enabled()
    end.

live_network_enabled() ->
    case application:get_env(i2per, live_network) of
        {ok, true} -> true;
        _ -> false
    end.

default_reseed_opts() ->
    case application:get_env(i2per, reseed) of
        {ok, Opts} when is_map(Opts) -> maps:remove(enabled, Opts);
        _ -> #{}
    end.

reseed_child_spec(Opts) ->
    #{
        id => i2p_reseed_srv,
        start => {i2p_reseed_srv, start_link, [Opts]},
        %% Temporary: never restarted — a finished or failed bootstrap waits
        %% for the next router boot.
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_reseed_srv]
    }.

%% Resolve our NTCP2 identity. Two modes:
%%
%% 1. Test/explicit: application env `i2per` -> `i2p_peer` carries
%%    `#{local := Local, seeds := Seeds}`.
%% 2. Persistent: application env `i2per` -> `data_dir` points at a
%%    directory where `m:i2p_identity` stores the identity file; `seeds`
%%    carries the bootstrap RouterInfos and `host` / `port` name the
%%    listening address.
-spec resolve_local() ->
    {ok, i2p_peer:local_keys(), [i2p_router_info:router_info()], listen | no_listen} | error.
resolve_local() ->
    case application:get_env(i2per, i2p_peer) of
        {ok, #{local := Local, seeds := Seeds}} ->
            {ok, Local, Seeds, no_listen};
        _ ->
            resolve_local_from_disk()
    end.

resolve_local_from_disk() ->
    case {application:get_env(i2per, data_dir), application:get_env(i2per, seeds)} of
        {{ok, Dir}, {ok, Seeds}} ->
            {ok, Id} = i2p_identity:ensure_identity(Dir),
            Host = application:get_env(i2per, host, <<"127.0.0.1">>),
            Port = application:get_env(i2per, port, 9150),
            {ok, Host1} = validate_host(Host),
            Local = i2p_identity:build_local(Id, Host1, Port, maps:get(sign_seed, Id)),
            {ok, Local, Seeds, listen};
        _ ->
            error
    end.

%% Reject non-public hosts so we never publish a private/loopback RouterInfo
%% on the live network (i2pd's `reservedrange` check would refuse it, and a
%% loopback RouterInfo is undialable). `allow_private_host = true` opts out —
%% tests and local-only boots use it. DNS hostnames resolve and must map to at
%% least one public address. Any invalid host raises the process (config error).
validate_host(Host) ->
    AllowPrivate =
        case application:get_env(i2per, allow_private_host) of
            {ok, true} -> true;
            _ -> false
        end,
    case {AllowPrivate, inet:parse_address(binary_to_list(Host))} of
        {true, _} ->
            {ok, Host};
        {false, {ok, Addr}} ->
            case public_addr(Addr, Host) of
                true -> {ok, Host};
                false -> exit({config_error, {non_public_host, Host}})
            end;
        {false, {error, _}} ->
            %% Not an IP literal: treat as a hostname and resolve it.
            case inet:getaddrs(binary_to_list(Host), inet) of
                {ok, Addrs} ->
                    case lists:any(fun(A) -> public_addr(A, Host) end, Addrs) of
                        true -> {ok, Host};
                        false -> exit({config_error, {non_public_host, Host}})
                    end;
                {error, _} ->
                    exit({config_error, {unresolvable_host, Host}})
            end
    end.

public_addr(Addr, Host) ->
    case tuple_size(Addr) of
        4 ->
            case Addr of
                {127, _, _, _} -> false;
                {169, 254, _, _} -> false;
                {0, _, _, _} -> false;
                {10, _, _, _} -> false;
                {172, B, _, _} when B >= 16, B =< 31 -> false;
                {192, 168, _, _} -> false;
                {A, _, _, _} when A >= 224 -> false;
                _ -> true
            end;
        8 ->
            case addr_family(Addr) of
                loopback -> false;
                unspecified -> false;
                link_local -> false;
                unique_local -> false;
                multicast -> false;
                public -> true
            end;
        _ ->
            exit({config_error, {unresolvable_host, Host}})
    end.

addr_family({0, 0, 0, 0, 0, 0, 0, 1}) -> loopback;
addr_family({0, 0, 0, 0, 0, 0, 0, 0}) -> unspecified;
addr_family({16#fe80, _, _, _, _, _, _, _}) -> link_local;
addr_family({16#febf, _, _, _, _, _, _, _}) -> link_local;
addr_family({16#fc, _, _, _, _, _, _, _}) -> unique_local;
addr_family({16#fd, _, _, _, _, _, _, _}) -> unique_local;
addr_family({16#ff, _, _, _, _, _, _, _}) -> multicast;
addr_family({_, _, _, _, _, _, _, _}) -> public.

peer_child_spec(Local, Seeds) ->
    #{
        id => i2p_peer,
        start => {i2p_peer, start_link, [Local, Seeds]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_peer]
    }.

tunnel_srv_child_spec(Local) ->
    #{
        id => i2p_tunnel_srv,
        start => {i2p_tunnel_srv, start_link, [Local]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_tunnel_srv]
    }.

%% In the persistent boot (`listen`) the SAM supervisor starts with a
%% listener bound on the configured `sam_port`; in the explicit (test) mode it
%% starts empty and the test owns its listeners.
sam_sup_child_spec(Local, listen) ->
    #{
        id => i2p_sam_sup,
        start => {i2p_sam_sup, start_link, [Local]},
        restart => permanent,
        shutdown => infinity,
        type => supervisor,
        modules => [i2p_sam_sup]
    };
sam_sup_child_spec(_Local, no_listen) ->
    #{
        id => i2p_sam_sup,
        start => {i2p_sam_sup, start_link, []},
        restart => permanent,
        shutdown => infinity,
        type => supervisor,
        modules => [i2p_sam_sup]
    }.
