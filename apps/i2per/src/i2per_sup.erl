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
When app env `i2per` -> `ssu2` serves UDP
(`f:i2p_identity:ssu2_available/0`), the SSU2 supervisor starts with a UDP boot
listener on the configured SSU2 port and the RouterInfo advertises the SSU2
address. In explicit test mode, app env `i2per` ->
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
    report_started_as(LocalSeeds),
    Children =
        [
            %% Counter home before the bus, deliberately. `i2p_events:start_link/0`
            %% samples the backlog gauge once before its first tick so the figure
            %% exists from boot rather than after one interval -- and that sample is
            %% a documented no-op while this process is absent. The other order left
            %% the read API carrying no backlog at all for the first tick, with an
            %% absent gauge indistinguishable from a sampler that had died.
            stats_child(),
            events_child(),
            config_srv_child(),
            peer_rep_child(),
            reachability_child()
        ] ++
            %% A list, because the NetDb brings two processes. A supervisor's child
            %% list must be **flat** — a list of lists is not a valid spec, and it
            %% fails as a `start_spec` badmatch from every test that boots the app.
            netdb_children() ++
            ntcp2_sup_children(LocalSeeds) ++ ssu2_sup_children(LocalSeeds) ++
            manager_children(LocalSeeds),
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, Children}}.

%% ADR 0002's "it started and I don't know with what".
%%
%% Reported from here rather than from `m:i2per_app` because this is where the
%% answers are computed: `f:resolve_local/0` is what turns a data directory into a
%% seed count and a listening address, and asking for them again from outside
%% would either run the identity path twice or restate its defaults here. Both are
%% worse than reporting the values this function already has.
%%
%% Before the children start, for the same reason the configuration line is: a
%% router that dies coming up has still told the operator what it was trying to be.
-spec report_started_as(local_seeds()) -> ok.
report_started_as({ok, Local, Seeds, Listen}) ->
    i2p_log:emit(
        started_as,
        "i2per started as: ~s",
        [render_started_as(Local, Seeds, Listen)]
    );
report_started_as(error) ->
    i2p_log:emit(
        started_as,
        "i2per started as: ~s",
        ["(no identity and no seed list; running without a listener)"]
    ).

%% The listen address is read off the RouterInfo rather than off the environment,
%% because the RouterInfo is what the network will be told and the environment is
%% only what the router was asked for. They agree today; reporting the published
%% one means the line stays true if they ever stop agreeing.
%%
%% The address map is in wire shape -- binary keys, and a port carried as its
%% decimal string -- so the values are interpolated as strings rather than decoded.
%% That is the port as the RouterInfo writes it, which is what the operator would
%% find in a RouterInfo dump, and decoding it would mean a second copy of the
%% `resolve_local_from_disk/0` defaults or a fallback for a non-numeric port.
-spec render_started_as(term(), list(), term()) -> string().
render_started_as(Local, Seeds, Listen) ->
    lists:flatten(
        io_lib:format(
            "version=~s ~s data_dir=~s live=~p seeds=~p ~s",
            [
                vsn(),
                render_listen(Local, Listen),
                render_data_dir(),
                live_network_enabled(),
                length(Seeds),
                render_distribution()
            ]
        )
    ).

-spec render_listen(term(), term()) -> string().
render_listen(_Local, no_listen) ->
    %% The explicit-identity mode: no listener is bound, so there is no address to
    %% report. `sam_port` is still reported, because it is a *configured* value and
    %% the answer to "did the operator ask for one" is the same either way.
    lists:flatten(
        io_lib:format("listen=none sam_port=~s", [render_opt(application:get_env(i2per, sam_port))])
    );
render_listen(Local, listen) ->
    SamPort = render_opt(application:get_env(i2per, sam_port)),
    case published_address(Local) of
        {ok, Host, Port} ->
            lists:flatten(io_lib:format("listen=~s:~s sam_port=~s", [Host, Port, SamPort]));
        none ->
            %% A listener *is* bound; what is missing is the published address,
            %% because the configured host is not reachable and
            %% `m:i2p_identity:validate_host/1` therefore refuses to put one in the
            %% RouterInfo. Reported as `unpublished` rather than `none` because the
            %% two mean opposite things to an operator deciding whether the router is
            %% working, and `none` here would read as "nothing is listening", which
            %% is false and would send them looking in the wrong place.
            lists:flatten(io_lib:format("listen=unpublished sam_port=~s", [SamPort]))
    end.

%% The NTCP2 address out of the published set, with its host and port.
%%
%% A RouterInfo can publish several addresses, so a UDP-serving boot carries an
%% NTCP2 and an SSU2 one and the list is not length one. NTCP2 is named
%% specifically: it is the transport `listen` means here, and an operator reading
%% "listen=" wants the transport the router dials peers over, not the peer-test one.
%%
%% Returns `none` rather than raising when the address carries no host or port,
%% which is what an unreachable configured host produces -- `m:i2p_identity`'s host
%% validation leaves the address in place and omits the pair, rather than dropping
%% the address. See `f:render_listen/2` for what the line says in that case.
-spec published_address(i2p_peer:local_keys()) -> {ok, binary(), binary()} | none.
published_address(Local) ->
    Addresses = i2p_router_info:addresses(maps:get(ri, Local)),
    Ntcp2 = [
        Address
     || Address <- Addresses,
        maps:get(transport, Address, undefined) =:= <<"NTCP2">>
    ],
    case Ntcp2 of
        [Address | _] -> address_host_port(Address);
        [] -> none
    end.

-spec address_host_port(map()) -> {ok, binary(), binary()} | none.
address_host_port(Address) ->
    Options = maps:get(options, Address),
    case {maps:find(<<"host">>, Options), maps:find(<<"port">>, Options)} of
        {{ok, Host}, {ok, Port}} -> {ok, Host, Port};
        _ -> none
    end.

%% `data_dir` is absent in the explicit-identity mode, which is the test and
%% embedded-boot mode. Reported as `none` rather than omitted so the line keeps the
%% same shape in both modes, and a reader is not left guessing whether the field
%% was absent or empty.
-spec render_data_dir() -> string().
render_data_dir() ->
    render_opt(application:get_env(i2per, data_dir)).

-spec render_opt({ok, term()} | undefined) -> string().
render_opt({ok, Value}) -> lists:flatten(io_lib:format("~0p", [Value]));
render_opt(undefined) -> "none".

%% The distribution posture, as the running node can actually observe it.
%%
%% `dist=on` with the node name is the part an operator needs: the name is what
%% `bin/i2per rpc` is given. `dist_range` is `kernel`'s configured
%% `inet_dist_listen_min`/`max`, which is the release's choice and the number a
%% firewall rule is written against.
%%
%% **What this line deliberately does not say: whether the node is listening.**
%% There is no reliable way to ask from inside the VM on this OTP. `net_kernel:info/0`
%% and `net_kernel:info/1` do not exist, `net_adm:local_port/0` does not exist, and
%% `erlang:system_info(dist_ctrl)` returns `[]` whether the node was started with
%% `-sname` or with `-dist_listen false` -- all four checked rather than assumed,
%% because a boot line that guesses at this would be reporting a firewall
%% question it has no access to. `vm.args` and the operator's firewall are where
%% that is answered; ADR 0002's release default keeps `-dist_listen false`.
%%
%% The cookie is never named. It is the secret, and this line is read by anybody who
%% can read the log.
-spec render_distribution() -> string().
render_distribution() ->
    case node() of
        nonode@nohost ->
            "dist=off";
        Node ->
            lists:flatten(
                io_lib:format("node=~p dist=on dist_range=~s", [Node, dist_range()])
            )
    end.

-spec dist_range() -> string().
dist_range() ->
    case
        {
            application:get_env(kernel, inet_dist_listen_min),
            application:get_env(kernel, inet_dist_listen_max)
        }
    of
        {{ok, Min}, {ok, Max}} -> lists:flatten(io_lib:format("~p-~p", [Min, Max]));
        _ -> "default"
    end.

-spec vsn() -> string().
vsn() ->
    case application:get_key(i2per, vsn) of
        {ok, Vsn} -> lists:flatten(io_lib:format("~s", [Vsn]));
        undefined -> "unknown"
    end.

%% The status event bus every other component announces on. Early, and ahead of
%% everything that subscribes: `m:i2p_ssu2_reachability` attaches in its `init/1`,
%% so a bus that is not yet up would block the supervisor rather than delay a
%% subscription.
events_child() ->
    #{
        id => i2p_events,
        start => {i2p_events, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_events]
    }.

%% First child: the counter home. Nothing blocks on it — `i2p_stats:add/2` and
%% `i2p_stats:set_gauge/2` are no-ops while it is absent — but the counters a
%% transport increments on its first packet should not be the ones lost to a start
%% order, and the bus samples its backlog gauge once at startup.
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

%% The NetDb and its writer, in that order.
%%
%% The writer is a child of the same supervisor rather than spawned on demand
%% because a save that needs a process to exist first is a save that can fail to
%% happen. `permanent` because the writer is what puts the store on disk.
%%
%% Order matters only for shutdown, and only mildly: `one_for_one` stops children
%% in reverse start order, so the writer stops first and the NetDb's `f:terminate/2`
%% saves in-process. See `m:i2p_netdb_srv:f:terminate/2` for why that is the
%% arrangement it wants anyway.
netdb_children() ->
    [
        #{
            id => i2p_netdb_srv,
            start => {i2p_netdb_srv, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [i2p_netdb_srv]
        },
        #{
            id => i2p_netdb_writer,
            start => {i2p_netdb_writer, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [i2p_netdb_writer]
        }
    ].

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

%% The SSU2 supervisor: a plain supervisor child unless the setting *serves* UDP
%% (app env `i2per` -> `ssu2`, see `f:i2p_identity:ssu2_available/0`), and in the
%% persistent boot it
%% additionally binds a UDP listener on the published SSU2 port (owner
%% `m:i2p_peer`) that accepts inbound sessions. The supervisor remains a child
%% when SSU2 is disabled so the session registry ETS tables exist for code
%% paths that consult them. The listener and outbound selection come online
%% only when enabled.
ssu2_sup_children(_LocalSeeds = {ok, Local, _Seeds, listen}) ->
    case i2p_identity:ssu2_available() of
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
%% The identity we resolved, the bootstrap seeds, and whether that identity has a
%% listener bound to it.
%%
%% Named rather than written out twice: `f:resolve_local/0` and the boot-line
%% reporter both need it, and a return type restated at each use is two places to
%% edit when the shape moves.
-type local_seeds() ::
    {ok, i2p_peer:local_keys(), [i2p_router_info:router_info()], listen | no_listen}
    | error.

-spec resolve_local() -> local_seeds().
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
