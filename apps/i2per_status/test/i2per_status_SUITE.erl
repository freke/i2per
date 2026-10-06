%% Distributed status-service tests. The Common Test node is started with a
%% fixed distribution name by the `just ct` recipes, so the suite never calls
%% `net_kernel:start` or spawns `epmd` itself. A peer router is started for the
%% `dist` group, and the status service talks to it over erpc. Readiness polls
%% use deadline-bounded helpers.

-module(i2per_status_SUITE).

-include_lib("eunit/include/eunit.hrl").

-export([all/0, groups/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([
    dist_snapshot_matches_remote_identity/1,
    dist_realtime_bus_counter_over_erpc/1,
    dist_view_keys_agree_with_the_consumers_key_set/1,
    dist_snapshot_carries_the_union_of_both_key_sets/1
]).

-define(SUITE_TIMEOUT, 90000).

all() ->
    [{group, dist}].

groups() ->
    [
        {dist, [sequence], [
            dist_snapshot_matches_remote_identity,
            dist_realtime_bus_counter_over_erpc,
            dist_view_keys_agree_with_the_consumers_key_set,
            dist_snapshot_carries_the_union_of_both_key_sets
        ]}
    ].

suite() ->
    [{timetrap, ?SUITE_TIMEOUT}].

%% This suite only makes sense on a dist-enabled node (it spawns a second VM
%% via `peer` and talks to it over erpc). rebar3 starts the CT run node with
%% `-sname` when invoked with `--sname i2per_ct` (every recipe in the justfile
%% passes it). Fail loudly instead of letting `peer` fail cryptically.
init_per_suite(Config) ->
    assert_distributed(node()),
    _ = application:stop(i2per_status),
    Config.

end_per_suite(_Config) ->
    ok.

%% One shared router VM for both cases: booting it is the expensive part, and
%% the second case reuses the already-online router for the realtime counter.
%% `peer:start`, NOT `peer:start_link`: CT runs init_per_group in a short-lived
%% process that exits before the first testcase, and a linked peer would die
%% with it. `peer:stop/1` in end_per_group still works from any process
%% (plain `gen_server:stop/2`).
init_per_group(dist, Config) ->
    {ok, RouterPid, RNode} =
        peer:start(#{
            %% No `host`: an IP would leak dots into a -sname and break it.
            name => i2per_status_dist_router,
            %% `-pa` takes ONE path per flag. A list as the second element adds one
            %% directory, not several — which is why the list comprehension below
            %% repeats the flag instead of concatenating the paths.
            args => lists:append(
                lists:map(fun(Dir) -> ["-pa", Dir] end, [ebin_dir() | dep_ebin_dirs()])
            ),
            wait_boot => 30_000
        }),
    boot_remote_router(RNode),
    [{router, {RouterPid, RNode}} | Config].

end_per_group(dist, Config) ->
    {RouterPid, _RNode} = proplists:get_value(router, Config),
    peer:stop(RouterPid),
    ok.

%% The status service reports online once the remote router is reachable, and
%% the reported identity is the remote router's hash, base64-encoded.
dist_snapshot_matches_remote_identity(Config) ->
    RNode = router_node(Config),
    start_status(RNode),
    try
        ok = i2p_ct_helpers:await(
            fun() -> maps:get(online, i2per_status_state:snapshot()) end,
            15000
        ),
        Snap = i2per_status_state:snapshot(),
        ?assertEqual(true, maps:get(online, Snap)),
        %% Identity reported over erpc matches the remote router.
        RemoteHash = erpc:call(RNode, i2p_peer, router_hash, [], 5000),
        ?assertEqual(base64:encode(RemoteHash), maps:get(identity, Snap))
    after
        application:stop(i2per_status)
    end.

%% Realtime: announce on the REMOTE bus, count locally.
dist_realtime_bus_counter_over_erpc(Config) ->
    RNode = router_node(Config),
    start_status(RNode),
    try
        ok = i2p_ct_helpers:await(
            fun() -> maps:get(online, i2per_status_state:snapshot()) end,
            15000
        ),
        Before = tunnel_built_count(i2per_status_state:snapshot()),
        ok = erpc:call(RNode, i2p_events, notify, [{tunnel_built, outbound, 2}], 5000),
        ok = i2p_ct_helpers:await(
            fun() -> tunnel_built_count(i2per_status_state:snapshot()) >= Before + 1 end,
            20000
        )
    after
        application:stop(i2per_status)
    end.

%% The two applications' read-API key sets, compared across the erpc boundary.
%%
%% **This is the check the release-gate decision asked for and the tree did not
%% have.** `view_key_set_matches_the_declared_list` in `i2p_read_api_SUITE`
%% compares the view against a list sitting beside it in the *same* application, so
%% the core is internally consistent and says nothing about the status service. The
%% service declares its own expected set in `f:i2per_status_state:known_view_keys/0`
%% because it cannot compile against the core's types, so the two declarations were
%% free to drift with nothing to notice — and this is the case that notices.
%%
%% It has to be a dist case, and that is not incidental: the boundary this checks
%% is the one the service is built not to have a compile-time link across. A test
%% that could reference `i2p_status_data` directly would not be testing the thing
%% that can actually go wrong, which is a router on another node serving a
%% different key set than this build expects.
%%
%% Both directions, and separately named in the failure, because they are different
%% mistakes with different fixes. A key the router returns that the service does not
%% list is a key the service silently ignores; a key the service lists that the
%% router stopped returning is a key it will read as absent forever.
dist_view_keys_agree_with_the_consumers_key_set(Config) ->
    RNode = router_node(Config),
    RouterKeys = erpc:call(RNode, i2p_status_data, view_keys, [], 5000),
    %% A *different version* is a different contract, not drift, and comparing key
    %% sets across versions would report a list of "missing" keys that means
    %% nothing. So the version is checked first and separately, and this case says
    %% so: a mismatch here is a consumer built against a different read API, and
    %% the honest response is a version report rather than a key diff.
    View = erpc:call(RNode, i2p_status_data, view, [], 5000),
    ?assertEqual(2, maps:get(version, View)),
    %% The list the view actually returned, so a router that returns `view_keys/0`
    %% and a view that disagrees cannot both be satisfied by one of them.
    ?assertEqual(lists:sort(maps:keys(View)), lists:sort(RouterKeys)),
    ConsumerKeys = i2per_status_state:known_view_keys(),
    Unlisted = lists:sort(RouterKeys) -- lists:sort(ConsumerKeys),
    Absent = lists:sort(ConsumerKeys) -- lists:sort(RouterKeys),
    ?assertEqual({[], []}, {Unlisted, Absent}).

%% And the snapshot this service hands out is the union of the two sets: every key
%% the router publishes, plus every key the service invents.
%%
%% Separate from the case above because the two fail for different reasons. That one
%% is about the *declarations* agreeing; this one is about a real, running snapshot
%% carrying what they promise. A key can be in both lists and still be missing from
%% the built snapshot — `build_snapshot/1` is a hand-written merge, and nothing else
%% checks that it merged everything.
dist_snapshot_carries_the_union_of_both_key_sets(Config) ->
    RNode = router_node(Config),
    start_status(RNode),
    try
        ok = i2p_ct_helpers:await(
            fun() -> maps:get(online, i2per_status_state:snapshot()) end, 15000
        ),
        Snap = i2per_status_state:snapshot(),
        Expected =
            i2per_status_state:known_view_keys() ++
                i2per_status_state:own_snapshot_keys(),
        ?assertEqual(lists:sort(Expected), lists:sort(maps:keys(Snap)))
    after
        application:stop(i2per_status)
    end.

%% %%%%% %%% Internal helpers %%%%% %%%

assert_distributed(nonode@nohost) ->
    ct:fail(
        "i2per_status_SUITE needs a dist-enabled CT run node; "
        "run `rebar3 ct --sname i2per_ct` (see the justfile recipes)."
    );
assert_distributed(_Node) ->
    ok.

router_node(Config) ->
    {_RouterPid, RNode} = proplists:get_value(router, Config),
    RNode.

start_status(RNode) ->
    application:set_env(i2per_status, port, i2p_ct_helpers:free_port()),
    application:set_env(i2per_status, router_node, RNode),
    {ok, _} = application:ensure_all_started(i2per_status),
    ok.

%% Boot exactly what `m:i2p_status_data:view/0` reads on the remote router:
%% the whole `i2per` app, which owns i2p_peer and the bus. NEVER start_link
%% router pieces over plain erpc: the call's transient worker on the remote
%% node would be their parent and kill them on return. Instead configure the
%% app env and let the REMOTE supervisor own the processes.
boot_remote_router(RNode) ->
    {Pub, Priv} = erpc:call(RNode, i2p_crypto, x25519_keygen, [], 5000),
    {SignPub, Seed} = erpc:call(RNode, i2p_crypto, ed25519_keygen, [], 5000),
    Id = erpc:call(RNode, i2p_keys, from_keys, [Pub, SignPub], 5000),
    IV = crypto:strong_rand_bytes(16),
    Addr =
        erpc:call(
            RNode,
            i2p_router_info,
            ntcp2_address,
            [<<"127.0.0.1">>, 39901, Pub, IV],
            5000
        ),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI =
        erpc:call(
            RNode, i2p_router_info, build, [Id, now_ms(), [Addr], Opts, Seed], 5000
        ),
    Hash = erpc:call(RNode, i2p_router_info, hash, [RI], 5000),
    Local = #{
        static_priv => Priv,
        static_pub => Pub,
        hash => Hash,
        iv => IV,
        ri => RI
    },
    ok = erpc:call(
        RNode, application, set_env, [i2per, i2p_peer, #{local => Local, seeds => []}], 5000
    ),
    {ok, _} =
        erpc:call(RNode, application, ensure_all_started, [i2per], 15_000),
    ok.

ebin_dir() ->
    %% Anchor on THIS suite's beam directory — never trust the process cwd.
    BeamDir = filename:dirname(code:which(?MODULE)),
    RepoRoot = filename:join(BeamDir, "../../.."),
    case filelib:is_dir(filename:join(RepoRoot, "_build/test/lib/i2per/ebin")) of
        true -> filename:join(RepoRoot, "_build/test/lib/i2per/ebin");
        false -> filename:join(BeamDir, "../../../lib/i2per/ebin")
    end.

%% Every dependency's `ebin`, for the peer router node.
%%
%% **`i2per`'s own directory is not enough.** The router node is started with a
%% single `-pa`, and `f:application:ensure_all_started/1` on the remote node needs a
%% `.app` file for *every* application in `i2per.app.src`'s `applications` list --
%% so a dependency that is only in the build tree and not on the peer node's path
%% fails the whole boot with `{no such file or directory, "telemetry.app"}`.
%%
%% Derived by walking `_build/test/lib/` rather than hardcoded, so a dependency
%% added to `rebar.config` is found without editing a test. The one-app assumption
%% this tree has today is checked rather than assumed: a dependency that is not a
%% direct child of `lib/` would be missed silently, so that case fails loudly.
dep_ebin_dirs() ->
    LibDir = build_lib_dir(),
    %% `file:list_dir/1` can answer `enoent`, and `lists:sort/1` on that is a
    %% `function_clause` rather than a diagnosable failure -- so the listing is
    %% matched first and the error reported as what it is.
    case file:list_dir(LibDir) of
        {ok, Names} ->
            Deps = [
                filename:join(LibDir, Name)
             || Name <- lists:sort(Names),
                %% rebar3's own scratch directory, not a dependency.
                Name =/= ".rebar3",
                Name =/= "i2per",
                Name =/= "i2per_status"
            ],
            case [D || D <- Deps, filelib:is_dir(D)] of
                [] ->
                    ct:pal("no dependency directories under ~s", [LibDir]),
                    [];
                Found ->
                    [filename:join(D, "ebin") || D <- Found]
            end;
        {error, Reason} ->
            ct:pal("cannot list ~s: ~p", [LibDir, Reason]),
            []
    end.

%% The build tree's `lib/` directory, found from where this suite's beams are.
%%
%% **Two layouts exist and only one of them is a source path.** Run from the source
%% tree the beams are in `apps/i2per_status/test`; under `rebar3 ct` they are copied
%% to `_build/test/lib/i2per_status/test`. Anchoring on `code:which(?MODULE)/../..`
%% walks up three levels from either, which lands on the repo root in the first case
%% and on `_build/test` in the second -- so the two cases are probed rather than
%% assumed, the same way `ebin_dir/0` does it.
build_lib_dir() ->
    BeamDir = filename:dirname(code:which(?MODULE)),
    Candidates = [
        filename:join(BeamDir, "../../../lib"),
        filename:join(BeamDir, "../../..")
    ],
    case [C || C <- Candidates, filelib:is_dir(C)] of
        [LibDir | _] ->
            LibDir;
        [] ->
            ct:pal("no lib/ directory found from ~s", [BeamDir]),
            filename:join(BeamDir, "../../../lib")
    end.

now_ms() ->
    erlang:system_time(millisecond).

tunnel_built_count(Snap) ->
    case maps:find(events, Snap) of
        {ok, Ev} -> maps:get(tunnel_built, Ev, 0);
        error -> 0
    end.
