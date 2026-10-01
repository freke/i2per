%% NetDb service tests. The suite exercises store, find, capacity, closest-peer
%% selection, persistence across a restart, expiry sweeps, and the stats map
%% against a standalone `i2p_netdb_srv`. The service is acquired or reused
%% safely and explicitly shut down after each case.

-module(i2p_netdb_srv_SUITE).

-include_lib("kernel/include/file.hrl").

-export([all/0, suite/0, init_per_testcase/2]).

-export([
    netdb_srv_roundtrip/1,
    netdb_srv_persistence_roundtrip/1,
    netdb_srv_timers_do_not_multiply/1,
    netdb_srv_corrupt_state_fails_closed/1,
    netdb_srv_load_error_blocks_rewrite/1,
    netdb_srv_remove_expired/1,
    netdb_srv_configured_expiration_is_honoured/1,
    netdb_srv_stats/1
]).

%% Run against a standalone srv: stop any i2per app a previous suite left
%% running (it owns the same registered name), so every case exercises the
%% acquire-or-reuse start branch and the persistence case can kill+restart
%% without the app supervisor racing the restart.
init_per_testcase(_Case, Config) ->
    _ = application:stop(i2per),
    Config.

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        netdb_srv_roundtrip,
        netdb_srv_persistence_roundtrip,
        netdb_srv_timers_do_not_multiply,
        netdb_srv_corrupt_state_fails_closed,
        netdb_srv_load_error_blocks_rewrite,
        netdb_srv_remove_expired,
        netdb_srv_configured_expiration_is_honoured,
        netdb_srv_stats
    ].

netdb_srv_roundtrip(_Config) ->
    %% Acquire-or-reuse: the i2per app may already be running (started by an
    %% earlier suite), which registers a global `i2p_netdb_srv'. If so, use
    %% the existing process; only tear down an instance we started.
    Pid =
        case whereis(i2p_netdb_srv) of
            undefined ->
                {ok, P} = i2p_netdb_srv:start_link(),
                P;
            Existing ->
                Existing
        end,
    try
        Now = now_ms(),
        {FF, _} = fixture_floodfill(Now),
        FFKey = i2p_router_info:hash(FF),
        {RI, _} = fixture_router(Now),
        Key = i2p_router_info:hash(RI),
        added = i2p_netdb_srv:store(RI, Now),
        {ok, RI} = i2p_netdb_srv:find(Key),
        not_found = i2p_netdb_srv:find(rand_hash()),
        1 = i2p_netdb_srv:count(),
        5000 = i2p_netdb_srv:capacity(),
        [Key] = i2p_netdb_srv:keys(),
        [RI] = i2p_netdb_srv:routers(),
        [Key] = i2p_netdb_srv:closest(Key, 3),
        [] = i2p_netdb_srv:closest_floodfills(Key, 3, []),
        [Key] = i2p_netdb_srv:closest_non_floodfills(Key, 3, []),
        added = i2p_netdb_srv:store(FF, Now),
        [FFKey] = i2p_netdb_srv:closest_floodfills(FFKey, 3, []),
        %% **Read the store after a lookup, not only before.** All three of the
        %% lookups above write their memoised store back into the process state, and
        %% a case that never reads the store again cannot tell that from one where
        %% the reply and the store were swapped — a list is a perfectly good reply
        %% and a perfectly bad store, so the mistake stays silent until something
        %% reads a field. The `count/0` and `keys/0` calls below are that read, and
        %% they are the reason this case is more than a smoke test.
        [Key] = i2p_netdb_srv:closest_non_floodfills(rand_hash(), 3, []),
        Bin = i2p_router_info:to_binary(RI),
        {ok, older} = i2p_netdb_srv:store_binary(Bin, Now),
        removed = i2p_netdb_srv:remove(Key),
        1 = i2p_netdb_srv:count(),
        %% LeaseSet operations through the same process
        NowSec = now_sec(),
        {LS, _} = fixture_ls(NowSec),
        LSKey = i2p_leaset:hash(LS),
        added = i2p_netdb_srv:store_ls(LS, NowSec),
        {ok, LS} = i2p_netdb_srv:find_ls(LSKey),
        not_found = i2p_netdb_srv:find_ls(rand_hash()),
        1 = i2p_netdb_srv:ls_count(),
        [LSKey] = i2p_netdb_srv:ls_keys(),
        {ok, older} = i2p_netdb_srv:store_ls_binary(i2p_leaset:to_binary(LS), NowSec)
    after
        %% If we started the process, tear it down; if the app supervisor
        %% owns it, exit triggers a restart with a fresh store — which is
        %% the desired state for subsequent tests.
        case whereis(i2p_netdb_srv) of
            Pid ->
                unlink(Pid),
                exit(Pid, shutdown);
            _ ->
                ok
        end
    end.

netdb_srv_persistence_roundtrip(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    try
        application:set_env(i2per, data_dir, Dir),
        %% start a fresh srv
        Pid =
            case whereis(i2p_netdb_srv) of
                undefined ->
                    {ok, P} = i2p_netdb_srv:start_link(),
                    P;
                Existing ->
                    Existing
            end,
        try
            Now = now_ms(),
            {RI, _} = fixture_router(Now),
            Key = i2p_router_info:hash(RI),
            added = i2p_netdb_srv:store(RI, Now),
            {ok, RI} = i2p_netdb_srv:find(Key),
            %% save to disk
            ok = i2p_netdb_srv:save(),
            {ok, Info} = file:read_file_info(filename:join(Dir, "netdb.bin")),
            8#600 = Info#file_info.mode band 8#777,
            %% kill and restart
            kill_and_wait(Pid),
            {ok, Pid2} = i2p_netdb_srv:start_link(),
            try
                %% data survives restart
                {ok, RI} = i2p_netdb_srv:find(Key),
                1 = i2p_netdb_srv:count(),
                Stats = i2p_netdb_srv:stats(),
                1 = maps:get(loads, Stats)
            after
                unlink(Pid2),
                exit(Pid2, shutdown)
            end
        after
            application:unset_env(i2per, data_dir),
            case whereis(i2p_netdb_srv) of
                undefined ->
                    ok;
                P3 ->
                    kill_and_wait(P3)
            end
        end
    after
        ok
    end.

netdb_srv_timers_do_not_multiply(_Config) ->
    application:set_env(i2per, netdb_autosave_ms, 20),
    application:set_env(i2per, netdb_expiry_ms, 1000000),
    {ok, Pid} = i2p_netdb_srv:start_link(),
    try
        ok = i2p_ct_helpers:await(
            fun() -> maps:get(saves, i2p_netdb_srv:stats()) >= 3 end,
            1000
        ),
        #{autosave := 1, expiry_sweep := 1} = i2p_netdb_srv:timer_counts()
    after
        unlink(Pid),
        exit(Pid, shutdown),
        application:unset_env(i2per, netdb_autosave_ms),
        application:unset_env(i2per, netdb_expiry_ms)
    end.

netdb_srv_corrupt_state_fails_closed(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Path = filename:join(Dir, "netdb.bin"),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, <<"not-a-netdb">>),
    application:set_env(i2per, data_dir, Dir),
    OldTrap = process_flag(trap_exit, true),
    try
        case i2p_netdb_srv:start_link() of
            {error, {netdb_load_failed, parse_error}} -> ok;
            Other -> erlang:error({unexpected_start_result, Other})
        end,
        {ok, <<"not-a-netdb">>} = file:read_file(Path)
    after
        process_flag(trap_exit, OldTrap),
        application:unset_env(i2per, data_dir),
        ok
    end.

netdb_srv_load_error_blocks_rewrite(Config) ->
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    Path = filename:join(Dir, "netdb.bin"),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, <<"not-a-netdb">>),
    {ok, Pid} = i2p_netdb_srv:start_link(),
    try
        application:set_env(i2per, data_dir, Dir),
        {error, parse_error} = i2p_netdb_srv:load(),
        {error, load_failed} = i2p_netdb_srv:save(),
        {ok, <<"not-a-netdb">>} = file:read_file(Path)
    after
        application:unset_env(i2per, data_dir),
        unlink(Pid),
        exit(Pid, shutdown)
    end.

netdb_srv_remove_expired(_Config) ->
    Pid =
        case whereis(i2p_netdb_srv) of
            undefined ->
                {ok, P} = i2p_netdb_srv:start_link(),
                P;
            Existing ->
                Existing
        end,
    try
        Now = now_ms(),
        {Fresh, _} = fixture_router(Now),
        added = i2p_netdb_srv:store(Fresh, Now),
        1 = i2p_netdb_srv:count(),
        %% no expiry yet: store is young
        {RRem1, _} = i2p_netdb_srv:remove_expired(),
        0 = RRem1,
        1 = i2p_netdb_srv:count(),
        Stats = i2p_netdb_srv:stats(),
        1 = maps:get(expired_sweeps, Stats),
        0 = maps:get(routers_expired, Stats)
    after
        case whereis(i2p_netdb_srv) of
            Pid ->
                unlink(Pid),
                exit(Pid, shutdown);
            _ ->
                ok
        end
    end.

%% The configured horizon reaches the store, and both the admission check and the
%% sweep honour it.
%%
%% The srv is where the configuration is read, so this is the case that says the
%% key in `sys.config` does something. `#RA5PVR1` is about making the *policy*
%% sliding; this is the part that already landed, namely that an operator can reach
%% the horizon at all.
%%
%% Structurally rather than by deadline: set a one-minute horizon, store a
%% RouterInfo published three minutes ago (admissible at the default 27-hour horizon,
%% and inside one minute at the configured one, so it has to be refused at the door),
%% then sweep and confirm nothing had to be removed.
netdb_srv_configured_expiration_is_honoured(_Config) ->
    application:set_env(i2per, netdb_expiration_ms, 60 * 1000),
    Pid =
        case whereis(i2p_netdb_srv) of
            undefined ->
                {ok, P} = i2p_netdb_srv:start_link(),
                P;
            Existing ->
                Existing
        end,
    try
        %% The store carries the configured value, not the module default.
        60000 = maps:get(expiration_ms, i2p_netdb_srv:stats()),

        Now = now_ms(),
        {RI, _} = fixture_router(Now - 3 * 60 * 1000),
        Key = i2p_router_info:hash(RI),
        %% Refused by the configured horizon, not admitted and then swept.
        too_old = i2p_netdb_srv:store(RI, Now),
        not_found = i2p_netdb_srv:find(Key),
        0 = i2p_netdb_srv:count(),

        %% And a fresh one is still accepted, so the horizon did not break the store.
        {Fresh, _} = fixture_router(Now),
        added = i2p_netdb_srv:store(Fresh, Now),
        1 = i2p_netdb_srv:count(),
        {0, _} = i2p_netdb_srv:remove_expired(),
        1 = i2p_netdb_srv:count()
    after
        application:unset_env(i2per, netdb_expiration_ms),
        case whereis(i2p_netdb_srv) of
            Pid ->
                unlink(Pid),
                exit(Pid, shutdown);
            _ ->
                ok
        end
    end.

netdb_srv_stats(_Config) ->
    Pid =
        case whereis(i2p_netdb_srv) of
            undefined ->
                {ok, P} = i2p_netdb_srv:start_link(),
                P;
            Existing ->
                Existing
        end,
    try
        Stats = i2p_netdb_srv:stats(),
        true = maps:is_key(expiration_ms, Stats),
        true = maps:is_key(routers, Stats),
        true = maps:is_key(lease_sets, Stats),
        true = maps:is_key(capacity, Stats),
        true = maps:is_key(saves, Stats),
        true = maps:is_key(loads, Stats),
        true = maps:is_key(expired_sweeps, Stats),
        true = maps:is_key(routers_expired, Stats),
        true = maps:is_key(ls_expired, Stats)
    after
        case whereis(i2p_netdb_srv) of
            Pid ->
                unlink(Pid),
                exit(Pid, shutdown);
            _ ->
                ok
        end
    end.

%% Kill a process and wait for its DOWN before returning, so a subsequent
%% start_link / acquire-or-reuse can't race the dying process's unregister.
kill_and_wait(Pid) ->
    Ref = erlang:monitor(process, Pid),
    unlink(Pid),
    exit(Pid, shutdown),
    receive
        {'DOWN', Ref, process, Pid, _} ->
            ok
    after 2000 ->
        erlang:error({kill_timeout, Pid})
    end.

%% --------------------------------------------------------------------------
%% Fixtures
%% --------------------------------------------------------------------------

now_ms() ->
    erlang:system_time(millisecond).

now_sec() ->
    erlang:system_time(second).

rand_hash() ->
    rand_hash(32).

rand_hash(N) ->
    crypto:strong_rand_bytes(N).

%% {RouterInfo, SeedKey} where SeedKey = {{SPub, Seed}, {CPub, _}} lets tests
%% rebuild the same identity with a different timestamp/version/caps.
fixture_router(Timestamp) ->
    SeedKey = new_seed_key(),
    {build_from(SeedKey, Timestamp, <<"0.9.74">>, <<"4">>, <<"192.0.2.10">>), SeedKey}.

fixture_floodfill(Timestamp) ->
    SeedKey = new_seed_key(),
    {build_from(SeedKey, Timestamp, <<"0.9.74">>, <<"Of">>, <<"192.0.2.10">>), SeedKey}.

new_seed_key() ->
    {{SPub, Seed}, {CPub, _}} = {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    {{SPub, Seed}, {CPub, rand_hash()}}.

build_from(SeedKey, Timestamp, Version, Caps, Host) ->
    {{SPub, Seed}, {CPub, _}} = SeedKey,
    Identity = i2p_keys:from_keys(CPub, SPub),
    Addr = i2p_router_info:ntcp2_address(Host, 4668, rand_hash(), rand_hash(16)),
    Opts = maps:merge(
        #{<<"netId">> => <<"2">>, <<"router.version">> => Version},
        caps_map(Caps)
    ),
    i2p_router_info:build(Identity, Timestamp, [Addr], Opts, Seed).

%% {LeaseSet, SeedKey} — the SeedKey signs the same destination identity, so a
%% rebuilt LeaseSet keeps the same hash.
fixture_ls(TimestampSec) ->
    SeedKey = new_seed_key(),
    build_ls(SeedKey, TimestampSec).

build_ls(SeedKey, TimestampSec) ->
    {{SPub, Seed}, {CPub, _}} = SeedKey,
    Identity = i2p_keys:from_keys(CPub, SPub),
    Lease = #{
        gateway => rand_hash(),
        tunnel_id => 1,
        end_date => (now_ms() + 60 * 1000) band 16#FFFFFFFF
    },
    {i2p_leaset:build(Identity, TimestampSec, 7, [Lease], Seed), SeedKey}.

caps_map(Caps) ->
    #{<<"caps">> => Caps}.
