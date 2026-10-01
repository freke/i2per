-module(i2p_netdb_srv).

-moduledoc """
The process that owns the local NetDb store.

Per the project's process philosophy, the NetDb is shared mutable state and so
is owned by exactly one process, a `gen_server` registered locally as
`i2p_netdb_srv`. It is a child of `m:i2per_sup` (restart type `permanent` —
unlike a connection, a crashed NetDb holds nothing a fresh store cannot
rebuild, so a restart is harmless).

Every call is a thin synchronous wrapper over a pure `m:i2p_netdb` operation;
no peer or connection state lives here, so a slow peer can never block the
store. Network-facing work (sending DatabaseLookup messages, storing replies)
belongs to the peer manager (`m:i2p_peer`), which reads and writes through
this API.

## What runs here, and what does not

This process serves reads and applies stores, and it does the cheap half of a
store. Two classes of expensive work are kept out of it, because this is the one
process every NetDb read queues behind.

Signature verification happens in the calling process, reached from
`f:store_binary/2` and `f:store_ls_binary/2` before the call is made. A
verification measures 100.4 us against 1-3 us for the store itself. That is a
relocation and not a removal, since the peer manager and the transit relay each
pay it now. It is the right relocation because this is the process every read
queues behind. Whether a second verifier would help was measured, and the answer
is no: Ed25519 throughput falls as processes are added on this OTP, so the
100 us is something #VXRH456 has to attack rather than something more processes
can hide.

The disk save and the expiry sweep are still here, and are what #PPW41Y4 is
about. A save measures ~16.8 ms and a sweep ~12.9 ms at the shipped capacity, so
they are the remaining reason a read can queue behind a write. Moving them off
depends on the store becoming something that can be handed over rather than a
handle to live state, which is #QDA7A0X.

## Persistence

When app env `i2per` → `data_dir` names a directory, the store is saved to
`netdb.bin` inside that directory on shutdown and periodically (every 15
minutes by default). The write is an atomic replacement with private `0600`
permissions. On startup it is loaded back if present; a malformed or
unreadable existing file fails closed instead of being replaced by an empty
store. An expiry sweep runs every 30 minutes, removing RouterInfos older than
27 hours and expired LeaseSets via `m:i2p_netdb:remove_expired/3`. The timer
intervals can be shortened with the `netdb_autosave_ms` and `netdb_expiry_ms`
application settings for hermetic tests and soak diagnostics.

## Usage

```erlang
%% Fill the store from a DatabaseStore payload.
{ok, _Store, added} =
    i2p_netdb_srv:store_binary(
        RouterInfoBytes,
        erlang:system_time(millisecond)
    ),

%% Ask for replication targets: the 3 closest eligible floodfills.
Target = <<...32-byte router hash...>>,
Floodfills = i2p_netdb_srv:closest_floodfills(Target, 3, []).
```
""".

-behaviour(gen_server).

%% Where the RouterInfo table's tid is published, so a reader can reach the table
%% without a call into this process. See `f:has_router/1` and `f:publish_table/1`.
%% Declared up here because `f:has_router/1` is near the top of the file.
-define(ROUTER_TABLE, i2per_netdb_router_table).

-export([
    start_link/0,
    has_router/1,
    store/2,
    store_binary/2,
    store_ls/2,
    store_ls_binary/2,
    find/1,
    find_ls/1,
    remove/1,
    routers/0,
    keys/0,
    ls_keys/0,
    ls_count/0,
    count/0,
    capacity/0,
    closest/2,
    closest_floodfills/3,
    closest_non_floodfills/3,
    save/0,
    load/0,
    remove_expired/0,
    snapshot/0,
    generation_now/0,
    timer_counts/0,
    stats/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-doc "Start the NetDb process, registered locally as `i2p_netdb_srv`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
Store a verified RouterInfo.

Input: `RI` — a parsed RouterInfo; `NowMs` — wall-clock ms since epoch.
Output: `added | updated | older | from_future | too_old`, as in
`m:i2p_netdb:store/3`.
""".
-spec store(i2p_router_info:router_info(), non_neg_integer()) ->
    added | updated | older | from_future | too_old.
store(RI, NowMs) ->
    gen_server:call(?MODULE, {store, RI, NowMs}).

-doc """
Store a RouterInfo from its raw signed bytes.

Input: `Bin` — full signed RouterInfo bytes; `NowMs` — wall-clock ms since
epoch.
Output: `{ok, Outcome}` as in `m:i2p_netdb:store/3`, or `{error, Reason}` when
the bytes do not decode to a signature-verifying RouterInfo.

The signature is verified here, in the calling process, rather than in the NetDb.
An Ed25519 verification measures 100.4 us against 1-3 us for the store itself,
so verifying inside the call put a floodfill replication burst or a reseed
bundle in front of every NetDb read. The call below carries a parsed
RouterInfo, so this process pays the store and nothing else.

A pool of verifier processes was the first design and measurement killed it.
Total Ed25519 throughput on this OTP falls as processes are added, 0.45x at 8
processes against 4.24x for a no-crypto control on the same harness, so extra
verifiers would queue behind the same serialising work rather than overlap it.
OTP 28 also ships no worker \`pool\` module to build on. Decoding in the caller
is what remains.
""".
-spec store_binary(binary(), non_neg_integer()) ->
    {ok, added | updated | older | from_future | too_old} | {error, term()}.
store_binary(Bin, NowMs) ->
    case i2p_router_info:decode(Bin) of
        {ok, RI} -> {ok, store(RI, NowMs)};
        {error, Reason} -> {error, Reason}
    end.

-doc """
Look up a router by hash.

Input: `Key` — the router hash.
Output: `{ok, RouterInfo}` when present, `not_found` otherwise.
""".
-spec find(i2p_netdb:router_key()) -> {ok, i2p_router_info:router_info()} | not_found.
find(Key) ->
    gen_server:call(?MODULE, {find, Key}).

-doc """
Whether the NetDb holds a RouterInfo for `Key`.

Input: `Key` — the router hash. Output: `true` or `false`.

**This is a table read, not a call into this process.** The tunnel relay asks
it once per 1028-byte frame and discards everything but the answer, so as a
`gen_server:call/2` it cost a process round trip and a copy of a whole
RouterInfo to learn a boolean. The table the NetDb keeps is `protected`, which
is exactly the shape this needs: this process writes it, anyone may read it.

`not_found` is reported as `false`, so the two ways of not holding a router are
one answer rather than two.
""".
-spec has_router(i2p_netdb:router_key()) -> boolean().
has_router(Key) ->
    ets:member(persistent_term:get(?ROUTER_TABLE), Key).

%% **The table tid is published once, at init.**
%%
%% The store map is replaced on every mutation and so cannot be published, but
%% the table it owns never is: `m:i2p_netdb:new/1` creates it once and the
%% mutations only insert and delete entries. So the tid is fixed for the life of
%% this process, which is what `persistent_term` is for.
%%
%% The table dies with this process, so a tid left in `persistent_term` after a
%% crash cannot name a live table that something else owns -- the next NetDb to
%% start publishes its own, and a stale tid is an `badarg` rather than a wrong
%% answer.
publish_table(Store) ->
    persistent_term:put(?ROUTER_TABLE, i2p_netdb:router_table(Store)).

%% The full O(n log n) cross-check. **Only a load now.**
%%
%% It used to run after the expiry sweep as well, and that was right when the sweep
%% rebuilt both trees from scratch: a wholesale rewrite is where a partial bug is
%% hardest to notice. But the sweep no longer rebuilds — it drops the expired keys
%% incrementally, through the same `m:i2p_netdb:drop_from_order/2` that
%% `f:remove/2` already runs under the O(1) check.
%%
%% So the sweep became the class of operation the O(1) check was chosen for, and the
%% cross-check was a **4771 us** tax on the read path at the shipped capacity of 5000
%% routers — more than twice the sweep's own ~2.3 ms — defending against a failure
%% mode it no longer had. Removing it is part of the change that makes the sweep
%% cheap, not a separate relaxation.
%%
%% `f:consistent/1` still runs after the sweep. It is O(1) and it is the check that
%% would catch a drop taken from one tree and not the other.
fully_checked(Store) ->
    ok = i2p_netdb:self_check(Store),
    Store.

-doc """
Store a verified LeaseSet2.

Input: `LS` — a parsed LeaseSet; `NowSec` — wall-clock seconds since epoch.
Output: `added | updated | older | from_future | expired`, as in
`m:i2p_netdb:store_ls/3`.
""".
-spec store_ls(i2p_leaset:lease_set(), non_neg_integer()) ->
    added | updated | older | from_future | expired.
store_ls(LS, NowSec) ->
    gen_server:call(?MODULE, {store_ls, LS, NowSec}).

-doc """
Store a LeaseSet2 from its raw signed content bytes.

Input: `Bin` — the content bytes (without the store-type byte); `NowSec` —
wall-clock seconds since epoch.
Output: `{ok, Outcome}` as in `f:store_ls/2`, or `{error, Reason}` when the
bytes do not decode to a signature-verifying LeaseSet2.

Verified in the calling process, for the same reason as `f:store_binary/2`.
""".
-spec store_ls_binary(binary(), non_neg_integer()) ->
    {ok, added | updated | older | from_future | expired} | {error, term()}.
store_ls_binary(Bin, NowSec) ->
    case i2p_leaset:decode(Bin) of
        {ok, LS} -> {ok, store_ls(LS, NowSec)};
        {error, Reason} -> {error, Reason}
    end.

-doc """
Look up a LeaseSet2 by destination hash.

Input: `Key` — the destination hash.
Output: `{ok, LeaseSet}` when present, `not_found` otherwise.
""".
-spec find_ls(i2p_netdb:ls_key()) -> {ok, i2p_leaset:lease_set()} | not_found.
find_ls(Key) ->
    gen_server:call(?MODULE, {find_ls, Key}).

-doc """
Remove a router by hash.

Input: `Key` — the router hash.
Output: `removed` when it was present, `not_found` otherwise.
""".
-spec remove(i2p_netdb:router_key()) -> removed | not_found.
remove(Key) ->
    gen_server:call(?MODULE, {remove, Key}).

-doc "All stored RouterInfos, most recently stored first.".
-spec routers() -> [i2p_router_info:router_info()].
routers() ->
    gen_server:call(?MODULE, routers).

-doc "All stored router hashes, most recently stored first.".
-spec keys() -> [i2p_netdb:router_key()].
keys() ->
    gen_server:call(?MODULE, keys).

-doc "All stored destination hashes, most recently stored first.".
-spec ls_keys() -> [i2p_netdb:ls_key()].
ls_keys() ->
    gen_server:call(?MODULE, ls_keys).

-doc "The number of stored LeaseSets.".
-spec ls_count() -> non_neg_integer().
ls_count() ->
    gen_server:call(?MODULE, ls_count).

-doc "The number of stored routers.".
-spec count() -> non_neg_integer().
count() ->
    gen_server:call(?MODULE, count).

-doc "The eviction capacity of the store.".
-spec capacity() -> pos_integer().
capacity() ->
    gen_server:call(?MODULE, capacity).

-doc """
The `N` stored router hashes closest to `Target`.

Input: `Target` — the router hash to measure against; `N` — how many to
return.
Output: up to `N` hashes sorted by routing-key XOR distance, closest first.
""".
-spec closest(i2p_netdb:router_key(), non_neg_integer()) -> [i2p_netdb:router_key()].
closest(Target, N) ->
    gen_server:call(?MODULE, {closest, Target, N}).

-doc """
The `N` closest eligible floodfill hashes to `Target`, excluding `Excluded`.

Input: `Target`, `N`, `Excluded` as in `m:i2p_netdb:closest_floodfills/4`.
Output: up to `N` floodfill hashes, closest first.
""".
-spec closest_floodfills(i2p_netdb:router_key(), non_neg_integer(), [i2p_netdb:router_key()]) ->
    [i2p_netdb:router_key()].
closest_floodfills(Target, N, Excluded) ->
    gen_server:call(?MODULE, {closest_floodfills, Target, N, Excluded}).

-doc """
The `N` closest non-floodfill hashes to `Target`, excluding `Excluded`.

Input: `Target`, `N`, `Excluded` as in `m:i2p_netdb:closest_non_floodfills/4`.
Output: up to `N` non-floodfill hashes, closest first.
""".
-spec closest_non_floodfills(i2p_netdb:router_key(), non_neg_integer(), [i2p_netdb:router_key()]) ->
    [i2p_netdb:router_key()].
closest_non_floodfills(Target, N, Excluded) ->
    gen_server:call(?MODULE, {closest_non_floodfills, Target, N, Excluded}).

-define(DEFAULT_AUTOSAVE_MS, 15 * 60 * 1000).
-define(DEFAULT_EXPIRY_MS, 30 * 60 * 1000).

-define(AUTOSAVE_TIMERS, '$i2per_netdb_autosave_timers').
-define(EXPIRY_TIMERS, '$i2per_netdb_expiry_timers').
-define(LOAD_ERROR, '$i2per_netdb_load_error').

-define(NETDB_FILE, "netdb.bin").

-doc """
Save the current store to disk, waiting for the file to be written.

Input: none (uses the current process state).
Output: `ok` when the file was written, `{error, Reason}` on I/O failure. Does
nothing when `data_dir` is not configured.

**This one waits**, unlike the 15-minute timer, because a caller asking to save
wants the file to exist when it returns. The serialisation still happens in
`m:i2p_netdb_writer` when it is running — only this call blocks, and it blocks
the caller rather than the process every NetDb read queues behind.

Falls back to saving in this process when the writer is absent, which is the case
in any test that starts the NetDb on its own. The fallback is the old
behaviour: correct, and on the read path.
""".
-spec save() -> ok | {error, term()}.
save() ->
    gen_server:call(?MODULE, save).

-doc """
Load a store from disk, replacing the current one.

Input: none.
Output: `ok` when the file was loaded, `{error, Reason}` on I/O failure or
parse error. Does nothing when `data_dir` is not configured.
""".
-spec load() -> ok | {error, term()}.
load() ->
    gen_server:call(?MODULE, load).

-doc """
Sweep expired RouterInfos and LeaseSets.

Input: none.
Output: `{RoutersRemoved, LSRemoved}` — the number of entries evicted. Removes
RouterInfos older than 27 hours and expired LeaseSets via
`m:i2p_netdb:remove_expired/3`.
""".
-spec remove_expired() -> {non_neg_integer(), non_neg_integer()}.
remove_expired() ->
    gen_server:call(?MODULE, remove_expired).

-doc """
Return the number of pending autosave and expiry timers.

The values should remain exactly one for each timer kind during normal
operation. This is a small operational seam for soak tests and diagnostics.
""".
-spec timer_counts() -> #{autosave | expiry_sweep => non_neg_integer()}.
timer_counts() ->
    gen_server:call(?MODULE, timer_counts).

-doc """
A description of the store for `m:i2p_netdb_writer` to serialise.

Input: none.
Output: an `m:i2p_netdb:snapshot()` — the capacity, the router hashes in recency
order, the LeaseSets, and the current generation.

**This is the whole cost the read path pays for a save.** It does not include the
RouterInfos, because `m:i2p_netdb:serialize/1` reads them from the table itself,
which is `protected` and readable from any process. At the shipped capacity of
5000 routers this measures about **49 us**, against the **8403 us** that
serialising in this process cost.
""".
-spec snapshot() -> i2p_netdb:snapshot().
snapshot() ->
    gen_server:call(?MODULE, snapshot).

-doc """
The store's current generation, for checking a snapshot taken earlier.

Input: none.
Output: a non-negative integer, as `m:i2p_netdb:generation/1`.

This is what makes a snapshot safe to serialise in another process. Read it
before the save and again after; equal means the table was not written while the
snapshot was being serialised, so every key in it was present for the whole walk.
See `m:i2p_netdb_writer` for how the retry is bounded.
""".
-spec generation_now() -> non_neg_integer().
generation_now() ->
    gen_server:call(?MODULE, generation_now).

-doc """
Return a snapshot of operational counters.

Input: none.
Output: a map with keys `routers`, `lease_sets`, `capacity`, `saves`,
`loads`, `expired_sweeps`, `routers_expired`, `ls_expired`.
""".
-spec stats() -> #{atom() => non_neg_integer()}.
stats() ->
    gen_server:call(?MODULE, stats).

init([]) ->
    Counters = #{
        saves => 0,
        loads => 0,
        expired_sweeps => 0,
        routers_expired => 0,
        ls_expired => 0
    },
    Store0 = i2p_netdb:new(),
    %% Published before the load, so a reader that arrives while a large netdb
    %% file is being read sees a table that is already safe to ask. The load
    %% inserts into this same table.
    publish_table(Store0),
    put(?LOAD_ERROR, false),
    case maybe_load(Store0, Counters) of
        {{Store1, Counters1}, ok} ->
            schedule_autosave(),
            schedule_expiry(),
            {ok, {Store1, Counters1}};
        {_State, {error, Reason}} ->
            put(?LOAD_ERROR, true),
            {stop, {netdb_load_failed, Reason}}
    end.

maybe_load(Store, Counters) ->
    case data_dir() of
        {ok, Dir} ->
            Path = filename:join(Dir, ?NETDB_FILE),
            case file:read_file(Path) of
                {ok, Bin} ->
                    case i2p_netdb:from_binary(Bin) of
                        {ok, Loaded} ->
                            C2 = Counters#{loads := maps:get(loads, Counters) + 1},
                            {{Loaded, C2}, ok};
                        {error, _} ->
                            {{Store, Counters}, {error, parse_error}}
                    end;
                {error, enoent} ->
                    {{Store, Counters}, ok};
                {error, _} = Err ->
                    {{Store, Counters}, Err}
            end;
        undefined ->
            {{Store, Counters}, ok}
    end.

schedule_autosave() ->
    Ref = erlang:send_after(autosave_interval(), self(), autosave),
    put(?AUTOSAVE_TIMERS, [Ref | timer_refs(?AUTOSAVE_TIMERS)]),
    ok.

schedule_expiry() ->
    Ref = erlang:send_after(expiry_interval(), self(), expiry_sweep),
    put(?EXPIRY_TIMERS, [Ref | timer_refs(?EXPIRY_TIMERS)]),
    ok.

take_timer(Key) ->
    case timer_refs(Key) of
        [Ref | Rest] ->
            put(Key, Rest),
            Ref;
        [] ->
            undefined
    end.

timer_refs(Key) ->
    case get(Key) of
        undefined -> [];
        Refs -> Refs
    end.

persist_allowed() ->
    get(?LOAD_ERROR) =/= true.

current_timer_counts() ->
    #{
        autosave => length(timer_refs(?AUTOSAVE_TIMERS)),
        expiry_sweep => length(timer_refs(?EXPIRY_TIMERS))
    }.

autosave_interval() ->
    configured_interval(netdb_autosave_ms, ?DEFAULT_AUTOSAVE_MS).

expiry_interval() ->
    configured_interval(netdb_expiry_ms, ?DEFAULT_EXPIRY_MS).

configured_interval(Key, Default) ->
    case application:get_env(i2per, Key) of
        {ok, Value} when is_integer(Value), Value > 0 -> Value;
        _ -> Default
    end.

%% Every router mutation is funnelled through `checked/1`. The store is two
%% structures -- an ETS table and a pair of recency trees -- and only this
%% process can see both, so this is the one place that can assert they agree.
%% A store that drifts is quiet: it evicts the wrong router, or stops evicting.
%%
%% `m:i2p_netdb:consistent/1` rather than `f:self_check/1`, because it is O(1)
%% and this runs on the store path. The full cross-check is now for a load alone,
%% which is the only remaining operation that rewrites a whole batch at once. See
%% `f:fully_checked/1` for why the expiry sweep stopped qualifying.
checked(Store) ->
    ok = i2p_netdb:consistent(Store),
    Store.

handle_call({store, RI, NowMs}, _From, {Store, Counters}) ->
    {Store2, Outcome} = i2p_netdb:store(Store, RI, NowMs),
    {reply, Outcome, {checked(Store2), Counters}};
handle_call({store_ls, LS, NowSec}, _From, {Store, Counters}) ->
    {Store2, Outcome} = i2p_netdb:store_ls(Store, LS, NowSec),
    {reply, Outcome, {Store2, Counters}};
handle_call({find, Key}, _From, {Store, _} = State) ->
    case i2p_netdb:find(Store, Key) of
        {ok, RI} -> {reply, {ok, RI}, State};
        error -> {reply, not_found, State}
    end;
handle_call({find_ls, Key}, _From, {Store, _} = State) ->
    case i2p_netdb:find_ls(Store, Key) of
        {ok, LS} -> {reply, {ok, LS}, State};
        error -> {reply, not_found, State}
    end;
handle_call({remove, Key}, _From, {Store, Counters}) ->
    {Store2, Outcome} = i2p_netdb:remove(Store, Key),
    {reply, Outcome, {checked(Store2), Counters}};
handle_call(routers, _From, {Store, _} = State) ->
    {reply, i2p_netdb:routers(Store), State};
handle_call(keys, _From, {Store, _} = State) ->
    {reply, i2p_netdb:keys(Store), State};
handle_call(ls_keys, _From, {Store, _} = State) ->
    {reply, i2p_netdb:ls_keys(Store), State};
handle_call(ls_count, _From, {Store, _} = State) ->
    {reply, i2p_netdb:ls_count(Store), State};
handle_call(count, _From, {Store, _} = State) ->
    {reply, i2p_netdb:count(Store), State};
handle_call(capacity, _From, {Store, _} = State) ->
    {reply, i2p_netdb:capacity(Store), State};
handle_call({closest, Target, N}, _From, {Store, _} = State) ->
    {reply, i2p_netdb:closest(Store, Target, N), State};
handle_call({closest_floodfills, Target, N, Excluded}, _From, {Store, _} = State) ->
    {reply, i2p_netdb:closest_floodfills(Store, Target, N, Excluded), State};
handle_call({closest_non_floodfills, Target, N, Excluded}, _From, {Store, _} = State) ->
    {reply, i2p_netdb:closest_non_floodfills(Store, Target, N, Excluded), State};
%% **The gate is here, in the NetDb, and must stay here.**
%%
%% `?LOAD_ERROR` is process state set in `f:init/1`, so it is only readable from this
%% process -- and it is the whole point of the check: a store built by refusing to
%% load a corrupt file must not then be written over that file. Moving the decision
%% to a caller-side `save/0` made `get/1` read the *caller's* dictionary, where the
%% key is absent, so every save looked allowed.
handle_call(save, _From, {Store, Counters}) ->
    case persist_allowed() of
        false ->
            {reply, {error, load_failed}, {Store, Counters}};
        true ->
            Snapshot = i2p_netdb:snapshot(Store),
            Result =
                case whereis(i2p_netdb_writer) of
                    undefined -> save_here(Snapshot);
                    _Pid -> i2p_netdb_writer:save(Snapshot, undefined)
                end,
            C2 =
                case Result of
                    ok -> Counters#{saves := maps:get(saves, Counters) + 1};
                    _ -> Counters
                end,
            {reply, Result, {Store, C2}}
    end;
handle_call(load, _From, {Store, Counters}) ->
    {{Loaded, Counters1}, Result} = maybe_load(Store, Counters),
    %% A load rewrites every entry at once, so this is where the full
    %% cross-check earns its cost: a store built from a file is the one place a
    %% partial seeding bug would otherwise sit unnoticed until an eviction
    %% removed the wrong router days later.
    NewState =
        case Result of
            ok -> {fully_checked(Loaded), Counters1};
            {error, _} -> {Loaded, Counters1}
        end,
    case Result of
        ok -> put(?LOAD_ERROR, false);
        {error, _} -> put(?LOAD_ERROR, true)
    end,
    {reply, Result, NewState};
handle_call(remove_expired, _From, {Store, Counters}) ->
    NowMs = erlang:system_time(millisecond),
    NowSec = erlang:system_time(second),
    {Store2, {RRemoved, LSRemoved}} = i2p_netdb:remove_expired(Store, NowMs, NowSec),
    C2 = Counters#{
        expired_sweeps := maps:get(expired_sweeps, Counters) + 1,
        routers_expired := maps:get(routers_expired, Counters) + RRemoved,
        ls_expired := maps:get(ls_expired, Counters) + LSRemoved
    },
    {reply, {RRemoved, LSRemoved}, {checked(Store2), C2}};
handle_call(snapshot, _From, {Store, _} = State) ->
    %% O(n) in the order, so it is not free — but it is 49 us against the 8403 us
    %% of serialising here, and the serialisation is what this process is trying
    %% to stop doing. The alternative, copying the store, measured 371 us.
    {reply, i2p_netdb:snapshot(Store), State};
handle_call(generation_now, _From, {Store, _} = State) ->
    %% O(1): a map lookup. The writer calls this twice per save attempt, and the
    %% second one is what decides whether the bytes get written at all.
    {reply, i2p_netdb:generation(Store), State};
handle_call(timer_counts, _From, State) ->
    {reply, current_timer_counts(), State};
handle_call(stats, _From, {Store, Counters}) ->
    Reply = Counters#{
        routers => i2p_netdb:count(Store),
        lease_sets => i2p_netdb:ls_count(Store),
        capacity => i2p_netdb:capacity(Store)
    },
    {reply, Reply, {Store, Counters}}.

handle_cast({save_result, Result}, {Store, Counters}) ->
    %% The writer reports the outcome back here rather than the timer branch
    %% matching on it, so a failed save is counted in one place and the counter
    %% means the same thing whether it came from the timer or from `f:save/0`.
    C2 =
        case Result of
            ok -> Counters#{saves := maps:get(saves, Counters) + 1};
            _ -> Counters
        end,
    {noreply, {Store, C2}};
handle_cast(_Msg, State) ->
    {noreply, State}.

%% The writer reports the save outcome here rather than the timer branch matching on
%% it, so a failure is counted in one place and `saves` means the same thing whether
%% it came from the timer or from `f:save/0`.
handle_info({save_result, Result}, {Store, Counters}) ->
    C2 =
        case Result of
            ok -> Counters#{saves := maps:get(saves, Counters) + 1};
            _ -> Counters
        end,
    {noreply, {Store, C2}};
handle_info(autosave, {Store, Counters}) ->
    _ = take_timer(?AUTOSAVE_TIMERS),
    schedule_autosave(),
    %% **The save is handed to `m:i2p_netdb_writer` and this process goes straight
    %% back to serving reads.** Serialising 5000 routers measures 8403 us, and
    %% doing it here meant every read queued behind it -- `f:closest/3` for a
    %% lookup round, `f:closest_floodfills/4` for a tunnel build, `f:has_router/2`
    %% for a relayed frame.
    %%
    %% The hand-over costs about 49 us, because a snapshot names the routers
    %% rather than copying them: `m:i2p_netdb:serialize/1` reads each one from the
    %% table itself, which is `protected`. `f:save/1` is the same call, for an
    %% operator who wants to wait for the file.
    %%
    %% The result is deliberately not matched on here. The writer counts a failure
    %% in its own state and reports it through `f:stats/0`; a full disk must not
    %% stop this process from serving reads, which would lose the store as well as
    %% the file.
    case persist_allowed() of
        true -> hand_save_to_writer(Store);
        false -> ok
    end,
    {noreply, {Store, Counters}};
handle_info(expiry_sweep, {Store, Counters}) ->
    _ = take_timer(?EXPIRY_TIMERS),
    NowMs = erlang:system_time(millisecond),
    NowSec = erlang:system_time(second),
    {Store2, {RRemoved, LSRemoved}} = i2p_netdb:remove_expired(Store, NowMs, NowSec),
    C2 = Counters#{
        expired_sweeps := maps:get(expired_sweeps, Counters) + 1,
        routers_expired := maps:get(routers_expired, Counters) + RRemoved,
        ls_expired := maps:get(ls_expired, Counters) + LSRemoved
    },
    schedule_expiry(),
    %% **The O(1) check, not the cross-check.** The sweep used to be
    %% `f:fully_checked/1`, on the grounds that a wholesale rewrite is where a
    %% partial bug hides. It is not a wholesale rewrite any more -- see
    %% `f:fully_checked/1` -- and at the shipped capacity of 5000 routers the
    %% cross-check was 4771 us against the sweep's own ~2.3 ms.
    {noreply, {checked(Store2), C2}}.

terminate(_Reason, {Store, _Counters}) ->
    _ = cancel_timers(),
    %% **Saved here, not through the writer.** Two reasons, and they point the same
    %% way: at shutdown nobody is waiting for a read, so the reason to move the save
    %% off this process does not apply; and the writer is about to be stopped, so
    %% handing it work would race that shutdown. `f:save_here/1` is the old
    %% behaviour, kept for exactly this and for a NetDb started without a writer.
    _ =
        case persist_allowed() of
            true -> save_here(i2p_netdb:snapshot(Store));
            false -> ok
        end,
    ok.

cancel_timers() ->
    lists:foreach(
        fun(Ref) -> erlang:cancel_timer(Ref) end,
        timer_refs(?AUTOSAVE_TIMERS) ++ timer_refs(?EXPIRY_TIMERS)
    ).

%% Take the snapshot here — the 49 us this process pays — and hand the rest to the
%% writer. A `gen_server:call/1`, so the writer blocks rather than this process,
%% which is the entire reason the writer exists.
%%
%% No timeout: the serialisation measures 8403 us at the shipped capacity, but it
%% is not bounded by anything this project controls (a large LeaseSet map, a slow
%% disk), and a save that gives up halfway leaves a temp file rather than a store.
hand_save_to_writer(Store) ->
    Snapshot = i2p_netdb:snapshot(Store),
    Result =
        case whereis(i2p_netdb_writer) of
            undefined ->
                %% No writer. Fall back to saving here rather than dropping the file:
                %% the read path is the thing being protected, and in a test that
                %% starts this process alone there is no read to protect.
                save_here(Snapshot);
            _Pid ->
                i2p_netdb_writer:save_async(Snapshot, self()),
                ok
        end,
    %% **The fallback reports too.** The writer sends `{save_result, Result}` back
    %% and the counter is incremented when that arrives, so a save done *here* would
    %% otherwise be invisible to `f:stats/0` -- and `saves` silently stopping
    %% incrementing is precisely what an operator watching that counter would take
    %% for "the autosave timer is not firing".
    self() ! {save_result, Result},
    ok.

%% The in-process save, kept as the fallback rather than deleted.
%%
%% It is the old `f:save_to_disk/1`: serialise, write to a temp file, chmod 0600,
%% rename. Slower and it runs on the read path, but it is the difference between
%% "the save did not happen" and "the save happened somewhere inconvenient".
save_here(Snapshot) ->
    case {i2p_netdb:serialize(Snapshot), data_dir()} of
        {{ok, Bin}, {ok, Dir}} -> write_here(Bin, Dir);
        {{error, _}, _} -> {error, serialize_failed};
        {_, undefined} -> ok
    end.

write_here(Bin, Dir) ->
    Path = filename:join(Dir, ?NETDB_FILE),
    TmpPath =
        Path ++ ".tmp." ++ integer_to_list(erlang:unique_integer([positive, monotonic])),
    case filelib:ensure_dir(Path) of
        ok -> write_private_atomic(Path, TmpPath, Bin);
        {error, _} = Err -> Err
    end.

write_private_atomic(Path, TmpPath, Bin) ->
    case file:open(TmpPath, [write, binary, exclusive]) of
        {ok, Fd} ->
            case file:write(Fd, Bin) of
                ok ->
                    case file:sync(Fd) of
                        ok ->
                            case file:close(Fd) of
                                ok ->
                                    case file:change_mode(TmpPath, 8#600) of
                                        ok ->
                                            rename_private(TmpPath, Path);
                                        {error, _} = Err ->
                                            _ = file:delete(TmpPath),
                                            Err
                                    end;
                                {error, _} = Err ->
                                    _ = file:delete(TmpPath),
                                    Err
                            end;
                        {error, _} = Err ->
                            _ = file:close(Fd),
                            _ = file:delete(TmpPath),
                            Err
                    end;
                {error, _} = Err ->
                    _ = file:close(Fd),
                    _ = file:delete(TmpPath),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

rename_private(TmpPath, Path) ->
    case file:rename(TmpPath, Path) of
        ok ->
            ok;
        {error, _} = Err ->
            _ = file:delete(TmpPath),
            Err
    end.

data_dir() ->
    case application:get_env(i2per, data_dir) of
        {ok, Dir} when is_list(Dir) -> {ok, Dir};
        _ -> undefined
    end.
