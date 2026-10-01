-module(i2p_netdb).

-moduledoc """
The Network Database (NetDb): a keyed store of RouterInfos plus the DHT
helpers a router needs to store and find network objects.

RouterInfos are keyed by their router hash (SHA-256 of the RouterIdentity) and
kept in a capacity-bounded LRU cache. Storing mirrors i2pd's
`NetDb::AddRouterInfo`: a RouterInfo with an equal or older publish timestamp
never replaces an existing one, one stamped too far in the future is rejected,
and one too old is rejected.

## The router table, and who may read it

The RouterInfos live in an ETS table rather than in the store's own state map,
because "do we hold this RouterInfo?" is asked on the data path, once per
1028-byte tunnel frame, by a process that is not the NetDb. As a `gen_server`
call that question cost a process round trip and a copy of a whole RouterInfo to
answer yes or no. As `ets:member/2` it costs neither, and it is **the only
thing that answers it** — which is the point. One authority for that question,
not two that can disagree.

The table is created by `f:new/0,1` and owned by the calling process, so it dies
with the NetDb that created it rather than outliving it. It is `protected`, so
the owner writes and everyone reads; the single-writer property is enforced by
ETS rather than by convention, and a non-owner write raises `badarg` instead of
silently doing nothing.

**The recency order is a value, not a table.** It is a pair of `gb_trees` held
in the store map: `Seq -> Hash` for eviction order, and `Hash -> Seq` so that
promoting a router we already hold is a lookup rather than a traversal. It
stays inside the store map on purpose. If the order were a second table it
would be side-effect state, and this module's central property — one function
stands between every mutation and both structures — would be lost.

**The table carries a generation counter, because a store that mutates a table
in place is only half a value.** Every mutation writes the table and then
returns a *new* store holding the order. A caller that drops that returned store
has mutated the table without moving the order, and nothing about the result
says so: the mutation inserted one row and evicted one, so the two sizes still
agree, and `f:consistent/1` cannot see it.

So the table holds one reserved row, under `?GEN_KEY`, carrying a counter that
advances on every table mutation; the store map holds the value it believes is
current. Every mutator claims the next generation before it writes, and the claim
fails with `stale_store` if the table's counter has already moved on. One
reserved row is not the order becoming a table: it is a single integer whose only
job is to notice a lost return value, and it is why `f:generation/1` exists.

Catching this at the mutator rather than in `f:consistent/1` is the whole point.
`f:consistent/1` is asked after the fact, when the wrong router has already been
evicted; the claim fires before a single row is written.

A `queue` was the obvious candidate for the order and is the wrong shape: its
O(1) removals (`out/1`, `drop/1`, `out_r/1`, `drop_r/1`) only reach the two
ends, and promoting a router to most-recent means deleting it from the middle,
which is `delete/2` and O(n). That is the hot operation, so the queue would leave
it exactly as slow and only speed up the cold one.

`f:self_check/1` asserts the table and the order agree. Both are written by the
same expressions, so they cannot drift while the code is correct; the check is
what makes that a property rather than a hope.

LeaseSets are stored alongside, keyed by their destination hash, in their own
capacity-bounded recency order. Storing mirrors i2pd's `NetDb::AddLeaseSet`:
an equal or older publish time never replaces an existing LeaseSet, and the
time-window checks from `m:i2p_leaset` `f:valid/2` reject one
published too far in the future or past its lifetime.

The DHT helpers follow i2pd's `IdentMetrics` / `NetDb`:

- **Routing key**: `SHA-256(routerHash ‖ yyyymmdd)` — the day-scoped key the
  XOR distance is computed over, so floodfill closeness varies by day.
- **XOR distance**: the byte-wise XOR of two routing keys, compared
  lexicographically (i2pd's `XORMetric`, `memcmp` over 32 bytes).
- **Floodfill eligibility**: version `>= 0.9.62` (`i2pd NETDB_MIN_FLOODFILL_VERSION`),
  router caps without `U`/`H`, and a published address — `published v4
  orelse (reachable v4 andalso published v6)` — matching
  `RouterInfo::IsEligibleFloodfill`. In 0.1.0 eligibility requires a published
  NTCP2 address; non-published NTCP2 addresses are ignored rather than treated
  as IPv6 endpoints.
- **Closest selection**: `f:closest/3` on routing-key distance,
  `f:closest_floodfills/4` restricted to eligible floodfills (the replication
  target set for a store), and `f:closest_non_floodfills/4` (the exploratory
  lookup set, mirroring `NetDb::GetExploratoryNonFloodfill`).

## Usage

```erlang
%% Build a store and fill it from DatabaseStore payloads.
Store0 = i2p_netdb:new(5000),
Now = erlang:system_time(millisecond),
{ok, Store1, added} = i2p_netdb:store_binary(Store0, RouterInfoBytes, Now),
{ok, Store2, updated} = i2p_netdb:store(Store1, RouterInfo, Now),

%% Find by router hash and pick replication targets.
Key = i2p_router_info:hash(RouterInfo),
{ok, RI} = i2p_netdb:find(Store2, Key),
Floodfills = i2p_netdb:closest_floodfills(Store2, Key, 3, []),
Exploratory = i2p_netdb:closest_non_floodfills(Store2, TargetKey, 3, []),

%% Store and find LeaseSets by destination hash.
DestHash = i2p_leaset:hash(LeaseSet),
{ok, Store3, added} = i2p_netdb:store_ls(Store2, LeaseSet, NowSec),
{ok, LeaseSet} = i2p_netdb:find_ls(Store3, DestHash),
```

The store is a value the gen_server in `m:i2p_netdb_srv` owns, and every
operation returns a new one. The RouterInfos inside it are reachable without
going through that process; see **The router table, and who may read it**.

```erlang
%% Existence is a table read, not a call into the NetDb process.
true = i2p_netdb:has_router(Store, Key).
```
""".

-export([
    new/0,
    new/1,
    new/2,
    store/3,
    store_binary/3,
    store_ls/3,
    store_ls_binary/3,
    find/2,
    find_ls/2,
    remove/2,
    routers/1,
    keys/1,
    ls_keys/1,
    ls_count/1,
    count/1,
    capacity/1,
    default_expiration_ms/0,
    expiration_ms/1,
    expiration_threshold_ms/0,
    set_expiration_ms/2,
    routing_key/1,
    routing_key/2,
    distance/2,
    closest/3,
    closest_floodfills/4,
    closest_non_floodfills/4,
    version_number/1,
    declared_floodfill/1,
    eligible_floodfill/1,
    is_ipv4/1,
    to_binary/1,
    from_binary/1,
    remove_expired/3,
    has_router/2,
    generation/1,
    snapshot/1,
    serialize/1,
    router_table/1,
    consistent/1,
    self_check/1
]).

-export_type([store/0, router_key/0, ls_key/0, snapshot/0]).

-define(DEFAULT_CAPACITY, 5000).
%% The RouterInfo expiry horizon, in ms. i2pd's \`NETDB_MAX_EXPIRATION_TIMEOUT\`.
%%
%% **This is the default, not the policy.** The value a store actually uses is in
%% the store (\`expiration_ms\`), settable per store and per configuration, because
%% both reference implementations make the horizon a *function of how full the store
%% is* rather than a constant. i2pd interpolates 1.5h..27h by \`routers/90\`;
%% i2p-java switches to an aggressive drop above 4000. See \`#RA5PVR1\`.
%%
%% What is decided here is only that i2per's own policy is the simplest of the
%% three: a fixed horizon at every size. If it becomes a sliding one, the change is
%% to \`horizon_ms/1\` and nothing else, because both callers already ask it.
-define(DEFAULT_EXPIRATION_MS, 27 * 60 * 60 * 1000).
%% The table is unnamed: a store's table is identified by the tid in its own
%% state, not by a global name, so two stores in one node cannot collide. The
%% srv reads the tid from its store and hands it to callers; see
%% `m:i2p_netdb_srv:has_router/1`.
-define(ROUTERS, i2per_netdb_routers).
%% The one table row that is not a RouterInfo. An atom, where every router key is
%% a 32-byte binary, so it cannot collide with one and no caller can name it by
%% accident. Its value is the generation counter; see `f:claim_generation/1`.
-define(GEN_KEY, '$generation').
%% i2pd NetDb.hpp: NETDB_MIN_FLOODFILL_VERSION = MAKE_VERSION_NUMBER(0, 9, 62).
-define(NETDB_MIN_FLOODFILL_VERSION, 962).
%% i2pd NetDb.cpp: reject RouterInfos stamped more than this into the future.
%%
%% **Not configurable, and deliberately so.** This is not a policy knob. It bounds
%% how far ahead of the local clock a RouterInfo may claim to be published, which is
%% a tolerance for clock skew between routers, and the number to use for that is
%% i2pd's. Making it configurable would invite an operator to set it wide enough to
%% accept RouterInfos that are meaningfully from the future, and the expiry sweep
%% would then have to reason about them too. See `expiration_threshold_ms/0`, which
%% exposes it as a read so a test or a status display can report the window the
%% store is actually enforcing.
-define(EXPIRATION_THRESHOLD_MS, 2 * 60 * 1000).
-define(CAPS_FLOODFILL, $f).
-define(CAPS_UNREACHABLE, $U).
-define(CAPS_HIDDEN, $H).
-define(NTCP2_TRANSPORT, <<"NTCP2">>).
-define(VERSION, 1).

-doc "The NetDb key of a router: SHA-256 of its RouterIdentity.".
-type router_key() :: i2p_crypto:hash().

-doc "The NetDb key of a LeaseSet: SHA-256 of its destination identity.".
-type ls_key() :: i2p_crypto:hash().

-doc """
A store: an ETS table of RouterInfos keyed by router hash, the paired recency
order used for capacity eviction, and a parallel map of destination hash to
LeaseSet with its own recency order.

`routers` is an `ets:tid()` rather than a map because the existence question is
asked per relayed frame from another process, and a table read answers it
without a round trip. `order` and `order_pos` are the two halves of the recency
order: `Seq -> Hash` for finding the least-recently-stored router, and
`Hash -> Seq` for promoting one we already hold. They are kept in step by the
same expressions that write the table, and `f:self_check/1` asserts they agree.

`generation` is the store's half of the counter the table carries under
`?GEN_KEY`. It is the store's belief about how many times its table has been
written; every mutator advances both together and refuses to write when they
disagree. See `f:generation/1`.

LeaseSets keep a plain map and list. Nothing on the data path asks about them
per frame, so they gain nothing from a table and would only pay for it. They also
need no generation: they live in the store map, so a dropped LeaseSet return
value loses nothing that is not already lost.
""".
-opaque store() :: #{
    capacity := pos_integer(),
    expiration_ms := pos_integer(),
    routers := ets:tid(),
    order := gb_trees:tree(non_neg_integer(), router_key()),
    order_pos := gb_trees:tree(router_key(), non_neg_integer()),
    next_seq := pos_integer(),
    generation := non_neg_integer(),
    lease_sets := #{ls_key() => i2p_leaset:lease_set()},
    ls_order := [ls_key()]
}.

-doc """
A fresh store with the default capacity (5000 routers) and the default RouterInfo
expiry horizon (27 hours).
""".
-spec new() -> store().
new() ->
    new(?DEFAULT_CAPACITY, ?DEFAULT_EXPIRATION_MS).

-doc """
A fresh store with a fixed `Capacity` and the default expiry horizon.

When a store would exceed the capacity, the least recently stored RouterInfo is
evicted.
""".
-spec new(pos_integer()) -> store().
new(Capacity) ->
    new(Capacity, ?DEFAULT_EXPIRATION_MS).

-doc """
A fresh store with a fixed `Capacity` and a fixed `ExpirationMs`.

`Capacity` is the number of RouterInfos the store holds before evicting the least
recently stored. `ExpirationMs` is how old a RouterInfo may be before the store
discards it — the horizon that decides both whether `f:store/3` admits a
RouterInfo at all and what the sweep removes. It is a plain window, **not** a
function of how full the store is, which is simpler than either reference
implementation and more permissive than both at size. See `#RA5PVR1`.

The two are independent: capacity bounds memory, the horizon bounds staleness. A
store can hold few routers for a long time, or many for a short time, and neither
setting affects the other.

The returned store owns a new `protected` ETS table, so it is only safe to use
from the process that called this: a `protected` table rejects writes from
anyone else, which is what makes the single-writer property hold rather than
merely be intended. The table dies with this process, so the store cannot
outlive its owner.
""".
-spec new(pos_integer(), pos_integer()) -> store().
new(Capacity, ExpirationMs) when
    is_integer(Capacity),
    Capacity > 0,
    is_integer(ExpirationMs),
    ExpirationMs > 0
->
    #{
        capacity => Capacity,
        expiration_ms => ExpirationMs,
        routers => new_table(),
        order => gb_trees:empty(),
        order_pos => gb_trees:empty(),
        next_seq => 1,
        generation => 0,
        lease_sets => #{},
        ls_order => []
    };
new(_, _) ->
    error(badarg).

%% The table is `protected`, not `public`: the owning process writes, everyone
%% reads. `read_concurrency` because the readers are exactly the case this
%% table exists for -- many processes asking "do we hold this router?" on their
%% own schedulers, with no writer in the middle.
%%
%% It starts with the generation row and nothing else, which is why every count
%% of stored routers in this module subtracts one: see `f:router_count/1`.
new_table() ->
    Tab = ets:new(?ROUTERS, [set, protected, {read_concurrency, true}]),
    true = ets:insert(Tab, {?GEN_KEY, 0}),
    Tab.

-doc """
Store a verified RouterInfo.

Input: `Store` — the current store; `RI` — a parsed RouterInfo
(`m:i2p_router_info:decode/1`); `NowMs` — wall-clock ms since epoch.
Output: `{Store2, Outcome}`. `Outcome` is `added` for a new key, `updated`
when a strictly newer RouterInfo replaces an older one for the same key,
`older` when the existing entry is kept (equal or newer publish timestamp),
`from_future` / `too_old` when the timestamp fails i2pd's window checks (the
store is returned unchanged).
""".
-spec store(store(), i2p_router_info:router_info(), non_neg_integer()) ->
    {store(), added | updated | older | from_future | too_old}.
store(Store, RI, NowMs) when is_integer(NowMs) ->
    Key = i2p_router_info:hash(RI),
    case router(Key, Store) of
        {ok, Existing} ->
            case i2p_router_info:published(Existing) >= i2p_router_info:published(RI) of
                true -> {Store, older};
                false -> insert_newer(Store, Key, RI, NowMs, updated)
            end;
        error ->
            insert_newer(Store, Key, RI, NowMs, added)
    end;
store(_Store, _RI, _NowMs) ->
    error(badarg).

-doc """
Store a RouterInfo from its raw signed bytes.

Input: `Store` — the current store; `Bin` — full signed RouterInfo bytes;
`NowMs` — wall-clock ms since epoch.
Output: `{ok, Store2, Outcome}` as in `f:store/3`, or `{error, Reason}` when
the bytes do not decode to a signature-verifying RouterInfo
(`m:i2p_router_info:decode/1` reasons).
""".
-spec store_binary(store(), binary(), non_neg_integer()) ->
    {ok, store(), added | updated | older | from_future | too_old} | {error, term()}.
store_binary(Store, Bin, NowMs) ->
    case i2p_router_info:decode(Bin) of
        {ok, RI} ->
            {Store2, Outcome} = store(Store, RI, NowMs),
            {ok, Store2, Outcome};
        {error, Reason} ->
            {error, Reason}
    end.

-doc """
Store a verified LeaseSet2.

Input: `Store` — the current store; `LS` — a parsed LeaseSet
(`m:i2p_leaset:decode/1`); `NowSec` — wall-clock seconds since epoch.
Output: `{Store2, Outcome}`. `Outcome` is `added` for a new key, `updated`
when a strictly newer LeaseSet replaces an older one for the same destination,
`older` when the existing entry is kept (equal or newer publish time),
`from_future` / `expired` when the publish time fails `m:i2p_leaset:valid/2`
(the store is returned unchanged). The same capacity bounds the LeaseSets, in
their own MRU order.
""".
-spec store_ls(store(), i2p_leaset:lease_set(), non_neg_integer()) ->
    {store(), added | updated | older | from_future | expired}.
store_ls(Store, LS, NowSec) when is_integer(NowSec) ->
    Key = i2p_leaset:hash(LS),
    case maps:find(Key, maps:get(lease_sets, Store)) of
        {ok, Existing} ->
            case i2p_leaset:published(Existing) >= i2p_leaset:published(LS) of
                true -> {Store, older};
                false -> insert_ls(Store, Key, LS, NowSec, updated)
            end;
        error ->
            insert_ls(Store, Key, LS, NowSec, added)
    end;
store_ls(_Store, _LS, _NowSec) ->
    error(badarg).

-doc """
Store a LeaseSet2 from its raw signed content bytes.

Input: `Store` — the current store; `Bin` — full signed LeaseSet2 content bytes
(without the DatabaseStore store-type byte); `NowSec` — wall-clock seconds
since epoch.
Output: `{ok, Store2, Outcome}` as in `f:store_ls/3`, or `{error, Reason}` when
the bytes do not decode to a signature-verifying LeaseSet2
(`m:i2p_leaset:decode/1` reasons).
""".
-spec store_ls_binary(store(), binary(), non_neg_integer()) ->
    {ok, store(), added | updated | older | from_future | expired} | {error, term()}.
store_ls_binary(Store, Bin, NowSec) ->
    case i2p_leaset:decode(Bin) of
        {ok, LS} ->
            {Store2, Outcome} = store_ls(Store, LS, NowSec),
            {ok, Store2, Outcome};
        {error, Reason} ->
            {error, Reason}
    end.

-doc """
Look up a router by hash.

Input: `Store` — the store; `Key` — the router hash.
Output: `{ok, RI}` or `error` when absent. A read does not promote the entry
in the LRU order.
""".
-spec find(store(), router_key()) -> {ok, i2p_router_info:router_info()} | error.
find(Store, Key) ->
    router(Key, Store).

%% The one place a RouterInfo is read out of the table, so there is a single
%% answer to "do we hold this router?" rather than one per call site.
router(Key, Store) ->
    case ets:lookup(maps:get(routers, Store), Key) of
        [{_, RI}] -> {ok, RI};
        [] -> error
    end.

-doc """
Whether the store holds a RouterInfo for `Key`.

Input: `Store` — the store; `Key` — the router hash.
Output: `true` or `false`. **This is the existence question, and it is answered
by the table alone.**

The relay path asks it once per 1028-byte frame, from the process that relays
other routers' tunnels, and only needs the yes or no. `ets:member/2` copies
nothing and does not reach the NetDb process, where a lookup would cost a round
trip and a copy of a whole RouterInfo to answer the same question.

It is deliberately not `f:find/2` narrowed: that returns the RouterInfo, and
the caller here discards it.
""".
-spec has_router(store(), router_key()) -> boolean().
has_router(Store, Key) ->
    ets:member(maps:get(routers, Store), Key).

-doc """
The store's generation: how many times its table has been written.

Input: `Store` — the store.
Output: a non-negative integer, equal to the counter the table carries under
`?GEN_KEY`.

A store that mutates a table in place is only half a value, and this is the half
that says which one you are holding. Two stores naming the same table have
different generations, because every mutation writes the table *and* returns a
new store, so the counter is what distinguishes "the store I just mutated" from
"the store I still hold" when the return value is lost.

The main use is a **cross-process snapshot**. Reading the order and the table
from another process can interleave with a mutation and produce a binary that
was never true of any store; reading `generation/1` before and after the read
and retrying when it moved is enough to make that safe. That is what lets the
periodic save run outside the process that serves reads, because the reader can
tell whether the writer saw a consistent store.
""".
-spec generation(store()) -> non_neg_integer().
generation(Store) ->
    maps:get(generation, Store).

-doc """
The tid of the store's RouterInfo table.

Input: `Store` — the store.
Output: the `ets:tid()`, which stays the same for the life of the store even as
entries are inserted and deleted.

It is published once at init by `m:i2p_netdb_srv` so that a reader can reach
the table without asking the NetDb process for the store, which is what
`m:i2p_netdb_srv:has_router/1` does. Publishing the tid rather than the store is
deliberate: the store is replaced on every mutation, the tid is not.
""".
-spec router_table(store()) -> ets:tid().
router_table(Store) ->
    maps:get(routers, Store).

-doc """
Look up a LeaseSet by destination hash.

Input: `Store` — the store; `Key` — the destination hash.
Output: `{ok, LeaseSet}` or `error` when absent. A read does not promote the
entry in the recency order.
""".
-spec find_ls(store(), ls_key()) -> {ok, i2p_leaset:lease_set()} | error.
find_ls(Store, Key) ->
    maps:find(Key, maps:get(lease_sets, Store)).

-doc """
Remove a router by hash.

Input: `Store` — the store; `Key` — the router hash.
Output: `{Store2, removed}` when it was present, `{Store, not_found}` otherwise.
""".
-spec remove(store(), router_key()) -> {store(), removed | not_found}.
remove(Store, Key) ->
    case ets:member(maps:get(routers, Store), Key) of
        true ->
            %% Claimed before the delete, for the reason `f:claim_generation/1`
            %% gives. A store that deletes from a table it no longer describes
            %% would drop a RouterInfo the order still claims to hold.
            Store1 = claim_generation(Store),
            true = ets:delete(maps:get(routers, Store1), Key),
            {drop_from_order(Store1, Key), removed};
        false ->
            {Store, not_found}
    end.

-doc "All stored RouterInfos, in storage-recency order (MRU first).".
-spec routers(store()) -> [i2p_router_info:router_info()].
routers(Store) ->
    [router_value(K, Store) || K <- mru_first(Store)].

-doc "All stored router hashes, in storage-recency order (MRU first).".
-spec keys(store()) -> [router_key()].
keys(Store) ->
    mru_first(Store).

%% MRU-first means **descending** `Seq`, because `Seq` increases with recency and
%% the tree iterates ascending. Getting this backwards would silently reorder
%% the on-disk netdb file and every `routers/1` listing, which is why it is
%% named rather than inlined at each use.
mru_first(Store) ->
    lists:reverse(order_hashes(Store)).

%% **The hashes held by the order, ascending in recency.**
%%
%% `gb_trees:keys/1` is the trap here: it returns the tree's *keys*, which for
%% this order are the `{Seq, Hash}` pairs, not the hashes. Reading it as hashes
%% hands `{Seq, Hash}` tuples to everything downstream, and the symptom shows up
%% far away as a byte-size failure inside an unrelated function.
order_hashes(Store) ->
    [Hash || {_Seq, Hash} <- gb_trees:to_list(maps:get(order, Store))].

-doc "The number of stored routers.".
-spec count(store()) -> non_neg_integer().
count(Store) ->
    gb_trees:size(maps:get(order, Store)).

-doc "All stored destination hashes, in storage-recency order (MRU first).".
-spec ls_keys(store()) -> [ls_key()].
ls_keys(Store) ->
    maps:get(ls_order, Store).

-doc "The number of stored LeaseSets.".
-spec ls_count(store()) -> non_neg_integer().
ls_count(Store) ->
    map_size(maps:get(lease_sets, Store)).

-doc "The eviction capacity of the store.".
-spec capacity(store()) -> pos_integer().
capacity(Store) ->
    maps:get(capacity, Store).

%% Both of these return a compile-time constant, so dialyzer's success typing is the
%% literal rather than `pos_integer()` and it reports the spec as wider than what the
%% body can produce. Suppressed, and deliberately kept as the wider `pos_integer()`:
%% the point of exposing the number is that a caller configures against it, and a
%% spec of `97200000` would break the build the day someone edits the macro to tune
%% it, which is the one thing this exists to allow.
-dialyzer({no_underspecs, [default_expiration_ms/0, expiration_threshold_ms/0]}).

-doc """
The default RouterInfo expiry horizon in ms, 27 hours.

i2pd's `NETDB_MAX_EXPIRATION_TIMEOUT`, and its *maximum*: i2pd interpolates down from
this towards 1.5 hours as its store fills. Exposed because
`m:i2p_netdb_srv` reads operator configuration and needs the default from here
rather than restating it, so there is one number and not two that can disagree.
""".
-spec default_expiration_ms() -> pos_integer().
default_expiration_ms() ->
    ?DEFAULT_EXPIRATION_MS.

-doc """
The RouterInfo expiry horizon in ms: how old a RouterInfo may be before this store
discards it.

Set at `f:new/2` and changeable with `f:set_expiration_ms/2`. Both the admission
check in `f:store/3` and `f:remove_expired/3` read this one value, so a store cannot
admit a RouterInfo it is about to expire.
""".
-spec expiration_ms(store()) -> pos_integer().
expiration_ms(Store) ->
    maps:get(expiration_ms, Store).

-doc """
How far ahead of the local clock a RouterInfo may claim to be published, in ms.

i2pd's `NETDB_EXPIRATION_TIMEOUT_THRESHOLD`, and not configurable: it is a tolerance
for clock skew rather than a policy, and the two halves of the admission window are
not the same decision. See `f:new/2` for the horizon that *is* a policy.
""".
-spec expiration_threshold_ms() -> pos_integer().
expiration_threshold_ms() ->
    ?EXPIRATION_THRESHOLD_MS.

-doc """
Set a store's RouterInfo expiry horizon, returning a new store.

Input: `Store` — the current store; `ExpirationMs` — the new horizon, which must be
a positive integer.
Output: `Store2`, identical to `Store` apart from the horizon. The table is not
touched, so this is a change of policy and not a mutation: no generation is claimed
and nothing is read or written.

**The horizon is read at both the admission check and the sweep**, so changing it
takes effect on the next store and the next sweep without either having to be told.
That is the point of putting it in the store rather than reading configuration at
two call sites.
""".
-spec set_expiration_ms(store(), pos_integer()) -> store().
set_expiration_ms(Store, Ms) when is_integer(Ms), Ms > 0 ->
    Store#{expiration_ms => Ms};
set_expiration_ms(_Store, _Ms) ->
    error(badarg).

-doc """
The cheap invariant: the table and the order hold the same number of entries.

Input: `Store` — the store. Output: `ok` or `{error, Reason}`.

**This is the check that runs on every mutation,** because it is the one that
catches the failure this arrangement actually risks. The dangerous mistake is a
promote that adds a new position without dropping the old one, and that shows up
immediately as a count disagreement: `count/1` reads the order while the table
holds one RouterInfo, so the store starts evicting the wrong router.

It is O(1): `ets:info/2` reads a field and `gb_trees:size/1` is stored in the
tree header. Measured at the shipped capacity of 5000 routers, this is a fraction
of a microsecond against **315 us** for the full `f:self_check/1`, which would
have been a tax on the store path to catch a bug the cheap check already catches.
""".
-spec consistent(store()) -> ok | {error, term()}.
consistent(#{order := Order, order_pos := Pos, routers := Tab}) ->
    N = gb_trees:size(Order),
    M = gb_trees:size(Pos),
    Table = router_count(Tab),
    case {N, M, Table} of
        {N, N, N} -> ok;
        _ -> {error, {size_disagreement, #{order => N, order_pos => M, table => Table}}}
    end.

-doc """
Assert the store is internally consistent, in full.

Input: `Store` — the store.
Output: `ok`, or `{error, Reason}` naming the first disagreement found.

**This is the property the whole two-structure arrangement rests on.** The
RouterInfos live in an ETS table and the recency order lives in a `gb_trees`
pair; nothing in the language stops them drifting apart, and if they did the
failure would be quiet and slow — a store that never evicts because its order
lost a key, or one that evicts a key it does not hold.

It is O(n log n) and it is therefore **not** what runs on every store; that is
`f:consistent/1`, which is O(1) and catches the likeliest failure. This is the
one for the wholesale operations, where a whole batch of entries is rewritten at
once and a partial bug is hardest to see: a load, and the expiry sweep.
\`i2p_netdb_srv\` calls it after both. What it verifies:

- the table and the order hold the same number of entries
- every hash in `order` is in the table, and vice versa
- `order_pos` is exactly the inverse of `order`
- no two entries share a `Seq`
""".
-spec self_check(store()) -> ok | {error, term()}.
self_check(Store) ->
    Order = maps:get(order, Store),
    Pos = maps:get(order_pos, Store),
    Tab = maps:get(routers, Store),
    InOrder = gb_trees:size(Order),
    InTable = router_count(Tab),
    %% `to_list/1` gives `{{Seq, Hash}, Hash}`; both levels are matched, so `Seq`
    %% is the integer and not the pair. Reading it one level shallow would count
    %% distinct tuples rather than distinct sequences, and a store holding the
    %% same `{Seq, Hash}` twice would pass this check.
    Seqs = [Seq || {{Seq, _Hash}, _Value} <- gb_trees:to_list(Order)],
    case {InOrder, InTable, gb_trees:size(Pos), length(lists:usort(Seqs))} of
        {N, N, N, N} ->
            case missing_from_table(Tab, Order) of
                [] ->
                    case missing_from_order(Tab, Pos) of
                        [] ->
                            %% Both sides are lists, not trees: the empty tree
                            %% is `{0, nil}`, so comparing a tree to a list
                            %% would fail even when both are empty.
                            case
                                gb_trees:to_list(Pos) =:=
                                    gb_trees:to_list(
                                        positions_of(Order)
                                    )
                            of
                                true ->
                                    ok;
                                false ->
                                    {error, order_pos_not_inverse_of_order}
                            end;
                        Missing ->
                            {error, {in_table_not_in_order, Missing}}
                    end;
                Missing ->
                    {error, {in_order_not_in_table, Missing}}
            end;
        {A, B, C, _} ->
            {error, {size_disagreement, #{order => A, table => B, order_pos => C}}}
    end.

%% The lookups go through `order_pos`, which *is* keyed by hash. Asking the
%% `order` tree instead would always miss: its keys are `{Seq, Hash}` pairs.
%% Each membership test is O(log n), so the whole check is O(n log n) rather
%% than the O(n^2) a list membership test would cost.
missing_from_order(Tab, Pos) ->
    [
        Key
     || [Key] <- ets:select(Tab, [{{'$1', '_'}, [], ['$1']}]),
        Key =/= ?GEN_KEY,
        not gb_trees:is_defined(Key, Pos)
    ].

missing_from_table(Tab, Order) ->
    [Hash || {{_Seq, Hash}, _Value} <- gb_trees:to_list(Order), not ets:member(Tab, Hash)].

-doc "The day-scoped routing key for the current UTC date: `SHA-256(Key ‖ yyyymmdd)`.".
-spec routing_key(router_key()) -> router_key().
routing_key(Key) ->
    routing_key(Key, current_day()).

%% `current_day/0` is not cheap. It is `calendar:universal_time()` plus an
%% `io_lib:format` plus a `list_to_binary`, and `routing_key/1` calls it -- so a
%% caller that needs many routing keys in one pass wants `routing_key/2` and a day
%% it looked up once. `f:closest_keys/3` is the caller that wants that.

-doc """
The day-scoped routing key for an explicit day.

Input: `Key` — the router hash; `Day` — 8 bytes, `yyyymmdd` in UTC.
Output: `SHA-256(Key ‖ Day)` — the value i2pd's `CreateRoutingKey` computes,
so XOR closeness between two routers varies by day.
""".
-spec routing_key(router_key(), binary()) -> router_key().
routing_key(Key, Day) when byte_size(Key) =:= 32, byte_size(Day) =:= 8 ->
    crypto:hash(sha256, <<Key/binary, Day/binary>>);
routing_key(_Key, _Day) ->
    error(badarg).

-doc """
The XOR distance between two router hashes.

Input: `Key1`, `Key2` — router hashes.
Output: the 32-byte XOR of their day-scoped routing keys. Two keys compare by
the lexicographic order of this value (i2pd's `XORMetric`); smaller is closer.
""".
-spec distance(router_key(), router_key()) -> binary().
distance(Key1, Key2) ->
    crypto:exor(routing_key(Key1), routing_key(Key2)).

-doc """
The `N` stored router hashes closest to `Target`.

Input: `Store` — the store; `Target` — the router hash to measure against;
`N` — how many to return.
Output: up to `N` hashes, sorted by routing-key XOR distance to `Target`,
closest first.
""".
-spec closest(store(), router_key(), non_neg_integer()) -> [router_key()].
closest(Store, Target, N) when is_integer(N), N >= 0 ->
    closest_keys(router_keys(Store), Target, N);
closest(_Store, _Target, _N) ->
    error(badarg).

-doc """
The `N` closest *eligible floodfill* hashes to `Target`, excluding `Excluded`.

Input: `Store`, `Target`, `N` as in `f:closest/3`; `Excluded` — a list of
hashes to skip (e.g. routers we already asked). Only routers that are both
declared (`caps` contains `f`) and eligible (`f:eligible_floodfill/1`) count —
this is the replication set i2pd picks (`GetClosestFloodfills(ident, 3, ...)`).
""".
-spec closest_floodfills(store(), router_key(), non_neg_integer(), [router_key()]) ->
    [router_key()].
closest_floodfills(Store, Target, N, Excluded) when
    is_integer(N), N >= 0, is_list(Excluded)
->
    Floodfills = [
        Key
     || Key <- router_keys(Store),
        not lists:member(Key, Excluded),
        is_eligible_floodfill(Store, Key)
    ],
    closest_keys(Floodfills, Target, N);
closest_floodfills(_Store, _Target, _N, _Excluded) ->
    error(badarg).

-doc """
The `N` closest *non-floodfill* hashes to `Target`, excluding `Excluded`.

Input: as in `f:closest_floodfills/4`. Routers that declare the floodfill cap
are skipped, mirroring i2pd's `GetExploratoryNonFloodfill` — the peer manager
uses this set to probe for routers close to a key without querying
floodfills.
""".
-spec closest_non_floodfills(store(), router_key(), non_neg_integer(), [router_key()]) ->
    [router_key()].
closest_non_floodfills(Store, Target, N, Excluded) when
    is_integer(N), N >= 0, is_list(Excluded)
->
    NonFloodfills = [
        Key
     || Key <- router_keys(Store),
        not lists:member(Key, Excluded),
        not declared_floodfill(router_value(Key, Store))
    ],
    closest_keys(NonFloodfills, Target, N);
closest_non_floodfills(_Store, _Target, _N, _Excluded) ->
    error(badarg).

-doc """
The numeric version of a RouterInfo.

Input: `RI` — a parsed RouterInfo.
Output: the `router.version` option's digits concatenated and read as an
integer (i2pd's `m_Version` parsing), e.g. `<<"0.9.74">>` → `974`,
`<<"0.9.62">>` → `962`. A missing or empty version yields `0`.
""".
-spec version_number(i2p_router_info:router_info()) -> non_neg_integer().
version_number(RI) ->
    Version = maps:get(<<"router.version">>, i2p_router_info:options(RI), <<>>),
    version_digits(Version, 0).

-doc """
Whether a RouterInfo declares the floodfill capability.

Input: `RI` — a parsed RouterInfo.
Output: `true` when its `caps` option contains `f` (i2pd's
`CAPS_FLAG_FLOODFILL`).
""".
-spec declared_floodfill(i2p_router_info:router_info()) -> boolean().
declared_floodfill(RI) ->
    binary:match(router_caps(RI), <<?CAPS_FLOODFILL>>) =/= nomatch.

-doc """
Whether a RouterInfo qualifies as a floodfill.

Input: `RI` — a parsed RouterInfo.
Output: `true` when it declares floodfill, is eligible: version
`>= 0.9.62`, router caps without `U`/`H`, and a published v4 address or
(reachable v4 and published v6). Mirrors i2pd's
`RouterInfo::IsEligibleFloodfill` narrowed to NTCP2-only transports; used to
decide whether a router joins the floodfill index.
""".
-spec eligible_floodfill(i2p_router_info:router_info()) -> boolean().
eligible_floodfill(RI) ->
    version_number(RI) >= ?NETDB_MIN_FLOODFILL_VERSION andalso
        not router_unreachable(RI) andalso
        (published_v4(RI) orelse (reachable_v4(RI) andalso published_v6(RI))).

-doc """
Whether a host string is an IPv4 literal.

Input: `Host` — e.g. `<<"192.0.2.10">>`.
Output: `true` for a valid dotted-quad IPv4, `false` otherwise (IPv6,
hostnames, malformed).
""".
-spec is_ipv4(binary()) -> boolean().
is_ipv4(Host) when is_binary(Host) ->
    case binary:split(Host, <<".">>, [global]) of
        [O1, O2, O3, O4] ->
            lists:all(fun is_octet/1, [O1, O2, O3, O4]);
        _ ->
            false
    end;
is_ipv4(_) ->
    false.

-doc """
A description of what to serialise, taken from a store.

`keys` is the recency order as a list of router hashes, `table` is the tid those
keys live in, and `generation` is the counter to check afterwards.

**This exists so the serialisation can happen in another process.** The
RouterInfos are not in the snapshot, because they do not have to be: `table` is
`protected`, so any process may read it, and `f:serialize/1` looks each entry up
as it walks the list. Sending a snapshot costs about **49 us** at the shipped
capacity of 5000 routers, against **8403 us** to serialise in the process that
owns the store — a 170x cut in what a read-serving process pays for a save.

`generation` is what makes a snapshot safe to use later. A key can be evicted
between the snapshot being taken and the serialisation running, and the entry
would then be in `keys` but not in `table`. `f:serialize/1` reports that as
`{error, {stale, Key}}` rather than crashing on a `badmatch`, and the caller can
compare the snapshot's generation against the store to decide whether to retry.
""".
-type snapshot() :: #{
    capacity := pos_integer(),
    keys := [router_key()],
    lease_sets := #{ls_key() => i2p_leaset:lease_set()},
    ls_order := [ls_key()],
    generation := non_neg_integer(),
    table := ets:tid()
}.

-doc """
Take a snapshot of the store, for serialising it elsewhere.

Input: `Store` — the store.
Output: a `snapshot()`, which `f:serialize/1` turns into the same bytes
`f:to_binary/1` would have produced for this store.

This is the cheap half of moving a save off the read path. See the `snapshot()`
type for why the RouterInfos are not included.
""".
-spec snapshot(store()) -> snapshot().
snapshot(Store) ->
    #{
        capacity => capacity(Store),
        keys => keys(Store),
        lease_sets => maps:get(lease_sets, Store),
        ls_order => maps:get(ls_order, Store),
        generation => maps:get(generation, Store),
        table => maps:get(routers, Store)
    }.

-doc """
Serialize a snapshot to a binary.

Input: `Snapshot` — from `f:snapshot/1`.
Output: `{ok, Bin}` in exactly the format `f:to_binary/1` writes, or
`{error, {stale, Key}}` when `Key` is in the snapshot's key list but no longer in
the table.

**The error is the point.** A snapshot outlives the store state it was taken
from, and a key evicted in between is in `keys` but absent from `table`. A clean
reason lets the caller re-snapshot and retry; a `badmatch` out of `f:router/2`
would not, and would take the calling process down with it.
""".
-spec serialize(snapshot()) -> {ok, binary()} | {error, term()}.
serialize(#{keys := Keys, table := Tab} = Snapshot) ->
    case snapshot_entries(Tab, Keys, []) of
        {ok, RouterBins} ->
            LSMaps = maps:get(lease_sets, Snapshot),
            LSOrder = maps:get(ls_order, Snapshot),
            LSBins = [ls_entry(Key, LSMaps) || Key <- LSOrder],
            {ok,
                <<"I2PNETDB", ?VERSION:8, (maps:get(capacity, Snapshot)):32/big,
                    (length(Keys)):32/big, (iolist_to_binary(RouterBins))/binary,
                    (length(LSOrder)):32/big, (iolist_to_binary(LSBins))/binary>>};
        {error, _} = Err ->
            Err
    end.

snapshot_entries(_Tab, [], Acc) ->
    {ok, lists:reverse(Acc)};
snapshot_entries(Tab, [Key | Rest], Acc) ->
    case ets:lookup(Tab, Key) of
        [{_, RI}] ->
            Bin = i2p_router_info:to_binary(RI),
            snapshot_entries(
                Tab, Rest, [<<Key/binary, (byte_size(Bin)):16/big, Bin/binary>> | Acc]
            );
        [] ->
            {error, {stale, Key}}
    end.

-doc """
Serialize the store to a binary.

Input: `Store` — a store.
Output: a binary encoding all stored RouterInfos and LeaseSets, preserving the
LRU order and capacity. Each RouterInfo and LeaseSet is encoded as raw signed
bytes via `m:i2p_router_info:to_binary/1` and `m:i2p_leaset:to_binary/1`. The
format is `<<"I2PNETDB">> ‖ version(1) ‖ capacity(4) ‖ router_count(4) ‖
entries ‖ ls_count(4) ‖ entries`.

Equivalent to `{ok, Bin} = f:serialize(f:snapshot(Store))` for a store nothing is
mutating, and it stays defined for one that is: it reads the table through the
store rather than through a snapshot.

**The file records capacity but not the expiry horizon.** Those are not the same
kind of value: capacity is a property of the store that was saved, while the
horizon is a policy the running router decides now, exactly as it decides the sweep
interval. A router restarted with a shorter horizon must honour the shorter one
against the routers it just loaded, so persisting the old value would be a way to
make configuration silently not apply. `f:from_binary/1` therefore loads at the
default and the caller applies whatever policy it is configured for with
`f:set_expiration_ms/2`.
""".
-spec to_binary(store()) -> binary().
to_binary(Store) ->
    Capacity = capacity(Store),
    RouterOrder = mru_first(Store),
    RouterCount = length(RouterOrder),
    RouterBins = [router_entry(Key, Store) || Key <- RouterOrder],
    LSOrder = maps:get(ls_order, Store),
    LSMaps = maps:get(lease_sets, Store),
    LSCount = length(LSOrder),
    LSBins = [ls_entry(Key, LSMaps) || Key <- LSOrder],
    <<"I2PNETDB", ?VERSION:8, Capacity:32/big, RouterCount:32/big,
        (iolist_to_binary(RouterBins))/binary, LSCount:32/big, (iolist_to_binary(LSBins))/binary>>.

-doc """
Deserialize a store from a binary produced by `f:to_binary/1`.

Input: `Bin` — the serialized store.
Output: `{ok, Store}` when the binary is well-formed and every RouterInfo /
LeaseSet signature verifies (`m:i2p_router_info:decode/1`,
`m:i2p_leaset:decode/1`); `{error, Reason}` otherwise. Entries with invalid
signatures or truncated bytes are silently dropped.

**Capacity is restored from the file; the expiry horizon is not.** The horizon
arrives at the default, and the caller sets the policy it is configured for with
`f:set_expiration_ms/2` — see `f:to_binary/1` for why it is not persisted.
""".
-spec from_binary(binary()) -> {ok, store()} | {error, term()}.
from_binary(<<"I2PNETDB", ?VERSION:8, Rest/binary>>) ->
    maybe
        {ok, Capacity, RouterCount, AfterCount} ?= split_header(Rest),
        {ok, Entries, AfterRouters} ?=
            parse_router_entries(AfterCount, RouterCount, []),
        {ok, LSCount, AfterLSCount} ?= split_ls_header(AfterRouters),
        {ok, LSMaps, LSOrder} ?= parse_ls_section(AfterLSCount, LSCount),
        %% The file records routers oldest-first, so the parsed list is already
        %% in ascending recency and can seed the order directly. Seeding it here
        %% rather than replaying each entry through `f:store/3` keeps a load from
        %% paying a signature verification per entry twice over.
        {ok, Store} = seed_order(new(Capacity), Entries),
        {ok, Store#{lease_sets => LSMaps, ls_order => lists:reverse(LSOrder)}}
    else
        {error, _} = Err -> Err;
        error -> {error, malformed_router}
    end;
from_binary(_) ->
    {error, bad_magic}.

%% split_header/1 — the fixed-width store header preceding the router entries.
split_header(<<Capacity:32/big, RouterCount:32/big, AfterCount/binary>>) ->
    {ok, Capacity, RouterCount, AfterCount};
split_header(_) ->
    {error, truncated}.

%% split_ls_header/1 — the lease-set count separating routers from LS entries.
split_ls_header(<<LSCount:32/big, AfterLSCount/binary>>) ->
    {ok, LSCount, AfterLSCount};
split_ls_header(_) ->
    {error, truncated}.

%% parse_ls_section/2 — decode all lease-set entries; the section must be
%% consumed exactly.
parse_ls_section(Bin, Count) ->
    case parse_ls_entries(Bin, Count, #{}, []) of
        {ok, LSMaps, LSOrder, <<>>} -> {ok, LSMaps, LSOrder};
        {ok, _, _, _} -> {error, trailing_bytes};
        error -> {error, malformed_ls}
    end.

-doc """
Remove expired RouterInfos and LeaseSets.

Input: `Store` — the store; `NowMs` — wall-clock ms since epoch; `NowSec` —
wall-clock seconds since epoch.
Output: `{Store2, {RoutersRemoved, LSRemoved}}` where the counts reflect how
many entries were evicted. A RouterInfo is expired when its published timestamp
plus the 27-hour i2pd expiration threshold has fully passed. A LeaseSet is
expired when `m:i2p_leaset:valid/2` returns `{error, expired}`.
""".
-spec remove_expired(store(), non_neg_integer(), non_neg_integer()) ->
    {store(), {non_neg_integer(), non_neg_integer()}}.
remove_expired(Store, NowMs, NowSec) when is_integer(NowMs), is_integer(NowSec) ->
    %% Claimed unconditionally, before the first delete rather than at the first
    %% delete. The sweep cannot know whether it will remove anything until it has
    %% walked the whole order, and a claim made mid-walk would be a claim made
    %% after rows were already gone. So a sweep that removes nothing still advances
    %% the generation by one. That costs a reader one retry of a cross-process
    %% snapshot every 30 minutes, and it is a far better trade than a sweep that
    %% deletes from a table it has not checked.
    Store1 = claim_generation(Store),
    Expired = expired_hashes(Store1, NowMs),
    Store2 = drop_each(Store1, Expired),
    LeaseSets0 = maps:get(lease_sets, Store2),
    LSOrder0 = maps:get(ls_order, Store2),
    {KeptLS, KeptLSOrder, RemovedLS} = partition_ls(
        LeaseSets0, LSOrder0, NowSec, 0, []
    ),
    Store3 = Store2#{
        lease_sets => KeptLS,
        ls_order => lists:reverse(KeptLSOrder)
    },
    {Store3, {length(Expired), RemovedLS}};
remove_expired(_Store, _NowMs, _NowSec) ->
    error(badarg).

%%%%%%% %%% Internal %%%%%%%

is_octet(Octet) when byte_size(Octet) =< 3, byte_size(Octet) > 0 ->
    %% Stays a case: the scrutinee is an is_all_digits/1 call, not
    %% guard-expressible.
    case is_all_digits(Octet) of
        true -> binary_to_integer(Octet) =< 255;
        false -> false
    end;
is_octet(_) ->
    false.

is_all_digits(Bin) ->
    lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(Bin)).

insert_newer(Store, Key, RI, NowMs, Outcome) ->
    Timestamp = i2p_router_info:published(RI),
    case valid_window(Timestamp, NowMs, Store) of
        true ->
            %% Claimed *before* the write, not after: the claim is what detects a
            %% stale store, and a store that has already been written is already
            %% corrupt. On the raise path nothing is written at all.
            Store1 = claim_generation(Store),
            true = ets:insert(maps:get(routers, Store1), {Key, RI}),
            {trim(promote(Store1, Key)), Outcome};
        false ->
            {Store, outcome_for_window(Timestamp, NowMs)}
    end.

%% Take the next generation, or fail loudly if the table has moved on without us.
%%
%% This is the fix for a store that mutates in place while documenting itself as a
%% value. A caller that drops the store `insert_newer/5` just returned has an
%% ETS table one RouterInfo ahead of the recency order it still holds, and no size
%% check can see it, because the mutation inserted a row and evicted a row. The
%% next mutation is where that becomes damage -- `promote/2` and `trim/1` both
%% reason about the order, so they evict against a store that no longer describes
%% the table, and `f:to_binary/1` persists the wrong order.
%%
%% Failing here means the store is caught before that mutation happens, at a point
%% where the table is still exactly as the last good store left it. Raising rather
%% than returning an error is deliberate: this is a programming error in a caller
%% that does not exist, `m:i2p_netdb_srv` is the only mutator and it always keeps
%% the result, and an `error` tuple would have to be threaded through every
%% mutator's spec for a case that should never be reachable.
%% **The number of RouterInfos in the table, which is one less than its size.**
%%
%% The table carries the generation row alongside the routers (see
%% `f:claim_generation/1`), so `ets:info(Tab, size)` counts one non-router row.
%% Every count of stored routers in this module goes through here rather than
%% subtracting one at each call site, because a place that forgets is a store that
%% reports a phantom router forever -- the count never matches the order and
%% `f:consistent/1` reports a disagreement that does not exist.
router_count(Tab) ->
    ets:info(Tab, size) - 1.

claim_generation(#{routers := Tab, generation := Mine} = Store) ->
    case ets:lookup(Tab, ?GEN_KEY) of
        [{?GEN_KEY, Mine}] ->
            Next = Mine + 1,
            true = ets:insert(Tab, {?GEN_KEY, Next}),
            Store#{generation := Next};
        [{?GEN_KEY, Theirs}] ->
            error({stale_store, #{expected => Mine, table => Theirs}});
        [] ->
            error({stale_store, #{expected => Mine, table => missing}})
    end.

%% Move `Key` to most-recently-stored. `order_pos` is what makes this cheap:
%% without it the old `Seq` would be unknown and the entry could only be found by
%% walking the whole order, which is the O(n) this replaced.
promote(#{order := Order, order_pos := Pos, next_seq := Seq} = Store, Key) ->
    {Order1, Pos1} =
        case gb_trees:take_any(Key, Pos) of
            error ->
                {Order, Pos};
            {OldSeq, Pos1a} ->
                %% The old position has to leave BOTH trees, not just the
                %% lookup one. Leaving it in `order` is what would make a
                %% re-stored router look like two entries: `count/1` reads the
                %% order, and the table holds one RouterInfo.
                {_Key, Order1a} = gb_trees:take({OldSeq, Key}, Order),
                {Order1a, Pos1a}
        end,
    Store#{
        order := gb_trees:enter({Seq, Key}, Key, Order1),
        order_pos := gb_trees:enter(Key, Seq, Pos1),
        next_seq := Seq + 1
    }.

%% Remove `Key` from the recency order entirely, without touching the table. The
%% caller decides whether the entry itself goes.
drop_from_order(#{order := Order, order_pos := Pos} = Store, Key) ->
    {Seq, Pos1} = gb_trees:take(Key, Pos),
    %% The order is keyed by the `{Seq, Key}` *pair*, not by `Seq` alone. Taking
    %% `Seq` on its own matches nothing and the walk runs off the end of the
    %% tree, which is a crash rather than a wrong answer -- so it is the kind of
    %% mistake `f:self_check/1` could not have caught on its own.
    {_, Order1} = gb_trees:take({Seq, Key}, Order),
    Store#{order := Order1, order_pos := Pos1}.

%% i2pd NetDb.cpp AddRouterInfo: reject from future (now + 2 min) and too old
%% (now > timestamp + the store's horizon).
%%
%% **Both bounds come from one place.** The future bound is
%% `?EXPIRATION_THRESHOLD_MS`, the clock-skew tolerance. The past bound is the
%% store's own horizon, which is the same value `expired_hashes/2` compares against.
%% They were written as two comparisons in two places, so they could drift and admit
%% a RouterInfo the sweep would immediately remove; now a store cannot do that to
%% itself.
valid_window(Timestamp, NowMs, Store) ->
    Timestamp =< NowMs + ?EXPIRATION_THRESHOLD_MS andalso
        NowMs =< Timestamp + expiration_ms(Store).

%% Insert a LeaseSet after the equal-or-newer check; the i2p_leaset:valid/2
%% window decides acceptance.
insert_ls(Store, Key, LS, NowSec, Outcome) ->
    case i2p_leaset:valid(LS, NowSec) of
        ok ->
            LeaseSets0 = maps:get(lease_sets, Store),
            LeaseSets = LeaseSets0#{Key => LS},
            Order0 = maps:get(ls_order, Store),
            Order1 = [Key | lists:delete(Key, Order0)],
            {trim_ls(Store#{lease_sets => LeaseSets, ls_order => Order1}), Outcome};
        {error, from_future} ->
            {Store, from_future};
        {error, expired} ->
            {Store, expired}
    end.

outcome_for_window(Timestamp, NowMs) when Timestamp > NowMs + ?EXPIRATION_THRESHOLD_MS ->
    from_future;
outcome_for_window(_Timestamp, _NowMs) ->
    too_old.

trim(Store) ->
    case gb_trees:size(maps:get(order, Store)) > maps:get(capacity, Store) of
        true ->
            %% `take_smallest/1` returns `{Key, Value, NewTree}` -- three
            %% elements, not two. The value is the evicted hash; the new tree is
            %% already pruned, so it replaces the order outright rather than
            %% going through `drop_from_order/2`.
            {{_Seq, Evicted}, _V, Order1} = gb_trees:take_smallest(
                maps:get(order, Store)
            ),
            true = ets:delete(maps:get(routers, Store), Evicted),
            {_DroppedSeq, Pos1} = gb_trees:take(Evicted, maps:get(order_pos, Store)),
            trim(Store#{order := Order1, order_pos := Pos1});
        false ->
            Store
    end.

%% Evict the least recently stored LeaseSet when the capacity is exceeded
%% (the LeaseSets share the router store's capacity bound).
trim_ls(Store) ->
    Order = maps:get(ls_order, Store),
    case length(Order) > maps:get(capacity, Store) of
        true ->
            [Evicted | Rest] = lists:reverse(Order),
            Store#{
                lease_sets := maps:remove(Evicted, maps:get(lease_sets, Store)),
                ls_order := lists:reverse(Rest)
            };
        false ->
            Store
    end.

%% Rank `Keys` by XOR distance to `Target` and return the first `N`, closest first.
%%
%% **Decorate, sort, undecorate. The distance is computed once per key, not once
%% per comparison.**
%%
%% This used to be a bare `lists:sort` with a comparator that called `routing_key/1`
%% on both operands. `routing_key/1` is a SHA-256 that also calls `current_day/0`,
%% so every comparison paid two hashes and two calendar reads, and sorting n keys is
%% O(n log n) comparisons. Traced at the shipped capacity of 5000: **118363 SHA-256
%% calls to return three hashes, 162.9 ms.**
%%
%% Two changes, both of which are what the old shape got wrong:
%%
%%   * the distance is a property of a key, so it is computed once and carried
%%     alongside it, leaving a comparator that compares two binaries;
%%   * `current_day/0` is called **once for the whole lookup**, not once per key.
%%     It is `calendar:universal_time()` plus an `io_lib:format` plus a
%%     `list_to_binary`, and at 5000 keys the old form called it 10000 times where
%%     one call would do.
%%
%% Measured together: 148293 us -> 8026 us, an 18.5x improvement, with results
%% identical to before.
%%
%% What is left is ~8000 us, and nearly all of it is 5000 SHA-256s that the
%% previous two steps did not remove. The routing key is `SHA256(Hash ‖ Day)`, so
%% it only changes once a day and could be memoised; that is the remaining 4.6x and
%% it is deliberately not done here, because a memo table in this module raises
%% questions about table ownership and eviction that want their own change. See
%% `#8YGZFB8`.
%%
%% `lists:sort/2` with `=<` rather than `<`: the elements are `{Distance, Key}`
%% pairs, so a comparator that only looked at the distance could see two equal
%% distances and call neither less than the other, which is a comparator `sort/2`
%% is not entitled to. Comparing the key as well makes it a total order.
%% The distance is stripped before returning. **The contract is a list of router
%% hashes**, and returning the `{Distance, Key}` pairs would satisfy the sort and
%% break every caller -- `closest_returns_distance_sorted_test` caught exactly that
%% when this function was first rewritten, which is what an existing test is for.
closest_keys(Keys, Target, N) ->
    Day = current_day(),
    TargetKey = routing_key(Target, Day),
    Ranked = [{crypto:exor(routing_key(Key, Day), TargetKey), Key} || Key <- Keys],
    Sorted = lists:sort(
        fun({D1, K1}, {D2, K2}) -> D1 < D2 orelse (D1 =:= D2 andalso K1 < K2) end, Ranked
    ),
    [Key || {_Distance, Key} <- lists:sublist(Sorted, N)].

is_eligible_floodfill(Store, Key) ->
    RI = router_value(Key, Store),
    declared_floodfill(RI) andalso eligible_floodfill(RI).

%% The order tree already holds every key we store, so the key set is read from
%% there rather than by sweeping the table. One less place that has to agree
%% with another.
router_keys(Store) ->
    order_hashes(Store).

router_value(Key, Store) ->
    {ok, RI} = router(Key, Store),
    RI.

router_caps(RI) ->
    maps:get(<<"caps">>, i2p_router_info:options(RI), <<>>).

router_unreachable(RI) ->
    Caps = router_caps(RI),
    contains_any(Caps, [?CAPS_UNREACHABLE, ?CAPS_HIDDEN]).

published_v4(RI) ->
    lists:any(fun published_v4_addr/1, published_ntcp2_addresses(RI)).

published_v6(RI) ->
    lists:any(fun published_v6_addr/1, published_ntcp2_addresses(RI)).

reachable_v4(RI) ->
    lists:any(fun is_v4_addr/1, ntcp2_addresses(RI)).

published_ntcp2_addresses(RI) ->
    [
        Addr
     || Addr <- ntcp2_addresses(RI),
        maps:is_key(<<"host">>, maps:get(options, Addr)),
        not addr_unreachable(Addr)
    ].

ntcp2_addresses(RI) ->
    [
        Addr
     || Addr <- i2p_router_info:addresses(RI),
        maps:get(transport, Addr) =:= ?NTCP2_TRANSPORT
    ].

published_v4_addr(Addr) ->
    is_ipv4(host_of(Addr)).

published_v6_addr(Addr) ->
    not is_ipv4(host_of(Addr)).

is_v4_addr(Addr) ->
    is_ipv4(host_of(Addr)).

host_of(Addr) ->
    maps:get(<<"host">>, maps:get(options, Addr), undefined).

addr_unreachable(Addr) ->
    Caps = maps:get(<<"caps">>, maps:get(options, Addr), <<>>),
    contains_any(Caps, [?CAPS_UNREACHABLE, ?CAPS_HIDDEN]).

contains_any(Caps, Chars) ->
    lists:any(fun(C) -> binary:match(Caps, <<C>>) =/= nomatch end, Chars).

version_digits(<<C, Rest/binary>>, Acc) when C >= $0, C =< $9 ->
    version_digits(Rest, Acc * 10 + (C - $0));
version_digits(<<_, Rest/binary>>, Acc) ->
    version_digits(Rest, Acc);
version_digits(<<>>, Acc) ->
    Acc.

current_day() ->
    {{Y, M, D}, _} = calendar:universal_time(),
    iolist_to_binary(io_lib:format("~4..0B~2..0B~2..0B", [Y, M, D])).

%% ---- to_binary helpers ----

router_entry(Key, Store) ->
    RI = router_value(Key, Store),
    Bin = i2p_router_info:to_binary(RI),
    <<Key/binary, (byte_size(Bin)):16/big, Bin/binary>>.

ls_entry(Key, LSMaps) ->
    LS = maps:get(Key, LSMaps),
    Bin = i2p_leaset:to_binary(LS),
    <<Key/binary, (byte_size(Bin)):16/big, Bin/binary>>.

%% The `Hash -> Seq` half, derived from the order. Written once so `f:promote/2`
%% and a load both reach the same shape.
%%
%% **The expiry sweep used to call this too**, and no longer does. It dropped the
%% expired keys through `f:drop_from_order/2` instead, which is the point of
%% `expired_hashes/2` and `drop_each/2`: this derivation is O(n log n) in what it
%% keeps, paid on every sweep whether anything had expired. `f:self_check/1` still
%% calls it, which is where it now earns its keep — it is the check, not the
%% mutation.
%%
%% **`gb_trees:to_list/1` returns `{TreeKey, Value}` pairs**, and for this order
%% the tree key is *itself* the `{Seq, Hash}` pair. So the list element is
%% `{{Seq, Hash}, Hash}` and the pattern has to reach through both levels. Reading
%% it as `{Seq, Hash}` binds `Seq` to the whole pair, and the rebuild then stores
%% tuples where every other path stores integers -- which then fails much later,
%% inside `drop_from_order/2`, on a lookup that cannot match.
positions_of(Order) ->
    lists:foldl(
        fun({{Seq, Hash}, _Value}, Acc) -> gb_trees:enter(Hash, Seq, Acc) end,
        gb_trees:empty(),
        gb_trees:to_list(Order)
    ).

%% Fill a fresh store from parsed entries. `Entries` is in **file order, which is
%% MRU-first** -- `f:to_binary/1` writes the recency order as it stands. The
%% entries are therefore walked backwards, so the last entry written (the oldest
%% router) takes the lowest `Seq` and the first (the most recent) takes the
%% highest. Getting this the wrong way round silently reverses the recency order
%% of every loaded store, and the symptom is an LRU that evicts the most recently
%% stored router first.
seed_order(#{order := EmptyOrder} = Store, []) ->
    {ok, Store#{order := EmptyOrder, order_pos := gb_trees:empty(), next_seq := 1}};
seed_order(Store, Entries) ->
    %% One claim for the whole load, not one per entry: this writes the table
    %% directly rather than through `f:store/3`, so it is the one bulk write path
    %% that bypasses the mutators, and it needs the same staleness check. Seeding
    %% runs once against a store `f:from_binary/1` has just built, so the claim
    %% cannot fail here; it is claimed anyway so that a future caller cannot
    %% introduce a path that writes the table unchecked.
    Store1 = claim_generation(Store),
    {Order, Pos, NextSeq} = lists:foldl(
        fun({Key, RI}, {OrderAcc, PosAcc, Seq}) ->
            true = ets:insert(maps:get(routers, Store1), {Key, RI}),
            {
                gb_trees:enter({Seq, Key}, Key, OrderAcc),
                gb_trees:enter(Key, Seq, PosAcc),
                Seq + 1
            }
        end,
        {gb_trees:empty(), gb_trees:empty(), 1},
        %% Oldest first. `Entries` arrives MRU-first, so reversing it puts the
        %% oldest router at `Seq` 1 and makes the LRU evict the right end.
        lists:reverse(Entries)
    ),
    {ok, Store1#{order := Order, order_pos := Pos, next_seq := NextSeq}}.

%% ---- from_binary helpers ----

%% Returns `{Key, RI}` pairs in **file order**, which is MRU-first because that is
%% the order `f:to_binary/1` writes. `f:seed_order/2` reverses it on the way in.
%% An entry whose signature does not verify is dropped here rather than counted
%% as an expiry, exactly as the map version did.
parse_router_entries(Bin, 0, Entries) ->
    {ok, lists:reverse(Entries), Bin};
parse_router_entries(<<>>, _Count, _Entries) ->
    error;
parse_router_entries(
    <<Key:32/binary, Len:16/big, RIBin:Len/binary, Rest/binary>>, Count, Entries
) ->
    case i2p_router_info:decode(RIBin) of
        {ok, RI} ->
            parse_router_entries(Rest, Count - 1, [{Key, RI} | Entries]);
        {error, _} ->
            parse_router_entries(Rest, Count - 1, Entries)
    end;
parse_router_entries(_, _, _) ->
    error.

parse_ls_entries(Bin, 0, LSMaps, LSOrder) ->
    {ok, LSMaps, LSOrder, Bin};
parse_ls_entries(<<>>, _Count, _LSMaps, _LSOrder) ->
    error;
parse_ls_entries(
    <<Key:32/binary, Len:16/big, LSBin:Len/binary, Rest/binary>>, Count, LSMaps, LSOrder
) ->
    case i2p_leaset:decode(LSBin) of
        {ok, LS} ->
            parse_ls_entries(
                Rest,
                Count - 1,
                LSMaps#{Key => LS},
                [Key | LSOrder]
            );
        {error, _} ->
            parse_ls_entries(Rest, Count - 1, LSMaps, LSOrder)
    end;
parse_ls_entries(_, _, _, _) ->
    error.

%% ---- remove_expired helpers ----

%% The expired router hashes, and nothing else.
%%
%% **This is the whole cost of the sweep.** Every router needs one lookup, because
%% expiry is a field inside the RouterInfo and there is no way to read it without
%% the RouterInfo: `map_get` is not permitted in a match spec guard, so
%% `ets:select/2` cannot do it either. Measured at 2297 us for 5000 routers.
%%
%% The list is accumulated before anything is deleted rather than deleting as it
%% walks. That is deliberate: a sweep that deletes while iterating a structure it
%% is deriving from is a sweep that can half-apply if it raises, and the two halves
%% are exactly what `f:self_check/1` exists to catch.
%%
%% `gb_trees:to_list/1` gives `{{Seq, Hash}, Hash}` -- the tree key is itself the
%% pair -- so both levels have to be matched. Reading it one level shallow binds
%% `Hash` to the pair.
%%
%% A key in the order but absent from the table is skipped rather than crashing.
%% That should be impossible, because the sweep runs in the process that owns the
%% table, but skipping means a store that has somehow drifted compacts the rest
%% rather than taking the NetDb down on the way.
expired_hashes(Store, NowMs) ->
    Tab = maps:get(routers, Store),
    Order = gb_trees:to_list(maps:get(order, Store)),
    %% **One comparison, one source.** The horizon is read once and hoisted out of
    %% the fold, which is both what the 5000-entry walk wants and the thing that
    %% keeps this in step with `valid_window/3`: a store that admits a RouterInfo
    %% cannot then expire it, because both sides read the same field.
    Horizon = expiration_ms(Store),
    lists:foldl(
        fun({_Position, Hash}, Gone) ->
            case ets:lookup(Tab, Hash) of
                [{_, RI}] ->
                    case i2p_router_info:published(RI) + Horizon < NowMs of
                        true -> [Hash | Gone];
                        false -> Gone
                    end;
                [] ->
                    Gone
            end
        end,
        [],
        Order
    ).

%% Remove each expired router from the table and from both halves of the order.
%%
%% **Incremental, and that is the point.** This used to rebuild `order` from all
%% 5000 entries and then rebuild `order_pos` from the survivors, every sweep,
%% whether or not anything had expired -- measured at ~13 ms, and the reason the
%% sweep cost the same whether it removed 0 routers or 1000. Dropping k keys is k
%% takes at O(log n) each, measured at 0.02 us for none and 1029 us for 1000.
%%
%% A surviving router keeps the `Seq` it already had. Expiry is not a recency
%% event, so the sweep must not reorder the store it is merely compacting -- and
%% dropping rather than rebuilding makes that true by construction rather than by
%% care: there is no code here that could renumber anything.
drop_each(Store, []) ->
    Store;
drop_each(#{routers := Tab} = Store, [Hash | Rest]) ->
    true = ets:delete(Tab, Hash),
    drop_each(drop_from_order(Store, Hash), Rest).

partition_ls(_LSMaps, [], _NowSec, Removed, Kept) ->
    {maps:from_list(Kept), Kept, Removed};
partition_ls(LSMaps, [Key | Rest], NowSec, Removed, Kept) ->
    LS = maps:get(Key, LSMaps),
    case i2p_leaset:valid(LS, NowSec) of
        {error, expired} ->
            partition_ls(LSMaps, Rest, NowSec, Removed + 1, Kept);
        _ ->
            partition_ls(LSMaps, Rest, NowSec, Removed, [{Key, LS} | Kept])
    end.
