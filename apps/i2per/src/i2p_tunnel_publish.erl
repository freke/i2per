-module(i2p_tunnel_publish).

-moduledoc """
LeaseSet publication, tunnel-pool management, and maintenance for
`m:i2p_tunnel_srv`.

Three concerns share this module because they all run off the manager's
periodic tick:

- **Client LeaseSet publication** — SAM destinations are recorded with
  `f:publish_into/5`; the freshest active inbound tunnel becomes the lease,
  the signed LeaseSet2 is stored locally and pushed to the closest floodfills.
  Destinations recorded before any tunnel existed (or whose lease is aging)
  are retried by `f:do_pool_tick/1`.
- **Tunnel pool** — app-env targets (`tunnel_pool`) and per-session length
  demands keep at least the wanted number of active or pending
  tunnels per direction alive; inbound is bootstrapped first because outbound
  builds need a reply path.
- **Exploratory pool** — the same `tunnel_pool` env map optionally declares
  `exploratory => N` (the size, default 2 when present) and
  `exploratory_hops => H` (1..3, default 2); without the `exploratory` key
  the pool stays off. When configured, the tick keeps `N` active-or-pending
  short-hop tunnels per direction in the lookup pools, inbound-first.
  Client traffic never touches these tunnels.
- **Selection + sweep** — random/preferred tunnel picks back the public
  `pick_outbound` / `pick_inbound` APIs, and `f:do_sweep/1` expires aged
  transit and local tunnels.

All functions are pure state transformers over
`t:i2p_tunnel_srv:tunnel_srv_state/0`.

## Usage

Called by `m:i2p_tunnel_srv`, not directly by user code:

```erlang
%% Record a destination for publication (retried by the pool tick)
State1 = i2p_tunnel_publish:publish_into(Dest, Seed, DestHash, InLen, State),

%% Periodic tick: top up pools, refresh published leases
State2 = i2p_tunnel_publish:do_pool_tick(State1),

%% Pick an outbound tunnel preferring 1-hop tunnels
{ok, TunID, Entry} = i2p_tunnel_publish:preferred_entry(Tunnels, 1).
```
""".

-export([
    store_demand/4,
    drop_demand/2,
    random_entry/1,
    preferred_entry/2,
    publish_into/5,
    do_pool_tick/1,
    do_sweep/1
]).

-define(NUM_HOPS, 3).
-define(TRANSIT_LIFETIME_S, 720).
-define(TUNNEL_LIFETIME_S, 600).
%% Exploratory lookup pool: target tunnels per direction and hop count when
%% the tunnel_pool env map omits them (lookup gossip on short towers).
-define(EXPLORE_TARGET, 2).
-define(EXPLORE_HOPS, 2).
%% Client LeaseSet publication: leases die with their tunnel; republish
%% this many seconds before lease end so lookups never see a gap.
-define(LEASE_END_MARGIN_S, 30).
-define(LEASE_REFRESH_MARGIN_S, 120).
-define(LS_VALID_DAYS, 1).

%%%%%%% %%% Public API %%%%%%%

-doc """
Record one session's tunnel-length demand under a monitor so it vanishes with
the session process.

Input: `Pid` — the session process; `InLen`/`OutLen` — demanded hop counts;
`State` — the manager state. Output: the state with the demand registered in
`demands` and its monitor in `demand_mons`.
""".
-spec store_demand(pid(), 1..?NUM_HOPS, 1..?NUM_HOPS, i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
store_demand(Pid, InLen, OutLen, State) ->
    Demands = maps:get(demands, State, #{}),
    Mons = maps:get(demand_mons, State, #{}),
    Mon =
        case maps:find(Pid, Mons) of
            {ok, Existing} -> Existing;
            error -> erlang:monitor(process, Pid)
        end,
    State#{
        demands := maps:put(Pid, #{in_len => InLen, out_len => OutLen}, Demands),
        demand_mons := maps:put(Pid, Mon, Mons)
    }.

-doc """
Drop a session's demand after its 'DOWN' arrived.

Input: `Pid` — the dead session process; `State` — the manager state.
Output: the state without the demand or its monitor (removing absent keys is
a no-op).
""".
-spec drop_demand(pid(), i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
drop_demand(Pid, #{demands := Demands, demand_mons := Mons} = State) ->
    State#{
        demands := maps:remove(Pid, Demands),
        demand_mons := maps:remove(Pid, Mons)
    }.

-doc "Uniform pick from a tunnel map for load spreading.".
-spec random_entry(#{0..16#FFFFFFFF := V}) -> {ok, 0..16#FFFFFFFF, V} | error.
random_entry(Map) when map_size(Map) =:= 0 ->
    error;
random_entry(Map) ->
    Entries = maps:to_list(Map),
    {TunnelID, Entry} = lists:nth(rand:uniform(length(Entries)), Entries),
    {ok, TunnelID, Entry}.

-doc """
Like `f:random_entry/1` but restricted to tunnels with exactly `Len` remote
hops; falls back to any entry when none matches.
""".
-spec preferred_entry(#{0..16#FFFFFFFF := V}, pos_integer()) ->
    {ok, 0..16#FFFFFFFF, V} | error.
preferred_entry(Map, Len) ->
    Filtered = maps:filter(fun(_K, E) -> entry_len(E) =:= Len end, Map),
    case map_size(Filtered) of
        0 -> random_entry(Map);
        _ -> random_entry(Filtered)
    end.

-doc """
Record the destination and attempt immediate publication against the current
inbound tunnels, preferring one with `InLen` remote hops.

Input: `Dest` — the client identity; `Seed` — its Ed25519 signing seed;
`DestHash` — its hash; `InLen` — preferred inbound hop count; `State` — the
manager state. Output: the state with the publication recorded; `until_sec`
is 0 while publication is still pending (no usable inbound tunnel yet) and
the previous lease is kept serving while a retry is outstanding.
""".
-spec publish_into(
    i2p_keys:identity(),
    i2p_crypto:ed25519_seed(),
    i2p_crypto:hash(),
    pos_integer(),
    i2p_tunnel_srv:tunnel_srv_state()
) -> i2p_tunnel_srv:tunnel_srv_state().
publish_into(Dest, Seed, DestHash, InLen, State) ->
    Entry =
        lease_or_pending(freshest_inbound_lease(State, InLen), Dest, Seed, DestHash, InLen, State),
    State#{published := maps:put(DestHash, Entry, maps:get(published, State, #{}))}.

%% lease_or_pending/6 — clause pair on the freshest-inbound-tunnel lookup:
%% a live tunnel publishes immediately; no tunnel records (or keeps serving)
%% a pending entry the periodic tick retries.
-spec lease_or_pending(
    {ok, i2p_crypto:hash(), 0..16#FFFFFFFF, non_neg_integer()} | error,
    i2p_keys:identity(),
    i2p_crypto:ed25519_seed(),
    i2p_crypto:hash(),
    pos_integer(),
    i2p_tunnel_srv:tunnel_srv_state()
) -> i2p_tunnel_srv:published_lease().
lease_or_pending({ok, Gw, Tid, UntilSec}, Dest, Seed, DestHash, InLen, State) ->
    build_and_publish(Dest, Seed, Gw, Tid, UntilSec, State),
    i2p_events:notify({leaseset_published, DestHash}),
    #{dest => Dest, seed => Seed, until_sec => UntilSec, in_len => InLen};
lease_or_pending(error, Dest, Seed, DestHash, InLen, State) ->
    case maps:find(DestHash, maps:get(published, State, #{})) of
        {ok, #{until_sec := OldUntil} = Prev} when OldUntil > 0 ->
            %% Keep serving the previous lease while retrying.
            Prev;
        _ ->
            #{dest => Dest, seed => Seed, until_sec => 0, in_len => InLen}
    end.

-doc """
The periodic pool tick: refresh published LeaseSets, top pools up to their
configured targets, serve per-session length demands.

Input: `State` — the manager state. Output: the state after at most one build
per direction per tick was queued and stale publications were retried.
""".
-spec do_pool_tick(i2p_tunnel_srv:tunnel_srv_state()) -> i2p_tunnel_srv:tunnel_srv_state().
do_pool_tick(State) ->
    refresh_published(pool_tick_demands(pool_tick_base(State))).

-doc """
Expire aged tunnels.

Input: `State` — the manager state. Output: the state with transit entries
older than `?TRANSIT_LIFETIME_S` and locally created tunnels older than
`?TUNNEL_LIFETIME_S` removed from their maps.
""".
-spec do_sweep(i2p_tunnel_srv:tunnel_srv_state()) -> i2p_tunnel_srv:tunnel_srv_state().
do_sweep(State) ->
    TransitCutoff = erlang:system_time(second) - ?TRANSIT_LIFETIME_S,
    TunnelCutoff = erlang:system_time(second) - ?TUNNEL_LIFETIME_S,
    AliveTransit = fun(CreatedAt) -> CreatedAt > TransitCutoff end,
    AliveTunnel = fun(BuiltAt) -> BuiltAt > TunnelCutoff end,
    Transit = maps:get(transit, State),
    Transit1 =
        maps:filter(
            fun(_RecvID, #{created_at := CreatedAt}) -> AliveTransit(CreatedAt) end,
            Transit
        ),
    lists:foldl(
        fun({Key, Direction}, Acc) -> sweep_pool(Acc, Key, Direction, AliveTunnel) end,
        State#{transit := Transit1},
        [
            {tunnels, outbound},
            {inbound, inbound},
            {exploratory, outbound},
            {exploratory_in, inbound}
        ]
    ).

%% sweep_pool/4 drops aged entries from one local tunnel map and announces each
%% expiry with the pool's direction. The `tunnels` key uses the `outbound` event
%% label.
-spec sweep_pool(
    i2p_tunnel_srv:tunnel_srv_state(),
    atom(),
    atom(),
    fun((non_neg_integer()) -> boolean())
) -> i2p_tunnel_srv:tunnel_srv_state().
sweep_pool(State, Key, Direction, AliveTunnel) ->
    Pool = maps:get(Key, State, #{}),
    notify_expired(Direction, Pool, AliveTunnel),
    State#{
        Key := maps:filter(fun(_RecvID, #{built_at := BuiltAt}) -> AliveTunnel(BuiltAt) end, Pool)
    }.

%% notify_expired/3 — announce each tunnel the sweep is about to drop.
notify_expired(Direction, Tunnels, Alive) ->
    [
        i2p_tunnel_outcome:expired(Direction)
     || {_ID, #{built_at := BuiltAt}} <- maps:to_list(Tunnels), not Alive(BuiltAt)
    ],
    ok.

%%%%%%% %%% Internal %%%%%%%

%% refresh_published/1 — republish destinations whose lease is about to
%% expire or that never published (until_sec = 0).
-spec refresh_published(i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
refresh_published(State) ->
    NowSec = erlang:system_time(second),
    Published = maps:get(published, State, #{}),
    Stale =
        maps:filter(
            fun(_DestHash, #{until_sec := UntilSec}) ->
                UntilSec - NowSec < ?LEASE_REFRESH_MARGIN_S
            end,
            Published
        ),
    maps:fold(
        fun(DestHash, #{dest := Dest, seed := Seed} = Entry, Acc) ->
            Len = maps:get(in_len, Entry, ?NUM_HOPS),
            publish_into(Dest, Seed, DestHash, Len, Acc)
        end,
        State,
        Stale
    ).

%% freshest_inbound_lease/2 — the youngest active inbound tunnel becomes the
%% published lease: its gateway hash and receive ID, valid until shortly
%% before the tunnel itself expires. Tunnels with exactly `Len` remote hops
%% are preferred; any active inbound tunnel is accepted when none matches.
-spec freshest_inbound_lease(i2p_tunnel_srv:tunnel_srv_state(), pos_integer()) ->
    {ok, i2p_crypto:hash(), 0..16#FFFFFFFF, non_neg_integer()} | error.
freshest_inbound_lease(#{inbound := Inbound}, Len) ->
    Matching = maps:filter(fun(_K, E) -> entry_len(E) =:= Len end, Inbound),
    case map_size(Matching) of
        0 -> freshest_from(Inbound);
        _ -> freshest_from(Matching)
    end.

%% freshest_from/1 — freshest entry of one inbound-tunnel map.
-spec freshest_from(#{0..16#FFFFFFFF := i2p_tunnel_srv:inbound_entry()}) ->
    {ok, i2p_crypto:hash(), 0..16#FFFFFFFF, non_neg_integer()} | error.
freshest_from(Inbound) when map_size(Inbound) =:= 0 ->
    error;
freshest_from(Inbound) ->
    [{_RecvID, Best} | _] =
        lists:sort(
            fun({_, A}, {_, B}) ->
                maps:get(built_at, A) >= maps:get(built_at, B)
            end,
            maps:to_list(Inbound)
        ),
    Gw = hd(maps:get(router_hashes, Best)),
    Tid = hd(maps:get(tunnel_ids, Best)),
    UntilSec =
        maps:get(built_at, Best) + ?TUNNEL_LIFETIME_S - ?LEASE_END_MARGIN_S,
    {ok, Gw, Tid, UntilSec}.

%% build_and_publish/6 — sign the LeaseSet2, store it locally and push it
%% to the closest floodfills.
-spec build_and_publish(
    i2p_keys:identity(),
    i2p_crypto:ed25519_seed(),
    i2p_crypto:hash(),
    0..16#FFFFFFFF,
    non_neg_integer(),
    i2p_tunnel_srv:tunnel_srv_state()
) -> ok.
build_and_publish(Dest, Seed, Gw, Tid, UntilSec, #{local := Local}) ->
    NowSec = erlang:system_time(second),
    Lease = #{
        gateway => Gw,
        tunnel_id => Tid,
        end_date => (UntilSec * 1000) band 16#FFFFFFFF
    },
    LS = i2p_leaset:build(Dest, NowSec, ?LS_VALID_DAYS, [Lease], Seed),
    _ = i2p_netdb_srv:store_ls(LS, NowSec),
    LsBin = i2p_leaset:to_binary(LS),
    OurHash = maps:get(hash, Local),
    Targets = i2p_netdb_srv:closest_floodfills(i2p_leaset:hash(LS), 3, [OurHash]),
    lists:foreach(
        fun(Target) ->
            i2p_peer:send_when_ready(
                Target,
                i2p_i2np:db_store(
                    i2p_leaset:hash(LS), i2p_leaset:store_type(), 0, undefined, LsBin
                )
            )
        end,
        Targets
    ),
    ok.

%% pool_tick_base/1 — top the configured `tunnel_pool` targets up, one build
%% per direction each. App env `tunnel_pool` counts active plus pending
%% builds; while an inbound build is still in flight the outbound arm waits
%% so its fallback (build the missing reply path first) does not queue a
%% duplicate inbound every tick. Without the app env this is a no-op
%% (manual-builds-only mode).
-spec pool_tick_base(i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
pool_tick_base(State) ->
    pool_tick_env(application:get_env(i2per, tunnel_pool), State).

-spec pool_tick_env(
    {ok,
        #{outbound := pos_integer(), inbound := pos_integer()}
        | #{exploratory => pos_integer(), exploratory_hops => 1..?NUM_HOPS}}
    | undefined
    | error,
    i2p_tunnel_srv:tunnel_srv_state()
) -> i2p_tunnel_srv:tunnel_srv_state().
pool_tick_env({ok, #{outbound := OutTarget, inbound := InTarget} = Pool}, State) ->
    ExpTarget = maps:get(exploratory, Pool, 0),
    ExpHops = maps:get(exploratory_hops, Pool, ?EXPLORE_HOPS),
    #{pending := Pending, tunnels := Tunnels, pending_in := PendingIn, inbound := Inbound} = State,
    NeedOut = OutTarget - (map_size(Tunnels) + map_size(Pending)),
    ReplyPathReady =
        map_size(Inbound) > 0 orelse map_size(PendingIn) =:= 0,
    State1 =
        case NeedOut > 0 andalso ReplyPathReady of
            true -> i2p_tunnel_build:do_build_outbound(State);
            false -> State
        end,
    #{pending_in := PendingIn1, inbound := Inbound1} = State1,
    State2 =
        case InTarget - (map_size(Inbound1) + map_size(PendingIn1)) of
            Need when Need > 0 -> i2p_tunnel_build:do_build_inbound(State1);
            _ -> State1
        end,
    exploratory_arm(State2, ExpTarget, ExpHops);
pool_tick_env(_, State) ->
    State.

%% exploratory_arm/3 — top the lookup pools up like the client arm:
%% at most one exploratory build per direction per tick, inbound first
%% (exploratory outbound builds need an exploratory reply path). Counts
%% include only builds tagged for the exploratory pool. The pool is
%% off unless `exploratory => N` is configured; ExpTarget 0 disables it.
-spec exploratory_arm(
    i2p_tunnel_srv:tunnel_srv_state(), non_neg_integer(), 1..?NUM_HOPS
) -> i2p_tunnel_srv:tunnel_srv_state().
exploratory_arm(State, 0, _) ->
    State;
exploratory_arm(State, ExpTarget, ExpHops) ->
    Exploratory = maps:get(exploratory, State, #{}),
    ExploratoryIn = maps:get(exploratory_in, State, #{}),
    Pending = maps:get(pending, State, #{}),
    PendingIn = maps:get(pending_in, State, #{}),
    NeedExpOut =
        ExpTarget - (map_size(Exploratory) + count_pool_builds(Pending, exploratory)),
    ReplyPathReady =
        map_size(ExploratoryIn) > 0 orelse count_pool_builds(PendingIn, exploratory) =:= 0,
    State1 =
        case NeedExpOut > 0 andalso ReplyPathReady of
            true -> i2p_tunnel_build:do_build_outbound(State, ExpHops, exploratory);
            false -> State
        end,
    PendingIn1 = maps:get(pending_in, State1, #{}),
    ExploratoryIn1 = maps:get(exploratory_in, State1, #{}),
    case ExpTarget - (map_size(ExploratoryIn1) + count_pool_builds(PendingIn1, exploratory)) of
        Need when Need > 0 ->
            i2p_tunnel_build:do_build_inbound(State1, ExpHops, exploratory);
        _ ->
            State1
    end.

%% count_pool_builds/2 — pending builds (outbound or inbound) tagged for one
%% tunnel pool; builds without the tag count as `client`.
-spec count_pool_builds(#{i2p_i2np:message_id() := map()}, i2p_tunnel_build:pool()) ->
    non_neg_integer().
count_pool_builds(Pending, Pool) ->
    maps:size(maps:filter(fun(_MsgID, B) -> maps:get(pool, B, client) =:= Pool end, Pending)).

%% pool_tick_demands/1 — one build per direction per tick for demanded
%% lengths with no tunnel of that length active or pending. Inbound demands
%% are served first: they are the outbound arm's reply paths, and while an
%% inbound build is still in flight the outbound arm waits (same rule as the
%% base arm).
-spec pool_tick_demands(i2p_tunnel_srv:tunnel_srv_state()) ->
    i2p_tunnel_srv:tunnel_srv_state().
pool_tick_demands(State) ->
    Demands = maps:get(demands, State, #{}),
    Lens = maps:values(Demands),
    InLens = lists:usort([L || #{in_len := L} <- Lens]),
    OutLens = lists:usort([L || #{out_len := L} <- Lens]),
    State1 =
        lists:foldl(
            fun(Len, Acc) ->
                case missing_len(Acc, in, Len) of
                    true -> i2p_tunnel_build:do_build_inbound(Acc, Len);
                    false -> Acc
                end
            end,
            State,
            InLens
        ),
    #{pending_in := PendingIn, inbound := Inbound} = State1,
    ReplyPathReady = map_size(Inbound) > 0 orelse map_size(PendingIn) =:= 0,
    lists:foldl(
        fun(Len, Acc) ->
            case ReplyPathReady andalso missing_len(Acc, out, Len) of
                true -> i2p_tunnel_build:do_build_outbound(Acc, Len);
                false -> Acc
            end
        end,
        State1,
        OutLens
    ).

%% missing_len/3 — whether no tunnel of `Len` hops exists in the direction's
%% active and pending maps (`out` checks tunnels+pending, `in` inbound+
%% pending_in).
-spec missing_len(i2p_tunnel_srv:tunnel_srv_state(), out | in, pos_integer()) -> boolean().
missing_len(State, out, Len) ->
    #{tunnels := Tunnels, pending := Pending} = State,
    count_len(Tunnels, Len) + count_len(Pending, Len) =:= 0;
missing_len(State, in, Len) ->
    #{inbound := Inbound, pending_in := PendingIn} = State,
    count_len(Inbound, Len) + count_len(PendingIn, Len) =:= 0.

-spec count_len(#{0..16#FFFFFFFF := _}, pos_integer()) -> non_neg_integer().
count_len(Map, Len) ->
    maps:size(maps:filter(fun(_K, E) -> entry_len(E) =:= Len end, Map)).

%% entry_len/1 — a tunnel's hop count (every entry carries router_hashes).
-spec entry_len(#{router_hashes := [i2p_crypto:hash()], _ => _}) -> non_neg_integer().
entry_len(#{router_hashes := Hashes}) ->
    length(Hashes).
