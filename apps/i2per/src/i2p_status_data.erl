-module(i2p_status_data).

-moduledoc """
Read-only status aggregation for external observers.

One function, `f:view/0`, gathering the router's introspection APIs into a
plain data map. It exists so remote processes (the `i2per_status` web
service on another node) can fetch a complete snapshot with a single
`erpc:call(Node, ?MODULE, view, [], Timeout)` — every module it touches is
guaranteed present wherever the router runs.

## The contract

This map is **public**: something outside this repository is entitled to read it
and to keep working when the router is upgraded underneath it. Two rules follow,
and both are tested rather than promised.

**Additive-only within a major version.** A key that exists is never removed,
never retyped, and never changes what it means. Adding a key bumps `version`.
A consumer that ignores `version` still keeps working, which is the point: the
version is there to let a consumer *notice*, not to make reading it mandatory.

**The key set has one source of truth.** `f:view_keys/0` is the list, a test
pins the returned map against it, and a consumer that needs the shape reads it
rather than retyping it. A key added to `f:view/0` without being added to the
list fails the build, which is the only place drift gets caught before a
consumer does.

Counters are **cumulative since router start** and come from `m:i2p_stats`.
The core supplies totals and its boot time; deriving a rate is the consumer's
job, by sampling twice and subtracting. Nothing here computes one.
""".

-export([view/0, view_keys/0, aggregate_peers/1]).

%% Bumped whenever a key is added. Not bumped for a value change, because a
%% value change is not allowed: see the additive-only contract above.
%%
%% 2 added `connecting` inside the `peers` map. The top-level key set did not
%% change, so `f:view_keys/0` and this stay in step — but a consumer reading
%% `peers` is being handed a shape it has not seen, and the version is what
%% tells it so. The rule above says a value change is not allowed rather than
%% unbumpable, which is why this is a new key and `other` still counts
%% connecting peers: the alternative would have changed what `other` means.
-define(VIEW_VERSION, 2).

%% `underspecs` is off for the read API's two functions, deliberately, and this
%% is the one place in the tree where that is the right call.
%%
%% Both specs are **contracts**, not descriptions of what happens to be built
%% today. `f:view/0` promises a map shape that is allowed to grow; `f:view_keys/0`
%% promises the list of keys that shape has. Dialyzer's success typing is the
%% literal shape and the literal list, so a strict spec would have to be edited
%% in lockstep with the implementation — turning the contract into a second copy
%% of the data, which is the one thing this project has a standing rule against.
%%
%% The agreement between the two is enforced by `apps/i2per/test/
%% i2p_read_api_SUITE.erl`, which fails when the returned map's keys and
%% `f:view_keys/0` disagree in either direction. That test is the enforcement
%% mechanism these suppressed warnings defer to; without it, deleting this
%% attribute would be a small improvement.
-dialyzer({no_underspecs, [view/0, view_keys/0]}).

-doc """
Aggregate router status.

Output: a map with the read API's `version`, the router's uptime and boot time,
the cumulative counters from `m:i2p_stats`, our identity (base64
destination-style hash encoding of the router hash), and the peer, tunnel, netdb
and SAM-session counts. Read-only; safe to call from any process on any
connected node via `erpc`.

The uptime and counters distinguish their own faults: when the router's stats
process is not running, `counters` is empty, `uptime_ms` is `0` and
`boot_time` is `undefined`. Those mean "nothing is counting", which is a
different fault from "counting, and the value is zero".
""".
-spec view() ->
    #{
        version := pos_integer(),
        uptime_ms := non_neg_integer(),
        boot_time := integer() | undefined,
        counters := #{atom() => non_neg_integer()},
        identity := binary(),
        peers := #{
            connected := non_neg_integer(),
            connecting := non_neg_integer(),
            other := non_neg_integer()
        },
        tunnels :=
            #{
                outbound := non_neg_integer(),
                inbound := non_neg_integer(),
                transit := non_neg_integer(),
                pending := non_neg_integer(),
                exploratory_outbound := non_neg_integer(),
                exploratory_inbound := non_neg_integer()
            },
        netdb := #{ri := non_neg_integer(), ls := non_neg_integer()},
        sessions := non_neg_integer()
    }.
view() ->
    Tunnels = i2p_tunnel_srv:status(),
    #{
        version => ?VIEW_VERSION,
        uptime_ms => i2p_stats:uptime_ms(),
        boot_time => i2p_stats:boot_time(),
        counters => i2p_stats:snapshot(),
        identity => identity_b64(i2p_peer:router_hash()),
        peers => aggregate_peers(i2p_peer:status()),
        tunnels => #{
            outbound => map_size(maps:get(tunnels, Tunnels)),
            inbound => map_size(maps:get(inbound, Tunnels)),
            transit => map_size(maps:get(transit, Tunnels)),
            pending =>
                map_size(maps:get(pending, Tunnels)) + map_size(maps:get(pending_in, Tunnels)),
            exploratory_outbound =>
                map_size(maps:get(exploratory, Tunnels, #{})),
            exploratory_inbound =>
                map_size(maps:get(exploratory_in, Tunnels, #{}))
        },
        netdb => #{ri => i2p_netdb_srv:count(), ls => i2p_netdb_srv:ls_count()},
        sessions => length(i2p_sam_sup:client_sessions())
    }.

-doc """
The read API's top-level keys, sorted.

Output: the list of keys `f:view/0` returns. This is the contract's source of
truth: a test asserts the view's keys equal this, and a consumer that wants to
validate or render the shape reads this rather than retyping it. Adding a key
means adding it here.
""".
-spec view_keys() -> [atom()].
view_keys() ->
    [
        boot_time,
        counters,
        identity,
        netdb,
        peers,
        sessions,
        tunnels,
        uptime_ms,
        version
    ].

%% identity_b64/1 — standard base64 of the 32-byte hash (display only).
identity_b64(Hash) when byte_size(Hash) =:= 32 ->
    base64:encode(Hash).

%% aggregate_peers/1 — collapse per-peer states into their buckets.
%% Exported so the pure aggregation can be unit-tested without a live router.
-doc """
Collapse the map returned by `f:i2p_peer:status/0` into
`#{connected, connecting, other}` counters.

Input: the peer-status map as returned by `i2p_peer:status/0`. Only peers
whose status map says `connected` count as connected; every other state —
connecting, backoff, idle, failed, excluded — counts as `other`, and the subset
of those with a dial in flight is counted again as `connecting`.

**`connecting` is a subset of `other`, not a replacement for part of it.** A
caller wanting the backoff count is `other - connecting`, which is worth stating
because the alternative reading — three disjoint buckets — would silently change
what `other` means for a consumer reading version 1 of this map, and the
additive-only rule above forbids exactly that. `other` keeps counting everything
that is not connected; `connecting` is a newer, finer question asked of the same
peers.
""".
-spec aggregate_peers(map()) ->
    #{
        connected => non_neg_integer(),
        connecting => non_neg_integer(),
        other => non_neg_integer()
    }.
aggregate_peers(PeerStatus) ->
    lists:foldl(
        fun
            (#{status := connected}, Acc) ->
                bump(connected, Acc);
            (#{status := connecting}, Acc) ->
                bump(other, bump(connecting, Acc));
            (_, Acc) ->
                bump(other, Acc)
        end,
        #{connected => 0, connecting => 0, other => 0},
        maps:values(PeerStatus)
    ).

%% One bucket, one peer. `maps:update_with/4` rather than a `+ 1` on a `maps:get`
%% so the seed carries every key the shape promises, in one place.
bump(Bucket, Acc) ->
    maps:update_with(Bucket, fun(N) -> N + 1 end, 1, Acc).
