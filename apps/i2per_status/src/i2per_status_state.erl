-module(i2per_status_state).

-moduledoc """
Snapshot collector for the status web service.

Keeps the latest view of one `i2per` router — realtime via a subscription to
the router's `m:i2p_events` bus, plus a periodic poll fallback over the same
Erlang distribution. The router may be on this node or any connected node
(`router_node` app env of `i2per_status`, default: this node); it may also be
absent entirely, which is expected state, not an error.

The poll interval is the `poll_ms` app env of `i2per_status`, five seconds by
default. It is the window the derived figures are differenced over, so it is
what bounds the resolution of every rate on the page; shorten it with
`poll_ms` for hermetic tests, where a case that waits for two readings would
otherwise wait a full interval, and for soak diagnostics that need a denser
series.

## Usage

```erlang
i2per_status_state:snapshot().
%% => #{online => true, router_node => node(), identity => <<...>>,
%%      peers => #{...}, tunnels => #{...}, netdb => #{...},
%%      sessions => N, events => #{...}}
```
""".

-behaviour(gen_server).

-export([
    start_link/0,
    snapshot/0,
    fetch/0,
    known_event_keys/0,
    known_view_keys/0,
    own_snapshot_keys/0
]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(DEFAULT_POLL_MS, 5000).

%% Every tag the router's event type admits, as of this version. Kept beside the
%% folding code because it *documents* the set, not because the folding depends on
%% it: `bump/2` counts anything, and a tag missing from this list is counted
%% anyway and flagged. Adding an event to the bus is therefore not a change to
%% this service, which is the property that stops the next five shapes being
%% dropped the way the last five were.
%%
%% It is still the list worth keeping current, because `unrecognised_event` is
%% the tripwire: a router that has learned a tag this service does not know about
%% pushes that counter off zero, and a non-zero reading says the two are out of
%% step. Losing an event entirely is impossible (see `f:bump/2`); failing to
%% *notice* that a new one exists is what the flag makes visible.
%%
%% The two variant vocabularies below mirror `m:i2p_ssu2_reachability:status/0`
%% and `m:i2p_peertest:result/0`. They are duplicated rather than referenced
%% because this application does not depend on the core at build time -- it is a
%% standalone service an operator runs on another node and reaches over erpc -- so
%% the core's types are not available to compile against.
-define(KNOWN_TAGS, [
    peer_connected,
    peer_disconnected,
    peer_connect_failed,
    peer_send_stalled,
    ssu2_dial_parked,
    tunnel_built,
    tunnel_failed,
    tunnel_expired,
    transit_denied,
    leaseset_published,
    leaseset_publish_failed,
    sam_session_created,
    sam_session_closed,
    ssu2_block_unhandled,
    db_store_not_stored,
    lookup_failed,
    config_changed
]).

-define(REACHABILITY_VERDICTS, [reachable, firewalled, unknown]).

-define(PEERTEST_ADDRESS_TYPES, [ipv4, ipv6]).

-define(PEERTEST_RESULTS, [ok, firewalled, unknown]).

%% The key an event this service does not recognise is flagged under, alongside the
%% event's own tag.
-define(UNRECOGNISED, unrecognised_event).
-define(RPC_TIMEOUT_MS, 2000).
%% How long a request handler waits for a snapshot. The collector holds no lock
%% across the poll — every message returns promptly — so this only needs to
%% cover scheduling; the RPC timeout inside the poll bounds the slow part. Set
%% generously rather than tightly, because a 503 costs the operator a retry and
%% a spurious timeout causes exactly that.
-define(FETCH_TIMEOUT_MS, 2000).

-doc "Start the collector. Registered locally as `i2per_status_state`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
Current view of the monitored router.

Output: `t:snapshot/0` — `online` is false whenever the last poll could not
reach the router; event counters accumulate what the bus delivered.

Exits if the collector is not running. For a request handler that must answer
either way, use `f:fetch/0`.
""".
-spec snapshot() -> snapshot().
snapshot() ->
    gen_server:call(?MODULE, snapshot).

-doc """
Current view, or why there is none.

Output: `{ok, t:snapshot/0()}`, or `{error, Reason}` if the collector is not
running or did not answer in time. This is the accessor for anything that has to
reply to a request regardless: the snapshot server being down is a state this
service can be in, because the two are supervised separately and the collector's
own poll can block.
""".
-spec fetch() -> {ok, snapshot()} | {error, term()}.
fetch() ->
    try gen_server:call(?MODULE, snapshot, ?FETCH_TIMEOUT_MS) of
        Snap -> {ok, Snap}
    catch
        exit:Reason -> {error, Reason}
    end.

%% Named `event_counters` rather than `counters` because the snapshot now carries
%% two unrelated things that would otherwise share a name: these are the event
%% bus fold, under the `events` key, while the router's own cumulative counters
%% arrive under `counters`. One word, two meanings, in one map.
-doc """
What this service has observed on the bus, since it attached.

Open by design, and that is deliberate: the map is keyed by whatever
`f:key_for/1` derives from an event, so a shape the router adds later is recorded
without a change here. A closed map would have been a second hand-written
description of the bus's event type, and would have been wrong the first time a
shape was added.

`f:known_event_keys/0` is the documented set: every key this service knows about
before any event arrives, plus `unrecognised_event`. A consumer should read that
rather than retyping it, and `maps:get/3` with a default covers anything a newer
router produces.

These are **observations since this service attached**, not router lifetime. That
is a different clock on purpose: the router's own lifetime totals are in
`m:i2p_stats` (#0HSTTVC), and presenting these as though they were lifetime would
make a figure look authoritative when it is not.
""".
-type event_counters() :: #{atom() | tuple() => non_neg_integer()}.

-doc """
Latest known state of the observed router.

The base keys (`online`, `router_node`, `subscribed`, `events`) are this
service's own. Everything else is the router's `m:i2p_status_data:view/0`
merged in whole, which is why those keys are optional here and required there:
when the router is unreachable there is no view, and this type has to describe
that case too. `identity` is optional for the same reason — it is required in
the view, because a view exists only for a router that was reached.

The view's shape is duplicated rather than referenced, because this app does not
depend on `i2per` at build time: it is a standalone service an operator can run
on a different node, and the router's modules reach it by name over erpc. So
there are two declarations on this side of that boundary — the `t:snapshot/0`
type, which the compiler checks, and `f:known_view_keys/0`, which a test can
read — and they are two rather than one because a type is not data and a test
cannot enumerate one. `f:own_snapshot_keys/0` is the third declaration: the keys
this service invents rather than reads.

**This module's doc used to claim a test that did not exist.** It said the
duplication was "pinned by a test
(`apps/i2per_status/test/i2per_status_contract_tests.erl`) which fails when the
two disagree". That module has never read `m:i2p_status_data:view_keys/0`, and
the only test that does is producer-side, comparing the view against a list
sitting beside it in the same application. So the two applications' key sets
were each internally consistent and mutually unverified, which is the drift
`dist_view_keys_agree_with_the_consumers_key_set` now closes.

A snapshot is the union of the two sets, and the union is what a reader of
`t:snapshot/0` is being promised.
""".
-type snapshot() :: #{
    online := boolean(),
    router_node := node(),
    subscribed := boolean(),
    version => pos_integer(),
    uptime_ms => non_neg_integer(),
    boot_time => integer() | undefined,
    counters => #{atom() => non_neg_integer()},
    identity => binary(),
    %% Optional because a snapshot built while the router is offline has no view
    %% merged into it at all (`f:offline_view/0` is `#{}`). Required *within*
    %% `peers` because the router always sends all three.
    peers => #{
        connected := non_neg_integer(),
        connecting := non_neg_integer(),
        other := non_neg_integer()
    },
    tunnels => #{
        outbound => non_neg_integer(),
        inbound => non_neg_integer(),
        transit => non_neg_integer(),
        pending => non_neg_integer(),
        exploratory_outbound => non_neg_integer(),
        exploratory_inbound => non_neg_integer()
    },
    netdb => #{ri => non_neg_integer(), ls => non_neg_integer()},
    sessions => non_neg_integer(),
    %% The router's current inbound-reachability verdict, or `undefined` before it
    %% has announced one. `n/a` on the page, not a guess.
    last_reachability => reachable | firewalled | unknown | undefined,
    events := event_counters(),
    %% What the client derived from consecutive readings. Absent until the first
    %% successful poll, and `undefined` inside before that. Not part of the
    %% router's read API: the core publishes cumulative totals and the client
    %% turns them into a rate and a ratio. See `m:i2per_status_derive`.
    derived => i2per_status_derive:derived() | undefined
}.

%% %%%%% %%% gen_server %%%%% %%%

init([]) ->
    RouterNode =
        case application:get_env(i2per_status, router_node) of
            {ok, N} -> N;
            undefined -> node()
        end,
    %% Node-lifecycle watch: nodeup fires once the router becomes reachable
    %% (a wake-up ping makes sure a first connect actually happens).
    ok = net_kernel:monitor_nodes(true),
    wake(RouterNode),
    Subscribed = subscribe(RouterNode),
    erlang:send_after(0, self(), poll),
    {ok, #{
        router_node => RouterNode,
        subscribed => Subscribed,
        online => false,
        view => offline_view(),
        events => empty_counters(),
        %% The router's current inbound-reachability verdict, or `undefined` until
        %% it has announced one. Not a counter: see `f:latest_reachability/2`.
        last_reachability => undefined,
        %% The reading before this one, for the rate. `undefined` until the first
        %% successful poll, which is why the first reading yields no rate: a rate
        %% is a difference and one reading has nothing to difference against.
        %% See `m:i2per_status_derive`.
        previous => undefined,
        derived => undefined
    }}.

handle_call(snapshot, _From, State) ->
    {reply, build_snapshot(State), State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Realtime path: one message per bus event.
handle_info({event, Event}, #{events := Events0} = State) ->
    Events = bump(Event, Events0),
    {noreply, State#{events := Events, last_reachability => latest_reachability(Event, State)}};
%% Reconnect path: resubscribe when the router node comes back.
handle_info({nodeup, Node}, #{router_node := Node} = State) ->
    Subscribed = subscribe(Node),
    erlang:send_after(0, self(), poll),
    {noreply, State#{subscribed => Subscribed}};
handle_info({nodedown, Node}, #{router_node := Node} = State) ->
    {noreply, State#{online := false, view := offline_view()}};
handle_info(poll, State) ->
    State1 = poll_once(State),
    erlang:send_after(poll_interval(), self(), poll),
    {noreply, State1};
handle_info(_Info, State) ->
    {noreply, State}.

%% The window the derived figures are differenced over. Read on every reschedule
%% rather than captured once in `init/1`, so that shortening it in a test takes
%% effect without restarting the service -- which is what lets a case set the
%% app env, start the service, and still get a short window.
poll_interval() ->
    case application:get_env(i2per_status, poll_ms) of
        {ok, Value} when is_integer(Value), Value > 0 -> Value;
        _ -> ?DEFAULT_POLL_MS
    end.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% %%%%% %%% Subscription %%%%% %%%

%% Trigger the distribution connection attempt so `nodeup` will fire; a
%% pang is fine — the retry happens on whatever nodeup eventually reports.
wake(Node) when Node =:= node() ->
    ok;
wake(Node) ->
    _ = net_adm:ping(Node),
    ok.

%% Attach to the router's bus (#WGV1SZ7).
%%
%% `m:i2p_events` ships with the router and its handler modules run on the
%% manager's node, so this service cannot install its own code there and asks the
%% router's own entry point to do it. The `erpc:call/5` is what carries the
%% request across: `m:i2p_events:f:subscribe/1` then runs *on the router*, where
%% the manager is registered locally, which is why this no longer names a
%% `{Name, Node}` tuple — the local/remote asymmetry went away with the entry
%% point.
%%
%% **Every outcome collapses to a boolean, and that is a deliberate limit rather
%% than an oversight.** This service exists to report on a router that may be
%% absent, so "are we attached" is the question the page asks and the reason is
%% for an operator reading logs. The reasons are distinguishable at the boundary
%% — `f:subscribe/1` answers `{error, no_bus}`, `{error, wedged}` or
%% `{error, {bus_error, _}}`, and `erpc` adds an unreachable-node case of its own
%% — and surfacing them on the page would mean changing the type of a published
%% key, which the additive-only contract forbids. `subscribed` stays a
%% `boolean()`.
%%
%% **Both waits here are bounded, and the outer one is the one that matters.**
%% The `erpc` timeout covers a router node that is not answering at all: measured
%% on this build, the expression this replaces waited **3,750–4,000 ms on 12 of 12
%% rounds** for a node that was simply down, against 18 ms for a name that does
%% not resolve — so the wait was a property of name resolution, bounded by
%% nothing in the code. `?RPC_TIMEOUT_MS` is the existing figure for reaching the
%% router over distribution and is used here rather than a new one.
subscribe(Node) ->
    Result = catch erpc:call(Node, i2p_events, subscribe, [self()], ?RPC_TIMEOUT_MS),
    Result =:= ok.

%% %%%%% %%% Folding bus events %%%%% %%%

%% Fold one bus event into the counters.
%%
%% **This function is total, and that is the whole point.** It derives the counter
%% key from the event's own tag rather than matching a list of shapes, so an event
%% the bus adds in future is counted without a line being changed here. The
%% previous version matched six shapes and had a catch-all that dropped the rest,
%% which is how `reachability` and `peertest_result` -- destination claim #2 of
%% this map -- came to be published over distribution and thrown away.
bump(Event, Ev) ->
    Ev1 = add(key_for(Event), Ev),
    case lists:member(tag_of(Event), ?KNOWN_TAGS) of
        true ->
            Ev1;
        false ->
            %% Counted under its own tag *and* flagged, so an event this service
            %% does not recognise is visible as such rather than blending into the
            %% keys it does know.
            add(?UNRECOGNISED, Ev1)
    end.

%% The most recent reachability verdict, kept alongside the counters because the
%% counters cannot supply it: "three `reachable` events" is a history, and what an
%% operator needs to know is what the router currently believes. The verdict is the
%% router's own aggregate inbound decision, derived from peer tests, so it is the
%% single number that says whether anyone can reach this router.
latest_reachability({reachability, _Transport, Verdict}, _State) ->
    Verdict;
latest_reachability(_Event, State) ->
    maps:get(last_reachability, State, undefined).

add(Key, Ev) ->
    maps:update_with(Key, fun(N) -> N + 1 end, 1, Ev).

tag_of(Event) when is_tuple(Event) ->
    element(1, Event);
tag_of(_Event) ->
    ?UNRECOGNISED.

%% The counter one event is counted under.
%%
%% Two shapes are broken out by payload rather than totalled, because their whole
%% value *is* the payload: a total of `reachability` events says only that
%% something happened, and what an operator needs to know is whether this router
%% is reachable. Both payloads are small closed vocabularies, so the breakdown is
%% bounded.
%%
%% `db_store_not_stored` is deliberately **not** broken out, for the opposite
%% reason: its reason vocabulary has an open `{atom()}` clause, so keying on it
%% would grow the map without bound. A total is the honest figure there, and the
%% reason is on the bus for anyone who needs it.
key_for({reachability, _Transport, Verdict}) ->
    {reachability, Verdict};
key_for({peertest_result, AddressType, Result}) ->
    {peertest_result, AddressType, Result};
key_for(Event) ->
    tag_of(Event).

%% `underspecs` is off here, for the reason it is off on the read API: the spec
%% is the promise ("every counter key this service knows about") and the success
%% typing is today's literal list of them. Narrowing the spec to match would make
%% it a hand-maintained copy that has to be edited whenever the bus gains a tag,
%% which is the maintenance this list exists to avoid. The published list is what a
%% consumer reads, and `every_shape_in_the_type_vocabulary_is_covered` in
%% `apps/i2per_status/test/i2per_status_events_tests.erl` is what pins it.
-dialyzer({no_underspecs, [known_event_keys/0]}).

-doc """
Every counter key this service knows about, before any event has arrived.

Output: the documented key set -- one per plain tag, plus the broken-out
`reachability` and `peertest_result` variants, plus `unrecognised_event`. A
consumer that wants to read every counter should read this rather than retyping
it. Keys a *newer* router produces are not in here, so read with a default.
""".
-spec known_event_keys() -> [atom() | tuple()].
known_event_keys() ->
    Plain = ?KNOWN_TAGS,
    Reachability = [{reachability, V} || V <- ?REACHABILITY_VERDICTS],
    Peertest = [{peertest_result, A, R} || A <- ?PEERTEST_ADDRESS_TYPES, R <- ?PEERTEST_RESULTS],
    lists:usort(Plain ++ Reachability ++ Peertest ++ [?UNRECOGNISED]).

%% Every known key present at zero, so a consumer can read any of them without a
%% default, and a dashboard can tell "nothing has happened" from "this key does not
%% exist". An unrecognised tag is the one key that appears only when it happens.
empty_counters() ->
    maps:from_list([{Key, 0} || Key <- known_event_keys()]).

%%% %%%%% %%% The read API's key set, as data %%%%% %%%%

%% The keys `m:i2p_status_data:view/0` returns, as of this version of the contract.
%%
%% Exists so the key set can be compared across the erpc boundary rather than only
%% described. `t:snapshot/0` says what a snapshot looks like to the compiler; this
%% says what it looks like to a test, and a test is the only thing that can catch
%% the two applications' views drifting apart.
%%
%% **This is a second declaration beside the type, and the duplication is
%% deliberate** — it is a consequence of the build-time boundary, not a preference.
%% This app cannot compile against the core's types, so the shape has to be written
%% down here; and a type is not enumerable at runtime, so the test cannot read what
%% is written there. The way the two are kept honest is that
%% `i2per_status_SUITE` asks a live router for its own `view_keys/0` and demands
%% the two agree.
%%
%% Ordering is the router's own — the list is compared sorted, so this is a
%% presentation detail and not a contract. **This is the consumer's expectation of
%% the key set at `?VIEW_VERSION` 2**, and a router reporting a different `version`
%% is a different contract rather than a drift; the suite asserts the version
%% matches before it compares the keys, so a mismatch is reported as a version
%% difference and not as a list of missing keys.
%%
%% Version 2 added `connecting` *inside* the `peers` map, so this list is
%% unchanged between 1 and 2 — which is the point of the list being top-level
%% keys. The bump is what tells this consumer the nested shape moved; the
%% version number in the suite's assertion is what would catch this app being
%% left behind by it.
-spec known_view_keys() -> [atom()].
known_view_keys() ->
    [
        boot_time,
        counters,
        gauges,
        identity,
        netdb,
        peers,
        sessions,
        tunnels,
        uptime_ms,
        version
    ].

%% The keys this service adds to a snapshot, which the router knows nothing about.
%%
%% The complement of `f:known_view_keys/0` in `t:snapshot/0`, and named separately
%% because they are not optional for the same reason: these are present whether or
%% not the router answered, which is what makes a snapshot readable while offline.
-spec own_snapshot_keys() -> [atom()].
own_snapshot_keys() ->
    [derived, events, last_reachability, online, router_node, subscribed].
%% `underspecs` is off on **both** key-set functions below, and for the same reason
%% it is off on the core's `m:i2p_status_data:view_keys/0`: the spec is a
%% **contract** -- the key set this service understands, which is allowed to grow as
%% the router's read API does -- while dialyzer's success typing is today's literal
%% list of it. Narrowing either spec to its literal union would make it a
%% hand-maintained copy that has to be edited in lockstep with the body, which is
%% the duplication this module exists to make visible rather than to add to. The
%% case that holds the two key sets in step is
%% `dist_view_keys_agree_with_the_consumers_key_set` in `i2per_status_SUITE`, which
%% asks a live router for its own key set and fails when the two disagree.
-dialyzer({no_underspecs, [known_view_keys/0, own_snapshot_keys/0]}).

%% %%%%% %%% Polling %%%%% %%%

%% One poll round: every source is independent — a missing piece stays at its
%% previous value instead of poisoning the whole view.
poll_once(#{router_node := Node, online := WasOnline} = State) ->
    View = fetch_all(Node),
    Online = is_map(View),
    Polled =
        State#{
            online => Online,
            view =>
                case Online of
                    true -> View;
                    false when WasOnline -> offline_view();
                    false -> maps:get(view, State)
                end
        },
    %% Derived only from a reading that exists. An offline poll leaves the last
    %% good reading in place, so a router that goes away does not also throw away
    %% the window the rate was computed over — the `online` flag says the data is
    %% stale, which is the honest thing to say, and a reader that needs to know
    %% how stale can look at the window beside it.
    case Online of
        false -> Polled;
        true -> derive_once(Polled, View)
    end.

%% One derivation per successful reading, from the reading before it.
derive_once(State, View) ->
    Current = sample(View),
    Derived = i2per_status_derive:derive(maps:get(previous, State), Current),
    State#{
        previous => Current,
        derived => Derived#{sampled_at => erlang:system_time(millisecond)}
    }.

%% The parts of the read API the derivation needs: cumulative counters and the
%% router's own monotonic uptime, which is the sample clock. No wall clock is
%% taken from the router, so a client clock step cannot produce a negative rate.
sample(#{counters := Counters, uptime_ms := UptimeMs, boot_time := BootTime}) ->
    #{counters => Counters, uptime_ms => UptimeMs, boot_time => BootTime}.
%% Fetch everything in one pass over erpc. erpc EXITS ({erpc,noconnection},
%% noproc, timeout) when the router is absent or slow — expected states here,
%% so the boundary collapses them into `error`, which marks offline.
fetch_all(Node) ->
    case catch erpc:call(Node, i2p_status_data, view, [], ?RPC_TIMEOUT_MS) of
        View when is_map(View) -> View;
        _ -> error
    end.
offline_view() ->
    #{}.

build_snapshot(#{router_node := Node, subscribed := Sub, events := Events} = State) ->
    Base = #{
        online => maps:get(online, State),
        router_node => Node,
        subscribed => Sub,
        events => Events,
        last_reachability => maps:get(last_reachability, State, undefined),
        derived => maps:get(derived, State, undefined)
    },
    case maps:get(view, State) of
        #{} = View when map_size(View) > 0 -> maps:merge(Base, View);
        _ -> Base
    end.
