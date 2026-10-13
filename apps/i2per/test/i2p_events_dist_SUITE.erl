%% Cross-node tests for the far-side backlog reading.
%%
%% `m:i2p_events:sample_far_backlog/0` is the only thing in the bus that asks a
%% question of another node, so two of its properties cannot be checked on one node
%% at all:
%%
%%   * that a subscriber's queue depth on another node is actually readable, and
%%   * that a subscriber which has *gone* stops being asked about.
%%
%% Both are checked here against a real second VM. The unit tier in
%% `m:i2p_events_tests` covers everything that does not cross the boundary -- the
%% node filter, the subscription hooks, the offered-not-pushed rule -- and this suite
%% covers only the two cases that cannot exist without a pid whose `node/1` differs.
%%
%% The peer is a **bare node**, not a router. Nothing here needs the `i2per`
%% application on the far side: the depth read is an `erpc` to
%% `m:erlang:process_info/2`, so the only thing that has to exist over there is the
%% collector. `m:i2per_status_SUITE` also starts a peer, but it boots a whole router
%% in it to serve the read API -- a different job, and sharing one harness would mean
%% the common one carried the more expensive requirement.

-module(i2p_events_dist_SUITE).

-include_lib("eunit/include/eunit.hrl").

-export([all/0, groups/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).

-export([
    far_backlog_reports_a_non_draining_remote_subscriber/1,
    far_backlog_falls_when_the_remote_subscriber_drains/1,
    a_dead_remote_subscriber_is_pruned/1
]).

%% Called on the PEER node by `f:peer:call/3`. Exported because the far side has to
%% be able to load this module to run it; see the `-pa` in `f:init_per_suite/1`.
-export([start_collector/0, drain_collector/0, collector_depth/0]).

-define(SUITE_TIMEOUT, 90000).
-define(AWAIT_MS, 20000).
-define(RPC_MS, 5000).

%% Events queued for the far collector. **Enough to be unmistakable, and equal to the
%% number the reading must report**, so a depth that also happens to be the answer for
%% some other queue is no use as a pass.
-define(QUEUED, 25).

all() ->
    [{group, dist}].

%% `sequence`, so the three cases run in order against one peer node and cannot
%% interleave -- each of them owns a collector and disposes of it, and two of them
%% running at once would have the sweep measuring the other's queue.
groups() ->
    [
        {dist, [sequence], [
            far_backlog_reports_a_non_draining_remote_subscriber,
            far_backlog_falls_when_the_remote_subscriber_drains,
            a_dead_remote_subscriber_is_pruned
        ]}
    ].

suite() ->
    [{timetrap, ?SUITE_TIMEOUT}].

init_per_suite(Config) ->
    %% Fail loudly rather than letting `peer` fail cryptically: a non-distributed CT
    %% node cannot start a peer at all, and every case here would report that as a
    %% backlog failure.
    assert_distributed(node()),
    {ok, _} = application:ensure_all_started(i2per),
    Config.

end_per_suite(_Config) ->
    ok.

%% One peer for the whole group: starting a node costs about a second and nothing here
%% needs it fresh. The *collector* is per testcase, because its queue depth is the
%% thing under test and a carried-over mailbox would make every case after the first
%% assert against the previous case's traffic.
%%
%% **A group rather than `init_per_suite`, because the peer does not survive the suite
%% init process.** Started there, it is reachable during `init_per_suite` and gone by
%% the first testcase: every case fails `peer:call` with `{noproc, ...}` naming the
%% peer node, which says nothing about the bus. `init_per_group` is where the tree's
%% other peer suite puts it, for the same reason, and `peer:start` rather than
%% `peer:start_link` because CT runs init callbacks in a short-lived process.
init_per_group(dist, Config) ->
    {ok, Peer, PeerNode} = peer:start(#{
        name => peer_name(),
        %% `-pa` because the collector is spawned on the far side by
        %% `f:start_collector/0`, so this module must be loadable there. Derived
        %% rather than written down: a hardcoded `_build` path is a second copy of
        %% the layout that goes stale the first time a directory moves.
        args => ["-pa", filename:dirname(code:which(?MODULE))],
        wait_boot => 30000
    }),
    %% **`erpc` rather than `f:peer:call/5` for reaching the far side**, which is the
    %% one thing worth knowing about a standard_io peer: `f:peer:call/5` resolves the
    %% `peer` *server* on the node it is given, and a standard_io peer does not run
    %% one there -- it answers `{noproc, {gen_server, call, [PeerNode, ...]}}` even
    %% though the node is up and answering `net_adm:ping/1` with `pong`. `m:i2per_status_SUITE`
    %% reaches its peer the same way for the same reason.
    [{peer, Peer}, {peer_node, PeerNode} | Config].

end_per_group(_Group, Config) ->
    %% `peer:stop/1` still works from any process, so this is not tied to the process
    %% that started it.
    peer:stop(proplists:get_value(peer, Config)),
    ok.

%% %%%%% %%% The cases %%%%% %%%

%% A subscriber on another node that is not draining has a queue, and the reading
%% sees it.
%%
%% **The reading is taken through the public entry point and the queue is grown before
%% it is read**, so this cannot pass against a reading that answers `0`
%% unconditionally: `f:await/2` will not return until the depth is the announced
%% count, and a reading stuck at zero times the case out rather than satisfying it.
far_backlog_reports_a_non_draining_remote_subscriber(Config) ->
    PeerNode = peer_node(Config),
    Collector = new_collector(PeerNode),
    ok = i2p_events:subscribe(Collector),
    try
        %% Asserted before the flood, so a case that passed by reading the
        %% *collector's* own node would show up as a reading already above zero.
        ?assertEqual(0, i2p_events:sample_far_backlog()),
        announce(?QUEUED),
        ok = await(
            fun() -> i2p_events:sample_far_backlog() =:= ?QUEUED end,
            ?AWAIT_MS
        ),
        %% And it is the far node's own count, not the router's guess at it.
        ?assertEqual(
            {message_queue_len, ?QUEUED},
            erpc:call(PeerNode, ?MODULE, collector_depth, [], ?RPC_MS)
        ),
        %% Nothing was published on the way: the core does not hand figures to a
        %% stats process it does not control, so `bus_far_backlog` must not exist even
        %% after a reading this deep.
        ?assertNot(maps:is_key(bus_far_backlog, i2p_stats:gauges()))
    after
        ok = i2p_events:unsubscribe(Collector),
        %% **Kill it, or the next case cannot register the same name.** The collector
        %% lives on the shared peer node and the name is one per group, so a case that
        %% unsubscribed without killing leaves the next case's `f:start_collector/0`
        %% raising `badarg` inside an `erpc`, which reports as a peer failure rather
        %% than as the leak it is.
        exit(Collector, kill)
    end.

%% The reading has to come back down, and this is the half that makes it a depth
%% rather than a high-water mark. **A reading that only ever rises is worse than no
%% reading**, because it would tell an operator a subscriber is permanently behind
%% after one slow minute.
far_backlog_falls_when_the_remote_subscriber_drains(Config) ->
    PeerNode = peer_node(Config),
    Collector = new_collector(PeerNode),
    ok = i2p_events:subscribe(Collector),
    try
        announce(?QUEUED),
        ok = await(
            fun() -> i2p_events:sample_far_backlog() =:= ?QUEUED end,
            ?AWAIT_MS
        ),
        ok = erpc:call(PeerNode, ?MODULE, drain_collector, [], ?RPC_MS),
        ok = await(fun() -> i2p_events:sample_far_backlog() =:= 0 end, ?AWAIT_MS)
    after
        ok = i2p_events:unsubscribe(Collector),
        %% **Kill it, or the next case cannot register the same name.** The collector
        %% lives on the shared peer node and the name is one per group, so a case that
        %% unsubscribed without killing leaves the next case's `f:start_collector/0`
        %% raising `badarg` inside an `erpc`, which reports as a peer failure rather
        %% than as the leak it is.
        exit(Collector, kill)
    end.

%% A subscriber that has died is dropped from the registry, and this is the case that
%% covers the sweep's own path.
%%
%% **It used to claim to be the only thing that pruned it, and no longer does.**
%% `m:i2per_status_state` never unsubscribes, so on the deployment this map calls
%% supported -- the status service on its own node, restarting -- every restart used to
%% leave a pid behind. The subsampler now holds a monitor on every registered
%% subscriber and drops the row the moment the pid goes (#DN82Z7J), which is what makes
%% that deployment sound.
%%
%% **What this still covers is the remote case, and it is the one the subsampler cannot
%% answer on its own.** The sweep is what turns "this remote pid no longer exists" into
%% a fact, using the `erpc` that is its whole reason for existing; the subsampler's
%% monitor would also fire here, and this case is what keeps the sweep's answer honest
%% rather than assuming the monitor already did the work.
%%
%% The collector is killed rather than detached, so the registry genuinely holds a pid
%% that no longer exists, which is the only input the sweep can learn anything from.
%% `is_process_alive/1` is awaited rather than slept past: the sweep's input is "this
%% pid does not exist", not "this pid is about to stop existing".
a_dead_remote_subscriber_is_pruned(Config) ->
    PeerNode = peer_node(Config),
    Collector = new_collector(PeerNode),
    ok = i2p_events:subscribe(Collector),
    ?assert(lists:member(Collector, i2p_events:subscribers())),
    exit(Collector, kill),
    %% **Liveness is asked of the node that owns the pid, not of this one.** Measured
    %% on OTP 28: `is_process_alive/1` and `process_info/2` against a *remote* pid both
    %% raise `badarg` -- which is the very fact `m:i2p_events:sample_far_backlog/0`
    %% works around, so asserting on it here would fail in the one place that is
    %% checking the workaround. An `erpc` executes the call where the pid is local.
    ok = await(
        fun() ->
            erpc:call(PeerNode, erlang, is_process_alive, [Collector], ?RPC_MS) =:= false
        end,
        ?AWAIT_MS
    ),
    ok = await(
        fun() ->
            i2p_events:sample_far_backlog(),
            not lists:member(Collector, i2p_events:subscribers())
        end,
        ?AWAIT_MS
    ),
    ?assertEqual(0, i2p_events:sample_far_backlog()).

%% %%%%% %%% Internal helpers %%%%% %%%

assert_distributed(nonode@nohost) ->
    ct:fail(
        "i2p_events_dist_SUITE needs a dist-enabled CT run node; "
        "run `rebar3 ct --sname i2per_ct` (see the justfile recipes)."
    );
assert_distributed(_Node) ->
    ok.

peer_node(Config) ->
    proplists:get_value(peer_node, Config).

%% A fresh collector on the far node, registered under one name.
%%
%% **One name, not one per case.** The cases run in sequence and each disposes of its
%% collector, so at most one is alive at a time; a per-case name would only add a way
%% for a case to read the wrong process's queue and call the depth its own.
new_collector(PeerNode) ->
    erpc:call(PeerNode, ?MODULE, start_collector, [], ?RPC_MS).

%% Announce `N` events on the local bus. Each reaches the far collector through the
%% shipped forwarder, which is the path the reading is measuring.
announce(N) ->
    Hash = crypto:strong_rand_bytes(32),
    [ok = i2p_events:notify({leaseset_published, Hash}) || _ <- lists:seq(1, N)],
    ok.

%% Poll `Pred` until it holds.
%%
%% **A barrier, not a deadline.** The assertions are about a depth that exists, so the
%% depth is the evidence. `f:i2p_ct_helpers:await/2` is the tree's own spelling of that
%% and is what a reader should reach for by default.
await(Pred, Timeout) ->
    i2p_ct_helpers:await(fun() -> Pred() end, Timeout).

%% A peer name unique to this case run, because a stale registration left on `epmd` by
%% an earlier interrupted run would otherwise fail the start with a name collision that
%% says nothing about the backlog.
peer_name() ->
    list_to_atom("i2p_events_dist_" ++ os:getpid()).

%% %%%%% %%% Called on the peer node %%%%% %%%

%% A process whose `receive` matches nothing but `drain` and `stop`, so every event
%% the bus forwards to it stays queued.
%%
%% **No catch-all clause, deliberately.** A clause matching the forwarded events would
%% drain them, and every case would then measure an idle collector instead of a lagging
%% one -- including the case that asserts the reading falls, which would pass for the
%% wrong reason.
start_collector() ->
    Collector = spawn(fun collector_loop/0),
    true = register(?MODULE, Collector),
    Collector.

%% Draining throws the mailbox away rather than consuming it a message at a time.
%% Throwing is the point: the question this suite asks is whether the **router**
%% notices, not what the far side made of what it received.
drain_collector() ->
    ?MODULE ! drain,
    ok.

collector_depth() ->
    process_info(whereis(?MODULE), message_queue_len).

collector_loop() ->
    receive
        drain ->
            ok = flush(),
            collector_loop();
        stop ->
            ok
    end.

flush() ->
    receive
        {event, _} -> flush()
    after 0 ->
        ok
    end.
