%% System-level tests for the counter home and the read API it feeds.
%%
%% The EUnit module beside this one proves the properties of the counter
%% mechanism in isolation: an atomic add, a registry, a volatile total, no timer.
%% This suite covers what only a running router can answer — that the counter
%% home is a real child of the router's supervision tree, that the read API's key
%% set matches the list that declares it, and that a counter survives a
%% presentation app that never attached.
%%
%% The router is started as an application here rather than assembled from parts,
%% because the claim under test is about the supervision tree's own contents.

-module(i2p_read_api_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-export([all/0, suite/0]).

-export([
    stats_is_a_supervised_child/1,
    stats_is_restarted_after_dying/1,
    view_key_set_matches_the_declared_list/1,
    view_reports_version_and_uptime/1,
    core_exposes_only_cumulative_values/1,
    backlog_reaches_the_read_api/1,
    counters_are_readable_with_no_presentation_app/1,
    bus_announcements_are_counted/1,
    counters_are_volatile_across_a_router_restart/1
]).

-define(APP, i2per).

all() ->
    [
        stats_is_a_supervised_child,
        stats_is_restarted_after_dying,
        view_key_set_matches_the_declared_list,
        view_reports_version_and_uptime,
        core_exposes_only_cumulative_values,
        backlog_reaches_the_read_api,
        counters_are_readable_with_no_presentation_app,
        bus_announcements_are_counted,
        counters_are_volatile_across_a_router_restart
    ].

suite() ->
    [{timetrap, 60000}].

%% %%%%% %%% The counter home is in the tree %%%%% %%%

%% A counter home that nothing supervises would keep its reference alive across
%% a crash while the tree reported it as running. The tree is the statement of
%% what is running, so the home belongs in it.
stats_is_a_supervised_child(_Config) ->
    ok = with_router(fun() ->
        Children = supervisor:which_children(i2per_sup),
        ?assert(lists:keymember(i2p_stats, 1, Children)),
        {i2p_stats, Pid, worker, _Modules} = lists:keyfind(i2p_stats, 1, Children),
        ?assert(is_pid(Pid)),
        ?assertEqual(Pid, whereis(i2p_stats))
    end).

%% Restart-bound, proved by killing it rather than by reading the child spec.
%% A spec that merely says `permanent` and a supervisor that actually honours it
%% are different claims, and only one of them survives a bad day.
stats_is_restarted_after_dying(_Config) ->
    ok = with_router(fun() ->
        Before = whereis(i2p_stats),
        exit(Before, kill),
        ok = i2p_ct_helpers:await(
            fun() ->
                case whereis(i2p_stats) of
                    undefined -> false;
                    Pid when Pid =:= Before -> false;
                    _ -> true
                end
            end,
            10000
        ),
        After = whereis(i2p_stats),
        ?assertNotEqual(Before, After),
        %% And the counters still work against the new reference, rather than
        %% against the one whose process is gone.
        ok = i2p_stats:add(events_notified, 2),
        ?assertEqual(2, maps:get(events_notified, i2p_stats:snapshot()))
    end).

%% %%%%% %%% The read API's shape %%%%% %%%

%% The key set has one source of truth. This is the only place drift gets caught
%% before a consumer finds it, and it is what makes "additive-only" enforceable
%% rather than aspirational: a key added to the view without being declared here
%% fails, and so does a declared key the view stopped returning.
view_key_set_matches_the_declared_list(_Config) ->
    ok = with_router(fun() ->
        View = i2p_status_data:view(),
        ?assertEqual(lists:sort(maps:keys(View)), lists:sort(i2p_status_data:view_keys()))
    end).

%% Version, uptime and boot time are what a consumer uses to decide whether it
%% understands the data it was handed. The version is a positive integer rather
%% than a string, so ordering two of them is a numeric comparison and a consumer
%% cannot mistake "10" for a parse failure against 9.
view_reports_version_and_uptime(_Config) ->
    ok = with_router(fun() ->
        View = i2p_status_data:view(),
        ?assert(is_integer(maps:get(version, View))),
        ?assert(maps:get(version, View) > 0),
        ?assert(is_integer(maps:get(uptime_ms, View))),
        ?assert(maps:get(uptime_ms, View) >= 0),
        ?assert(is_integer(maps:get(boot_time, View))),
        %% It is a wall clock reading and not a duration that has been mistaken
        %% for one. Both bounds matter: a duration would be small and would pass
        %% a positivity check, and a monotonic reading would be arbitrary and
        %% would pass a "before now" check.
        Boot = maps:get(boot_time, View),
        ?assert(Boot > 1_000_000_000_000),
        ?assert(Boot =< erlang:system_time(millisecond)),
        %% And it is the same boot the uptime is measured from, rather than a
        %% second independently-taken reading that could disagree with it. Boot
        %% time is stored, so two reads are equal; uptime is recomputed from the
        %% clock on every call, so two reads are only equal within the
        %% millisecond that elapsed between them. Asserting they were equal was a
        %% flake that only showed up when the whole suite ran.
        ?assertEqual(i2p_stats:boot_time(), maps:get(boot_time, View)),
        %% What can be said about uptime without racing the clock: a second
        %% reading is never behind the first.
        ?assert(i2p_stats:uptime_ms() >= maps:get(uptime_ms, View))
    end).

%% The other half of the division of labour, asserted from the core's side.
%%
%% The client is supposed to difference and divide; the core is supposed to
%% publish cumulative totals and a boot time and nothing else. If a rate or a
%% ratio ever appears here, the counter home has acquired a timer or a smoothing
%% window, and the property that lets the whole thing stay cheap — one atomic add
%% on a packet path, no derived state to keep — has been given up. A derived value
%% in the read API is also the thing that cannot be recomputed by a reader, which
%% is the property that makes the displayed ratio trustworthy.
%%
%% Checked three ways, because a name filter alone would miss a ratio hidden
%% under an innocent-looking key: the key names, the value types, and that a
%% second reading of an unchanged router is bit-identical. That last one is the
%% strong form — any timer, smoothing, or window would make two readings differ.
core_exposes_only_cumulative_values(_Config) ->
    ok = with_router(fun() ->
        View = i2p_status_data:view(),

        %% Nothing named like a derived quantity.
        Derived = [K || K <- i2p_status_data:view_keys(), looks_derived(K)],
        ?assertEqual([], Derived),
        DerivedCounters = [K || K <- maps:keys(maps:get(counters, View)), looks_derived(K)],
        ?assertEqual([], DerivedCounters),
        ?assertEqual([], [N || N <- i2p_stats:counters(), looks_derived(N)]),

        %% Every counter is a plain non-negative integer: a total, not an average.
        Values = maps:values(maps:get(counters, View)),
        ?assertEqual([], [V || V <- Values, not (is_integer(V) andalso V >= 0)]),

        %% And no gauge is named like a derived quantity either. The filter above
        %% walks the key names, and `bus_backlog` would pass it while a
        %% `backlog_rate` would not -- so the check reaches the gauges' own names,
        %% which is the only place a derived value could hide now that they are
        %% carried beside the counters rather than inside them.
        DerivedGauges = [K || K <- maps:keys(maps:get(gauges, View)), looks_derived(K)],
        ?assertEqual([], DerivedGauges),

        %% And two readings of an unchanged router agree on everything except the
        %% clock. A timer, a smoothing window, or any other derived state would
        %% make a cumulative value move between two reads; cumulative totals and a
        %% boot time cannot.
        %%
        %% Two fields legitimately differ between readings, and neither is a
        %% derived *quantity*:
        %%
        %% `uptime_ms` is recomputed from the clock on every call. It is the sample
        %% clock the client differences against, not a total, and it may only move
        %% forwards.
        %%
        %% `gauges` holds sampled instantaneous values -- `bus_backlog`, refreshed
        %% on a timer by `m:i2p_events:sample_backlog/0` -- so a reading may change
        %% because the sampler ran between two calls. **This is a real exception and
        %% it is why gauges are a separate key rather than entries in `counters`**:
        %% putting them in the counters would have made the bit-identical assertion
        %% below false on a timer, which is precisely the property that proves a
        %% counter is a total. A gauge is allowed to move without anyone deriving
        %% anything from it.
        %%
        %% So the strong form is asserted where it is meaningful: over everything
        %% except the two fields that are sampled rather than counted.
        Again = i2p_status_data:view(),
        Sampled = [uptime_ms, gauges],
        ?assertEqual(
            maps:without(Sampled, View),
            maps:without(Sampled, Again)
        ),
        ?assert(maps:get(uptime_ms, Again) >= maps:get(uptime_ms, View)),

        %% And the gauges are gauges, not counters in disguise: whatever they hold,
        %% every value is an instant's reading, and nothing in them is derived from
        %% the counters. A gauge that were a running total would reintroduce the
        %% ambiguity `f:i2p_stats:add/2` refuses to create.
        Gauges = maps:get(gauges, View),
        ?assertEqual([], [V || V <- maps:values(Gauges), not is_number(V)])
    end).

%% The bus backlog reaches the read API, on a whole router.
%%
%% **This is the case that makes the gauge a read-API figure rather than a
%% curiosity in `m:i2p_stats`.** `m:i2p_events_tests` covers the sampling and the
%% value under a wedge; that module does not start `m:i2p_tunnel_srv`, so it cannot
%% call `f:view/0`. Only a whole router can, so only here can it be shown that the
%% key is carried rather than merely held.
%%
%% **Presence is the assertion, not the value.** A backlog of zero on an idle router
%% is correct and uninteresting, and a case that waited for a non-zero reading would
%% be a deadline in disguise -- so this takes the reading it is given. The wedge
%% case in `m:i2p_events_tests` is where the interesting value lives.
backlog_reaches_the_read_api(_Config) ->
    ok = with_router(fun() ->
        View = i2p_status_data:view(),
        Gauges = maps:get(gauges, View),
        ?assert(maps:is_key(bus_backlog, Gauges)),
        %% Absent-before-first-sample is a distinction `f:gauges/0` promises, and on
        %% a freshly started router the sampler may not have run yet -- so the
        %% value is only constrained when the name is there at all.
        case maps:find(bus_backlog, Gauges) of
            {ok, Depth} -> ?assert(is_integer(Depth) andalso Depth >= 0);
            error -> ok
        end,
        %% And it is not in the counters, which is the property the derive layer's
        %% differencing depends on.
        ?assertNot(maps:is_key(bus_backlog, maps:get(counters, View)))
    end).

%% A counter or key whose name says it was computed from other numbers rather than
%% counted. Deliberately narrow: it looks for the vocabulary of derived
%% quantities, not for "anything new".
looks_derived(Name) when is_atom(Name) ->
    Text = string:lowercase(atom_to_list(Name)),
    lists:any(
        fun(Word) -> string:find(Text, Word) =/= nomatch end,
        [
            "rate",
            "ratio",
            "per_second",
            "persecond",
            "average",
            "ewma",
            "smoothed",
            "_pct",
            "percent",
            "window",
            "recent"
        ]
    ).

%% The reason the counters live in the core. Before this, the only counters in
%% the tree were in the separate status application, so every total was measured
%% from the moment somebody attached to watch: a router nobody watched reported
%% nothing, and a router watched for an hour reported an hour rather than its
%% lifetime. Nothing is attached here at all.
counters_are_readable_with_no_presentation_app(_Config) ->
    ok = with_router(fun() ->
        ?assertEqual(undefined, whereis(i2per_status_state)),
        Counters = maps:get(counters, i2p_status_data:view()),
        ?assertEqual(lists:sort(i2p_stats:counters()), lists:sort(maps:keys(Counters))),
        Before = maps:get(events_notified, Counters),
        ok = i2p_events:notify({tunnel_expired, outbound}),
        ?assertEqual(Before + 1, maps:get(events_notified, i2p_stats:snapshot()))
    end).

%% The one counter this work shipped, on a path that already existed. Announcing
%% on the bus moves it whether or not anyone is listening, which is what makes it
%% usable as the "is anything instrumented yet" figure: a router whose status page
%% is empty can be asked whether the bus is even being used.
bus_announcements_are_counted(_Config) ->
    ok = with_router(fun() ->
        Before = maps:get(events_notified, i2p_stats:snapshot()),
        N = 5,
        lists:foreach(
            fun(I) -> ok = i2p_events:notify({tunnel_expired, expired_direction(I)}) end,
            lists:seq(1, N)
        ),
        ?assertEqual(Before + N, maps:get(events_notified, i2p_stats:snapshot()))
    end).

%% Volatile, and the boot time moves with the counters. A total that survived a
%% restart while the uptime reset would make the first rate derived after that
%% restart wrong, and wrong in the shape of a traffic spike — the one thing an
%% operator watching a graph cannot be left to guess about.
counters_are_volatile_across_a_router_restart(_Config) ->
    ok = start_readable_router(),
    ok = i2p_events:notify({tunnel_expired, outbound}),
    Before = maps:get(events_notified, i2p_stats:snapshot()),
    FirstBoot = i2p_stats:boot_time(),
    %% Let the first run accumulate uptime worth measuring, so an uptime carried
    %% through the stop and start would be visibly different from a restarted
    %% one. Without this the two are both small and the assertion proves nothing.
    timer:sleep(1500),
    UptimeBefore = i2p_stats:uptime_ms(),
    ?assert(UptimeBefore >= 1500),
    ok = stop_readable_router(),
    ok = start_readable_router(),
    try
        ?assert(maps:get(events_notified, i2p_stats:snapshot()) < Before),
        ?assert(i2p_stats:boot_time() > FirstBoot),
        %% The new uptime is smaller than the old one, so it restarted: it is
        %% measuring the run happening now, not the run before it.
        ?assert(i2p_stats:uptime_ms() < UptimeBefore)
    after
        ok = stop_readable_router()
    end.

%% %%%%% %%% Internal helpers %%%%% %%%

%% The bus's event type wants a direction, and alternating keeps the fixture from
%% depending on a single shape.
expired_direction(N) when N rem 2 =:= 1 -> outbound;
expired_direction(_N) -> inbound.

%% Start a router the read API can actually answer for, run the case, stop it.
%% Stopping in the same helper is what keeps one case's router out of the next
%% case's assertions — and out of the next *suite*, which is how an
%% `already_started` failure ends up blamed on the wrong file.
with_router(Fun) ->
    ok = start_readable_router(),
    try
        Fun()
    after
        ok = stop_readable_router()
    end.

%% The read API is not answerable by the application alone: it asks the peer
%% manager, the tunnel manager and the SAM supervisor, and none of those three is
%% a child of the router's supervision tree. A case that only wants the counters
%% does not need them; a case that wants `i2p_status_data:view/0` does.
start_readable_router() ->
    {ok, _} = application:ensure_all_started(?APP),
    Local = local_identity(),
    unlinked(fun() -> i2p_peer:start_link(Local, []) end),
    unlinked(fun() -> i2p_tunnel_srv:start_link(Local) end),
    unlinked(fun() -> i2p_sam_sup:start_link() end),
    ok.

stop_readable_router() ->
    %% Reverse start order, and tolerate a case that killed one of them.
    _ = catch gen_server:stop(i2p_sam_sup),
    _ = catch i2p_tunnel_srv:stop(),
    _ = catch i2p_peer:stop(),
    ok = i2p_ct_helpers:stop_app(),
    ok.

%% Started unlinked on purpose. `start_link/1` from the test-case process means
%% a manager that correctly decides to stop takes the test process with it, and
%% the failure then reads as a crashed case rather than as the shutdown that
%% caused it.
unlinked(Start) ->
    {ok, Pid} = Start(),
    true = unlink(Pid),
    Pid.

%% A minimal router identity: the keys the peer and tunnel managers want, and a
%% RouterInfo built from them so the NetDb and the identity agree.
%%
%% This fixture is copy-pasted across roughly twenty suites, because
%% `m:i2p_ct_helpers:floodfill_router_info/2` deliberately keeps no private keys
%% and a manager that owns a connection needs them. Collapsing it onto the shared
%% helper is the right fix and is worth doing, but it touches every suite in the
%% tree and does not belong in a telemetry ticket. Duplicating the existing
%% recipe here is the lesser evil, and this comment is where the next person
%% looks before adding a twenty-third copy.
local_identity() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(
        <<"127.0.0.1">>, i2p_ct_helpers:free_port(), StaticPub, IV
    ),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        hash => i2p_router_info:hash(RI),
        iv => IV,
        ri => RI
    }.
