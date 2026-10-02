-module(i2per_status_derive_tests).

-moduledoc """
Tests for the client's half of the telemetry contract.

Every function here is a pure function of two cumulative readings, so every
assertion is an exact equality. That is the point of the division: the core
publishes totals, the client differences them, and neither side needs a clock or
a timer to be checked.
""".

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%%%% A first reading has no rate %%%%% %%%%%

first_reading_has_no_rate_test() ->
    Derived = i2per_status_derive:derive(undefined, sample(#{ntcp2_bytes_out => 5000}, 1000, 1)),
    ?assertEqual(no_previous_sample, maps:get(window_status, Derived)),
    ?assertEqual(undefined, maps:get(window_ms, Derived)),
    Undefined = maps:get(total, maps:get(transfer_bps, Derived)),
    ?assertEqual(undefined, Undefined).

%% A rate is a difference, so with one reading there is nothing to difference
%% against. The four fields are all `undefined` rather than zero: a zero would be
%% read as "no traffic in this window", which is a different claim.
first_reading_has_no_rate_at_all_test() ->
    Bps = maps:get(transfer_bps, i2per_status_derive:derive(undefined, sample(#{}, 0, 1))),
    ?assertEqual(
        [undefined, undefined, undefined, undefined],
        [maps:get(K, Bps) || K <- [ntcp2, ssu2, transit, total]]
    ).

%% The ratio needs no window -- it is cumulative over the router's life -- so it
%% is available from the first reading. Withholding it would be a false "no data".
first_reading_still_has_a_ratio_test() ->
    Derived = i2per_status_derive:derive(undefined, sample(tunnel_counters(3, 1), 1000, 1)),
    ?assertEqual(0.75, maps:get(tunnel_success_ratio, Derived)),
    ?assertEqual(3, maps:get(tunnels_built, Derived)),
    ?assertEqual(1, maps:get(tunnels_failed, Derived)).

%% %%%%% %%%%% A rate over a window %%%%% %%%%%

rate_is_the_difference_over_the_window_test() ->
    %% 20 000 bytes over a 5 000 ms window is 4 000 B/s.
    Before = sample(#{ntcp2_bytes_out => 0}, 1000, 7),
    After = sample(#{ntcp2_bytes_out => 20_000}, 6000, 7),
    Derived = i2per_status_derive:derive(Before, After),
    ?assertEqual(ok, maps:get(window_status, Derived)),
    ?assertEqual(5000, maps:get(window_ms, Derived)),
    Bps = maps:get(transfer_bps, Derived),
    ?assertEqual(4000, maps:get(ntcp2, Bps)),
    ?assertEqual(4000, maps:get(total, Bps)).

%% The window is the router's monotonic uptime, not a wall clock, so a client
%% whose clock steps produces no wrong rate. Here the client clock is not even
%% consulted -- the two readings carry no timestamps at all.
rate_uses_the_routers_uptime_not_a_wall_clock_test() ->
    Before = sample(#{ssu2_bytes_in => 0}, 0, 7),
    After = sample(#{ssu2_bytes_in => 10_000}, 2000, 7),
    Derived = i2per_status_derive:derive(Before, After),
    ?assertEqual(5000, maps:get(ssu2, maps:get(transfer_bps, Derived))).

both_transports_are_summed_into_the_total_test() ->
    Before = sample(#{}, 0, 7),
    After = sample(#{ntcp2_bytes_out => 1000, ssu2_bytes_in => 3000}, 1000, 7),
    Bps = maps:get(transfer_bps, i2per_status_derive:derive(Before, After)),
    ?assertEqual(1000, maps:get(ntcp2, Bps)),
    ?assertEqual(3000, maps:get(ssu2, Bps)),
    ?assertEqual(4000, maps:get(total, Bps)).

%% Transit is reported but kept out of the total, because it is a wire upper
%% bound for other routers' traffic and adding it to our own would be a
%% category error. That distinction is the point of counting it separately.
transit_is_reported_separately_from_the_total_test() ->
    Before = sample(#{}, 0, 7),
    After = sample(#{transit_bytes_in => 9000, ntcp2_bytes_out => 1000}, 1000, 7),
    Bps = maps:get(transfer_bps, i2per_status_derive:derive(Before, After)),
    ?assertEqual(9000, maps:get(transit, Bps)),
    ?assertEqual(1000, maps:get(total, Bps)).

%% A smaller window over the same bytes is a higher rate. Without this, a
%% window-independent rate would pass every other case here.
rate_scales_with_the_window_test() ->
    Bytes = #{ntcp2_bytes_out => 10_000},
    Slow = maps:get(
        total,
        maps:get(
            transfer_bps,
            i2per_status_derive:derive(sample(#{}, 0, 7), sample(Bytes, 10_000, 7))
        )
    ),
    Fast = maps:get(
        total,
        maps:get(
            transfer_bps,
            i2per_status_derive:derive(sample(#{}, 0, 7), sample(Bytes, 1000, 7))
        )
    ),
    ?assertEqual(1000, Slow),
    ?assertEqual(10_000, Fast).

%% %%%%% %%%%% Discarding a window %%%%% %%%%%

%% Counters are volatile, so across a restart the later reading is lower. The
%% window is discarded rather than differenced into a large negative rate.
router_restart_discards_the_window_test() ->
    Before = sample(#{ntcp2_bytes_out => 9000}, 5000, 7),
    After = sample(#{ntcp2_bytes_out => 10}, 20, 8),
    Derived = i2per_status_derive:derive(Before, After),
    ?assertEqual(router_restarted, maps:get(window_status, Derived)),
    ?assertEqual(undefined, maps:get(window_ms, Derived)),
    ?assertEqual(undefined, maps:get(total, maps:get(transfer_bps, Derived))).

%% A restart is a new life, so the ratio restarts with it rather than being
%% carried across the boundary.
router_restart_resets_the_ratio_test() ->
    Before = sample(tunnel_counters(9, 1), 5000, 7),
    After = sample(tunnel_counters(0, 0), 20, 8),
    Derived = i2per_status_derive:derive(Before, After),
    ?assertEqual(router_restarted, maps:get(window_status, Derived)),
    ?assertEqual(undefined, maps:get(tunnel_success_ratio, Derived)).

%% Same boot, same uptime: a difference over a zero window is a division by zero,
%% not a rate.
zero_window_is_discarded_test() ->
    Derived = i2per_status_derive:derive(
        sample(#{ntcp2_bytes_out => 0}, 5000, 7), sample(#{ntcp2_bytes_out => 500}, 5000, 7)
    ),
    ?assertEqual(zero_window, maps:get(window_status, Derived)),
    ?assertEqual(undefined, maps:get(total, maps:get(transfer_bps, Derived))).

%% A counter that decreased within one boot should be impossible: `i2p_stats`
%% refuses a negative amount precisely so it cannot happen. The window is
%% discarded anyway, because a reading we cannot believe is not a reading to
%% difference -- the guard is about not reporting a wrong number, not about
%% distrusting the code.
counter_going_backwards_discards_the_window_test() ->
    Before = sample(#{ntcp2_bytes_out => 9000}, 0, 7),
    After = sample(#{ntcp2_bytes_out => 10}, 1000, 7),
    Derived = i2per_status_derive:derive(Before, After),
    ?assertEqual(counter_went_backwards, maps:get(window_status, Derived)),
    ?assertEqual(undefined, maps:get(total, maps:get(transfer_bps, Derived))).

%% A counter that disappeared is a change of shape, not a difference.
counter_disappearing_discards_the_window_test() ->
    Before = sample(#{ntcp2_bytes_out => 100, ssu2_bytes_out => 100}, 0, 7),
    After = sample(#{ntcp2_bytes_out => 200}, 1000, 7),
    Derived = i2per_status_derive:derive(Before, After),
    ?assertEqual(counter_went_backwards, maps:get(window_status, Derived)).

%% %%%%% %%%%% The success ratio %%%%% %%%%%

%% A plain cumulative ratio, which is the honest reproducible figure. The
%% reference implementation's displayed value is a modified exponentially-weighted
%% average starting from a 10% prior and smoothing by attempt count, so it is not
%% reproducible from counters even for the implementation that computes it. Ours
%% can be recomputed by hand from the two totals shown beside it.
ratio_is_a_plain_cumulative_ratio_test() ->
    ?assertEqual(0.5, i2per_status_derive:success_ratio(sample(tunnel_counters(1, 1), 0, 7))),
    ?assertEqual(0.75, i2per_status_derive:success_ratio(sample(tunnel_counters(3, 1), 0, 7))),
    ?assertEqual(0.0, i2per_status_derive:success_ratio(sample(tunnel_counters(0, 4), 0, 7))),
    ?assertEqual(1.0, i2per_status_derive:success_ratio(sample(tunnel_counters(4, 0), 0, 7))).

%% Every failure reason counts, and both directions. A ratio that ignored the
%% rejected reason would overstate success on a network where hops decline.
ratio_counts_every_direction_and_reason_test() ->
    %% One built against one failure, in each direction and for each reason, and
    %% a magnitude case. All the fractions are exactly representable, so these are
    %% equalities and not approximations: 1/2, 1/2, 1/4.
    ?assertEqual(
        0.5,
        i2per_status_derive:success_ratio(
            sample(#{tunnels_built_inbound => 1, tunnels_failed_inbound_rejected => 1}, 0, 7)
        )
    ),
    ?assertEqual(
        0.5,
        i2per_status_derive:success_ratio(
            sample(#{tunnels_built_outbound => 1, tunnels_failed_outbound_invalid => 1}, 0, 7)
        )
    ),
    %% The direction of the failure and the direction of the build are counted
    %% separately, so a build that succeeded inbound is not cancelled by an
    %% unrelated failure on the outbound side.
    ?assertEqual(
        0.5,
        i2per_status_derive:success_ratio(
            sample(#{tunnels_built_inbound => 1, tunnels_failed_outbound_invalid => 1}, 0, 7)
        )
    ),
    ?assertEqual(
        0.25,
        i2per_status_derive:success_ratio(
            sample(#{tunnels_built_inbound => 1, tunnels_failed_inbound_rejected => 3}, 0, 7)
        )
    ).

ratio_with_no_attempts_is_undefined_test() ->
    ?assertEqual(undefined, i2per_status_derive:success_ratio(sample(#{}, 0, 7))),
    Derived = i2per_status_derive:derive(undefined, sample(#{}, 0, 7)),
    ?assertEqual(undefined, maps:get(tunnel_success_ratio, Derived)).

%% The ratio is independent of the window, so two readings a millisecond apart and
%% two readings a minute apart give the same answer from the same totals.
ratio_does_not_depend_on_the_window_test() ->
    Counter = tunnel_counters(3, 1),
    Narrow = i2per_status_derive:derive(sample(Counter, 0, 7), sample(Counter, 1, 7)),
    Wide = i2per_status_derive:derive(sample(Counter, 0, 7), sample(Counter, 600_000, 7)),
    ?assertEqual(maps:get(tunnel_success_ratio, Narrow), maps:get(tunnel_success_ratio, Wide)).

%% %%%%% %%%%% Helpers %%%%% %%%%%

sample(Counters, UptimeMs, BootTime) ->
    #{counters => Counters, uptime_ms => UptimeMs, boot_time => BootTime}.

tunnel_counters(Built, Failed) ->
    #{tunnels_built_inbound => Built, tunnels_failed_inbound_invalid => Failed}.
