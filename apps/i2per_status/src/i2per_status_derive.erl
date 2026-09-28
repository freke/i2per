-module(i2per_status_derive).

-moduledoc """
Turn two cumulative readings from the router into a rate and a ratio.

The router's read API publishes cumulative counters and a boot time, and nothing
else. Everything time-dependent — a transfer rate, a tunnel success ratio — is
computed here, in the presentation app, by differencing two readings. That
division is the whole point: it is what lets the core's counter home be
timer-free, and this module is where the consequence lands.

## The sample clock is the router's

No clock is read in this module, and none is passed in. The window between two
readings is the difference in the router's own `uptime_ms`, which is monotonic.
So a client needs no trustworthy wall clock, an NTP step on the client cannot
produce a negative rate, and the two clocks that matter — the router's uptime and
the client's — cannot disagree about how much time passed.

## Cumulative in, cumulative out

Every figure here is a function of two readings, so it is exact and repeatable:
the same two readings always produce the same answer, which is also why the
tests can assert equality rather than a range.

## A reading is not enough for a rate

A rate is a difference, and one reading has nothing to difference against. The
first reading therefore yields `undefined` and says so, rather than a spike or a
division by zero. The **ratio** needs no window — it is cumulative over the
router's whole life — so it is available from the first reading, and withholding
it would be a false "no data".

## Discarding a window

Three things can make a difference between two readings meaningless, and each
discards the rate rather than reporting a wrong one:

- **the router restarted** (`boot_time` changed). Counters are volatile, so the
  later reading is lower than the earlier one for no reason other than a new
  process. Differencing across that would report a large negative rate.
- **a counter went backwards** within one boot. `m:i2p_stats` refuses to let one
  happen, so this is the guard against a wrong number rather than against a wrong
  code: if it is ever observed, the reading is not believed.
- **the window is zero**, which is a division by zero rather than a rate.
""".

-export([derive/2, success_ratio/1]).

-export_type([sample/0, derived/0]).

-doc """
One cumulative reading: the parts of the read API this module needs.

Input: the `counters` and `uptime_ms` of an `m:i2p_status_data:view/0` map.
Output: a map with the three fields below, all cumulative.
""".
-type sample() :: #{
    boot_time := integer() | undefined,
    uptime_ms := non_neg_integer(),
    counters := #{atom() => non_neg_integer()}
}.

-doc """
What two readings yield.

`window_status` says which of the three discard conditions applied, so a consumer
can tell "no rate yet" from "no rate because the router restarted" instead of
both arriving as `undefined`.
""".
-type derived() :: #{
    window_status :=
        no_previous_sample
        | ok
        | router_restarted
        | counter_went_backwards
        | zero_window,
    window_ms := non_neg_integer() | undefined,
    sampled_at_uptime_ms := non_neg_integer() | undefined,
    transfer_bps := bps(),
    tunnel_success_ratio := float() | undefined,
    tunnels_built := non_neg_integer() | undefined,
    tunnels_failed := non_neg_integer() | undefined
}.

-type bps() :: #{
    ntcp2 := non_neg_integer() | undefined,
    ssu2 := non_neg_integer() | undefined,
    transit := non_neg_integer() | undefined,
    total := non_neg_integer() | undefined
}.

-doc """
Derive a rate and a ratio from a previous and a current reading.

Input: the earlier reading or `undefined`, and the current reading. Output: a
`t:derived/0` map.

A ratio needs no window and so is present whenever the current reading is, even
on the first call. A rate needs a window, so every `transfer_bps` field is
`undefined` unless `window_status` is `ok`.
""".
-spec derive(sample() | undefined, sample()) -> derived().
derive(undefined, Current) ->
    derived(Current, no_previous_sample, undefined, undefined);
derive(Previous, Current) ->
    case {maps:get(boot_time, Previous), maps:get(boot_time, Current)} of
        {B, B} -> windowed(Previous, Current);
        _ -> derived(Current, router_restarted, undefined, undefined)
    end.

%% The boot times agree, so a difference between the counters is real — provided
%% none of them went backwards, which would mean the reading is not to be
%% believed.
windowed(Previous, Current) ->
    WindowMs = maps:get(uptime_ms, Current) - maps:get(uptime_ms, Previous),
    Prev = maps:get(counters, Previous),
    Now = maps:get(counters, Current),
    if
        WindowMs =< 0 ->
            derived(Current, zero_window, undefined, undefined);
        true ->
            windowed_ok(WindowMs, Prev, Now, Current)
    end.

%% The counters only have to be compared once the window is known to be usable.
windowed_ok(WindowMs, Prev, Now, Current) ->
    case backwards(Prev, Now) of
        true ->
            derived(Current, counter_went_backwards, undefined, undefined);
        false ->
            derived(Current, ok, WindowMs, bps(Prev, Now, WindowMs))
    end.

backwards(Prev, Now) ->
    lists:any(
        fun({Name, Before}) ->
            case maps:find(Name, Now) of
                {ok, After} -> After < Before;
                %% A counter that vanished was not re-registered, which is a
                %% change of shape and not a difference we can reason about.
                error -> true
            end
        end,
        maps:to_list(Prev)
    ).

%% Bytes per second over the window, as a rounded integer: an exact function of
%% its two readings, and unambiguous on the page where the window is stated
%% beside it. `total` is the two client-facing transports only — transit is
%% reported separately because it is a wire upper bound for other people's
%% traffic and is not comparable with them.
bps(Prev, Now, WindowMs) ->
    Per = fun(Names) ->
        lists:sum([delta(Name, Prev, Now) || Name <- Names])
    end,
    Ntcp2 = Per([ntcp2_bytes_in, ntcp2_bytes_out]),
    Ssu2 = Per([ssu2_bytes_in, ssu2_bytes_out]),
    Transit = Per([transit_bytes_in, transit_bytes_out]),
    Rate = fun(Bytes) -> round(Bytes * 1000 / WindowMs) end,
    #{
        ntcp2 => Rate(Ntcp2),
        ssu2 => Rate(Ssu2),
        transit => Rate(Transit),
        total => Rate(Ntcp2 + Ssu2)
    }.

delta(Name, Prev, Now) ->
    maps:get(Name, Now, 0) - maps:get(Name, Prev, 0).

derived(Current, Status, WindowMs, Bps) ->
    Counters = maps:get(counters, Current),
    #{
        window_status => Status,
        window_ms => WindowMs,
        sampled_at_uptime_ms => maps:get(uptime_ms, Current, undefined),
        transfer_bps => default_bps(Bps),
        tunnel_success_ratio => ratio_of_counters(Counters),
        tunnels_built => built(Counters),
        tunnels_failed => failed(Counters)
    }.

default_bps(undefined) ->
    #{ntcp2 => undefined, ssu2 => undefined, transit => undefined, total => undefined};
default_bps(Bps) ->
    Bps.

%% A plain cumulative ratio over the router's whole life, which is the honest and
%% reproducible figure.
%%
%% It is deliberately **not** the reference implementation's displayed value.
%% That is a modified exponentially-weighted average — it starts from a 10% prior
%% and smooths by attempt count — so it is not reproducible from counters even
%% for the implementation that computes it. Ours can be recomputed by hand from
%% the two totals shown beside it, which is the property worth having on a page
%% meant to be trusted. The divergence is recorded here and stated on the page.
%%
%% No attempts at all is `undefined`, not 0.0: a ratio of zero over zero has no
%% value, and rendering it as "0% successful" would read as total failure.
ratio_of_counters(Counters) ->
    Built = built(Counters),
    Failed = failed(Counters),
    case Built + Failed of
        0 -> undefined;
        Attempts -> Built / Attempts
    end.

built(Counters) ->
    counter(Counters, tunnels_built_inbound) + counter(Counters, tunnels_built_outbound).

failed(Counters) ->
    counter(Counters, tunnels_failed_inbound_invalid) +
        counter(Counters, tunnels_failed_inbound_rejected) +
        counter(Counters, tunnels_failed_outbound_invalid) +
        counter(Counters, tunnels_failed_outbound_rejected).

counter(Counters, Name) -> maps:get(Name, Counters, 0).

-doc """
The tunnel success ratio from one cumulative reading.

Input: a `t:sample/0`. Output: a fraction in `[0,1]`, or `undefined` when no
build has been attempted. Exported so the page and the tests read the same
definition rather than each having their own idea of the ratio.
""".
-spec success_ratio(sample()) -> float() | undefined.
success_ratio(Sample) -> ratio_of_counters(maps:get(counters, Sample)).
