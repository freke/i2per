-module(i2p_soak).

-moduledoc """
A soak run: drive metered load at a router, watch the node for unbounded
structures, and report what the numbers support.

**A diagnostic, not a gate.** It is not in `just check` and must not be: a
five-minute window cannot support a stability claim, and putting it in the gate
would assert one. `scripts/live_smoke.escript` is the precedent for "run
deliberately, never automatically", and the reason it lives in the tree rather
than an agent's scratch directory is that a measurement which exists only
somewhere else does not exist.

## What it does not exercise

Stated rather than implied, because the honest list is short:

- **The tunnel and transit paths under real load.** Those hold the tree's largest
  unbounded structures and have their own ticket (#KF1MX96); this run reaches the
  bus and the listener lifecycle, not a tunnel carrying frames.
- **Live network behaviour.** Hermetic by default, like `f:live_smoke` —
  self-seeded, offline. `--live` exists and is the operator's call.
- **Anything about crash recovery.** Nothing here kills a process on purpose and
  then asserts what restarted.

## Why the rate is a bounded parameter

The first version of this harness offered load in bursts separated by
`erlang:yield/0`, which is an **unbounded offer rate** — `yield/0` returns
immediately when there is nothing to yield to, so the generator offered as fast
as it could build. That drove refc binaries to 11 GB in under ten seconds and
produced an alarming number that had nothing to do with the router.

So the rate is named (`?MIN_RATE`..`?MAX_RATE`), bounded, and enforced through
`m:i2p_token_bucket` — the tree's own rate limiter, chosen because it is a pure
function of `(Bucket, Amount, NowMs)` and therefore testable without a clock.
An unbounded generator measures the generator; that is the whole lesson, and it
is why `f:load_window/2` refuses a rate outside the bounds rather than clamping
it: a silent clamp would let a reader believe they asked for something they did
not get.

## Why the fixtures stop their own children

`restart => temporary` children are **never stopped automatically**. A reconnect
path that opens a fresh listener without stopping the old one leaks the whole
subtree — measured at 8 processes per cycle, and *arithmetic rather than
traffic*, because it happens with zero traffic at all. `f:reconnect_cycle/1`
therefore takes a process census before and after N cycles with no traffic
offered, and reports the delta. A non-zero delta means the harness is dirty, not
that the router is: that distinction is the only reason the number is worth
taking.
""".

-export([run/1, load_window/2, reconnect_cycle/1, parse_rate/1]).
-export([offered_events/1]).

-export_type([opts/0, report/0]).

%% %%%%% %%% %%% Types %%%%% %%%

-doc """
What to run, and for how long.

Every field is a **named** parameter with a bounded range, and none of them has a
default that is chosen for the caller. `window_ms`, `quiet_ms`, `rate`,
`burst`, `cycles` and `top` are all explicit, because a soak whose shape is
implicit is a soak whose shape two runs of the same command do not share.
""".
-type opts() :: #{
    data_dir := file:filename_all(),
    port := inet:port_number(),
    window_ms := pos_integer(),
    quiet_ms := pos_integer(),
    rate := pos_integer(),
    burst := pos_integer(),
    cycles := pos_integer(),
    top := pos_integer(),
    live => boolean()
}.

-doc """
The run's whole answer: the self-checks, the verdict, and the fixture delta.

`ok` is the single field a caller should branch on, because it folds in the
self-checks — a run whose instrument could not demonstrate it detects a known
fault has measured nothing, however healthy the router looked.
""".
-type report() :: #{
    ok := boolean(),
    self_checks := [i2p_soak_selfcheck:check()],
    verdict := i2p_soak_census:verdict(),
    top_consumers := [i2p_soak_census:row()],
    top_mailboxes := [i2p_soak_census:row()],
    fixture_delta := non_neg_integer(),
    cycles := pos_integer(),
    offered_events => non_neg_integer(),
    rate => pos_integer(),
    failures => [string()]
}.

%% %%%%% %%% %%% Bounds %%%%% %%%

%% The offered-rate bounds. **Not tuning**: the lower bound is small enough to be
%% useless and the upper is where the harness, not the router, dominates. A
%% generator that outruns the thing it measures reports the generator.
%%
%% These live here and nowhere else. There is deliberately **no `rate_bounds/0`
%% accessor**: it would be a second copy of two numbers, in a shape dialyzer then
%% demands a spec for, and every caller would have to trust it agrees with these.
%% `f:parse_rate/1` is the only way in, and `m:i2p_soak_tests` pins the boundary
%% by asserting which rates it accepts -- so the behaviour is the source of truth
%% and these constants are its implementation.
-define(MIN_RATE, 1).
-define(MAX_RATE, 20000).

-doc """
Parse and range-check an offered rate.

Input: a string or integer. Output: `{ok, Rate}` or `{error, Reason}`.

**It refuses rather than clamps, and it does not coerce.** A rate of `"fast"` is
an error rather than a default. A clamped rate would let a reader believe they
asked for a million events a second and got 20,000, which is exactly the
"confident wrong answer" this harness exists to stop producing. The error names
the number asked for, so a reader can see what was rejected rather than infer it
from a ceiling.
""".
-spec parse_rate(integer() | string()) -> {ok, pos_integer()} | {error, string()}.
parse_rate(Rate) when is_integer(Rate) ->
    check_rate(Rate);
parse_rate(Rate) when is_list(Rate) ->
    try
        parse_rate(list_to_integer(Rate))
    catch
        error:badarg -> {error, "the offered rate is not an integer"}
    end.

-spec check_rate(integer()) -> {ok, pos_integer()} | {error, string()}.
check_rate(Rate) when Rate < ?MIN_RATE; Rate > ?MAX_RATE ->
    {error,
        lists:flatten(
            io_lib:format("offered rate ~p is outside ~p..~p", [Rate, ?MIN_RATE, ?MAX_RATE])
        )};
check_rate(Rate) ->
    {ok, Rate}.

%% %%%%% %%% %%% The run %%%%% %%%

-doc """
Run one soak and report.

Input: `t:opts/0`. Output: `t:report/0`.

The order is the argument for the order. The self-checks run **first**, because
everything after them is a measurement and a measurement from an instrument that
cannot demonstrate it detects a known fault is worth nothing. The fixture cycle
runs **last**, so its delta is taken against a node the load has already left, and
a non-zero delta is attributable to the reconnect path rather than to load still
in flight.
""".
-spec run(opts()) -> report().
run(Opts) ->
    Checks = i2p_soak_selfcheck:run(),
    {Rate, RateReason} = rate_of(Opts),
    ok = i2p_smoke:boot(boot_opts(Opts)),
    try
        {Offered, LoadBefore, LoadAfter} = load_window(Opts, Rate),
        Drained = quiet_window(Opts),
        FixtureDelta = reconnect_cycle(Opts),
        report(
            Opts, Checks, LoadBefore, LoadAfter, Drained, Offered, Rate, FixtureDelta, RateReason
        )
    after
        ok = i2p_smoke:shutdown()
    end.

-spec rate_of(opts()) -> {pos_integer(), string()}.
rate_of(Opts) ->
    case parse_rate(maps:get(rate, Opts)) of
        {ok, Rate} -> {Rate, ""};
        {error, Reason} -> {?MIN_RATE, Reason}
    end.

-doc """
The soak's options, shaped as the one options type `m:i2p_smoke` boots against.

Dialyzer treats a map type as closed, so the two maps this function passes on
have to have the shape `m:i2p_smoke` declares — not a superset with the soak's
extra knobs on it. So the soak's own fields are dropped here rather than handed
over, and a boot contract stays a statement about booting.
""".
-spec boot_opts(opts()) -> i2p_smoke:opts().
boot_opts(Opts) ->
    #{
        window_ms => maps:get(window_ms, Opts),
        data_dir => maps:get(data_dir, Opts),
        port => maps:get(port, Opts),
        live => maps:get(live, Opts, false)
    }.

-spec report(
    opts(),
    [i2p_soak_selfcheck:check()],
    i2p_soak_census:census(),
    i2p_soak_census:census(),
    i2p_soak_census:census(),
    non_neg_integer(),
    pos_integer(),
    non_neg_integer(),
    string()
) -> report().
report(Opts, Checks, LoadBefore, LoadAfter, Drained, Offered, Rate, FixtureDelta, RateReason) ->
    Loaded = i2p_soak_census:delta(LoadBefore, LoadAfter),
    Drain = i2p_soak_census:delta(LoadAfter, Drained),
    Top = maps:get(top, Opts),
    Verdict = i2p_soak_census:verdict(Loaded, Drain, Offered),
    Failures = failures(Checks, RateReason, FixtureDelta),
    #{
        ok => Failures =:= [],
        self_checks => Checks,
        verdict => Verdict,
        top_consumers => i2p_soak_census:top_consumers(Loaded, Top),
        top_mailboxes => i2p_soak_census:top_mailboxes(Loaded, Top),
        fixture_delta => FixtureDelta,
        cycles => maps:get(cycles, Opts),
        offered_events => Offered,
        rate => Rate,
        failures => Failures
    }.

-spec failures([i2p_soak_selfcheck:check()], string(), non_neg_integer()) -> [string()].
failures(Checks, RateReason, FixtureDelta) ->
    Checked = [Evidence || #{ok := false, evidence := Evidence} <- Checks],
    Rate =
        case RateReason of
            "" -> [];
            _ -> [RateReason]
        end,
    Fixture =
        case FixtureDelta of
            0 ->
                [];
            N ->
                [lists:flatten(io_lib:format("the reconnect cycle left ~p processes behind", [N]))]
        end,
    Checked ++ Rate ++ Fixture.

%% %%%%% %%% %%% The load window %%%%% %%%

-doc """
Offer metered load for `window_ms` and return what happened.

Input: `Opts` and the offered rate. Output: `{OfferedCount, CensusAfterLoad}`.

**The rate is metered by a token bucket, not by a sleep.** A sleep between
bursts is the bug this function exists to avoid: `erlang:yield/0` separates
bursts at the speed of the scheduler, which is no bound at all. `f:i2p_token_bucket`
accrues at the named rate against an explicit clock, so the offered count is a
function of the rate and the window rather than of how busy the machine was.
""".
-spec load_window(opts(), pos_integer()) ->
    {non_neg_integer(), i2p_soak_census:census(), i2p_soak_census:census()}.
load_window(Opts, Rate) ->
    Before = census(),
    Offered = offer(maps:get(window_ms, Opts), Rate, maps:get(burst, Opts)),
    {Offered, Before, census()}.

-doc """
Offer load for `WindowMs` at `Rate` per second, and return how many were offered.

The count is **returned rather than assumed**, so the verdict can state how much
traffic the number is about — a slope beside "0 events offered" is a slope with
nothing to attribute it to.

**It is the offered count, not a delivered one.** Per `CONTEXT.md`, notified and
delivered are different figures and a rising offered count says nothing about
receipt, so this function measures neither and does not claim to.
""".
-spec offer(pos_integer(), pos_integer(), pos_integer()) -> non_neg_integer().
offer(WindowMs, Rate, Burst) ->
    Bucket = i2p_token_bucket:new(Rate, Burst),
    Deadline = now_ms() + WindowMs,
    offer_until(Bucket, Rate, Deadline, 0).

%% `i2p_token_bucket:consume/3` accrues `Elapsed * Rate / 1000` tokens, so it
%% needs **epoch** milliseconds. `erlang:monotonic_time/1` is a different clock
%% and is negative on this platform, which makes every `Elapsed` negative, which
%% accrues nothing -- the bucket then hands out exactly its initial burst and
%% never another token. That failure is silent: the run reports a plausible
%% offered count and a load window an order of magnitude lighter than asked for.
-spec now_ms() -> integer().
now_ms() ->
    erlang:system_time(millisecond).

-spec offer_until(i2p_token_bucket:bucket(), pos_integer(), integer(), non_neg_integer()) ->
    non_neg_integer().
offer_until(Bucket0, Rate, Deadline, Count) ->
    Now = now_ms(),
    case Now >= Deadline of
        true ->
            Count;
        false ->
            case i2p_token_bucket:consume(Bucket0, 1, Now) of
                {allow, Bucket1} ->
                    ok = i2p_events:notify({peer_disconnected, soak_hash()}),
                    offer_until(Bucket1, Rate, Deadline, Count + 1);
                deny ->
                    %% The bucket is empty, so this generator has offered
                    %% everything the named rate allows. Sleeping until a token
                    %% accrues is what makes the rate a bound rather than an
                    %% average.
                    timer:sleep(tick(Rate)),
                    offer_until(Bucket0, Rate, Deadline, Count)
            end
    end.

%% The event this harness announces to generate load.
%%
%% **The shape is written out at the call site on purpose.**
%% `m:i2p_events_vocabulary_tests` scans the router sources for every call to the
%% bus's `f:notify/1` and requires each argument to *begin* with a literal tuple,
%% so that the bus's vocabulary is readable from the call sites rather than only
%% from the type. Wrapping the shape in a helper would hide it behind a function
%% call, and that scan would then report a smaller world than the router
%% announces -- which is the failure the test exists to prevent. One line of
%% duplication at the call site is cheaper than being invisible to the tree's own
%% check. (The call is therefore written out here rather than factored out, and
%% this comment cannot name it verbatim without becoming a false call site.)
%%
%% `{peer_disconnected, Hash}` is the cheapest event on a router that is churning
%% peers, and costs the emitter nothing but the bus. It is a **fabricated fact,
%% deliberately**: the soak is not measuring whether peers disconnect, it is
%% measuring what the node does with a bounded number of announcements. So the
%% report's count is labelled *offered* and the verdict claims nothing about
%% delivery (`CONTEXT.md`: notified and delivered are different figures). A
%% subscriber counting these would be counting a fiction.
%%
%% `t:i2p_events:event/0` is a closed union of real events, so the harness cannot
%% invent a shape of its own.
-doc """
The hash every announcement is about, so they are all about the same absent peer.

`t:i2p_events:event/0` wants an `t:i2p_crypto:hash/0` and the tree has no zero-arg
hash constructor, so this is one `crypto:hash/2` over a fixed label — and it is a
hash of nothing real, which is the point: a reader of a bus log can tell a soak's
traffic from a router's without needing to know the soak ran.
""".
-spec soak_hash() -> i2p_crypto:hash().
soak_hash() ->
    crypto:hash(sha256, <<"i2per-soak">>).

-doc """
How long to wait for one token, in milliseconds.

Input: the offered rate. Output: a positive number of milliseconds.

Derived from the rate so there is one knob rather than two: a hardcoded tick is
either too slow at low rates (soaking the harness instead of the router) or too
fast at high ones (which is the unbounded offer rate again).
""".
-spec tick(pos_integer()) -> pos_integer().
tick(Rate) ->
    max(1, 1000 div Rate).

-doc """
Stop offering and let the node settle, then read it again.

Input: `Opts`. Output: `{DrainedCount, Census}`.

This is the window that separates the two retention causes in
`m:i2p_soak_census`: a structure that gives its memory back once the traffic
stopped was retaining in proportion to what it was given, and one that does not
has been filled by something else.
""".
-spec quiet_window(opts()) -> i2p_soak_census:census().
quiet_window(Opts) ->
    timer:sleep(maps:get(quiet_ms, Opts)),
    census().

-spec offered_events(report()) -> non_neg_integer().
offered_events(#{offered_events := Offered}) ->
    Offered.

-spec census() -> i2p_soak_census:census().
census() ->
    {ok, Census} = i2p_soak_census:snapshot(),
    Census.

%% %%%%% %%% %%% The reconnect cycle %%%%% %%%

-doc """
Run `cycles` reconnect cycles with **no traffic**, and report the process delta.

Input: `Opts`. Output: the change in the node's process count, or a negative
figure if it shrank.

**No traffic is the point.** A `restart => temporary` child is never stopped by
its supervisor, so a reconnect path that opens a fresh child without stopping the
old one leaks the subtree — measured here at **2 processes per cycle**, with
nothing offered, so it is arithmetic rather than something load-dependent.
Running the cycle under load would make the number depend on two things at once,
so it is deliberately traffic-free and the delta it reports is about the fixtures
alone.

A delta of 0 is the only passing answer. Anything else means the harness left the
node dirty, and a harness that dirties the node cannot measure the next run.
`i2p_soak_tests` measures **both** halves of this — with the stop, and without —
so that a flat count is known to be a result rather than a decoration.
""".
-spec reconnect_cycle(opts()) -> integer().
reconnect_cycle(Opts) ->
    Cycles = maps:get(cycles, Opts),
    IntroKey = crypto:strong_rand_bytes(32),
    Before = length(erlang:processes()),
    lists:foreach(fun(_) -> reconnect_once(IntroKey) end, lists:seq(1, Cycles)),
    length(erlang:processes()) - Before.

-doc """
One reconnect: start a `temporary` child and stop it again.

**The stop is the whole point of the function.** Without it the previous child is
still alive — `temporary` means nobody else will reap it — and the count above
grows by a subtree per cycle.

This is the router's own reconnect path rather than a fixture invented for the
harness: `m:i2p_ssu2_listener`'s `restart_charlie/1` replaces a dead Charlie
responder this same way, and says so in a comment. It is a Charlie responder
rather than an NTCP2 listener because a responder needs one X25519 key where a
listener needs a whole `t:i2p_ntcp2_conn:local_keys/0` including a signed
RouterInfo — so the cycle stays cheap enough for the unit tier, and what is under
test is the supervisor's `temporary` policy rather than key material.
""".
-spec reconnect_once(i2p_crypto:key()) -> ok.
reconnect_once(IntroKey) ->
    case i2p_ssu2_sup:start_charlie(IntroKey) of
        {ok, _Charlie} ->
            ok = stop_charlie();
        {error, _Reason} ->
            %% A supervisor that will not start a child is not a finding. The
            %% cycle is about what is left behind, not about what got opened.
            ok
    end.

-doc """
Stop every Charlie responder this supervisor is holding.

**`terminate_child/2` alone, with no `delete_child/2` after it** — because these
are `temporary` children, and terminating one deletes it from the supervisor's
table as part of the same call. Adding the delete makes the second call answer
`{error, not_found}` on every cycle. That is worth writing down rather than
rediscovering: the two calls look like the obvious pair, and the supervisor
contract says the first one already did both jobs.
""".
-spec stop_charlie() -> ok.
stop_charlie() ->
    lists:foreach(fun stop_child/1, charlie_child_ids()),
    ok.

-spec stop_child(term()) -> ok.
stop_child(Id) ->
    ok = supervisor:terminate_child(i2p_ssu2_sup, Id).

-spec charlie_child_ids() -> [tuple()].
charlie_child_ids() ->
    [
        Id
     || {Id, _Pid, _Type, _Modules} <- supervisor:which_children(i2p_ssu2_sup),
        is_tuple(Id),
        element(1, Id) =:= ssu2_charlie
    ].
