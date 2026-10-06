-module(i2p_soak_tunnel).

-moduledoc """
A soak of the **tunnel and transit** paths: the router's own largest unbounded
structures, under sustained load, with a verdict about what the numbers support.

`m:i2p_soak` drives the bus and the listener lifecycle and says plainly in its
module doc that it does **not** reach a tunnel carrying frames. This module is
the other half, and it exists because of the one gap that mattered: the run that
motivated #KF1MX96 reported flat retention across five phases and **every tunnel
counter in it read zero**. A clean result from an instrument pointed at the wrong
structures is the failure mode this whole harness family exists to prevent, and
the ticket's first acceptance criterion is that the run **asserts** the counters
moved rather than assuming it.

## What it exercises, and what it does not

**Exercised**, all of it the router's own code and its own crypto:

- **Real inbound tunnel builds** — `m:i2p_tunnel_build`, ECIES record encryption,
  hop selection from the NetDb, the returning ShortTunnelBuild, and activation
  into the inbound pool.
- **Real outbound tunnel builds** — the same, plus the reply path: the
  OutboundTunnelBuildReply travels back **through an active inbound tunnel's data
  path**, fragmented by the inbound gateway, so the inbound endpoint and the
  gateway roles are on the measured path too.
- **Real transit** — a ShortTunnelBuild from a remote creator is admitted into
  the transit map and 1028-byte frames are relayed through it with real layer
  encryption.
- **The NetDb writer**, under the real supervisor, writing the store the builds
  read from.

**Not exercised**, and the distinction is the ticket's whole argument rather than
a disclaimer bolted on:

- **The wire between hops.** A build's garlic is intercepted and its records are
  walked hop by hop in this process with the router's own
  `m:i2p_tunnel:process_short_tunnel_build/4` and `f:apply_build_reply/3`, then
  handed back as a sealed ShortTunnelBuild. This is the substitution
  `i2p_tunnel_srv_SUITE` makes, and it is the **only** substitution: every byte of
  crypto, every state transition and every counter is the router's.
- **The transports.** No socket carries any of this, so nothing here says
  anything about NTCP2, SSU2, or what a build costs on a real network.

## Why the router is booted without its peer manager

A fully booted router cannot be this harness, and that was measured rather than
assumed. Boot it the way `m:i2p_smoke` does — self-seeded, hermetic — and the
NetDb holds exactly one RouterInfo, the router's own, so `f:select_hops/2` has
nothing to select and the build **silently skips**: `tunnels_built_inbound` stays
`0`. `m:i2p_peer` is also live, so a mock cannot take the name.

The seam is the supervisor's own resolve. `m:i2per_sup:resolve_local/0` returns
`error` when `data_dir` is set and `seeds` is **not**, and `manager_children(error)`
is `[]`. So `f:boot/1` here sets a data dir and deliberately leaves `seeds` unset,
then starts its own `m:i2p_tunnel_srv` and registers its own `m:i2p_peer`.
Measured, the NetDb, **the NetDb writer**, `m:i2p_stats` and the bus are all live
under `m:i2per_sup`; only the peer manager and the tunnel manager are absent.

**That is a configuration shape `m:i2per_sup` already has, not a test hook added
for this harness.** No production code branches on being soaked.

## Why the mock peer forwards

It forwards every `{send_when_ready, Hash, Garlic}` to this process, which is what
lets a build be driven to completion. The obvious wrong version — a mock that
swallows the cast — reports "no builds happened", which is indistinguishable from
a build path that is broken. That was measured while writing this module: the
first probe had exactly that bug and its output read as a broken router.

It also means **this process's own mailbox is on the measured path**, so the load
loop drains one message per build it asked for. A generator that asks for N builds
and consumes N replies has a mailbox proportional to nothing; one that asks and
forgets has one proportional to the traffic, and would report itself as the leak
it was sent to find.

## The verdict has four answers, not two

`m:i2p_soak_census:f:verdict/3` classifies on one load window against one quiet
window, separating *traffic-proportional retention* from *traffic-independent
filling*. **That cannot tell a cache from a leak**, and the ticket is explicit
that a single slope cannot either: a bounded cache that fills once and then
plateaus, and a structure with no bound, produce the same slope inside one window.

So this run takes **several measured phases** and compares them. Growth that
appears in the first phase and then flattens is a cache, and the verdict says so
rather than reporting a number with no shape. Per `CONTEXT.md`, neither answer is
called a leak: telling an unbounded structure from a cache that filled once needs
a window longer than any run here has.

## A diagnostic, not a gate

Not in `just check`, for the reason `m:i2p_soak` gives: a bounded window cannot
support a stability claim. `scripts/soak_tunnels.escript` is the entry point and
every parameter is named and bounded.
""".

-export([run/1, boot/1, shutdown/0, load_window/2, minimum_phases/0, offered_rate/1]).
-export([warm_phase/2, phase/3, verdict/1, failures/3, total_offered/1]).
-export([retained_words/0, mailbox_slope/3, pools/0, counters/0, router_pids/0]).

-export_type([opts/0, report/0, phase/0, offered/0, verdict/0, retention/0, pools/0]).
-export_type([fabric/0, hop/0]).

%% %%%%% %%% %%% Bounds %%%%% %%%

%% The fewest measured phases that can answer the question.
%%
%% **Two, and it is a floor rather than a default.** One phase has one slope, and
%% the difference between a cache and a structure with no bound is *whether the
%% slope continues*, which needs at least two slopes to see. `f:phases/1` refuses
%% a run configured below it rather than answering with the weaker verdict it is
%% capable of.
-define(MIN_PHASES, 2).

%% How long to wait for one build to come back round.
%%
%% **A deadline that bounds how long the run waits, not what it concludes.** A
%% build which produced no garlic is the silent skip `m:i2p_tunnel_build` performs
%% when the NetDb cannot supply hops, so a harness that waited forever would turn
%% a `requested` figure the built counts disagree with into a stuck run.
-define(BUILD_WAIT_MS, 10000).

%% How many hops one record set may name before it is called corrupt. A build is
%% three hops; the bound is on the walk, not on the protocol.
-define(MAX_WALK, 16).

%% How often to re-read a pool while waiting for it to hold a key. The wait is
%% ordered by `status/0` being a `gen_server:call`; this only bounds how often it
%% is asked.
-define(POOL_POLL_MS, 10).

%% One tunnel frame is 1028 bytes and `transit_bytes_in` counts the carried body,
%% so the delta converts to a frame count exactly. Deriving the frames from the
%% router's own byte count is what keeps the two figures from drifting apart.
-define(TRANSIT_FRAME_BYTES, 1028).

%% %%%%% %%% %%% Types %%%%% %%%

-doc """
What to soak, and for how long.

Every field is named and none has a default chosen for the caller, for the reason
`m:i2p_soak` gives: a soak whose shape is implicit is a soak whose shape two runs
of the same command do not share.

`phases` is the one that decides the verdict. `f:minimum_phases/0` is the floor and
`f:boot/1` refuses anything below it.
""".
-type opts() :: #{
    data_dir := file:filename_all(),
    port := inet:port_number(),
    warm_ms := pos_integer(),
    window_ms := pos_integer(),
    quiet_ms := pos_integer(),
    phases := pos_integer(),
    rate := pos_integer(),
    burst := pos_integer(),
    hops := pos_integer(),
    top := pos_integer(),
    live => boolean()
}.

-doc """
What the load actually accomplished, as opposed to what it was asked for.

**Three of the four are the router's own counters**, read back across the window:

| field | source |
|---|---|
| `requested` | build casts this module issued |
| `built_inbound` | `tunnels_built_inbound` delta |
| `built_outbound` | `tunnels_built_outbound` delta |
| `transit_frames` | `transit_bytes_in` delta ÷ 1028 |

A harness counting its own builds would be measuring itself. If the drive reported
three builds and the router's counter said one, **that difference is the finding** —
it means two never activated, which is exactly the case a retention figure beside
it cannot explain. So `requested` is carried next to the router's counts
deliberately, so a reader can see them disagree.
""".
-type offered() :: #{
    requested := non_neg_integer(),
    built_inbound := non_neg_integer(),
    built_outbound := non_neg_integer(),
    transit_frames := non_neg_integer()
}.

-doc """
One measured phase: the load offered, and what the node looked like around it.

`retained_words` is the figure that carries the argument. It is read through
`m:i2p_soak_census:f:retained/1`, which forces a full collection **and waits for
it** — a plain `total_heap_size` reading reports allocation since the last
collection, and on this build the two differ by up to 400x (#VH7Z0KJ).

`pools` is the structural reading: `map_size/1` of each map in the tunnel manager's
own state, which is exact where a heap reading is an inference. The `size/1`
from `erts_debug` is deliberately **not** used for this: measured on this build,
a two-key map measures 0 words, because small terms are literals and share no
storage.
""".
-type phase() :: #{
    index := 0 | pos_integer(),
    offered := offered(),
    retained_words := integer(),
    loaded_words := integer(),
    ets_bytes := non_neg_integer(),
    pools := pools(),
    mailbox_slope => [i2p_soak_census:row()],
    counters => #{atom() => non_neg_integer()}
}.

-doc """
The named structures this ticket is about, by `map_size/1`.

The four pools plus the two pending maps, named exactly as
`t:i2p_tunnel_srv:tunnel_srv_state/0` names them. `transit` is the one the ticket
calls out: bounded transit is a shipped feature, so this is where a per-tunnel
record that was never released would accumulate.
""".
-type pools() :: #{
    outbound := non_neg_integer(),
    inbound := non_neg_integer(),
    transit := non_neg_integer(),
    exploratory_outbound := non_neg_integer(),
    exploratory_inbound := non_neg_integer(),
    pending_outbound := non_neg_integer(),
    pending_inbound := non_neg_integer()
}.

-doc """
Why the structures grew, as far as several phases can tell.

- `traffic_proportional` — grew under load and **gave it back** once the load
  stopped. `CONTEXT.md`'s first cause: bounded by construction.
- `traffic_independent` — grew under load and kept it. A real finding, and still
  not a leak: it is what a cache filling once looks like over a window long enough
  to watch it fill.
- `plateau` — grew and then stopped. **This is the answer a two-window verdict
  cannot give**, and it is the difference between "something is filling up" and
  "something filled up and finished".
- `inconclusive` — nothing grew, or the load never happened.
""".
-type retention() :: traffic_proportional | traffic_independent | plateau | inconclusive.

-doc """
The run's answer, and the figures it reasoned from.

There is no `leak` field and there cannot be one: `CONTEXT.md` is explicit that
naming a slope a leak claims the structure is unbounded, which a bounded run
cannot show.
""".
-type verdict() :: #{
    retention := retention(),
    phase_words := [integer()],
    slope_words := integer(),
    note := binary()
}.

-doc """
The run's whole answer.

`ok` is the one field a caller should branch on, because it folds in the
self-checks **and the assertion that traffic actually happened** — a run whose
instrument could not demonstrate it detects a known fault, and which built no
tunnels, has measured nothing however healthy the router looked.
""".
-type report() :: #{
    ok := boolean(),
    self_checks := [i2p_soak_selfcheck:check()],
    verdict := verdict(),
    phases := [phase()],
    warm := phase(),
    offered := offered(),
    fixture_delta := integer(),
    offered_events := non_neg_integer(),
    rate := pos_integer(),
    failures := [string()]
}.

-doc """
One synthetic router the harness builds through.

A real signed RouterInfo with a real X25519 static key, because
`m:i2p_tunnel_build:f:extract_hop_descs/3` reads the hop's static key out of the
NetDb and the first record is encrypted to it. A stub hash would exercise hop
selection and nothing downstream of it.
""".
-type hop() :: #{
    static_priv := i2p_crypto:key(),
    static_pub := i2p_crypto:key(),
    hash := i2p_crypto:hash(),
    ri := i2p_router_info:router_info()
}.

-doc """
Everything the load loop needs: our own keys, the hops it builds through, and the
index the STB walk resolves `next_hash` against.

Returned by `f:boot/1` rather than kept in process state, so a caller — or
`i2p_soak_tunnel_tests` — can drive the fabric directly without a fifteen-second
window. **The hop keys are random per boot**, which is why this is threaded rather
than re-derived from the NetDb: a hop that expired mid-run would then be addressed
by a key nothing can open, which is a confusing way to lose a phase.
""".
-type fabric() :: #{
    local := i2p_peer:local_keys(),
    hops := [hop()],
    by_hash := #{i2p_crypto:hash() => hop()}
}.

%% %%%%% %%% %%% Parameters %%%%% %%%

minimum_phases() ->
    ?MIN_PHASES.

-doc """
Offered rate and the reason it was refused, normalised from `m:i2p_soak:f:parse_rate/1`.

**Same function and same bound; the shape is normalised here.** `f:parse_rate/1`
answers `{ok, Rate} | {error, Reason}`, and a second copy of its two constants
would be a second thing to keep correct -- the tree's rule is that data is never
duplicated. So the rate is borrowed and only the shape adapted, to
`{Rate, Reason}`: a refused rate arrives as the floor with the reason beside it,
which is what `m:i2p_soak` does too, and the reason is carried into the report's
failures rather than swallowed.

An out-of-range rate is **refused, not clamped** -- a clamp would let a reader
believe they asked for something they did not get, which is the
confident-wrong-answer mode this harness family exists to stop.
""".
-spec offered_rate(opts()) -> {pos_integer(), string()}.
offered_rate(Opts) ->
    case i2p_soak:parse_rate(maps:get(rate, Opts)) of
        {ok, Rate} -> {Rate, ""};
        {error, Reason} -> {1, Reason}
    end.

%% %%%%% %%% %%% The run %%%%% %%%

-doc """
Soak the tunnel and transit paths and report what the numbers support.

Input: `t:opts/0`. Output: `t:report/0`.

**The order is the argument for the order.** The self-checks run first, because
everything after them is a measurement, and a measurement from an instrument that
cannot demonstrate it detects a known fault is worth nothing. The warm phase runs
second and is **not** part of the verdict, for the reason the ticket insists on:
every cache on this path fills once, so a first measured phase taken against a cold
node reports that fill as growth proportional to nothing. Then the measured phases,
each a load window and a quiet window, so traffic-proportional retention and
traffic-independent filling are separable rather than being one slope.
""".
-spec run(opts()) -> report().
run(Opts) ->
    Checks = i2p_soak_selfcheck:run(),
    {Rate, RateReason} = offered_rate(Opts),
    Fabric = boot(Opts),
    try
        Warm = warm_phase(Fabric, Opts),
        %% Taken **after** the warm phase and not before the boot. The figure
        %% answers "did the load leave anything behind", so the router's own
        %% startup must be outside the window -- measured across the boot it
        %% would report ~11 processes every run and read as a leak in the
        %% fixtures. The warm phase is inside it, because warming the caches is
        %% work the run did and any process it left behind is genuinely dirty.
        Before = length(erlang:processes()),
        Measured = [phase(Fabric, Opts, N) || N <- lists:seq(1, maps:get(phases, Opts))],
        report(Checks, Warm, Measured, Rate, RateReason, length(erlang:processes()) - Before)
    after
        ok = shutdown()
    end.

%% %%%%% %%% %%% The fabric %%%%% %%%

-doc """
Boot the router the way this soak needs it: no transports, no peer manager, and a
tunnel manager of its own.

Input: `t:opts/0`. Output: `t:fabric/0`.

**`seeds` is left unset on purpose** — see the module doc. That is the whole
mechanism, and it is a shape `m:i2per_sup` already has rather than a branch added
for this harness.
""".
-spec boot(opts()) -> fabric().
boot(Opts) ->
    Dir = maps:get(data_dir, Opts),
    {ok, Id} = i2p_identity:ensure_identity(Dir),
    _ = application:load(i2per),
    ok = application:set_env(i2per, data_dir, Dir),
    ok = application:set_env(i2per, allow_private_host, true),
    ok = application:set_env(i2per, live_network, maps:get(live, Opts, false)),
    {ok, _} = application:ensure_all_started(i2per),
    ok = check_phase_floor(Opts),
    Local = i2p_identity:build_local(
        Id, <<"127.0.0.1">>, maps:get(port, Opts), maps:get(sign_seed, Id)
    ),
    ok = install_mock_peer(),
    {ok, _} = i2p_tunnel_srv:start_link(Local),
    Hops = seed_hops(maps:get(hops, Opts)),
    #{local => Local, hops => Hops, by_hash => index(Hops)}.

-spec check_phase_floor(opts()) -> ok.
check_phase_floor(Opts) ->
    case maps:get(phases, Opts) >= ?MIN_PHASES of
        true -> ok;
        false -> error({too_few_phases, maps:get(phases, Opts), ?MIN_PHASES})
    end.

-doc """
Stop everything `f:boot/1` started, in the reverse order.

**Idempotent and total**, because a fixture teardown that raises on a component
which already died would replace the finding with a crash — the reason
`m:i2p_smoke:f:shutdown/0` is the same shape.
""".
-spec shutdown() -> ok.
shutdown() ->
    ok = stop_tunnel_manager(),
    ok = uninstall_mock_peer(),
    _ = application:stop(i2per),
    ok.

%% The mock peer %%%%% %%%

-doc """
Register a process under `i2p_peer` that forwards what it is handed.

**It forwards, and that is the design.** A mock that discards reports "no builds
happened", which is indistinguishable from a build path that is broken.
""".
-spec install_mock_peer() -> ok.
install_mock_peer() ->
    case whereis(i2p_peer) of
        undefined ->
            _ = start_mock_peer(),
            ok;
        _ ->
            ok
    end.

-spec start_mock_peer() -> ok.
start_mock_peer() ->
    Parent = self(),
    Pid = spawn(fun() -> forward(Parent) end),
    true = register(i2p_peer, Pid),
    ok.

-spec forward(pid()) -> no_return().
forward(Parent) ->
    receive
        {'$gen_cast', Cast} ->
            Parent ! {peer_sent, Cast},
            forward(Parent);
        _Other ->
            %% The relay path handing us a frame to send onward. Dropped: the
            %% soak asks how much transit the router carried, and the router's
            %% own counters answer that far better than a tally kept here.
            forward(Parent)
    end.

-spec uninstall_mock_peer() -> ok.
uninstall_mock_peer() ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            true = unregister(i2p_peer),
            exit(Pid, kill),
            ok
    end.

-spec stop_tunnel_manager() -> ok.
stop_tunnel_manager() ->
    case whereis(i2p_tunnel_srv) of
        undefined ->
            ok;
        Pid ->
            unlink(Pid),
            _ = catch i2p_tunnel_srv:stop(),
            ok
    end.

%% Synthetic hops %%%%% %%%

-doc """
Build `Count` signed RouterInfos, store them, and return them.

**Stored through the NetDb's own public API** rather than injected, so the lookup
`f:select_hops/2` performs at build time is the real one — including the distance
ordering, which is what decides which hop becomes the inbound gateway and therefore
which record the walk has to stop at.
""".
-spec seed_hops(pos_integer()) -> [hop()].
seed_hops(Count) ->
    Hops = [new_hop(N) || N <- lists:seq(1, Count)],
    Now = erlang:system_time(millisecond),
    lists:foreach(
        fun(Hop) ->
            {ok, _} = i2p_netdb_srv:store_binary(
                i2p_router_info:to_binary(maps:get(ri, Hop)), Now
            ),
            ok
        end,
        Hops
    ),
    Hops.

-spec new_hop(pos_integer()) -> hop().
new_hop(N) ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, 40000 + N, StaticPub, IV),
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        Seed
    ),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        hash => i2p_router_info:hash(RI),
        ri => RI
    }.

-spec index([hop()]) -> #{i2p_crypto:hash() => hop()}.
index(Hops) ->
    maps:from_list([{maps:get(hash, Hop), Hop} || Hop <- Hops]).

-spec our_hash(fabric()) -> i2p_crypto:hash().
our_hash(#{local := Local}) ->
    maps:get(hash, Local).

-spec hop_of(fabric(), i2p_crypto:hash()) -> hop() | undefined.
hop_of(#{by_hash := ByHash}, Hash) ->
    maps:get(Hash, ByHash, undefined).

%% %%%%% %%% %%% The load loop %%%%% %%%

-doc """
Offer `window_ms` of load and report **what the router's own counters say it did**.

Input: `t:fabric/0` and `t:opts/0`. Output: `t:offered/0`.

**The rate is a ceiling, not a target.** One unit is a build round trip — a cast,
an intercepted garlic, a walk through every hop, a sealed reply handed back — so
the ceiling rarely binds and the loop is bounded by how fast the router completes
a build. Reporting the ceiling would be a number about the harness.
""".
-spec load_window(fabric(), opts()) -> offered().
load_window(Fabric, Opts) ->
    {Rate, _} = offered_rate(Opts),
    Bucket = i2p_token_bucket:new(Rate, maps:get(burst, Opts)),
    Deadline = now_ms() + maps:get(window_ms, Opts),
    Before = counters(),
    Requested = loop(Fabric, Bucket, Rate, Deadline, empty_offered(), none),
    After = counters(),
    Requested#{
        built_inbound => moved(tunnels_built_inbound, Before, After),
        built_outbound => moved(tunnels_built_outbound, Before, After),
        transit_frames => moved(transit_bytes_in, Before, After) div ?TRANSIT_FRAME_BYTES
    }.

-spec loop(fabric(), i2p_token_bucket:bucket(), pos_integer(), integer(), offered(), term()) ->
    offered().
loop(Fabric, Bucket, Rate, Deadline, Count, Inbound) ->
    case now_ms() >= Deadline of
        true ->
            Count;
        false ->
            case i2p_token_bucket:consume(Bucket, 1, now_ms()) of
                {allow, Bucket1} ->
                    {Count1, Inbound1} = unit(Fabric, Count, Inbound),
                    loop(Fabric, Bucket1, Rate, Deadline, Count1, Inbound1);
                deny ->
                    timer:sleep(max(1, 1000 div Rate)),
                    loop(Fabric, Bucket, Rate, Deadline, Count, Inbound)
            end
    end.

%% `erlang:monotonic_time/1` is a different clock and is negative on this
%% platform, which makes every elapsed interval negative and so accrues nothing.
%% `m:i2p_soak` documents this; the token bucket needs epoch milliseconds.
-spec now_ms() -> integer().
now_ms() ->
    erlang:system_time(millisecond).

empty_offered() ->
    #{requested => 0, built_inbound => 0, built_outbound => 0, transit_frames => 0}.

-spec moved(atom(), #{atom() => non_neg_integer()}, #{atom() => non_neg_integer()}) ->
    non_neg_integer().
moved(Key, Before, After) ->
    max(0, maps:get(Key, After, 0) - maps:get(Key, Before, 0)).

-doc """
One unit of work: an inbound build, an outbound build through it, and one frame
relayed through a transit tunnel this same unit installed.

Returns the running tally **and** the inbound entry the outbound direction names
as its reply path. The entry cannot ride inside `t:offered/0` — that is a set of
counts, and a tunnel entry in a count field is a type that says nothing — so the
unit returns a pair and the loop threads the entry alongside.

**Inbound first, then outbound.** An outbound build needs an active inbound tunnel
to name as its reply path; without one
`m:i2p_tunnel_build:f:do_build_outbound/3` silently builds an inbound instead. The
order is what keeps both directions moving, and `requested` sitting beside the
router's own `built_inbound` / `built_outbound` counts is what would expose it if
that order ever stopped holding.
""".
-spec unit(fabric(), offered(), term()) -> {offered(), term()}.
unit(Fabric, Count, _Inbound) ->
    %% Two casts per unit: one inbound, one outbound. Counted up front so the
    %% figure is about what was asked of the manager, not about what came back.
    Count1 = Count#{requested => maps:get(requested, Count) + 2},
    Built = inbound(Fabric),
    _ =
        case Built of
            {ok, ReplyPath} -> outbound(Fabric, ReplyPath);
            error -> error
        end,
    {add_transit(Fabric, Count1), Built}.

-doc """
Ask the manager for one inbound build and drive it to activation.

Returns the activated entry, because the outbound direction needs it as a reply
path.
""".
-spec inbound(fabric()) -> {ok, map()} | error.
inbound(Fabric) ->
    ok = i2p_tunnel_srv:build_inbound(),
    case await_garlic(?BUILD_WAIT_MS) of
        {ok, IbgwHash, Garlic} -> drive_inbound(Fabric, IbgwHash, Garlic);
        timeout -> error
    end.

-doc """
Ask the manager for one outbound build and drive its reply back through `Entry`.

The reply is what makes this the outbound direction rather than a second inbound:
the OutboundTunnelBuildReply travels down an active inbound tunnel's data path, so
the inbound gateway and the inbound endpoint are on the measured path too.
""".
-spec outbound(fabric(), map()) -> ok | error.
outbound(Fabric, Entry) ->
    ok = i2p_tunnel_srv:build_outbound(),
    case await_garlic(?BUILD_WAIT_MS) of
        {ok, ObgwHash, Garlic} -> drive_outbound(Fabric, ObgwHash, Garlic, Entry);
        timeout -> error
    end.

-spec add_transit(fabric(), offered()) -> offered().
add_transit(Fabric, Count) ->
    case install_transit(Fabric) of
        ok ->
            ok = push_transit_frame(Fabric),
            Count#{transit_frames => maps:get(transit_frames, Count) + 1};
        error ->
            Count
    end.

%% %%%%% %%% %%% Driving a build %%%%% %%%

-doc """
Wait for the next build garlic the mock peer was handed.

**Bounded, and a timeout is a reported shortfall rather than a hang.** A build that
produced no garlic is the silent skip `m:i2p_tunnel_build` performs when the NetDb
cannot supply hops; waiting for it forever would turn a visible disagreement
between `requested` and the built counts into a stuck run.
""".
-spec await_garlic(pos_integer()) -> {ok, i2p_crypto:hash(), i2p_i2np:i2np_message()} | timeout.
await_garlic(Timeout) ->
    receive
        {peer_sent, {send_when_ready, Hash, #{type := 11} = Garlic}} ->
            {ok, Hash, Garlic}
    after Timeout ->
        timeout
    end.

-spec drive_inbound(fabric(), i2p_crypto:hash(), i2p_i2np:i2np_message()) ->
    {ok, map()} | error.
drive_inbound(Fabric, IbgwHash, Garlic) ->
    case open_stb(Garlic, IbgwHash, Fabric) of
        {ok, MsgID, Records} ->
            #{pending_in := PendingIn} = i2p_tunnel_srv:status(),
            case maps:find(MsgID, PendingIn) of
                {ok, Build} ->
                    stop_at_us(Fabric, IbgwHash, Records, MsgID, Build);
                error ->
                    %% No pending build under this message id, so the manager
                    %% dropped it. Not credited to either direction.
                    error
            end;
        error ->
            error
    end.

-spec drive_outbound(fabric(), i2p_crypto:hash(), i2p_i2np:i2np_message(), map()) ->
    ok | error.
drive_outbound(Fabric, ObgwHash, Garlic, Entry) ->
    case open_stb(Garlic, ObgwHash, Fabric) of
        {ok, MsgID, Records} ->
            #{pending := Pending} = i2p_tunnel_srv:status(),
            case maps:find(MsgID, Pending) of
                {ok, Build} ->
                    finish_outbound(Fabric, ObgwHash, Records, MsgID, Build, Entry);
                error ->
                    error
            end;
        error ->
            error
    end.

%% The inbound walk stops when a record points back at us: that record is the one
%% addressed to our own receive ID.
-spec stop_at_us(
    fabric(), i2p_crypto:hash(), [binary()], i2p_i2np:message_id(), map()
) ->
    {ok, map()} | error.
stop_at_us(Fabric, IbgwHash, Records, MsgID, Build) ->
    Ids = maps:get(tunnel_ids, Build),
    Ours = our_hash(Fabric),
    case
        walk(IbgwHash, Records, Fabric, fun(Info, _Next) ->
            maps:get(next_hash, Info) =:= Ours
        end)
    of
        {ok, _Visited, Sealed} ->
            Stb = i2p_i2np:short_tunnel_build(Sealed),
            i2p_tunnel_srv ! {i2np, self(), IbgwHash, Stb#{msg_id => MsgID}},
            RecvID = lists:last(Ids),
            case await_pool(inbound, RecvID, ?BUILD_WAIT_MS) of
                ok ->
                    %% The activated entry is what the outbound direction names
                    %% as its reply path, so the unit hands the real one on.
                    #{inbound := Pool} = i2p_tunnel_srv:status(),
                    {ok, maps:get(RecvID, Pool)};
                error ->
                    error
            end;
        error ->
            error
    end.

%% The outbound walk stops at the endpoint role, which is where the OBEP seals the
%% reply record that becomes the OutboundTunnelBuildReply.
-spec finish_outbound(
    fabric(),
    i2p_crypto:hash(),
    [binary()],
    i2p_i2np:message_id(),
    map(),
    map()
) ->
    ok | error.
finish_outbound(Fabric, ObgwHash, Records, MsgID, Build, Entry) ->
    Ids = maps:get(tunnel_ids, Build),
    #{rgarlic_key := RKey, rgarlic_tag := RTag} = lists:last(maps:get(hop_keys, Build)),
    case
        walk(ObgwHash, Records, Fabric, fun(Info, _Next) ->
            maps:get(role, Info) =:= endpoint
        end)
    of
        {ok, _Visited, Sealed} ->
            Otbrm = i2p_i2np:outbound_tunnel_build_reply(Sealed),
            Clove = #{
                delivery => local,
                type => 26,
                msg_id => MsgID,
                expiration => erlang:system_time(second) + 60,
                data => maps:get(body, Otbrm)
            },
            Session = i2p_garlic:wrap_existing_session([Clove], RKey, RTag),
            %% `encode_std` wants exactly these keys -- the session map itself
            %% also carries `expiration`, and a closed map type means any extra
            %% key is a type error, so the four it names are picked out
            %% explicitly.
            StdMsg = i2p_i2np:encode_std(#{
                type => 11,
                msg_id => maps:get(msg_id, Session),
                expiration_ms => 60000,
                body => maps:get(body, Session)
            }),
            ok = relay_through_inbound(Entry, StdMsg),
            await_pool(tunnels, hd(Ids), ?BUILD_WAIT_MS);
        error ->
            error
    end.

-doc """
Push a standard message down an active inbound tunnel the way production data
travels: the inbound gateway fragments it, every participant seals one wire layer,
and the frames are handed back as TunnelData addressed to the entry's receive ID.

**This is the reply path for an outbound build**, and it is why the outbound
direction is measured rather than assumed.
""".
-spec relay_through_inbound(i2p_tunnel_srv:inbound_entry(), binary()) -> ok.
relay_through_inbound(Entry, StdMsg) ->
    Layers = maps:get(layers, Entry),
    TunnelIds = maps:get(tunnel_ids, Entry),
    RecvID = lists:last(TunnelIds),
    {Frames, _GwState} = i2p_tunnel:gateway_all(hd(TunnelIds), local, undefined, StdMsg),
    lists:foreach(
        fun(Frame) ->
            i2p_tunnel_srv !
                {i2np, self(), self(), tunnel_data(wire_layers(Layers, TunnelIds, Frame))}
        end,
        Frames
    ),
    _ = RecvID,
    ok.

-spec tunnel_data(<<_:32, _:_*8>>) ->
    #{body := <<_:32, _:_*8>>, expiration := integer(), msg_id := <<_:32>>, type := 18}.
tunnel_data(Body) ->
    #{
        type => 18,
        msg_id => i2p_i2np:fresh_msg_id(),
        expiration => erlang:system_time(second) + 60,
        body => Body
    }.

-spec wire_layers([map()], [term()], binary()) -> binary().
wire_layers(Layers, TunnelIds, Frame0) ->
    <<_:32/big, Rest0/binary>> = Frame0,
    #{layer_key := LK, iv_key := IVK} = hd(Layers),
    NextID = lists:nth(2, TunnelIds),
    Wire1 = i2p_tunnel:encrypt_layer(<<NextID:32/big, Rest0/binary>>, LK, IVK),
    lists:foldl(
        fun({Layer, TargetID}, Wire) ->
            {ok, Out} = i2p_tunnel:process_tunnel_data(
                Wire, Layer, TargetID, i2p_i2np:fresh_msg_id()
            ),
            Out
        end,
        Wire1,
        lists:zip(tl(Layers), lists:sublist(TunnelIds, 3, length(Layers)))
    ).

-spec open_stb(i2p_i2np:i2np_message(), i2p_crypto:hash(), fabric()) ->
    {ok, i2p_i2np:message_id(), [binary()]} | error.
open_stb(Garlic, HopHash, Fabric) ->
    case hop_of(Fabric, HopHash) of
        undefined ->
            error;
        Hop ->
            try
                {ok, #{data := Encrypted}} = i2p_i2np:decode_garlic(maps:get(body, Garlic)),
                {ok, Blocks} = i2p_garlic:unwrap_router(Encrypted, maps:get(static_priv, Hop)),
                [Clove | _] = i2p_garlic:extract_cloves(Blocks),
                {ok, #{records := Records}} = i2p_i2np:decode_short_tunnel_build(
                    maps:get(data, Clove)
                ),
                {ok, maps:get(msg_id, Clove), Records}
            catch
                %% A garlic this cannot open is a fact about the harness, so it
                %% is not swallowed into a quiet zero.
                _:_ ->
                    error
            end
    end.

-doc """
Walk a build's records through every hop, with the router's own hop code.

Each participant opens its own record under its own static key and seals its reply
slot, and the list is then handed to whatever `next_hash` that record names — so
the walk follows the router's own chaining rather than an order this harness chose.
`Stop` says when to stop.

**Every byte of this is production code.** What is substituted is only that the
handoff between hops happens in this process rather than on a socket.
""".
-spec walk(
    i2p_crypto:hash(), [binary()], fabric(), fun((map(), i2p_crypto:hash()) -> boolean())
) ->
    {ok, [map()], [binary()]} | error.
walk(Hash, Records, Fabric, Stop) ->
    walk(Hash, Records, Fabric, Stop, [], 0).

-spec walk(
    i2p_crypto:hash(),
    [binary()],
    fabric(),
    fun((map(), i2p_crypto:hash()) -> boolean()),
    [map()],
    non_neg_integer()
) ->
    {ok, [map()], [binary()]} | error.
walk(_Hash, _Records, _Fabric, _Stop, _Seen, Depth) when Depth > ?MAX_WALK ->
    error;
walk(Hash, Records, Fabric, Stop, Seen, Depth) ->
    case hop_of(Fabric, Hash) of
        undefined ->
            error;
        Hop ->
            try
                {ok, Info} = i2p_tunnel:process_short_tunnel_build(
                    maps:get(static_priv, Hop),
                    maps:get(static_pub, Hop),
                    maps:get(hash, Hop),
                    Records
                ),
                Sealed = i2p_tunnel:apply_build_reply(Info, 0, Records),
                Next = maps:get(next_hash, Info),
                case Stop(Info, Next) orelse Next =:= our_hash(Fabric) of
                    true -> {ok, lists:reverse([Info | Seen]), Sealed};
                    false -> walk(Next, Sealed, Fabric, Stop, [Info | Seen], Depth + 1)
                end
            catch
                _:_ ->
                    error
            end
    end.

-doc """
Wait until a map in the tunnel manager's state holds `Key`.

A deadline poll, and **that is treated as a barrier** by the tree's own rule:
`status/0` is a `gen_server:call`, so each poll is ordered by the runtime after the
message that caused the change. The deadline only bounds how long the run waits —
it is not what makes the assertion true.
""".
-spec await_pool(atom(), term(), pos_integer()) -> ok | error.
await_pool(Pool, Key, Budget) ->
    #{Pool := Map} = i2p_tunnel_srv:status(),
    case maps:is_key(Key, Map) of
        true ->
            ok;
        false when Budget =< 0 -> error;
        false ->
            timer:sleep(?POOL_POLL_MS),
            await_pool(Pool, Key, Budget - ?POOL_POLL_MS)
    end.

%% %%%%% %%% %%% Transit %%%%% %%%

-doc """
Build and deliver one transit tunnel's ShortTunnelBuild, as a remote creator.

The record addressed to us carries the transit role and its next pointer, so the
manager admits it into the transit map and forwards the sealed build onward — the
admission path, the `transit_max_tunnels` bound and the relay path are all on the
measured path, and a per-tunnel record that was never released would accumulate in
the transit map rather than somewhere the census cannot see.
""".
-spec install_transit(fabric()) -> ok | error.
install_transit(#{local := Local, hops := Hops}) ->
    Next = hd(Hops),
    Base = transit_base(),
    Plaintexts = [
        i2p_tunnel:build_request_record(Base, Base + 1, maps:get(hash, Next), #{}),
        i2p_tunnel:build_request_record(Base + 1, 0, crypto:strong_rand_bytes(32), #{
            endpoint => true
        })
    ],
    Descs = [
        #{eph_priv => Priv, hop_pub => Pub, id_hash => Hash}
     || {Pub, Hash, {_E, Priv}} <- lists:zip3(
            [maps:get(static_pub, R) || R <- [Local, Next]],
            [maps:get(hash, R) || R <- [Local, Next]],
            [i2p_crypto:x25519_keygen() || _ <- lists:seq(1, 2)]
        )
    ],
    {Encrypted, _CreatorKeys} = i2p_ecies:encrypt_build_records(Descs, Plaintexts, 1),
    Stb = i2p_i2np:short_tunnel_build(Encrypted),
    i2p_tunnel_srv !
        {i2np, self(), crypto:strong_rand_bytes(32), Stb#{
            msg_id => crypto:strong_rand_bytes(4)
        }},
    await_pool(transit, Base, ?BUILD_WAIT_MS).

%% A receive id from the clock, so each install claims a distinct one. Reusing one
%% would be refused as `duplicate_receive_id` and the transit map would never grow,
%% which is the opposite of what this harness exists to measure.
-spec transit_base() -> 0..16#FFFFFFFF.
transit_base() ->
    erlang:system_time(microsecond) band 16#FFFFFFFF.

-doc """
Push one 1028-byte TunnelData frame through a transit entry.

Charged against the relay path's own bandwidth bucket and counted by the router's
own `transit_bytes_in` / `transit_bytes_out`, so the report's traffic figure is the
router's rather than this module's.
""".
-spec push_transit_frame(fabric()) -> ok.
push_transit_frame(_Fabric) ->
    #{transit := Transit} = i2p_tunnel_srv:status(),
    case maps:keys(Transit) of
        [] ->
            ok;
        [RecvID | _] ->
            Body =
                <<RecvID:32/big, (crypto:strong_rand_bytes(16))/binary,
                    (crypto:strong_rand_bytes(1008))/binary>>,
            i2p_tunnel_srv !
                {i2np, self(), crypto:strong_rand_bytes(32), #{
                    type => 18,
                    msg_id => i2p_i2np:fresh_msg_id(),
                    expiration => erlang:system_time(second) + 60,
                    body => Body
                }},
            ok
    end.

%% %%%%% %%% %%% The readings %%%%% %%%

-doc """
The router's own processes: the supervisor and every child it holds.

**Enumerated from `m:i2per_sup`, not listed here.** A hand-written list of names
would be a second copy of the supervision tree, drifting the moment a child is
added — and the tree's rule is that data is never duplicated. Enumerating means a
new child is measured without anyone remembering to add it.

The tunnel manager is included separately because `f:boot/1` starts it outside the
supervisor, which is the one thing about it not in that list.
""".
-spec router_pids() -> [pid()].
router_pids() ->
    Supervisor = whereis(i2per_sup),
    Children =
        case Supervisor of
            undefined ->
                [];
            _ ->
                [Pid || {_Id, Pid, _, _} <- supervisor:which_children(i2per_sup), is_pid(Pid)]
        end,
    Candidates = [Supervisor | Children] ++ [whereis(i2p_tunnel_srv)],
    lists:usort([Pid || Pid <- Candidates, is_pid(Pid)]).

-doc """
Words the router's own processes are holding, after a forced full collection.

The reading the ticket asks for, and the one a plain census cannot give: it goes
through `m:i2p_soak_census:f:retained/1`, which forces the collection **and waits
for it**, because `erlang:garbage_collect/1` alone is a request and a reading
taken straight after it oscillates by 2x on this build.
""".
-spec retained_words() -> integer().
retained_words() ->
    i2p_soak_census:words(i2p_soak_census:retained(router_pids())).

-doc """
The processes whose mailboxes grew most across one window.

The existing whole-node census rather than the retained reading, because mailbox
depth is exact either way and the forced collection is what makes *heap*
meaningful — there is nothing here for it to fix.
""".
-spec mailbox_slope(i2p_soak_census:census(), i2p_soak_census:census(), pos_integer()) ->
    [i2p_soak_census:row()].
mailbox_slope(Before, After, Top) ->
    i2p_soak_census:top_mailboxes(i2p_soak_census:delta(Before, After), Top).

-doc """
The size of every named structure in the tunnel manager, by `map_size/1`.

Exact where a heap reading is an inference, and the figure that answers "did the
transit map move" directly rather than by way of memory.
""".
-spec pools() -> pools().
pools() ->
    #{
        outbound => pool_size(tunnels),
        inbound => pool_size(inbound),
        transit => pool_size(transit),
        exploratory_outbound => pool_size(exploratory),
        exploratory_inbound => pool_size(exploratory_in),
        pending_outbound => pool_size(pending),
        pending_inbound => pool_size(pending_in)
    }.

pool_size(Key) ->
    case whereis(i2p_tunnel_srv) of
        undefined ->
            0;
        _ ->
            #{Key := Map} = i2p_tunnel_srv:status(),
            map_size(Map)
    end.

-doc """
The counters this ticket names, and the writer's saves.

Read back through `m:i2p_stats:f:snapshot/0`, so every figure is the router's own
counting. Selected by **prefix** rather than by a hand-listed set of names, for the
same reason `f:router_pids/0` enumerates: a list of counter names here would be a
second copy of `m:i2p_stats:f:counters/0`.
""".
-spec counters() -> #{atom() => non_neg_integer()}.
counters() ->
    Snapshot = i2p_stats:snapshot(),
    Selected = maps:with([K || K <- maps:keys(Snapshot), wanted_counter(K)], Snapshot),
    Writer = i2p_netdb_writer:stats(),
    Selected#{writer_saves => maps:get(saves, Writer, 0)}.

-spec wanted_counter(atom()) -> boolean().
wanted_counter(Key) ->
    Name = atom_to_list(Key),
    lists:prefix("tunnels_", Name) orelse lists:prefix("transit_", Name).

%% %%%%% %%% %%% Phases %%%%% %%%

-doc """
The warm phase: offer load, measure nothing, and say so.

**Deliberately excluded from the verdict.** Every cache on this path fills once —
the NetDb's stored RouterInfos, the pools themselves, the ECIES code's first-use
structures — and a first measured phase taken against a cold node reports that fill
as growth proportional to nothing. The run that motivated this ticket interposed a
warm phase before its first measurement, and that is the reason its verdict was
trustworthy; so the phase is returned with its offered figures and a retained
reading, and `f:verdict/1` is built from the phases after it.
""".
-spec warm_phase(fabric(), opts()) -> phase().
warm_phase(Fabric, Opts) ->
    Offered = load_window(Fabric, Opts#{window_ms => maps:get(warm_ms, Opts)}),
    #{
        index => 0,
        offered => Offered,
        retained_words => retained_words(),
        loaded_words => 0,
        ets_bytes => ets_bytes(),
        pools => pools()
    }.

-doc """
One measured phase: a census, a load window, a quiet window, and a forced-collection
reading at each end.

Input: `t:fabric/0`, `t:opts/0`, and the phase number. Output: `t:phase/0`.

**The quiet window is not idle bookkeeping** — it is the half that separates the
two retention causes, because it is the only measurement that can show a structure
giving its memory back.
""".
-spec phase(fabric(), opts(), pos_integer()) -> phase().
phase(Fabric, Opts, N) ->
    Before = census(),
    Offered = load_window(Fabric, Opts),
    %% Both retained readings are forced collections, so they are comparable.
    %% The one at the end of the load window and the one after the quiet window
    %% are the pair that says whether memory was given back -- and reading only
    %% the quiet-window figure would make `traffic_proportional` unreachable,
    %% which is a verdict with three answers out of four.
    Loaded = retained_words(),
    timer:sleep(maps:get(quiet_ms, Opts)),
    After = census(),
    #{
        index => N,
        offered => Offered,
        retained_words => retained_words(),
        loaded_words => Loaded,
        ets_bytes => ets_bytes(),
        pools => pools(),
        mailbox_slope => mailbox_slope(Before, After, maps:get(top, Opts)),
        counters => counters()
    }.

-spec census() -> i2p_soak_census:census().
census() ->
    {ok, Census} = i2p_soak_census:snapshot(),
    Census.

-spec ets_bytes() -> non_neg_integer().
ets_bytes() ->
    lists:sum(maps:values(i2p_soak_census:ets_bytes())).

%% %%%%% %%% %%% The verdict %%%%% %%%

-doc """
Classify a series of measured phases.

Input: `[t:phase/0]`. Output: `t:verdict/0`.

**Four answers, because a two-window verdict cannot tell a cache from a leak.**
`m:i2p_soak_census:f:verdict/3` compares one load window against one quiet window.
That is a different question from the ticket's, which is whether a structure that
grew kept growing -- and answering that needs at least two slopes, because growth
that appears in the first phase and then flattens is a cache filling once, and
reporting it as continued growth would send a reader looking for a leak in a
bounded structure.

**Both signals, and both are load-bearing.** The classification reads the shape
*across* phases and the behaviour *within* one:

1. **Nothing grew** anywhere → `inconclusive`. A run that moved no memory has no
   finding, and saying so is the honest answer rather than reporting a flat line
   as a clean bill of health.
2. **Grew under load and gave it back** in the quiet window →
   `traffic_proportional`. `CONTEXT.md`'s first cause: bounded by construction.
   This needs both readings of a phase — the one at the end of the load window
   and the one after the quiet window — and a verdict built only on the phase
   series can never reach it.
3. **Kept what it was given, and kept rising through every phase** →
   `traffic_independent`. A real finding, and still not a leak.
4. **Kept it, then flattened** → `plateau`. The fill happened and stopped, which
   is the shape of a bounded cache.

Per `CONTEXT.md` none of these is called a leak, and there is no `leak` field to
say it in.
""".
-spec verdict([phase()]) -> verdict().
verdict([]) ->
    #{
        retention => inconclusive,
        phase_words => [],
        slope_words => 0,
        note => note(inconclusive, [], 0)
    };
verdict(Phases) ->
    Words = [maps:get(retained_words, P) || P <- Phases],
    Slope = slope(Words),
    Retention = classify(Phases, Words, Slope),
    #{
        retention => Retention,
        phase_words => Words,
        slope_words => Slope,
        note => note(Retention, Words, Slope)
    }.

%% Words gained between the first and the last phase, which is the figure that
%% separates a fill that stopped from one that did not.
-spec slope([integer()]) -> integer().
slope([Only]) ->
    %% One phase has no slope to speak of -- there is nothing to difference it
    %% against. `f:boot/1` refuses fewer than two for the same reason.
    _ = Only,
    0;
slope(Words) ->
    lists:last(Words) - hd(Words).

-spec classify([phase()], [integer()], integer()) -> retention().
classify(_Phases, _Words, Slope) when Slope =< 0 ->
    inconclusive;
classify(Phases, Words, _Slope) ->
    %% The two signals are **orthogonal**, and reading them as one condition is
    %% how an earlier version of this lost `traffic_proportional` entirely.
    %
    %% *within* a phase -- did the quiet window give the load's memory back? That
    %% is what makes retention proportional to the traffic rather than to
    %% something else.
    %% *across* phases -- did the total keep rising, or did it stop? That is what
    %% separates a cache filling once from a structure still filling.
    %
    %% A structure can do both: grow every phase while handing back most of each
    %% phase's allocation. Demanding the across-phase signal be flat before
    %% believing the within-phase one refuses that case, and the answer it gives
    %% instead -- `traffic_independent` -- names a finding the numbers do not
    %% contain.
    case lists:all(fun gives_back/1, Phases) of
        true -> traffic_proportional;
        false -> maybe_plateau(Words)
    end.

%% Did this phase's quiet window return memory? **Negative** means it went down,
%% which is the only evidence of a return: memory cannot be given back below what
%% it held before the load unless the load's own structures were released.
-spec gives_back(phase()) -> boolean().
gives_back(#{loaded_words := Loaded, retained_words := Rest}) ->
    Rest < Loaded.

%% Kept its memory: either it kept rising every phase, or it rose and then
%% stopped. A single rise that flattened is the shape of a cache filling once.
-spec maybe_plateau([integer(), ...]) -> traffic_independent | plateau.
maybe_plateau(Words) ->
    case rising_throughout(Words) of
        true -> traffic_independent;
        false -> plateau
    end.

%% True only when **every** step is positive. One flat step after a rise is the
%% shape of a cache that filled once; a structure with no bound would keep rising
%% for as long as traffic kept arriving, which is the whole difference.
rising_throughout([_One]) ->
    true;
rising_throughout([A, B | Rest]) ->
    B > A andalso rising_throughout([B | Rest]).

-spec note(retention(), [integer()], integer()) -> binary().
note(Retention, Words, Slope) ->
    list_to_binary(
        lists:flatten(
            io_lib:format(
                "retained heap per measured phase ~p words, and ~p words gained across "
                "the run, classified ~p. A retained slope is not a leak: a slope "
                "shows that the structure kept what it was given, and telling a "
                "structure with no bound from a cache that filled once needs a "
                "window longer than this run has.",
                [Words, Slope, Retention]
            )
        )
    ).

%% %%%%% %%% %%% The report %%%%% %%%

-spec report(
    [i2p_soak_selfcheck:check()],
    phase(),
    [phase()],
    pos_integer(),
    string(),
    integer()
) ->
    report().
report(Checks, Warm, Phases, Rate, RateReason, FixtureDelta) ->
    Failures = failures(Checks, Phases, {RateReason, FixtureDelta}),
    Offered = total_offered(Phases),
    #{
        ok => Failures =:= [],
        self_checks => Checks,
        verdict => verdict(Phases),
        phases => Phases,
        warm => Warm,
        offered => Offered,
        fixture_delta => FixtureDelta,
        offered_events => maps:get(requested, Offered),
        rate => Rate,
        failures => Failures
    }.

-doc """
Sum what every measured phase offered, field by field.

**Summing, not averaging and not taking the last.** A slope is only interpretable
next to the work that produced it, and the traffic figure has to be the total over
the whole run for the verdict's phase series to mean anything.
""".
-spec total_offered([phase()]) -> offered().
total_offered(Phases) ->
    lists:foldl(
        fun
            (#{offered := O}, Acc) ->
                maps:merge_with(fun(_Key, A, B) -> A + B end, Acc, O);
            (_, Acc) ->
                Acc
        end,
        empty_offered(),
        Phases
    ).

-doc """
Everything that makes this run's answer untrustworthy, in words.

The traffic check is the one worth reading twice. **`built_inbound` and
`built_outbound` must both be non-zero across the run**, because a soak whose
tunnel counters read zero has measured the bus again — which is precisely what the
run that motivated this ticket did, and why its clean retention was not evidence of
anything. Asserting it is what turns "I soaked the tunnels" into a claim a reader
can check.
""".
-spec failures([i2p_soak_selfcheck:check()], [phase()], {string(), integer()}) -> [string()].
failures(Checks, Phases, {RateReason, FixtureDelta}) ->
    Failed = [Evidence || #{ok := false, evidence := Evidence} <- Checks],
    Failed ++ traffic_failures(Phases) ++ rate_failures(RateReason) ++
        fixture_failures(FixtureDelta).

-spec traffic_failures([phase()]) -> [string()].
traffic_failures([]) ->
    ["no phase was measured, so nothing was exercised"];
traffic_failures(Phases) ->
    Offered = total_offered(Phases),
    absent(Offered, built_inbound, "inbound tunnel build") ++
        absent(Offered, built_outbound, "outbound tunnel build") ++
        absent(Offered, transit_frames, "transit frame") ++
        idle_phases(Phases).

-spec absent(offered(), built_inbound | built_outbound | transit_frames, string()) -> [string()].
absent(Offered, Key, What) ->
    case maps:get(Key, Offered) of
        0 ->
            [
                lists:flatten(
                    io_lib:format(
                        "no ~s happened; a run whose tunnel counters read zero has measured the bus again",
                        [What]
                    )
                )
            ];
        _N ->
            []
    end.

-spec idle_phases([phase()]) -> [string()].
idle_phases(Phases) ->
    [
        lists:flatten(
            io_lib:format("phase ~p moved nothing: ~p builds requested", [
                maps:get(index, P), maps:get(requested, maps:get(offered, P))
            ])
        )
     || P <- Phases,
        maps:get(requested, maps:get(offered, P)) =:= 0
    ].

-spec rate_failures(string()) -> [string()].
rate_failures("") ->
    [];
rate_failures(Reason) ->
    [Reason].

-spec fixture_failures(integer()) -> [string()].
fixture_failures(0) ->
    [];
fixture_failures(N) ->
    [lists:flatten(io_lib:format("the run left ~p processes behind", [N]))].
