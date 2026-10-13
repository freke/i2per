-module(i2p_ssu2_reachability).

-moduledoc """
The router's inbound-reachability decision for SSU2 (firewalled-mode input).

Two layers, answering two different questions:

**The coarse verdict** (`f:status/0,1`: `firewalled | reachable | unknown`) is
the hysteresis-smoothed operational decision that drives the published address
form and the reachability caps. It is `firewalled` when the host is
private/loopback (`m:i2p_identity:allow_private_host/0`) — such a router
provably cannot be dialed inbound — and `unknown` otherwise until a test moves
it. One firewalled demotion demotes it; `peertest_promote_after` consecutive
`reachable` conclusions promote it. The asymmetry follows from which mistake
costs more: wrongly believing we are firewalled means we publish introducers
and peers relay through us — degraded but working; wrongly believing we are
reachable means we advertise a dialable address, peers try it, fail, and
**nobody thinks to use a Charlie at all**, so intros break outright.

**The measured detail** (`f:detail/0`) is the latest concluded test per family:
a rung of the reachability ladder (`unknown` · `testing` · `unreachable` ·
`introducer_only` · `reachable`) and, when the chain broke, the typed reason
naming where. It moves with every test and is the raw measurement the coarse
verdict smooths.

Both are fed by `{peertest_result, AddrType, {Rung, Reason}}` events on the
`m:i2p_events` bus — one per concluded test — and the rung also by the
driver's `f:test_started/1` announcement when a test goes in flight. The
driver (the peer manager) initiates tests on every newly established SSU2
session plus a periodic re-test, drawing a fresh Bob each round, and never
while `allow_private_host` is set — the operator's assertion is the
short-circuit, and the reason `own_config` is what a profile pinned that way
reports.

A demotion also drives the published caps and, when introducers are available,
the firewalled-mode address swap, with the same asymmetry: the measured
verdict is written to app env `measured_reachability` for
`f:i2p_identity:local_caps/0` to read at use time, and the swap runs through
`f:i2p_peer:advertise_introducers/1` — so the published address form and the
caps can never contradict each other. A promotion restores both. Until the
relay machinery issues tags, no introducers exist, so the swap holds off and
the caps alone follow the verdict.

The coarse decision is published as `{reachability, ssu2, Status}` events
whenever it changes. `Status` is the aggregate over the IPv4 and IPv6
families: `firewalled` if either family is firewalled, `unknown` while neither
family is decided, otherwise `reachable`.
""".

-behaviour(gen_server).

%% API
-export([start_link/0, status/0, status/1, detail/0, test_started/1]).
%% gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(FAMILIES, [ipv4, ipv6]).

-doc "Start the reachability manager, registered locally as `?MODULE`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
The aggregate inbound-reachability coarse verdict: `firewalled` | `reachable` |
`unknown` (see the module doc for the aggregation rule).
""".
-spec status() -> firewalled | reachable | unknown.
status() ->
    gen_server:call(?MODULE, status).

-doc "The per-family inbound-reachability coarse verdict for `AddrType`.".
-spec status(i2p_peertest:address_type()) -> firewalled | reachable | unknown.
status(AddrType) ->
    gen_server:call(?MODULE, {status, AddrType}).

-doc """
The measured reachability detail: the latest concluded test per family.

Output: a map `Family => #{rung => Rung, reason => Reason}` — the ladder rung
(`t:i2p_peertest:rung/0`) and, when the chain broke, the typed reason
(`t:i2p_peertest:reason/0`); an `undefined` reason means the test succeeded.
While a test is in flight the rung reads `testing`. The coarse verdict
(`f:status/0`) smooths this with hysteresis; this is the raw measurement.
""".
-spec detail() ->
    #{
        i2p_peertest:address_type() => #{
            rung => i2p_peertest:rung() | undefined,
            reason => i2p_peertest:reason() | undefined
        }
    }.
detail() ->
    gen_server:call(?MODULE, detail).

-doc """
Announce that a peer test started for `AddrType`, moving the family's rung to
`testing`. Best-effort: an absent manager is a skip rather than a raise — the
same announce contract as `f:i2p_events:notify/1`.
""".
-spec test_started(i2p_peertest:address_type()) -> ok.
test_started(AddrType) when AddrType =:= ipv4; AddrType =:= ipv6 ->
    case whereis(?MODULE) of
        undefined -> ok;
        _Pid -> gen_server:cast(?MODULE, {test_started, AddrType})
    end.

init([]) ->
    %% Subscribe to the bus so peer-test results keep the decision fresh.
    %% Through the published entry point (#WGV1SZ7), which is bounded: a bus
    %% wedged by a subscriber that never returns would otherwise park the
    %% supervisor's own `init/1` here, and the router would never finish
    %% starting. A refusal is deliberately not fatal — the reachability decision
    %% still answers, it just stops tracking new peer tests, and the alternative
    %% is a router that does not boot at all.
    _ = i2p_events:subscribe(self()),
    State0 = #{families => boot_families(), emitted => undefined},
    %% The private-host boot emits its firewalled coarse now instead of waiting
    %% for the first peer test; a non-private boot is undecided, and an
    %% undecided decision is not an event (the shipped rule: `undefined` never
    %% emits — the first test announces the first measurement).
    {ok, boot_emit(State0)}.

handle_call(status, _From, State) ->
    {reply, aggregate_coarse(families(State)), State};
handle_call({status, AddrType}, _From, State) ->
    {reply, family_coarse(AddrType, families(State)), State};
handle_call(detail, _From, State) ->
    {reply, family_details(families(State)), State};
handle_call(_Other, _From, State) ->
    {reply, ok, State}.

handle_cast({test_started, AddrType}, State) ->
    {noreply, test_in_flight(AddrType, State)};
handle_cast(_Other, State) ->
    {noreply, State}.

handle_info({event, {peertest_result, AddrType, {Rung, Reason}}}, State) ->
    {noreply, fold_result(AddrType, Rung, Reason, State)};
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    _ = i2p_events:unsubscribe(self()),
    ok.

%% ----------------------------------------------------------------------
%% Boot

%% The boot state per family. The coarse is `firewalled` when the host is
%% private/loopback — such a router provably cannot be dialed inbound — and
%% undecided otherwise, waiting on the first test. The measured rung is
%% `unknown` with reason `own_config` under `allow_private_host`: the operator
%% asserted inbound is impossible, so no test ran, and that is the honest
%% answer for the shipped profile. A non-private boot runs tests, so its
%% reason is undefined until the first conclusion names one.
boot_families() ->
    Private = i2p_identity:allow_private_host(),
    maps:from_keys(?FAMILIES, #{
        coarse =>
            case Private of
                true -> firewalled;
                false -> undefined
            end,
        rung => unknown,
        reason =>
            case Private of
                true -> own_config;
                false -> undefined
            end,
        consecutive => 0,
        in_flight => 0
    }).

boot_emit(State = #{families := Families}) ->
    case aggregate_coarse(Families) of
        firewalled -> emit_coarse(firewalled, State);
        _ -> State
    end.

%% ----------------------------------------------------------------------
%% The hysteresis

%% Fold one concluded test into its family. A `reachable` conclusion adds to
%% the consecutive count and promotes the coarse at `promote_after/0`; an
%% `introducer_only` or `unreachable` conclusion demotes it immediately — one
%% is enough, because a punch that did not land is the firewall evidence and
%% wrongly believing we are reachable is the expensive mistake. An `unknown`
%% conclusion (nothing arrived, the introducer rejected) is no evidence about
%% our reachability and moves neither the coarse nor the count — so a peer
%% that cannot run the test at all never demotes us.
fold_result(AddrType, Rung, Reason, State) when AddrType =:= ipv4; AddrType =:= ipv6 ->
    Family = maps:get(AddrType, families(State)),
    Family1 = Family#{
        rung => Rung,
        reason => Reason,
        in_flight => test_done(Family)
    },
    case Rung of
        reachable ->
            Cons = maps:get(consecutive, Family) + 1,
            Family2 = Family1#{consecutive => Cons},
            case Cons >= promote_after() of
                true -> conclude_promotion(AddrType, Family2, State);
                false -> put_family(AddrType, Family2, State)
            end;
        Rung when Rung =:= introducer_only; Rung =:= unreachable ->
            conclude_demotion(AddrType, Family1#{consecutive => 0}, State);
        _ ->
            %% `unknown` and anything else unnamed carries no evidence, so it
            %% neither moves the promotion streak nor resets it — matches the
            %% module documentation.
            put_family(AddrType, Family1, State)
    end.

test_done(Family) ->
    max(maps:get(in_flight, Family, 0) - 1, 0).

%% A family promoted to `reachable`: the coarse moves, the measured verdict
%% reaches the caps, and the published address is restored.
conclude_promotion(AddrType, Family, State) ->
    Was = maps:get(coarse, Family),
    State1 = put_family(AddrType, Family#{coarse => reachable}, State),
    State2 = emit_coarse_change(State1),
    case Was of
        reachable -> State2;
        _ -> drive_reachable(State2)
    end.

%% A family demoted: the coarse moves, the caps follow, and the address swap
%% runs when introducers are available.
conclude_demotion(AddrType, Family, State) ->
    Was = maps:get(coarse, Family),
    State1 = put_family(AddrType, Family#{coarse => firewalled}, State),
    State2 = emit_coarse_change(State1),
    case Was of
        firewalled -> State2;
        _ -> drive_firewalled(State2)
    end.

%% A test went in flight: the rung reads `testing` until its conclusion. The
%% coarse is untouched — a test in flight is not a verdict about anything, and
%% the coarse is the hysteresis-smoothed decision, not the last event.
test_in_flight(AddrType, State) when AddrType =:= ipv4; AddrType =:= ipv6 ->
    Families = families(State),
    Family = maps:get(AddrType, Families),
    Family1 = Family#{
        rung => testing,
        in_flight => maps:get(in_flight, Family, 0) + 1
    },
    State#{families := Families#{AddrType => Family1}}.

%% How many consecutive `reachable` conclusions promote the coarse. App env
%% `peertest_promote_after` overrides; three is the default because one lucky
%% test promoting us is the expensive mistake and a rotating Bob makes each
%% conclusion an independent measurement.
promote_after() ->
    application:get_env(i2per, peertest_promote_after, 3).

%% ----------------------------------------------------------------------
%% The verdict's effects

%% The measured verdict reaches the published caps through app env
%% `measured_reachability`, read by `f:i2p_identity:local_caps/0` at use time —
%% the same shape as the coordinator switches, whose runtime state also lives
%% in the app env. An absent key means no test has yet contradicted the
%% operator's configured reachability, which is what `local_caps/0`'s static
%% rule already answers.
%%
%% The swap is best-effort like every announce: a boot with no identity runs no
%% peer manager, and the verdict's effects must never fail the verdict work —
%% the same contract as `f:i2p_events:notify/1`. Resolved by name per use.
drive_reachable(State) ->
    application:set_env(i2per, measured_reachability, reachable),
    drive_peer(restore_introducers()),
    State.

drive_firewalled(State) ->
    application:set_env(i2per, measured_reachability, firewalled),
    %% The address swap runs only with introducers in hand: a non-published
    %% address with no introducer options is an address nobody can reach us
    %% through, which is strictly worse than the current one. Until the relay
    %% machinery issues tags, this is always empty and the caps alone follow.
    drive_peer(introducers_to_advertise()),
    State.

introducers_to_advertise() ->
    case whereis(i2p_peer) of
        undefined ->
            none;
        _Peer ->
            case i2p_peer:relay_introducers() of
                [] -> none;
                Introducers -> {swap, Introducers}
            end
    end.

restore_introducers() ->
    case whereis(i2p_peer) of
        undefined -> none;
        _Peer -> {swap, []}
    end.

drive_peer(none) ->
    ok;
drive_peer({swap, Introducers}) ->
    i2p_peer:advertise_introducers(Introducers),
    ok.

%% ----------------------------------------------------------------------
%% Publishing

%% Emit `{reachability, ssu2, Aggregate}` only when the coarse changed, so
%% a one-family transition does not spam the bus with identical messages.
emit_coarse_change(State = #{families := Families, emitted := Prev}) ->
    Agg = aggregate_coarse(Families),
    case Agg of
        Prev -> State;
        _ -> emit_coarse(Agg, State)
    end.

emit_coarse(Agg, State) ->
    i2p_events:notify({reachability, ssu2, Agg}),
    i2p_log:debug(reachability, #{ssu2 => Agg}),
    State#{emitted => Agg}.

%% ----------------------------------------------------------------------
%% State access

families(#{families := Families}) ->
    Families.

put_family(AddrType, Family, State = #{families := Families}) ->
    State#{families := Families#{AddrType => Family}}.

family_coarse(AddrType, Families) ->
    case maps:get(AddrType, Families) of
        #{coarse := undefined} -> unknown;
        #{coarse := Coarse} -> Coarse
    end.

family_details(Families) ->
    maps:map(
        fun(_Family, #{rung := Rung, reason := Reason}) ->
            #{rung => Rung, reason => Reason}
        end,
        Families
    ).

aggregate_coarse(Families) ->
    Decided = [
        Coarse
     || Family <- ?FAMILIES, Coarse <- [family_coarse(Family, Families)], Coarse =/= unknown
    ],
    case {lists:member(firewalled, Decided), Decided} of
        {true, _} -> firewalled;
        {false, []} -> unknown;
        {false, _} -> reachable
    end.
