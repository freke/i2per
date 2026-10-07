-module(i2p_ssu2_reachability).

-moduledoc """
The router's inbound-reachability decision for SSU2 (firewalled-mode input).

A router is `firewalled` when it cannot accept inbound SSU2 connections —
behind NAT without a forwarded port, or loopback/private-host boot — and then
must rely on introducers to be reachable at all. The decision is fed by the
SSU2 peer-test machinery, which announces one `{peertest_result, AddrType,
Result}` event per concluded test on the `m:i2p_events` bus:

* `ok` (Charlie reached us directly) resolves the family to `reachable`;
* `firewalled` resolves it to `firewalled`;
* `unknown` or another unhandled result leaves the family undecided.

The boot state is `firewalled` when the host is private/loopback
(`m:i2p_identity:allow_private_host/0`) — such a router provably cannot be
dialed inbound — and `unknown` otherwise, waiting on the first test result.

The decision is published as `{reachability, ssu2, Status}` events whenever it
changes. `Status` is the aggregate over the IPv4 and IPv6 families:
`firewalled` if either family is firewalled, `unknown` while neither family is
decided, otherwise `reachable`. Router components do not consume this event in
0.1.0.
""".

-behaviour(gen_server).

%% API
-export([start_link/0, status/0, status/1]).
%% gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(FAMILIES, [ipv4, ipv6]).

-doc "Start the reachability manager, registered locally as `?MODULE`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
The aggregate inbound-reachability decision: `firewalled` | `reachable` |
`unknown` (see the module doc for the aggregation rule).
""".
-spec status() -> firewalled | reachable | unknown.
status() ->
    gen_server:call(?MODULE, status).

-doc "The per-family inbound-reachability decision for `AddrType`.".
-spec status(i2p_peertest:address_type()) -> firewalled | reachable | unknown.
status(AddrType) ->
    gen_server:call(?MODULE, {status, AddrType}).

init([]) ->
    %% Subscribe to the bus so peer-test results keep the decision fresh.
    %% Through the published entry point (#WGV1SZ7), which is bounded: a bus
    %% wedged by a subscriber that never returns would otherwise park the
    %% supervisor's own `init/1` here, and the router would never finish
    %% starting. A refusal is deliberately not fatal — the reachability decision
    %% still answers, it just stops tracking new peer tests, and the alternative
    %% is a router that does not boot at all.
    _ = i2p_events:subscribe(self()),
    State0 = #{status => maps:from_keys(?FAMILIES, undefined)},
    %% Emit the boot decision now instead of waiting for the first peer test.
    {ok, apply_decision(boot_decision(), State0)}.

handle_call(status, _From, State) ->
    {reply, aggregate(maps:get(status, State)), State};
handle_call({status, AddrType}, _From, State) ->
    {reply, family_status(AddrType, maps:get(status, State)), State};
handle_call(_Other, _From, State) ->
    {reply, ok, State}.

handle_cast(_Other, State) ->
    {noreply, State}.

handle_info({event, {peertest_result, AddrType, Result}}, State) ->
    Decision =
        case Result of
            ok -> reachable;
            firewalled -> firewalled;
            _Other -> undefined
        end,
    {noreply, apply_decision(Decision, AddrType, State)};
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    _ = i2p_events:unsubscribe(self()),
    ok.

%% ----------------------------------------------------------------------
%% Decision

%% The boot decision across every family, before any peer test ran.
boot_decision() ->
    case i2p_identity:allow_private_host() of
        true -> firewalled;
        false -> undefined
    end.

apply_decision(Decision, State) ->
    lists:foldl(fun(Family, St) -> apply_decision(Decision, Family, St) end, State, ?FAMILIES).

apply_decision(Decision, AddrType, State = #{status := Status}) when
    AddrType =:= ipv4; AddrType =:= ipv6
->
    case maps:get(AddrType, Status) of
        Decision ->
            State;
        Current when Current =/= undefined ->
            %% A family that resolved once keeps its decision until a later
            %% test moves it again; `unknown` results never alter it. Only a
            %% real decision transitions the family, so the emitted aggregate
            %% changes at most once per resolution.
            case Decision of
                undefined -> State;
                _ -> emit_change(Decision, State#{status := Status#{AddrType => Decision}})
            end;
        undefined ->
            case Decision of
                undefined ->
                    State;
                _ ->
                    emit_change(Decision, State#{status := Status#{AddrType => Decision}})
            end
    end.

%% Emit `{reachability, ssu2, Aggregate}` only when the aggregate changed, so
%% a one-family transition does not spam the bus with identical messages.
emit_change(_Decision, State = #{status := Status}) ->
    Prev = maps:get(emitted, State, undefined),
    Agg = aggregate(Status),
    case Agg of
        Prev ->
            State;
        _ ->
            i2p_events:notify({reachability, ssu2, Agg}),
            State#{emitted => Agg}
    end.

family_status(AddrType, Status) ->
    case maps:get(AddrType, Status) of
        undefined -> unknown;
        D -> D
    end.

aggregate(Status) ->
    Decided = [
        D
     || Family <- ?FAMILIES,
        D <- [maps:get(Family, Status)],
        D =/= undefined
    ],
    case {lists:member(firewalled, Decided), Decided} of
        {true, _} -> firewalled;
        {false, []} -> unknown;
        {false, _} -> reachable
    end.
