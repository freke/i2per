-module(i2p_peertest_coord).

-moduledoc """
The SSU2 PeerTest introducer (Bob) relay coordinator.

A coordinator bridges the introducer's two SSU2 sessions for an in-session
PeerTest (messages 1-4): the intro-side session (Alice dialed us) and the
Charlie-side session (we dialed Charlie). It owns both sessions, so it
receives every PeerTest and RouterInfo block they forward to their owner, and
routes them:

* Alice's message 1 (+ her RouterInfo) → relayed to the Charlie session as
  message 2, with Alice's router hash;
* Charlie's message 3 (+ his RouterInfo) → relayed back to the Alice session
  as message 4, carrying Charlie's router hash.

Charlie selection is now NetDb-driven: when a message 1 arrives and no Charlie
session is dialed yet, the coordinator selects a qualifying RouterInfo from the
NetDb (SSU2 address with the `B` peer-test capability and a public host/port),
dials it, and relays. Alice's RouterInfo, held from the moment it was learned,
goes to the freshly dialed session ahead of message 2 as the spec requires.
A manual path remains via `f:dial_charlie/3` for tests
and operators. The coordinator binds the intro-side listener as both its owner
and `peer_test_coordinator`, so an inbound Alice message 1 is forwarded here
instead of auto-rejected.

Out-of-session messages 5, 6 and 7 are handled directly by the Alice and
Charlie SSU2 sessions — the coordinator does not participate in them.

## Two start shapes

`f:start_link/1` binds the coordinator's own SSU2 listener as both its owner
and `peer_test_coordinator` — the standalone Bob shape the tests own.
`f:start_attach/1` starts it with no listener of its own — the shape
`m:i2per_sup` starts it in, when app env `i2per` -> `peertest_coord` is
enabled (defaulting off): the sessions it routes between are the ones the
router's own SSU2 listener spawned, owned by `m:i2p_peer`, and their
peer-test and RouterInfo blocks reach this process forwarded by the peer
manager. When no Charlie session is dialed yet, an in-session message 1 triggers
NetDb-driven Charlie selection and a dial; if selection fails the request is
answered with the deterministic "no Charlie available" reject (code 2).
""".

-behaviour(gen_server).

%% API
-export([
    start_link/1,
    start_attach/1,
    port/1,
    dial_charlie/3,
    charlie_sess/1,
    stop/1
]).
%% gen_server
-export([enabled/0, init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-doc """
Whether the coordinator is enabled.

App env `i2per` -> `peertest_coord` is `true`. Unlike `f:i2p_relay_coord:enabled/0`
there is no `live_network` requirement: the resolved decision on the peer-test
policy gates this coordinator on its own key alone. Read from the application
environment rather than asked of a process, so boot, supervisor restart, and a
hot set all consult this one predicate.
""".
-spec enabled() -> boolean().
enabled() ->
    case application:get_env(i2per, peertest_coord) of
        {ok, true} -> true;
        _ -> false
    end.

-doc """
Start a PeerTest relay coordinator for Bob.

`BobLocal` is Bob's full local keys map (static keys, intro key, signing keys,
`hash`, `ri`) as `t:i2p_ssu2_conn:local_keys/0`. The coordinator binds Bob's
intro-side SSU2 listener as both its owner and its `peer_test_coordinator`.
""".
-spec start_link(map()) -> {ok, pid()}.
start_link(BobLocal) ->
    gen_server:start_link(?MODULE, BobLocal, []).

-doc """
Start the coordinator attached to the running router's SSU2 sessions.

`BobLocal` is as `f:start_link/1`. No listener is bound: the sessions this
process routes between are the ones the router's own SSU2 listener spawned
(owned by `m:i2p_peer`), and their peer-test and RouterInfo blocks reach it
forwarded by the peer manager. This is the shape `m:i2per_sup` starts the
coordinator in when app env `i2per` -> `peertest_coord` is enabled.
""".
-spec start_attach(map()) -> {ok, pid()}.
start_attach(BobLocal) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, {attach, BobLocal}, []).

-doc "The introducer's bound SSU2 listener port.".
-spec port(pid()) -> 0..65535 | {error, no_listener}.
port(Coord) ->
    gen_server:call(Coord, port).

-doc """
Establish Bob's Charlie-side session.

Input: `CharlieOpts` (SSU2 address options as
`t:i2p_ssu2_conn:remote_opts/0`) and the decoded Charlie `RouterInfo` to
relay to Alice before message 4 (its `ri` must be a `m:i2p_router_info` map).
The SessionConfirmed routes Bob's own RouterInfo. Returns once the session is
established. In attach mode the dial sends through the running router's SSU2
listener, resolved by name; with no listener up the answer is
`{error, no_listener}`, and an unreachable or slow Charlie answers
`{error, {dial_failed, Reason}}` — the coordinator survives either way.
""".
-spec dial_charlie(pid(), map(), term()) ->
    ok | {error, no_listener | {dial_failed, term()}}.
dial_charlie(Coord, CharlieOpts, CharlieRI) ->
    gen_server:call(Coord, {dial_charlie, CharlieOpts, CharlieRI}).

-doc "The established Charlie-side session pid (or `undefined`).".
-spec charlie_sess(pid()) -> pid() | undefined.
charlie_sess(Coord) ->
    gen_server:call(Coord, charlie_sess).

-doc "Stop the coordinator.".
-spec stop(pid()) -> ok.
stop(Coord) ->
    gen_server:stop(Coord).

%% ----------------------------------------------------------------------
%% gen_server

init({attach, BobLocal}) ->
    {ok, routing_state(BobLocal)};
init(BobLocal) ->
    {ok, Listener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self(), self()),
    {ok, (routing_state(BobLocal))#{listener => Listener}}.

-define(ALICE_RATE_LIMIT_MS, 60000).

routing_state(BobLocal) ->
    #{
        bob_local => BobLocal,
        alice_sess => undefined,
        charlie_sess => undefined,
        alice_hash => undefined,
        alice_ri => undefined,
        charlie_ri => undefined,
        alice_rate_limits => #{}
    }.

handle_call(port, _From, State = #{listener := Listener}) ->
    {reply, i2p_ssu2_listener:port(Listener), State};
handle_call(port, _From, State) ->
    {reply, listener_port(State), State};
handle_call(
    {dial_charlie, CharlieOpts, CharlieRI},
    _From,
    State = #{bob_local := _BobLocal}
) ->
    case dial_charlie_in_state(State, CharlieOpts, CharlieRI) of
        {error, no_listener} ->
            {reply, {error, no_listener}, State};
        {error, {dial_failed, Reason}} ->
            {reply, {error, {dial_failed, Reason}}, State};
        {ok, State1} ->
            {reply, ok, State1}
    end;
handle_call(charlie_sess, _From, State) ->
    {reply, maps:get(charlie_sess, State), State};
handle_call(_Other, _From, State) ->
    {reply, ok, State}.

handle_cast(_Other, State) ->
    {noreply, State}.

handle_info({ssu2_data, Pid, Blocks}, State) ->
    {noreply, route_blocks(Pid, Blocks, State)};
%% A session this process routes between died. A stale pid in the state would
%% be cast to — a cast to a dead process is silently dropped, which is harmless
%% here but leaves the state describing a session that is not there, and a
%% later message 3 would be skipped against a session pid that can no longer
%% answer. Clear the slots the dead session held.
handle_info({ssu2_closed, Pid, _Reason}, State) ->
    {noreply, forget_session(Pid, State)};
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, #{listener := Listener}) ->
    catch i2p_ssu2_listener:stop(Listener),
    ok;
terminate(_Reason, _State) ->
    ok.

%% Clear the routing slots a dead session held, so the state stops naming a
%% session that is not there.
forget_session(Pid, State = #{alice_sess := Alice, charlie_sess := Charlie}) ->
    State#{
        alice_sess => clear_if(Pid, Alice),
        charlie_sess => clear_if(Pid, Charlie)
    }.

clear_if(Pid, Pid) -> undefined;
clear_if(_Pid, Other) -> Other.

%% The listener an outbound Charlie dial sends through. The standalone shape
%% binds its own and holds it from init; attach mode sends through the running
%% router's listener, resolved by name per use — a listener restart changes the
%% pid and the registered name is the stable handle.
dial_listener(#{listener := Listener}) ->
    Listener;
dial_listener(_State) ->
    whereis(i2p_ssu2_listener).

%% The port an operator asks for. The standalone shape's own listener in the
%% first clause; the running router's listener in attach mode, where that is
%% the port peers dial. No listener, no port to name.
listener_port(#{listener := Listener}) ->
    i2p_ssu2_listener:port(Listener);
listener_port(_State) ->
    case whereis(i2p_ssu2_listener) of
        undefined -> {error, no_listener};
        Listener -> i2p_ssu2_listener:port(Listener)
    end.

%% ----------------------------------------------------------------------
%% Routing

%% Route an in-session block to the other side, keyed only on the Charlie
%% session: anything that is not the hand-rolled Charlie session is the
%% Alice (intro) side. Learning the Alice pid lazily from the data messages
%% themselves avoids any startup race with Alice's `ssu2_ready`.
route_blocks(Pid, Blocks, State = #{charlie_sess := Charlie}) ->
    case Pid =:= Charlie of
        true ->
            i2p_log:debug({coord_route, charlie_to_alice}, []),
            relay_charlie_to_alice(Blocks, State);
        false ->
            i2p_log:debug({coord_route, alice_to_charlie}, []),
            State1 = relay_alice_to_charlie(Pid, Blocks, State),
            case maps:get(alice_sess, State1, undefined) of
                undefined -> State1#{alice_sess => Pid};
                _ -> State1
            end
    end.

%% Alice -> Charlie. Learn Alice's hash (and hold her RouterInfo binary) from
%% her RouterInfo block, forward any RouterInfo blocks to the current Charlie
%% session, flush a message 1 buffered before her hash was known, then relay a
%% message 1 as message 2 to the Charlie session. The order matters: a freshly
%% dialed Charlie must receive her RouterInfo ahead of message 2 per the spec,
%% so the flush that may perform the dial runs after the forward.
relay_alice_to_charlie(Pid, Blocks, State) ->
    State1 = learn_alice_hash(Blocks, State),
    State2 = forward_router_infos(Blocks, State1),
    State3 = flush_pending_msg1(State2),
    case lists:keyfind(peertest, 1, Blocks) of
        {peertest, 1, Code, Flags, _Hash, Ver, Nonce, Ts, Port, Ip, Sig} ->
            relay_msg1_or_buffer(Pid, Code, Flags, Ver, Nonce, Ts, Port, Ip, Sig, State3);
        _ ->
            State3
    end.

relay_msg1_or_buffer(Pid, Code, Flags, Ver, Nonce, Ts, Port, Ip, Sig, State) ->
    case alice_hash(State) of
        undefined ->
            i2p_log:debug({coord_msg1, buffered}, []),
            %% Alice's hash not yet learned; hold the request until her
            %% RouterInfo arrives (SSU2 delivers blocks in order, so the
            %% RouterInfo will be handled in a later message).
            State#{
                pending_msg1 => {peertest, 1, Code, Flags, <<0:256>>, Ver, Nonce, Ts, Port, Ip, Sig}
            };
        AliceHash ->
            case maps:get(charlie_sess, State) of
                undefined ->
                    %% No Charlie session yet: select one from the NetDb and dial it.
                    %% On any failure (rate-limited, no candidate, dial error) reply
                    %% with the deterministic "no Charlie available" reject (code 2).
                    auto_select_charlie(
                        Pid, Code, Flags, Ver, Nonce, Ts, Port, Ip, Sig, AliceHash, State
                    );
                CharlieSess ->
                    i2p_log:debug({coord_msg1, sent}, []),
                    Msg2 = {peertest, 2, Code, Flags, AliceHash, Ver, Nonce, Ts, Port, Ip, Sig},
                    i2p_ssu2_conn:send_peertest(CharlieSess, Msg2),
                    State#{pending_msg1 => undefined}
            end
    end.

learn_alice_hash(Blocks, State) ->
    case maps:get(alice_hash, State, undefined) of
        undefined ->
            case lists:keyfind(router_info, 1, Blocks) of
                {router_info, Flag, RIData} ->
                    case i2p_router_info:decode(RIData) of
                        {ok, RI} ->
                            %% Hold the binary, not only the hash: the Charlie
                            %% session may not exist yet, and when one is
                            %% dialed it must receive Alice's RouterInfo ahead
                            %% of message 2 (docs/protocol.md:2058).
                            State#{
                                alice_hash => i2p_router_info:hash(RI),
                                alice_ri => {Flag, RIData}
                            };
                        _ ->
                            State
                    end;
                _ ->
                    State
            end;
        _ ->
            State
    end.

%% A RouterInfo has been learned; if a message 1 was buffered before Alice's
%% hash was available, relay it now.
flush_pending_msg1(State) ->
    case {maps:get(pending_msg1, State, undefined), alice_hash(State)} of
        {{peertest, 1, Code, Flags, _Hash, Ver, Nonce, Ts, Port, Ip, Sig}, AliceHash} when
            is_binary(AliceHash)
        ->
            case maps:get(charlie_sess, State) of
                undefined ->
                    %% Alice's hash just learned; still no Charlie dialed — try
                    %% NetDb-driven selection now that we can build message 2.
                    auto_select_charlie(
                        undefined, Code, Flags, Ver, Nonce, Ts, Port, Ip, Sig, AliceHash, State
                    );
                CharlieSess ->
                    i2p_log:debug({coord_msg1, flushed_from_buffer}, []),
                    Msg2 = {peertest, 2, Code, Flags, AliceHash, Ver, Nonce, Ts, Port, Ip, Sig},
                    i2p_ssu2_conn:send_peertest(CharlieSess, Msg2),
                    State#{pending_msg1 => undefined}
            end;
        _ ->
            State
    end.

forward_router_infos(_Blocks, State = #{charlie_sess := undefined}) ->
    %% No Charlie session yet: there is nobody to forward a RouterInfo to, and
    %% sending to no session at all would raise this process. The block is
    %% held in `alice_ri` and goes out when a Charlie is dialed, ahead of
    %% message 2; the same block is also the one that learns Alice's hash.
    State;
forward_router_infos(Blocks, State = #{charlie_sess := Charlie}) ->
    lists:foreach(
        fun
            ({router_info, Flag, RIData}) -> i2p_ssu2_conn:send_router_info(Charlie, Flag, RIData);
            (_) -> ok
        end,
        Blocks
    ),
    State.

%% Charlie -> Alice. Relay Charlie's message 3 as message 4, carrying his
%% router hash, preceded by his RouterInfo so Alice can recover his SSU2 intro
%% key (Bob forwards signed blocks unmodified; the msg4 hash field is not part
%% of the signed data).
relay_charlie_to_alice(Blocks, State = #{charlie_ri := CharlieRI}) ->
    Alice = maps:get(alice_sess, State, undefined),
    case {lists:keyfind(peertest, 1, Blocks), Alice, CharlieRI} of
        {{peertest, 3, Code, Flags, _Hash, Ver, Nonce, Ts, Port, Ip, Sig}, APid, CRI} when
            is_pid(APid), CRI =/= undefined
        ->
            i2p_log:debug({coord_msg4, sent}, []),
            i2p_ssu2_conn:send_router_info(Alice, 0, i2p_router_info:to_binary(CRI)),
            Msg4 =
                {peertest, 4, Code, Flags, i2p_router_info:hash(CRI), Ver, Nonce, Ts, Port, Ip,
                    Sig},
            i2p_ssu2_conn:send_peertest(Alice, Msg4);
        _ ->
            i2p_log:debug(
                {coord_msg4, skipped, peek_pt(Blocks), is_pid(Alice), CharlieRI =/= undefined}, []
            ),
            ok
    end,
    State.

peek_pt(Blocks) ->
    case lists:keyfind(peertest, 1, Blocks) of
        {peertest, N, _Code, _Flags, _Hash, _Ver, _Nonce, _Ts, _Port, _Ip, _Sig} -> N;
        _ -> none
    end.

alice_hash(State) ->
    maps:get(alice_hash, State, undefined).

%% ----------------------------------------------------------------------
%% NetDb-driven Charlie selection (0.6.0)

%% Resolve the Alice session pid to reply to: prefer the supplied Pid, fall
%% back to the lazily-learned slot.
alice_session_pid(Pid, _State) when is_pid(Pid) ->
    Pid;
alice_session_pid(_Pid, State) ->
    maps:get(alice_sess, State, undefined).

%% Dial Charlie using the same path as `f:dial_charlie/3`, returning the
%% updated state or `{error, no_listener}` / `{error, {dial_failed, Reason}}`.
%% `connect/4` awaits the handshake for up to 20 s and answers `{error,
%% Reason}` for an unreachable or slow candidate — an ordinary case here,
%% since candidates come from the NetDb. Handle it, don't crash: this
%% gen_server owns the intro-side listener.
-spec dial_charlie_in_state(map(), map(), term()) ->
    {ok, map()} | {error, no_listener | {dial_failed, term()}}.
dial_charlie_in_state(State, CharlieOpts, CharlieRI) ->
    case dial_listener(State) of
        undefined ->
            {error, no_listener};
        Listener ->
            BobLocal = maps:get(bob_local, State),
            BobRIBlock = i2p_router_info:to_binary(maps:get(ri, BobLocal)),
            case i2p_ssu2_conn:connect(BobLocal, CharlieOpts, BobRIBlock, Listener) of
                {ok, CharlieSess, _Keys} ->
                    erlang:unlink(CharlieSess),
                    State1 = State#{charlie_sess => CharlieSess, charlie_ri => CharlieRI},
                    ok = send_held_alice_ri(CharlieSess, State1),
                    {ok, State1};
                {error, Reason} ->
                    {error, {dial_failed, Reason}}
            end
    end.

%% Alice's RouterInfo, held from the moment it was learned. Charlie must
%% receive it before message 2, so a freshly dialed session gets it right
%% away: the block may have arrived while no Charlie session existed to
%% forward it to.
-spec send_held_alice_ri(pid(), #{alice_ri := {non_neg_integer(), binary()}, _ => _}) -> ok.
send_held_alice_ri(CharlieSess, State) ->
    case maps:get(alice_ri, State, undefined) of
        {Flag, RIData} -> i2p_ssu2_conn:send_router_info(CharlieSess, Flag, RIData);
        undefined -> ok
    end.

%% Pick one qualifying Charlie from the NetDb: SSU2 address with the `B`
%% peer-test capability and a public host/port, excluding ourselves. Uniform
%% random among candidates.
-spec select_charlie(#{hash := i2p_crypto:hash(), _ => _}) ->
    {ok, i2p_router_info:router_info(), map()} | {error, no_candidate}.
select_charlie(#{hash := OurHash}) ->
    Candidates = [
        RI
     || RI <- i2p_netdb_srv:routers(),
        i2p_router_info:hash(RI) =/= OurHash,
        {ok, Opts} <- [i2p_router_info:ssu2_address_options(RI)],
        maps:get(peer_test, Opts, false) =:= true,
        maps:get(published, Opts, false) =:= true
    ],
    case Candidates of
        [] ->
            {error, no_candidate};
        _ ->
            RI = lists:nth(rand:uniform(length(Candidates)), Candidates),
            {ok, Opts} = i2p_router_info:ssu2_address_options(RI),
            {ok, RI, Opts}
    end.

%% Per-Alice rate limit: true when a dial happened within the window.
rate_limited(AliceHash, State) ->
    Now = erlang:system_time(millisecond),
    Last = maps:get(AliceHash, maps:get(alice_rate_limits, State, #{}), 0),
    Now - Last < ?ALICE_RATE_LIMIT_MS.

%% Reply to Alice with the deterministic "no Charlie available" reject (code 2).
reply_reject(Pid, Nonce, Ts, Port, Ip) ->
    AlicePid = Pid,
    case AlicePid of
        undefined ->
            ok;
        _ ->
            Reject = {peertest, 4, 2, 0, <<0:256>>, 2, Nonce, Ts, Port, Ip, <<>>},
            catch i2p_ssu2_conn:send_peertest(AlicePid, Reject)
    end.

%% Auto-select a Charlie and relay message 2, or reject on any failure.
auto_select_charlie(Pid, Code, Flags, Ver, Nonce, Ts, Port, Ip, Sig, AliceHash, State) ->
    _ = i2p_counters:add(charlie_selections_attempted, 1),
    AlicePid = alice_session_pid(Pid, State),
    RateLimits = maps:get(alice_rate_limits, State, #{}),
    case rate_limited(AliceHash, State) of
        true ->
            _ = i2p_counters:add(charlie_selections_rejected, 1),
            i2p_log:debug({coord_msg1, auto_select, rate_limited}, []),
            reply_reject(AlicePid, Nonce, Ts, Port, Ip),
            State#{
                pending_msg1 => undefined,
                alice_rate_limits => RateLimits
            };
        false ->
            BobLocal = maps:get(bob_local, State),
            case select_charlie(BobLocal) of
                {error, no_candidate} ->
                    _ = i2p_counters:add(charlie_selections_rejected, 1),
                    i2p_log:debug({coord_msg1, auto_select, no_candidate}, []),
                    reply_reject(AlicePid, Nonce, Ts, Port, Ip),
                    State#{pending_msg1 => undefined};
                {ok, RI, Opts} ->
                    case dial_charlie_in_state(State, Opts, RI) of
                        {error, no_listener} ->
                            _ = i2p_counters:add(charlie_selections_rejected, 1),
                            i2p_log:debug({coord_msg1, auto_select, no_listener}, []),
                            reply_reject(AlicePid, Nonce, Ts, Port, Ip),
                            State#{pending_msg1 => undefined};
                        {error, {dial_failed, Reason}} ->
                            _ = i2p_counters:add(charlie_selections_rejected, 1),
                            i2p_log:debug(
                                {coord_msg1, auto_select, {dial_failed, Reason}}, []
                            ),
                            reply_reject(AlicePid, Nonce, Ts, Port, Ip),
                            State#{pending_msg1 => undefined};
                        {ok, State1} ->
                            _ = i2p_counters:add(charlie_selections_succeeded, 1),
                            Now = erlang:system_time(millisecond),
                            RL1 = maps:put(
                                AliceHash, Now, maps:get(alice_rate_limits, State1, #{})
                            ),
                            CharlieSess = maps:get(charlie_sess, State1),
                            i2p_log:debug({coord_msg1, auto_select, sent}, []),
                            Msg2 =
                                {peertest, 2, Code, Flags, AliceHash, Ver, Nonce, Ts, Port, Ip,
                                    Sig},
                            i2p_ssu2_conn:send_peertest(CharlieSess, Msg2),
                            State1#{pending_msg1 => undefined, alice_rate_limits => RL1}
                    end
            end
    end.
