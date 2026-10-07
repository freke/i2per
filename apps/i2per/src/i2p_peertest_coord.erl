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

Charlie selection is supplied by the caller. Automatic NetDb-driven selection
is not implemented in this release: the coordinator receives the Charlie RouterInfo to
relay, not a hash to resolve. It binds the intro-side listener as both its owner
and `peer_test_coordinator`, so an inbound Alice message 1 is forwarded here
instead of auto-rejected.

Out-of-session messages 5, 6 and 7 are handled directly by the Alice and
Charlie SSU2 sessions — the coordinator does not participate in them.
""".

-behaviour(gen_server).

%% API
-export([
    start_link/1,
    port/1,
    dial_charlie/3,
    charlie_sess/1,
    stop/1
]).
%% gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-doc """
Start a PeerTest relay coordinator for Bob.

`BobLocal` is Bob's full local keys map (static keys, intro key, signing keys,
`hash`, `ri`) as `t:i2p_ssu2_conn:local_keys/0`. The coordinator binds Bob's
intro-side SSU2 listener as both its owner and its `peer_test_coordinator`.
""".
-spec start_link(map()) -> {ok, pid()}.
start_link(BobLocal) ->
    gen_server:start_link(?MODULE, BobLocal, []).

-doc "The introducer's bound SSU2 listener port.".
-spec port(pid()) -> 0..65535.
port(Coord) ->
    gen_server:call(Coord, port).

-doc """
Establish Bob's Charlie-side session.

Input: `CharlieOpts` (SSU2 address options as
`t:i2p_ssu2_conn:remote_opts/0`) and the decoded Charlie `RouterInfo` to
relay to Alice before message 4 (its `ri` must be a `m:i2p_router_info` map).
The SessionConfirmed routes Bob's own RouterInfo. Returns once the session is
established.
""".
-spec dial_charlie(pid(), map(), term()) -> ok.
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

init(BobLocal) ->
    {ok, Listener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self(), self()),
    {ok, #{
        listener => Listener,
        bob_local => BobLocal,
        alice_sess => undefined,
        charlie_sess => undefined,
        alice_hash => undefined,
        charlie_ri => undefined
    }}.

handle_call(port, _From, State = #{listener := Listener}) ->
    {reply, i2p_ssu2_listener:port(Listener), State};
handle_call(
    {dial_charlie, CharlieOpts, CharlieRI},
    _From,
    State = #{bob_local := BobLocal, listener := Listener}
) ->
    BobRIBlock = i2p_router_info:to_binary(maps:get(ri, BobLocal)),
    {ok, CharlieSess, _Keys} =
        i2p_ssu2_conn:connect(BobLocal, CharlieOpts, BobRIBlock, Listener),
    erlang:unlink(CharlieSess),
    {reply, ok, State#{charlie_sess => CharlieSess, charlie_ri => CharlieRI}};
handle_call(charlie_sess, _From, State) ->
    {reply, maps:get(charlie_sess, State), State};
handle_call(_Other, _From, State) ->
    {reply, ok, State}.

handle_cast(_Other, State) ->
    {noreply, State}.

handle_info({ssu2_data, Pid, Blocks}, State) ->
    {noreply, route_blocks(Pid, Blocks, State)};
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, #{listener := Listener}) ->
    catch i2p_ssu2_listener:stop(Listener),
    ok.

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
            State1 = relay_alice_to_charlie(Blocks, State),
            case maps:get(alice_sess, State1, undefined) of
                undefined -> State1#{alice_sess => Pid};
                _ -> State1
            end
    end.

%% Alice -> Charlie. Learn Alice's hash from her RouterInfo block, then relay a
%% message 1 as message 2 to the Charlie session. Alice's RouterInfo, when
%% present, is forwarded ahead of message 2 per the spec.
relay_alice_to_charlie(Blocks, State = #{charlie_sess := Charlie}) ->
    State1 = learn_alice_hash(Blocks, State),
    State2 = forward_router_infos(Blocks, Charlie, State1),
    case lists:keyfind(peertest, 1, Blocks) of
        {peertest, 1, Code, Flags, _Hash, Ver, Nonce, Ts, Port, Ip, Sig} ->
            relay_msg1_or_buffer(Code, Flags, Ver, Nonce, Ts, Port, Ip, Sig, State2);
        _ ->
            State2
    end.

relay_msg1_or_buffer(Code, Flags, Ver, Nonce, Ts, Port, Ip, Sig, State) ->
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
            i2p_log:debug({coord_msg1, sent}, []),
            Msg2 = {peertest, 2, Code, Flags, AliceHash, Ver, Nonce, Ts, Port, Ip, Sig},
            i2p_ssu2_conn:send_peertest(maps:get(charlie_sess, State), Msg2),
            State#{pending_msg1 => undefined}
    end.

learn_alice_hash(Blocks, State) ->
    case maps:get(alice_hash, State, undefined) of
        undefined ->
            case lists:keyfind(router_info, 1, Blocks) of
                {router_info, _Flag, RIData} ->
                    case i2p_router_info:decode(RIData) of
                        {ok, RI} ->
                            flush_pending_msg1(State#{alice_hash => i2p_router_info:hash(RI)});
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
            i2p_log:debug({coord_msg1, flushed_from_buffer}, []),
            Msg2 = {peertest, 2, Code, Flags, AliceHash, Ver, Nonce, Ts, Port, Ip, Sig},
            i2p_ssu2_conn:send_peertest(maps:get(charlie_sess, State), Msg2),
            State#{pending_msg1 => undefined};
        _ ->
            State
    end.

forward_router_infos(Blocks, Charlie, State) ->
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
