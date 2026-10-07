-module(i2p_relay_coord).

-moduledoc """
The SSU2 introducer (Bob) relay coordinator.

A coordinator serves the introducer half of the introducer relay on one bound
listener. It owns every session the listener spawns against dialing routers,
so it receives their forwarded relay and router-info blocks (see
`m:i2p_ssu2_conn`) and routes them:

* a relay-tag request (block 15) earns the requesting session a fresh relay
  tag: a RelayTag block (16) answers it, and the tag is recorded against the
  session in the transport-wide `i2p_ssu2_relay_tags` registry, whose rows
  the listener manages (`f:i2p_ssu2_listener:register_relay_tag/4`). When the
  registry is at capacity the request is left unanswered — per the spec, the
  only refusal channel for a tag request. A repeated request is answered
  with the same tag and re-arms its registry expiry (the tagged peer's
  keepalive), so a tag lives as long as the tagged session lives.
* a RelayRequest (block 7) against a registered, unexpired tag is served by
  forwarding the requester's RouterInfo (learned from her SessionConfirmed)
  ahead of a RelayIntro (block 9) to the tagged session; the tagged session's
  RelayResponse (block 8) — accept or Charlie-side reject — is relayed
  unmodified back to the requester.
* a RelayRequest against an unknown or expired tag is refused with Bob's
  "relay tag not found" (code 5); one whose requester RouterInfo is not known
  is refused with "Alice's RouterInfo not found" (code 6); a concurrent relay
  while another is in flight is refused with "limit exceeded" (code 3).

Sessions are identified by behavior: whichever session asks for a relay tag
is the tagged peer being introduced; whichever sends a RelayRequest is the
requester. One coordinator serves one tagged peer and one requester at a
time, mirroring `m:i2p_peertest_coord`'s single-alice/single-charlie model.

Relay-request signature verification and the out-of-session HolePunch path
are not implemented in this release. The coordinator relays signed blocks
unmodified.
""".

-behaviour(gen_server).

%% API
-export([
    start_link/1,
    port/1,
    tagged_sess/1,
    stop/1
]).
%% gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% How long a handed-out relay tag stays valid (the tag is tied to the
%% session's lifetime and this lease bounds stale registry entries).
-define(RELAY_TAG_TTL, 600).
%% Registry cap: at this many live tags, tag requests go unanswered and relay
%% requests against a tag service refuse with code 3 "limit exceeded".
-define(MAX_RELAY_TAGS, 100).

-doc """
Start an introducer relay coordinator for Bob.

`BobLocal` is Bob's full local keys map (static keys, intro key, signing keys,
`hash`, `ri`) as `t:i2p_ssu2_conn:local_keys/0`. The coordinator binds Bob's
intro-side SSU2 listener as its owner, so every session that dials it is
spawned into `m:i2p_ssu2_sup` and owned by this process.
""".
-spec start_link(map()) -> {ok, pid()}.
start_link(BobLocal) ->
    gen_server:start_link(?MODULE, BobLocal, []).

-doc "The introducer's bound SSU2 listener port.".
-spec port(pid()) -> 0..65535.
port(Coord) ->
    gen_server:call(Coord, port).

-doc """
The session that currently holds a relay tag (or `undefined`).

The tagged peer's identity is learned lazily from its relay-tag request, so
before any block 15 arrives the answer is `undefined`.
""".
-spec tagged_sess(pid()) -> pid() | undefined.
tagged_sess(Coord) ->
    gen_server:call(Coord, tagged_sess).

-doc "Stop the coordinator.".
-spec stop(pid()) -> ok.
stop(Coord) ->
    gen_server:stop(Coord).

%% ----------------------------------------------------------------------
%% gen_server

init(BobLocal) ->
    {ok, Listener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    {ok, #{
        listener => Listener,
        bob_local => BobLocal,
        sessions => #{},
        tagged_sess => undefined,
        tag => undefined,
        requester_sess => undefined
    }}.

handle_call(port, _From, State = #{listener := Listener}) ->
    {reply, i2p_ssu2_listener:port(Listener), State};
handle_call(tagged_sess, _From, State) ->
    {reply, maps:get(tagged_sess, State), State};
handle_call(_Other, _From, State) ->
    {reply, ok, State}.

handle_cast(_Other, State) ->
    {noreply, State}.

%% Every established session reports its dialing peer's RouterInfo (bob side)
%% right after confirmation; the requester's hash and wire bytes are recovered
%% from it when a relay request arrives (no in-session RouterInfo block needed).
%% Re-decoding from the RouterInfo's own wire bytes recovers the opaque
%% `router_info()` type (the message tuple is untyped); its identity is
%% unchanged — the map round-trips through its `binary` key.
handle_info({ssu2_ready, Pid, _Keys, RemoteRI}, State = #{sessions := Sessions}) when
    is_map(RemoteRI)
->
    case i2p_router_info:decode(maps:get(binary, RemoteRI)) of
        {ok, RI} ->
            Sessions1 = Sessions#{Pid => RI},
            {noreply, State#{sessions => Sessions1}};
        _ ->
            {noreply, State}
    end;
handle_info({ssu2_ready, _Pid, _Keys, undefined}, State) ->
    {noreply, State};
handle_info({ssu2_data, Pid, Blocks}, State) ->
    {noreply, route_blocks(Pid, Blocks, State)};
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, #{listener := Listener}) ->
    catch i2p_ssu2_listener:stop(Listener),
    ok.

%% ----------------------------------------------------------------------
%% Routing

%% Route an in-session block to the other leg, keyed only on the tagged
%% session: whatever presents a relay-tag request (block 15) is the tagged
%% peer and earns the tag, whatever presents a RelayRequest (block 7) is the
%% requester. Learning both lazily from the data avoids any startup race with
%% the sessions' `ssu2_ready`. A repeated tag request on the tagged session
%% re-answers the same tag, keeping Data retransmission idempotent.
route_blocks(Pid, Blocks, State = #{tagged_sess := Tagged}) ->
    State1 = maybe_issue_tag(Pid, Blocks, State),
    case Pid =:= Tagged of
        true ->
            i2p_log:debug({coord_route, tagged_to_requester}, []),
            relay_tagged_to_requester(Blocks, State1);
        false ->
            i2p_log:debug({coord_route, requester_to_tagged}, []),
            relay_requester_to_tagged(Pid, Blocks, State1)
    end.

%% ----------------------------------------------------------------------
%% Tag handshake (blocks 15/16)

%% A relay-tag request (block 15) from an untagged session makes it the tagged
%% peer and earns it a tag, answered with a RelayTag block (16) in-session.
maybe_issue_tag(Pid, Blocks, State = #{tagged_sess := undefined}) ->
    case lists:member(relay_tag_request, Blocks) of
        true ->
            issue_tag(State#{tagged_sess => Pid});
        false ->
            State
    end;
maybe_issue_tag(Pid, Blocks, State = #{tagged_sess := Pid}) ->
    case lists:member(relay_tag_request, Blocks) of
        true ->
            %% Keepalive: the tagged peer re-arms its tag before the registry
            %% TTL elapses; refresh the row's expiry so the tag stays servable
            %% as long as the tagged session lives.
            _ = refresh_tag(State),
            tag_answer(maps:get(tag, State, undefined), Pid, State);
        false ->
            State
    end;
maybe_issue_tag(_Pid, _Blocks, State) ->
    State.

issue_tag(State = #{tagged_sess := Tagged, listener := Listener}) ->
    case live_tags() >= ?MAX_RELAY_TAGS of
        true ->
            %% Registry at capacity: leave the request unanswered, the spec's
            %% only refusal channel for a tag request.
            i2p_log:debug({tag, refused, cap_reached}, []),
            State;
        false ->
            Tag = fresh_tag(),
            Expires = erlang:system_time(second) + ?RELAY_TAG_TTL,
            i2p_log:debug({tag, issued, Tag}, []),
            _ = i2p_ssu2_listener:register_relay_tag(Listener, Tag, Tagged, Expires),
            tag_answer(Tag, Tagged, State#{tag => Tag})
    end.

%% Re-arm the handed-out tag with a fresh expiry (upsert into the registry).
refresh_tag(State = #{listener := Listener}) ->
    case maps:get(tag, State, undefined) of
        undefined ->
            State;
        Tag ->
            Expires = erlang:system_time(second) + ?RELAY_TAG_TTL,
            i2p_log:debug({tag, refreshed, Tag}, []),
            _ =
                i2p_ssu2_listener:register_relay_tag(
                    Listener, Tag, maps:get(tagged_sess, State), Expires
                ),
            State
    end.

tag_answer(Tag, Tagged, State) when Tag =/= undefined ->
    i2p_ssu2_conn:send_relay(Tagged, {relay_tag, Tag}),
    State;
tag_answer(undefined, _Tagged, State) ->
    State.

live_tags() ->
    case ets:info(i2p_ssu2_relay_tags, size) of
        undefined -> 0;
        Size -> Size
    end.

%% A fresh, nonzero, unregistered 32-bit tag (a zero tag is invalid on the
%% wire; the codec refuses to decode it).
fresh_tag() ->
    Tag = rand:uniform(16#FFFFFFFF - 1) + 1,
    case ets:lookup(i2p_ssu2_relay_tags, Tag) of
        [] -> Tag;
        _ -> fresh_tag()
    end.

%% ----------------------------------------------------------------------
%% Relay serving (blocks 7/8/9)

relay_requester_to_tagged(Pid, Blocks, State) ->
    case lists:keyfind(relay_request, 1, Blocks) of
        {relay_request, _Flag, Nonce, Tag, Ts, Ver, Port, Ip, Sig} ->
            serve_relay_request(Pid, Ver, Nonce, Tag, Ts, Port, Ip, Sig, State);
        false ->
            State
    end.

serve_relay_request(
    Pid, Ver, Nonce, _Tag, _Ts, _Port, _Ip, _Sig, State = #{requester_sess := Other}
) when
    is_pid(Other),
    Other =/= Pid
->
    %% One relay is already in flight; a concurrent request is refused with
    %% Bob's "limit exceeded" (code 3).
    i2p_log:debug({relay, refused, nonce, Nonce}, []),
    reject_requester(Pid, 3, Ver, Nonce, State);
serve_relay_request(Pid, Ver, Nonce, Tag, Ts, Port, Ip, Sig, State) ->
    case request_ri(Pid, State) of
        error ->
            %% The requester's RouterInfo never arrived with her handshake.
            i2p_log:debug({relay, refused, nonce, Nonce}, []),
            reject_requester(Pid, 6, Ver, Nonce, State);
        {RIBin, AHash} ->
            case lookup_tag(Tag) of
                {ok, Tagged} ->
                    State1 = State#{requester_sess => Pid},
                    serve_tagged(Tagged, RIBin, AHash, Ver, Nonce, Tag, Ts, Port, Ip, Sig, State1);
                error ->
                    i2p_log:debug({relay, refused, nonce, Nonce}, []),
                    reject_requester(Pid, 5, Ver, Nonce, State)
            end
    end.

%% Serve: the requester's RouterInfo precedes the RelayIntro (block 9) so the
%% tagged peer can recover her signing key and verify the forwarded signature.
serve_tagged(Tagged, RIBin, AHash, Ver, Nonce, Tag, Ts, Port, Ip, Sig, State) ->
    i2p_log:debug({relay, served, tag, Tag}, []),
    i2p_ssu2_conn:send_router_info(Tagged, 0, RIBin),
    Intro = i2p_relay:intro_block(Ver, AHash, Nonce, Tag, Ts, Port, Ip, Sig),
    i2p_ssu2_conn:send_relay(Tagged, Intro),
    State.

%% The tagged peer's RelayResponse (block 8) — accept or Charlie-side reject —
%% is relayed unmodified to the pending requester. Bob does not re-sign it.
relay_tagged_to_requester(Blocks, State = #{requester_sess := Requester}) when is_pid(Requester) ->
    case lists:keyfind(relay_response, 1, Blocks) of
        {relay_response, _, _, _, _, _, _, _, _, _} = Response ->
            i2p_log:debug({relay, relayed_to, Requester}, []),
            i2p_ssu2_conn:send_relay(Requester, Response),
            State;
        false ->
            State
    end;
relay_tagged_to_requester(_Blocks, State) ->
    State.

%% A Bob-side RelayResponse reject: signed with Bob's own key, no endpoint
%% (csz 0), echoing the request's nonce.
reject_requester(Pid, Code, Ver, Nonce, State = #{bob_local := BobLocal}) ->
    BobHash = maps:get(hash, BobLocal),
    Ts = erlang:system_time(second),
    Sig = i2p_relay:sign_response(BobHash, Ver, Nonce, Ts, 0, <<>>, maps:get(sign_seed, BobLocal)),
    Reject = i2p_relay:response_block(Code, Ver, Nonce, Ts, 0, <<>>, Sig, undefined),
    i2p_ssu2_conn:send_relay(Pid, Reject),
    State.

%% The requester's RouterInfo learned from her SessionConfirmed: its wire
%% bytes (forwarded to the tagged peer) and hash (the RelayIntro's AliceHash).
request_ri(Pid, State) ->
    case maps:get(Pid, maps:get(sessions, State, #{}), undefined) of
        undefined ->
            error;
        RI ->
            {i2p_router_info:to_binary(RI), i2p_router_info:hash(RI)}
    end.

%% A live relay tag: registered in the listener-owned registry against a live
%% session and not yet expired.
lookup_tag(Tag) ->
    case ets:lookup(i2p_ssu2_relay_tags, Tag) of
        [{Tag, Pid, Expires}] when is_pid(Pid) ->
            case Expires > erlang:system_time(second) of
                true -> {ok, Pid};
                false -> error
            end;
        _ ->
            error
    end.

%%%%%%% %%% Internal %%%%%%%
