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

## The Charlie half

The tagged session is not passive. Whoever holds a tag is *selected as a
Charlie* — that is what a tag is for — so the same process that hands tags out
must also answer the RelayIntro that selection earns. An inbound `relay_intro`
on the tagged session is therefore this router being asked to play Charlie, and
it is answered the way `HandleRelayIntro` in i2pd answers it:

* Alice's Ed25519 router signing key, taken from the RouterInfo the introducer
  forwarded ahead of the intro, verifies her request signature over
  `"RelayRequestData" || bhash || chash || nonce || tag || ts || ver || asz ||
  port || ip` (`m:i2p_relay:verify_request/10`, unchanged). A failure is
  Charlie-side code 67.
* The asserted endpoint is Alice's *own* claim, and it frequently differs from
  her published SSU2 address — that is the entire reason she needs a Charlie —
  so it is not matched against her RouterInfo. It is checked for being
  punchable (`m:i2p_addr_policy:punchable/2`) and nothing more.
* On accept, this router signs a RelayResponse with **its own** router signing
  key and answers twice: in-session to the introducer, which relays it to
  Alice, and again inside the out-of-session HolePunch (type 11) sent straight
  to her asserted endpoint. Both copies carry the same code, nonce and
  endpoint, so Alice reaches one conclusion whichever path lands.
* The accept **grants a session token**, and the requester presents it in the
  redirect's SessionRequest. `f:requester_relay_response/2` accepts only an
  integer token, so an accept without one is read by the requester as
  `{relay_rejected, 0}` — Charlie agreeing and the dial reported as refused.
  Nothing on this side checks the token against anything; it is carried because
  the protocol has the field and a requester may insist on it. #98GAVQK.

**Two bounds the references do not have.** The punch is a datagram this router
emits to a third party's address, so a hostile tag-holder must not be able to
turn it into an amplifier: `f:punch_allowed/1` spends a per-session token
bucket before each send, and the endpoint predicate refuses loopback, private
and link-local literals and privileged ports. i2pd checks `IsSupported` on the
address and relies on its own session tables for the rest; the bucket is the
part that would otherwise be unbounded here, because the coordinator serves one
tagged peer for as long as its session lives.

## Two start shapes

`f:start_link/1` binds the coordinator's own SSU2 listener (the standalone
Bob shape the tests own). `f:start_attach/1` starts it with no listener of
its own — the shape `m:i2per_sup` starts it in, when app env `i2per` ->
`relay_coord` is enabled (defaulting off, and additionally requiring
`live_network`): the sessions it routes between are the ones the router's own
SSU2 listener spawned, owned by `m:i2p_peer`, and their relay blocks reach
this process forwarded by the peer manager. The relay-tag registry is the
running listener's in both shapes; in attach mode it is resolved by name per
use rather than held, because a listener restart changes the pid and the
name is the stable handle.

Relay-response verification is `m:i2p_ssu2_conn`'s on the requester leg: the
requester checks Charlie's signature against the target RouterInfo it configured
before dialling. The coordinator itself signs its own responses and relays
Charlie's unmodified.
""".

-behaviour(gen_server).

%% API
-export([
    start_link/1,
    start_attach/1,
    port/1,
    tagged_sess/1,
    stop/1
]).
%% gen_server
-export([enabled/0, init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Exported for the tests that pin the punch bounds without a live session: the
%% endpoint predicate is `m:i2p_addr_policy`'s, and the rate limit is the only
%% part of this module with arithmetic in it.
-export([punch_allowed/1]).

-doc """
Whether the coordinator is enabled.

App env `i2per` -> `relay_coord` is `true` and additionally `live_network` is
`true` — the resolved decision on the Charlie/introducer role, which gates the
capability on the one "am I really on the network" switch. Read from the
application environment rather than asked of a process, so the check is an ETS
read on the forwarding path, and boot, supervisor restart, and a hot set all
consult this one predicate.
""".
-spec enabled() -> boolean().
enabled() ->
    case application:get_env(i2per, relay_coord) of
        {ok, true} ->
            case application:get_env(i2per, live_network) of
                {ok, true} -> true;
                _ -> false
            end;
        _ ->
            false
    end.

%% How long a handed-out relay tag stays valid (the tag is tied to the
%% session's lifetime and this lease bounds stale registry entries).
-define(RELAY_TAG_TTL, 600).
%% Registry cap: at this many live tags, tag requests go unanswered and relay
%% requests against a tag service refuse with code 3 "limit exceeded".
-define(MAX_RELAY_TAGS, 100).
%% Hole-punch rate limit, per coordinator (and so per tagged session, since one
%% coordinator serves one tagged peer at a time). A punch is an unsolicited
%% datagram this router emits to an address a third party asserted, so the
%% bound is on the send and not on the accept: a tag-holder who replays one
%% intro gets `?PUNCH_BURST` punches and then Charlie-side code 66. One per
%% second sustained, which is far above the rate any legitimate relay arrives at
%% and far below the rate an amplifier would want.
-define(PUNCH_RATE, 1).
-define(PUNCH_BURST, 4).

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

-doc """
Start the coordinator attached to the running router's SSU2 sessions.

`BobLocal` is as `f:start_link/1`. No listener is bound: the sessions this
process routes between are the ones the router's own SSU2 listener spawned
(owned by `m:i2p_peer`), and their relay blocks reach it forwarded by the
peer manager. The relay-tag registry is the running listener's, resolved by
name per use. This is the shape `m:i2per_sup` starts the coordinator in when
app env `i2per` -> `relay_coord` is enabled.
""".
-spec start_attach(map()) -> {ok, pid()}.
start_attach(BobLocal) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, {attach, BobLocal}, []).

-doc "The introducer's bound SSU2 listener port.".
-spec port(pid()) -> 0..65535 | {error, no_listener}.
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

init({attach, BobLocal}) ->
    {ok, routing(BobLocal)};
init(BobLocal) ->
    {ok, Listener} =
        i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    {ok, (routing(BobLocal))#{listener => Listener}}.

routing(BobLocal) ->
    #{
        bob_local => BobLocal,
        sessions => #{},
        tagged_sess => undefined,
        tag => undefined,
        requester_sess => undefined,
        alice_ri => undefined,
        punch_bucket => i2p_token_bucket:new(?PUNCH_RATE, ?PUNCH_BURST)
    }.

handle_call(port, _From, State = #{listener := Listener}) ->
    {reply, i2p_ssu2_listener:port(Listener), State};
handle_call(port, _From, State) ->
    {reply, listener_port(State), State};
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
    {noreply, route_blocks(Pid, Blocks, learn_alice_ri(Blocks, State))};
%% A session this process knows died. Its RouterInfo row is stale the moment
%% the pid is, and a requester or tagged session pid left in the state would be
%% cast to -- a cast to a dead process is silently dropped, which is harmless
%% here but leaves the state describing a session that is not there. The
%% attach shape routes every inbound session through `m:i2p_peer`, so without
%% this the `sessions` map would grow by one entry per inbound session over the
%% life of the router and never shrink.
handle_info({ssu2_closed, Pid, _Reason}, State = #{sessions := Sessions}) ->
    {noreply, forget_session(Pid, State#{sessions => maps:remove(Pid, Sessions)})};
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, #{listener := Listener}) ->
    catch i2p_ssu2_listener:stop(Listener),
    ok;
terminate(_Reason, _State) ->
    ok.

%% Forget a dead session wherever the state still names it: its RouterInfo row
%% (removed by the caller) and the tagged/requester slots, which are cast to on
%% the relay paths.
forget_session(Pid, State = #{tagged_sess := Tagged, requester_sess := Requester}) ->
    State#{
        tagged_sess => clear_if(Pid, Tagged),
        requester_sess => clear_if(Pid, Requester)
    }.

clear_if(Pid, Pid) -> undefined;
clear_if(_Pid, Other) -> Other.

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
            serve_intro(Blocks, relay_tagged_to_requester(Blocks, State1));
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

issue_tag(State = #{tagged_sess := Tagged}) ->
    case live_tags() >= ?MAX_RELAY_TAGS of
        true ->
            %% Registry at capacity: leave the request unanswered, the spec's
            %% only refusal channel for a tag request.
            i2p_log:debug({tag, refused, cap_reached}, []),
            State;
        false ->
            case relay_listener(State) of
                undefined ->
                    %% No listener owns a registry (SSU2 disabled, or the
                    %% listener is down): the same refusal channel as the
                    %% registry at capacity, and for the same reason — a tag
                    %% nobody can look up is not a tag.
                    i2p_log:debug({tag, refused, no_listener}, []),
                    State;
                Listener ->
                    Tag = fresh_tag(),
                    Expires = erlang:system_time(second) + ?RELAY_TAG_TTL,
                    i2p_log:debug({tag, issued, Tag}, []),
                    _ = i2p_ssu2_listener:register_relay_tag(Listener, Tag, Tagged, Expires),
                    tag_answer(Tag, Tagged, State#{tag => Tag})
            end
    end.

%% Re-arm the handed-out tag with a fresh expiry (upsert into the registry).
refresh_tag(State) ->
    case maps:get(tag, State, undefined) of
        undefined ->
            State;
        Tag ->
            case relay_listener(State) of
                undefined ->
                    State;
                Listener ->
                    Expires = erlang:system_time(second) + ?RELAY_TAG_TTL,
                    i2p_log:debug({tag, refreshed, Tag}, []),
                    _ =
                        i2p_ssu2_listener:register_relay_tag(
                            Listener, Tag, maps:get(tagged_sess, State), Expires
                        ),
                    State
            end
    end.

%% The listener that owns the relay-tag registry. Held from init in the
%% standalone shape; resolved by name per use in attach mode, where the
%% registry belongs to the running router's listener — a listener restart
%% changes the pid and the registered name is the stable handle.
relay_listener(#{listener := Listener}) ->
    Listener;
relay_listener(_State) ->
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

%% ----------------------------------------------------------------------
%% Charlie half (blocks 9/8, type 11)

%% Alice's RouterInfo as the introducer forwarded it on the tagged session,
%% held so a RelayIntro from that same session can be answered. The intro names
%% Alice by hash and carries no key, so the introducer sends her RouterInfo ahead
%% of it — in the same Data message or the one before, which SSU2 ordering makes
%% either way. One slot is the whole requirement, because the coordinator serves
%% one relay at a time; an intro arriving with no RouterInfo of its own is
%% refused as 70 rather than answered from a stale identity.
%%
%% Only the tagged session's RouterInfo is learned. A requester session also
%% carries one (it is how `f:request_ri/2` serves Alice), and reading that would
%% be reading the other half of the relay we may be asked to be the far end of.
%%
%% The RI is also what supplies Alice's introduction key, which is what the
%% out-of-session punch is sealed under. There is no path to a punch without it.
learn_alice_ri(Blocks, State = #{tagged_sess := Tagged}) ->
    case {Tagged, lists:keyfind(router_info, 1, Blocks)} of
        {undefined, _} -> State;
        {_, false} -> State;
        {_, {router_info, _Flag, RIData}} -> decode_ri(RIData, State)
    end;
learn_alice_ri(_Blocks, State) ->
    State.

decode_ri(RIData, State) ->
    case i2p_router_info:decode(RIData) of
        {ok, RI} -> State#{alice_ri => RI};
        {error, _Malformed} -> State
    end.

%% A RelayIntro on the tagged session is this router being selected as the
%% Charlie. Answer it in-session (the introducer relays the response to Alice)
%% and, on an accept, punch out of session.
serve_intro(Blocks, State) ->
    case lists:keyfind(relay_intro, 1, Blocks) of
        {relay_intro, _Flag, _AliceHash, Nonce, Tag, Ts, Ver, Port, Ip, Sig} ->
            answer_intro(Nonce, Tag, Ts, Ver, Port, Ip, Sig, State);
        false ->
            State
    end.

%% Charlie's verdict on an intro, in the order i2pd reaches it: the signature
%% is checked first, because an unverified endpoint is not one we are willing to
%% act on; the endpoint is checked next, because a punch at a private or
%% loopback literal is the one thing this router must never do and the refusal
%% costs nothing; and the punch budget is spent last, because a denial should
%% not consume the budget of the legitimate request behind it.
answer_intro(Nonce, Tag, Ts, Ver, Port, Ip, Sig, State = #{tagged_sess := Tagged}) ->
    case verify_intro(Nonce, Tag, Ts, Ver, Port, Ip, Sig, State) of
        {error, Code} ->
            i2p_log:debug({charlie, refused, nonce, Nonce, code, Code}, []),
            reject_charlie(Tagged, Code, Ver, Nonce, State);
        ok ->
            case i2p_addr_policy:punchable(Port, Ip) of
                false ->
                    i2p_log:debug({charlie, refused, nonce, Nonce, endpoint}, []),
                    reject_charlie(Tagged, 65, Ver, Nonce, State);
                true ->
                    case punch_allowed(State) of
                        {allow, State1} ->
                            accept_intro(Tagged, Ver, Nonce, Port, Ip, State1);
                        deny ->
                            reject_charlie(Tagged, 66, Ver, Nonce, State)
                    end
            end
    end.

%% Alice's signature over `"RelayRequestData" || bhash || chash || nonce || tag
%% || ts || ver || asz || port || ip`, verified with the router signing key her
%% own forwarded RouterInfo publishes. `chash` is this router and `bhash` the
%% introducer whose session forwarded the intro: both hashes are inside the
%% signed bytes, which is what makes the request unreflectable and unplayable
%% against a different pair of parties.
%%
%% Failure codes are Charlie's (64-70), not Bob's: the requester distinguishes
%% the two sides, and answering with a Bob code here would name the wrong party
%% as the refuser. A missing or unusable Alice RouterInfo is 70 ("Alice
%% unknown") and a bad signature 67, matching i2pd.
verify_intro(Nonce, Tag, Ts, Ver, Port, Ip, Sig, State = #{bob_local := BobLocal}) ->
    case {maps:get(alice_ri, State, undefined), introducer_hash(State)} of
        {undefined, _} ->
            {error, 70};
        {error, _} ->
            {error, 70};
        {AliceRI, {ok, BobHash}} ->
            Pub = i2p_keys:signing_key(i2p_router_info:identity(AliceRI)),
            OurHash = maps:get(hash, BobLocal),
            case
                i2p_relay:verify_request(
                    BobHash, OurHash, Ver, Nonce, Tag, Ts, Port, Ip, Sig, Pub
                )
            of
                true -> ok;
                false -> {error, 67}
            end
    end.

%% The hash of the introducer on the other end of the tagged session — the
%% `bhash` Alice signed against. It comes from that session's own handshake
%% RouterInfo, the same row `f:request_ri/2` reads, so an unknown peer is 70
%% rather than a verification against nothing.
introducer_hash(State = #{tagged_sess := Tagged}) ->
    case maps:get(Tagged, maps:get(sessions, State, #{}), undefined) of
        undefined -> error;
        RI -> {ok, i2p_router_info:hash(RI)}
    end.

%% A Charlie-side reject: our own signing key, no endpoint (csz 0), the
%% requester's nonce echoed. Sent to the introducer, which relays it to Alice.
reject_charlie(Tagged, Code, Ver, Nonce, State = #{bob_local := BobLocal}) ->
    Ts = erlang:system_time(second),
    %% `bhash` is the introducer's, not our own, and `introducer_hash/1` is
    %% exactly what `verify_intro/6` already required.
    case introducer_hash(State) of
        {ok, IntroHash} ->
            Sig = i2p_relay:sign_response(
                IntroHash, Ver, Nonce, Ts, 0, <<>>, maps:get(sign_seed, BobLocal)
            ),
            Reject = i2p_relay:response_block(Code, Ver, Nonce, Ts, 0, <<>>, Sig, undefined),
            i2p_ssu2_conn:send_relay(Tagged, Reject),
            State;
        error ->
            State
    end.

%% The accept. Charlie's endpoint is this router's own published SSU2 address,
%% signed with our router signing key — Alice verifies both against the
%% RouterInfo she was configured with, so this is the edge the whole relay
%% exists to make possible.
%%
%% The same response block is then sent twice: once in-session to the
%% introducer, and once inside the out-of-session HolePunch to Alice's asserted
%% endpoint. i2pd builds it once and reuses the bytes, and so does this: two
%% separately-built blocks could disagree, and Alice only reaches one conclusion
%% whichever lands.
accept_intro(Tagged, Ver, Nonce, Port, Ip, State = #{bob_local := BobLocal}) ->
    Ts = erlang:system_time(second),
    case published_endpoint(BobLocal) of
        {ok, OurPort, OurIp} ->
            {ok, IntroHash} = introducer_hash(State),
            Sig = i2p_relay:sign_response(
                IntroHash,
                Ver,
                Nonce,
                Ts,
                OurPort,
                OurIp,
                maps:get(sign_seed, BobLocal)
            ),
            Token = grant_token(),
            Response = i2p_relay:response_block(0, Ver, Nonce, Ts, OurPort, OurIp, Sig, Token),
            i2p_log:debug({charlie, accepted, nonce, Nonce}, []),
            i2p_ssu2_conn:send_relay(Tagged, Response),
            punch(Nonce, Ts, OurPort, OurIp, Port, Ip, Response, State);
        error ->
            %% No published SSU2 address of our own to hand Alice, so there is
            %% nothing for her to dial: refusing beats an accept she cannot use.
            i2p_log:debug({charlie, refused, nonce, Nonce, no_published_address}, []),
            reject_charlie(Tagged, 70, Ver, Nonce, State)
    end.

%% The session token this accept grants Alice, for the SessionRequest of her
%% redirect dial. Nonzero, because `requester_relay_response/2` treats `0` and
%% `undefined` alike and a zero token would buy nothing over the plain dial.
%%
%% **The accept has to carry one.** `requester_relay_response/2` gates its accept
%% branch on `is_integer(Token)`, so a tokenless accept falls through to its
%% reject arm and the requester exits `{relay_rejected, 0}` — Charlie agreed, and
%% the dial was reported as refused. That made the Charlie half of an indirect
%% dial unable to serve an i2per requester at all, which is why #98GAVQK's
%% coverage gap mattered: nothing ever ran the two halves against each other.
%%
%% The token is not checked against anything on our side: Charlie's own Bob
%% answers the redirect's SessionRequest whatever token it carries, so today the
%% redirect is authorised by arriving on the nonce-derived connection IDs and
%% the token is carried because the protocol has the field and a requester may
%% insist on it. See #BFKFGY0.
grant_token() ->
    %% `rand:uniform/1` on the full 64-bit range, then +1, so the result is in
    %% 1..2^64-1 and never zero. The same shape as the relay tag at line 396.
    rand:uniform(16#FFFFFFFFFFFFFFFF) + 1.

%% This router's own published SSU2 endpoint — the address Alice will dial after
%% the punch opens the path, and the endpoint the accept response carries. Read
%% from our RouterInfo rather than from the listener, because the listener's
%% port is what we bound and the published one is what peers can reach, and the
%% two differ on every firewalled router. The IP comes back as wire bytes, which
%% is what a relay block carries and what `f:punch_blocks/4` needs.
published_endpoint(BobLocal) ->
    case i2p_router_info:ssu2_address_options(maps:get(ri, BobLocal)) of
        {ok, #{published := true, host := Host, port := Port}} ->
            case endpoint_tuple(Host, Port) of
                {ok, {IP, Port}} -> {ok, Port, ip_bytes(IP)};
                error -> error
            end;
        _Unpublished ->
            error
    end.

%% Relay endpoint bytes come from the IP tuple the listener parsed. IPv4 is 4
%% bytes and IPv6 16, which is the length the codec fixes an endpoint at, so
%% reuse the SSU2 conn encoder rather than truncating.
ip_bytes(IP) ->
    i2p_ssu2_conn:ip_bin(IP).

%% The out-of-session HolePunch (type 11), sent straight to Alice's asserted
%% endpoint: a long-header datagram AEAD-sealed under **Alice's** introduction
%% key, carrying the same RelayResponse as the in-session copy. The connection
%% IDs derive from the relay nonce exactly as PeerTest's do, which is how Alice's
%% listener routes it to the session waiting on this relay.
punch(Nonce, Ts, OurPort, OurIp, Port, Ip, Response, State) ->
    case {maps:get(alice_ri, State, undefined), punch_endpoint(Port, Ip)} of
        {undefined, _} ->
            State;
        {AliceRI, {ok, Endpoint}} ->
            case alice_intro_key(AliceRI) of
                error ->
                    State;
                {ok, Bik} ->
                    Blocks = i2p_relay:punch_blocks(Ts, OurPort, OurIp, Response),
                    {ok, Packet} = i2p_ssu2:encode_holepunch(
                        Bik,
                        rand:uniform(16#FFFFFFFF),
                        i2p_relay:dst_conn_id(Nonce),
                        i2p_relay:src_conn_id(Nonce),
                        Blocks
                    ),
                    case relay_listener(State) of
                        undefined ->
                            State;
                        Listener ->
                            i2p_log:debug({charlie, punched, Nonce, Endpoint}, []),
                            i2p_ssu2_listener:send(Listener, Packet, Endpoint),
                            State
                    end
            end;
        {_AliceRI, error} ->
            State
    end.

%% The endpoint Alice asserted, as the listener's `{IP, Port}` shape. The
%% punchable check is here rather than in `punch/9` because it is a property of
%% the bytes as they arrived: 4 or 16 of them, and an address on the public
%% internet, or this router emits nothing at all.
punch_endpoint(Port, Ip) ->
    case i2p_addr_policy:punchable(Port, Ip) of
        true -> {ok, {ip_tuple(Ip), Port}};
        false -> error
    end.

%% Build the `inet:ip_address()` the punch datagram needs directly from the
%% asserted bytes, which `f:i2p_addr_policy:punchable/2` has already fixed at 4
%% or 16 bytes.
ip_tuple(<<A, B, C, D>>) ->
    {A, B, C, D};
ip_tuple(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

%% `{IP, Port}` from an address that may be a host string or a literal.
endpoint_tuple(Host, Port) when is_binary(Host), is_integer(Port), Port > 0 ->
    case inet:parse_address(binary_to_list(Host)) of
        {ok, IP} -> {ok, {IP, Port}};
        {error, _} -> error
    end;
endpoint_tuple(_Host, _Port) ->
    error.

%% The introduction key the punch is sealed under, recovered from Alice's
%% RouterInfo. Without it the datagram is undecryptable to her, so a RouterInfo
%% publishing no SSU2 address at all is a refusal rather than a send.
alice_intro_key(AliceRI) ->
    case i2p_router_info:ssu2_address_options(AliceRI) of
        {ok, Opts} -> {ok, maps:get(intro_key, Opts)};
        error -> error
    end.

-doc """
Spend one token from the HolePunch budget.

Input: coordinator state. Output: `{allow, State}` with the bucket debited, or
`deny` unchanged — the caller answers Charlie-side code 66 ("limit exceeded")
and sends nothing.

The bound is on the punch and not on the accept, because the punch is what
costs something outside this router: an accepted relay sends one datagram to an
address a third party chose, and an unbounded series of accepts is an
amplification vector aimed wherever the tag-holder likes. The budget is
`?PUNCH_BURST` punches and then one per second, which covers a legitimate
intro arriving with the burst of retransmits SSU2 can produce and stops a
replay.
""".
-spec punch_allowed(#{punch_bucket := i2p_token_bucket:bucket(), _ => _}) ->
    {allow, #{punch_bucket := i2p_token_bucket:bucket(), _ => _}} | deny.
punch_allowed(State = #{punch_bucket := Bucket}) ->
    case i2p_token_bucket:consume(Bucket, 1, erlang:system_time(millisecond)) of
        {allow, Bucket1} -> {allow, State#{punch_bucket => Bucket1}};
        deny -> deny
    end.

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
