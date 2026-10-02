-module(i2p_ssu2_listener).

-moduledoc """
Owns the SSU2 UDP socket and classifies every inbound datagram.

One listener per bound `Host`:`Port`. Classification resolves in order of
certainty, because the type byte cannot be trusted on its own: bytes 8..15 of a
datagram are masked with the peer's header protection key, which this process
does not hold, so a short header's type at offset 12 decodes to noise here.

1. Unmask bytes 0..7 with our introduction key and look up
   `i2p_ssu2_sessions`; a known connection ID is forwarded verbatim to that
   session process. Exact for both header forms.
2. Otherwise look up `i2p_ssu2_pending` by source endpoint. That is how a
   `SessionCreated` or `Retry` reaches the dialer waiting for it, and it needs
   no header interpretation at all, so it is exact too.
3. Only for a datagram from an endpoint nothing is waiting on is the type byte
   trustworthy: there, and only there, unmasking header bytes 8..15 with the
   introduction key reflects what an out-of-session peer actually did. That one
   open answers all three of the remaining cases at once, since the types are
   disjoint — an out-of-session `PeerTest`, which routes to a live session when
   the connection ID matches and is otherwise answered as Charlie; a
   `SessionRequest` or a `TokenRequest`, either of which spawns a fresh Bob-side
   session via `m:i2p_ssu2_sup` and hands it the datagram plus the peer endpoint;
   and anything else.
4. Anything else — corrupt, unknown type, or unclassifiable — is dropped
   without response; a bad datagram can never kill the listener.

Steps 1 and 2 precede any type inspection deliberately. Reading the type first
diverts a `SessionCreated` whose masked byte happens to read `PeerTest` into
the Charlie responder, which drops it, and the peer then dies with
`{handshake_timeout, session_request}` roughly one time in 256.

## Crypto per datagram: one pass, and where the others go

Unmasking a long header is one raw ChaCha20 pass per tail-derived mask, plus one
that decrypts header bytes 16..31 -- three for a full `f:i2p_ssu2:open_long/3`.
The receiving session then spends one AEAD decrypt on the datagram body, which is
the work the session exists to do. Measured here, on a 1472-byte datagram:

| | passes | µs |
| --- | --- | --- |
| `f:open_conn_id/3` -- step 1, routing | **1** | 0.76 |
| `f:open_header16/3` -- step 3, the type byte | 2 | 1.55 |
| `f:open_long/3` -- what routing used to cost | 3 | 2.30 |
| the AEAD decrypt the session then runs | (1) | 1.40 |
| answering one out-of-session probe, Charlie role | 8 | 6.80 |

So the socket owner spends, per datagram:

| the datagram is... | passes | µs |
| --- | --- | --- |
| claimed by a session or a pending dialer | **1** | 0.76 |
| from an unknown endpoint, and a probe, a SessionRequest or junk | 3 | 1.55 |
| from an unknown endpoint, and a TokenRequest | 5 | 4.80 |

One pass for a claimed datagram, because bytes 0..7 are the destination
connection id and that is what both lookups key on, so nothing else is worth
opening until a lookup has failed. It used to open the whole 32-byte header up
front -- three passes, two of them discarded on every datagram that had a session
-- and then open it again, twice more, in the handshake fallback. A claimed
datagram cost 2.30 µs, more than the 1.40 µs AEAD decrypt it existed to enable,
and is now 0.76. See #YNBT5ZD.

## What runs here, and what does not

Only routing happens on the socket owner. The Charlie responder
(`m:i2p_ssu2_charlie`) is a separate process reached by a cast, because answering
a probe is 6.80 µs -- nine times routing -- and this process is the only one that
can send, so its time is also every other session's send latency.

The socket is driven `{active, once}` so a flood can only starve itself;
each datagram re-arms the socket. Sessions send through this process
(`f:send/2`) because it alone owns the socket.
""".

-behaviour(gen_server).

-define(TYPE_SESSION_REQUEST, 0).
-define(TYPE_TOKEN_REQUEST, 10).
-define(TYPE_PEER_TEST, 7).

-export([
    listen/4,
    listen/5,
    port/1,
    stop/1,
    send/3,
    register_session/2,
    register_relay_tag/4,
    start_link/5,
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-define(HANDSHAKE_TYPES, [?TYPE_SESSION_REQUEST, ?TYPE_TOKEN_REQUEST]).

%% ------------------------------------------------------------------
%% API

-doc """
Bind an SSU2 listener on `Host`:`Port`.

Input: host IP string (e.g. `"127.0.0.1"`); port; the local keys map
(`static_priv`, `static_pub`, `intro_key`); the owner pid (informational,
monitored for shutdown).
Output: `{ok, Pid}` once the socket is bound.
""".
listen(Host, Port, LocalKeys, Owner) ->
    listen(Host, Port, LocalKeys, Owner, undefined).

-doc """
Bind an SSU2 listener, optionally naming a peer-test coordinator that owns the
introside Bob sessions this listener spawns.

Input: as `f:listen/4` plus `Coordinator`, either `undefined` (default; every
inbound session keeps the deterministic Bob-side peer-test reject) or a pid.
When a coordinator is given, each session this listener spawns is tagged with
it, so an inbound Alice message 1 is forwarded to the coordinator instead of
being auto-answered with the "no Charlie available" reject; the coordinator
routes it to a Charlie session or replies with the reject itself.
""".
-spec listen(binary(), 0..65535, map(), pid(), undefined | pid()) ->
    {ok, pid()}.
listen(Host, Port, LocalKeys, Owner, Coordinator) ->
    supervisor:start_child(
        i2p_ssu2_sup,
        #{
            id => {ssu2_listener, erlang:unique_integer([positive, monotonic])},
            start => {?MODULE, start_link, [Host, Port, LocalKeys, Owner, Coordinator]},
            restart => temporary,
            shutdown => 5000,
            type => worker,
            modules => [?MODULE]
        }
    ).

-doc "The actually bound UDP port (useful after requesting port 0).".
-spec port(pid()) -> 0..65535.
port(Pid) ->
    gen_server:call(Pid, port).

-doc "Stop the listener; sessions keep running under `m:i2p_ssu2_sup`.".
stop(Pid) ->
    gen_server:stop(Pid).

-doc "Send one datagram to `Endpoint` through the listener's socket.".
send(Pid, Datagram, Endpoint = {_IP, _Port}) when is_binary(Datagram) ->
    gen_server:cast(Pid, {send, Datagram, Endpoint}).

-doc """
Register a session for connection-id routing and start monitoring it; the
entry is removed automatically when the session dies.
""".
register_session(Pid, ConnId) ->
    gen_server:cast(Pid, {register, self(), ConnId}).

-doc """
Register a handed-out relay tag against the session holding it.

Input: the listener pid; the 32-bit relay `Tag`; the `SessionPid` that owns
the tag; and the Unix-second `Expires` deadline. The row
`{Tag, SessionPid, Expires}` is inserted into the public `i2p_ssu2_relay_tags`
table and the session is monitored, so the row is deleted automatically when
the session dies (see the `'DOWN'` handler). The introducer coordinator
(`m:i2p_relay_coord`) calls this when it answers a relay-tag request.
""".
-spec register_relay_tag(pid(), pos_integer(), pid(), non_neg_integer()) -> ok.
register_relay_tag(Pid, Tag, SessionPid, Expires) when is_pid(SessionPid) ->
    gen_server:cast(Pid, {register_relay_tag, Tag, SessionPid, Expires}).

%% ------------------------------------------------------------------
%% gen_server

-spec start_link(
    inet:ip_address() | binary() | string(),
    0..65535,
    map(),
    pid(),
    undefined | pid()
) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, LocalKeys, Owner, Coordinator) when
    Coordinator =:= undefined; is_pid(Coordinator)
->
    gen_server:start_link(?MODULE, {Host, Port, LocalKeys, Owner, Coordinator}, []).

init({Host, Port, LocalKeys, Owner, Coordinator}) ->
    case inet:parse_address(binary_to_list(Host)) of
        {ok, IPAddress} ->
            open_socket(IPAddress, Port, LocalKeys, Owner, Coordinator);
        _BadHost ->
            {stop, badarg}
    end.

open_socket(IPAddress, Port, LocalKeys, Owner, Coordinator) ->
    case
        gen_udp:open(Port, [
            binary, {active, once}, {reuseaddr, true}, {ip, IPAddress}
        ])
    of
        {ok, Sock} ->
            {ok, BoundPort} = inet:port(Sock),
            erlang:monitor(process, Owner),
            catch register(i2p_ssu2_listener, self()),
            {ok, #{
                sock => Sock,
                port => BoundPort,
                local => LocalKeys,
                owner => Owner,
                %% `undefined` until the first probe needs answering. A listener
                %% cannot ask its own supervisor for a child from `init/1` -- that
                %% re-enters the supervisor that is in the middle of starting this
                %% very listener, and deadlocks -- so the responder is started on
                %% first use instead. That is also the cheaper shape: a router that
                %% is never tested as Charlie never starts one.
                charlie => undefined,
                peer_test_coordinator => Coordinator
            }};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(port, _From, State = #{port := Port}) ->
    {reply, Port, State};
handle_call(_Other, _From, State) ->
    {noreply, State}.

handle_cast({send, Datagram, Endpoint}, State = #{sock := Sock}) ->
    Size = byte_size(Datagram),
    i2p_log:debug({listener_send, self(), Endpoint, Size}, []),
    %% The single funnel for every outbound datagram — data, keepalives,
    %% handshake retransmits and data-phase resends all arrive here — so this is
    %% the only place a byte can be charged once and counted once. A resend
    %% therefore counts again, which is what bytes-on-the-wire means.
    ok = i2p_stats:add(ssu2_bytes_out, Size),
    ok = gen_udp:send(Sock, Endpoint, Datagram),
    {noreply, State};
handle_cast({register, Pid, ConnId}, State) ->
    _ = ets:insert(i2p_ssu2_sessions, {ConnId, Pid}),
    erlang:monitor(process, Pid),
    {noreply, State};
handle_cast({register_pending, Pid, Endpoint}, State) ->
    _ = ets:insert(i2p_ssu2_pending, {Endpoint, Pid}),
    erlang:monitor(process, Pid),
    {noreply, State};
handle_cast({register_relay_tag, Tag, Pid, Expires}, State) ->
    _ = ets:insert(i2p_ssu2_relay_tags, {Tag, Pid, Expires}),
    erlang:monitor(process, Pid),
    {noreply, State};
%% A finished Charlie reply, sealed by `m:i2p_ssu2_charlie`. Bytes and endpoint,
%% nothing decoded: this process's part is the send, and the byte count is charged
%% here for the same reason every other outbound datagram is -- the socket funnel
%% is the one place a byte can be counted exactly once. Kept as its own clause and
%% not folded into the `{send, ...}` one above because a reply is not session
%% traffic, and a reader of the counter should be able to see that.
handle_cast({charlie_reply, {Datagram, Endpoint}}, State = #{sock := Sock}) ->
    Size = byte_size(Datagram),
    i2p_log:debug({charlie_msg7_reply, Endpoint, Size}, []),
    ok = i2p_stats:add(ssu2_bytes_out, Size),
    ok = gen_udp:send(Sock, Endpoint, Datagram),
    {noreply, State};
handle_cast({charlie_reply, _Malformed}, State) ->
    {noreply, State};
handle_cast(_Other, State) ->
    {noreply, State}.

handle_info({udp, Sock, IP, PortNum, Datagram}, State = #{sock := Sock}) ->
    %% Charged on arrival, before classification. UDP preserves message
    %% boundaries, so this is the exact datagram size with no framing guesswork
    %% in it.
    ok = i2p_stats:add(ssu2_bytes_in, byte_size(Datagram)),
    %% Re-armed before classification, not after. It matters only while the
    %% responder is being started on a probe, which is a supervisor call from
    %% inside this process -- but re-arming first means the socket is already
    %% listening again by the time we go looking for it, so a datagram arriving in
    %% that window waits in the driver's buffer rather than being missed.
    _ = inet:setopts(Sock, [{active, once}]),
    {noreply, classify(self(), Datagram, IP, PortNum, State)};
handle_info({'DOWN', _MRef, process, Pid, _Info}, State = #{charlie := Pid}) ->
    %% The responder died on unauthenticated input, which is what it is for. The
    %% socket owner does not die with it, and does not lose its send path: replace
    %% the responder and carry on. Its work is optional by construction, so unlike a
    %% session there is nothing here worth failing the listener over -- and a
    %% replacement that cannot start is not worth losing the socket for either.
    i2p_log:debug({charlie_responder_died, Pid}, []),
    restart_charlie(State);
handle_info({'DOWN', _MRef, process, Pid, _Info}, State) ->
    %% Remove any session entries owned by the dead pid; the tables die
    %% with the supervisor during shutdown, so tolerate that too.
    catch ets:match_delete(i2p_ssu2_sessions, {'_', Pid}),
    catch ets:match_delete(i2p_ssu2_pending, {'_', Pid}),
    catch ets:match_delete(i2p_ssu2_relay_tags, {'_', Pid, '_'}),
    {noreply, State};
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, #{sock := Sock}) ->
    catch gen_udp:close(Sock),
    ok.

%% Replace a dead responder. A `temporary` child is never restarted by the
%% supervisor, so this has to ask for a new one explicitly; there is no bound on
%% how often, because a responder dying on hostile input is not a condition the
%% listener can fix by waiting.
restart_charlie(State = #{local := Local}) ->
    case i2p_ssu2_sup:start_charlie(maps:get(intro_key, Local)) of
        {ok, Charlie} ->
            erlang:monitor(process, Charlie),
            {noreply, State#{charlie := Charlie}};
        {error, _Reason} ->
            %% Back to `undefined`, and that is not a tidiness point: a dead pid
            %% left in the state would be found by the next probe's
            %% `f:ensure_charlie/1` and cast to, and a cast to a dead process is
            %% silently dropped -- so one failed replacement would cost the role for
            %% the life of the listener, with nothing left to try again. As
            %% `undefined` the next probe asks for a responder, which is the one
            %% thing that can fix it.
            i2p_log:debug(charlie_responder_restart_failed, []),
            {noreply, State#{charlie => undefined}}
    end.

%% ------------------------------------------------------------------
%% Classification

%% Every branch returns the listener's state, not `ok`/`drop`. That is not tidiness:
%% the one branch that changes state is the Charlie responder's lazy start, and a
%% classifier that returned `drop` would throw away the pid it just created and
%% start a second responder on the next probe.
classify(ListenerPid, Datagram, IP, PortNum, State = #{local := Local}) ->
    Bik = maps:get(intro_key, Local),
    case i2p_ssu2:open_conn_id(Datagram, Bik, Bik) of
        {ok, ConnId} ->
            route_or_handshake(ListenerPid, ConnId, Datagram, IP, PortNum, State);
        error ->
            %% Shorter than ?MIN_PACKET, so not an SSU2 packet at all.
            i2p_log:debug({classify, ListenerPid, drop, {IP, PortNum}}, []),
            State
    end.

%% Out-of-session PeerTest (type 7). Route to a live session by nonce-derived
%% connection id when one matches (Alice-role: the datagram is for one of our
%% initiated tests); otherwise hand it to the tested-peer responder
%% (Charlie-role).
route_peertest(ConnId, Datagram, IP, PortNum, State) ->
    case ets:lookup(i2p_ssu2_sessions, ConnId) of
        [{_Id, Pid}] ->
            i2p_log:debug({route_peertest, session, ConnId}, []),
            Pid ! {ssu2_packet, Datagram},
            State;
        [] ->
            charlie_peertest(Datagram, IP, PortNum, State)
    end.

%% Charlie-role responder: this router is the tested peer, and an inbound
%% Alice->Charlie message 6 gets a Charlie->Alice message 7 back to the source
%% endpoint.
%%
%% Handed to `m:i2p_ssu2_charlie` rather than done here, because answering a probe
%% is 6.7 us against 0.73 us to route -- and this process is the only one that can
%% send, so its time is also every session's send latency. There is no session to
%% attach the role to (the probe arrives out-of-session, addressed to the intro
%% key), which is why it became its own process rather than a session child.
%%
%% `answer/4` is a cast, so a responder that is busy, dead or wedged cannot delay
%% classification of the next datagram.
charlie_peertest(Datagram, IP, PortNum, State) ->
    {Charlie, State1} = ensure_charlie(State),
    i2p_log:debug({route_peertest, charlie_responder, Charlie}, []),
    ok = i2p_ssu2_charlie:answer(Charlie, self(), Datagram, {IP, PortNum}),
    State1.

%% Start the responder on first use. It cannot be started in `init/1` -- that
%% re-enters the supervisor that is in the middle of starting this listener -- so
%% this is where it happens, and it happens once because the pid lands in the
%% state and the next probe finds it there.
%%
%% A failure is not the listener's problem: without a responder this router does
%% not answer peer tests as Charlie, which costs the role and nothing else.
%% Classification and every session carry on. That asymmetry is the point of having
%% moved the work off this process at all.
ensure_charlie(State = #{charlie := undefined, local := Local}) ->
    case i2p_ssu2_sup:start_charlie(maps:get(intro_key, Local)) of
        {ok, Charlie} ->
            erlang:monitor(process, Charlie),
            {Charlie, State#{charlie := Charlie}};
        {error, _Reason} ->
            i2p_log:debug(charlie_responder_start_failed, []),
            {undefined, State}
    end;
ensure_charlie(State = #{charlie := Charlie}) ->
    {Charlie, State}.

%% Routing order is deliberate, and it is a correctness fix rather than a
%% preference. Bytes 8..15 of an in-session short header are masked with THAT
%% session's header protection key, which this listener does not hold, so the
%% type byte at offset 12 decodes to noise in any short-header datagram. The
%% classifier used to compare that noise against ?TYPE_PEER_TEST, so a
%% SessionCreated whose masked byte happened to read 7 was hijacked into the
%% Charlie responder, failed to decode, and was dropped -- the peer then
%% exhausted its retransmits and died with {handshake_timeout, session_request}.
%% That misroute happens for roughly one packet in 256, which is why it read as
%% an unreproducible flake.
%%
%% So resolve in order of certainty. A live session is matched by connection ID,
%% which is exact: both header forms mask bytes 0..7 with our intro key. A
%% pending outbound session is matched by source endpoint, also exact, and that
%% is the path a SessionCreated or Retry must take. Only once neither matches --
%% a datagram from an endpoint nothing is waiting on -- is an out-of-session
%% PeerTest possible, and only there does unmasking the whole header with the
%% intro key reflect what the out-of-session sender actually did, so only there
%% is the type byte trustworthy.
%%
%% **One unmask per datagram, at the point the answer needs it.** `f:classify/5`
%% recovers the connection id with a single ChaCha20 pass (`f:open_conn_id/3`) and
%% the two lookups above need nothing more, so a datagram either of them claims
%% stops there. Only a datagram that matches neither pays for the type byte. It
%% used to ask for the whole header up front -- three passes, of which two were
%% discarded on every datagram that had a session -- and then re-derive the whole
%% header twice more in the handshake fallback. Measured on a 1472-byte datagram:
%% routing was 2.30 us and is now 0.76, against 1.40 us for the AEAD decrypt the
%% receiving session then does. See #YNBT5ZD.
route_or_handshake(ListenerPid, ConnId, Datagram, IP, PortNum, State) ->
    case ets:lookup(i2p_ssu2_sessions, ConnId) of
        [{_Id, Pid}] ->
            i2p_log:debug({route_or_handshake, session, ConnId}, []),
            Pid ! {ssu2_packet, Datagram},
            State;
        [] ->
            case ets:lookup(i2p_ssu2_pending, {IP, PortNum}) of
                [{_Ep, PendingPid}] ->
                    i2p_log:debug({route_or_handshake, pending, {IP, PortNum}}, []),
                    PendingPid ! {ssu2_packet, Datagram},
                    State;
                [] ->
                    route_unowned(ListenerPid, ConnId, Datagram, IP, PortNum, State)
            end
    end.

%% The only datagram that needs a second look, because it is the only one whose
%% type byte may be believed -- a datagram no session and no pending dialer
%% claimed. The type byte lives in header bytes 8..15, under the *second* mask,
%% so this cannot reuse the connection id from `f:classify/5`, and it stops at
%% byte 15 rather than opening all 32: bytes 16..31 are a source connection id and
%% a token that nothing here reads, and the Bob session that ends up owning the
%% datagram opens them under the keys its own handshake derives.
%%
%% **One open, three answers.** The three types are disjoint, so which one is
%% tested first is immaterial and the header is opened once for all of them. It
%% used to be opened three times for a datagram that was none of them: once here
%% to look for a PeerTest, once inside `f:decode_token_request/2` on the way to
%% the SessionRequest test, and once more for that test -- nine ChaCha20 passes to
%% decide to drop a datagram. It is now three.
route_unowned(ListenerPid, ConnId, Datagram, IP, PortNum, State = #{local := Local}) ->
    Bik = maps:get(intro_key, Local),
    case i2p_ssu2:open_header16(Datagram, Bik, Bik) of
        {ok, <<_:64/big-unsigned-integer, _Num:32, ?TYPE_PEER_TEST:8, _/binary>>} ->
            i2p_log:debug({classify, ListenerPid, peertest, ConnId}, []),
            route_peertest(ConnId, Datagram, IP, PortNum, State);
        {ok, <<_:64/big-unsigned-integer, _Num:32, ?TYPE_SESSION_REQUEST:8, 2:8, 2:8, _:8>>} ->
            %% Type, version and net ID, all inside the 16 bytes already opened.
            %% The spawned session reads the source connection id and the token
            %% itself, under keys this process does not have.
            i2p_log:debug({handshake, session_request, ConnId}, []),
            spawn_bob(ConnId, Datagram, IP, PortNum, Local, State);
        {ok, <<_:64/big-unsigned-integer, _Num:32, ?TYPE_TOKEN_REQUEST:8, _/binary>>} ->
            i2p_log:debug({handshake, token_request, ConnId}, []),
            try_token_request(ConnId, Datagram, IP, PortNum, Local, State);
        _NotAHandshake ->
            i2p_log:debug({handshake, drop, ConnId}, []),
            State
    end.

%% The one type that needs the payload read here, and so the one type allowed to
%% pay for it: `f:decode_token_request/2` opens the header again, and has to,
%% because a TokenRequest carries blocks this process must read to decide whether
%% it is one -- the Bob session is handed the datagram and re-opens it under the
%% keys the handshake derives.
%%
%% A type byte that says TokenRequest and does not decode as one is a drop, and
%% that is what it gets, by the same door as every other unreadable datagram: it
%% frames as `drop` there, one line for every reason the socket owner stays
%% silent, rather than two lines that differ only in a clause nobody reading them
%% can tell apart.
try_token_request(ConnId, Datagram, IP, PortNum, Local, State) ->
    Bik = maps:get(intro_key, Local),
    case i2p_ssu2:decode_token_request(Bik, Datagram) of
        {ok, _TokenReqInfo} ->
            spawn_bob(ConnId, Datagram, IP, PortNum, Local, State);
        error ->
            State
    end.

spawn_bob(
    ConnId,
    Datagram,
    IP,
    PortNum,
    Local,
    State = #{owner := Owner, peer_test_coordinator := Coordinator}
) ->
    Args0 =
        #{
            role => bob,
            owner => Owner,
            local => Local,
            listener => self(),
            first_packet => Datagram,
            endpoint => {IP, PortNum}
        },
    Args = maybe_coordinator(Args0, Coordinator),
    case i2p_ssu2_sup:start_session(i2p_ssu2_sup:session_child(Args)) of
        {ok, _Pid} ->
            State;
        _StartFailed ->
            %% At the session limit, most likely. The datagram is simply not
            %% answered, exactly as a dropped datagram is not answered; the peer
            %% retransmits and someone else answers.
            ets:delete(i2p_ssu2_sessions, ConnId),
            State
    end.

maybe_coordinator(Args, undefined) ->
    Args;
maybe_coordinator(Args, Coordinator) ->
    Args#{peer_test_coordinator => Coordinator}.
