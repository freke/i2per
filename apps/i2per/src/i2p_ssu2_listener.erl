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
3. Only for a datagram from an endpoint nothing is waiting on can it be an
   out-of-session `PeerTest`. There, and only there, unmasking the whole header
   with the introduction key reflects what an out-of-session peer actually did,
   so the type byte is finally trustworthy: route it to a live session when the
   connection ID matches, otherwise answer it as Charlie.
4. Otherwise try a long-header handshake message (`TokenRequest` or
   `SessionRequest`); valid ones spawn a fresh Bob-side session via
   `m:i2p_ssu2_sup` and hand it the datagram plus the peer endpoint.
5. Anything else — corrupt, unknown type, or unclassifiable — is dropped
   without response; a bad datagram can never kill the listener.

Steps 1 and 2 precede any type inspection deliberately. Reading the type first
diverts a `SessionCreated` whose masked byte happens to read `PeerTest` into
the Charlie responder, which drops it, and the peer then dies with
`{handshake_timeout, session_request}` roughly one time in 256.

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
handle_cast(_Other, State) ->
    {noreply, State}.

handle_info({udp, Sock, IP, PortNum, Datagram}, State = #{sock := Sock}) ->
    %% Charged on arrival, before classification. UDP preserves message
    %% boundaries, so this is the exact datagram size with no framing guesswork
    %% in it.
    ok = i2p_stats:add(ssu2_bytes_in, byte_size(Datagram)),
    classify(self(), Datagram, IP, PortNum, State),
    _ = inet:setopts(Sock, [{active, once}]),
    {noreply, State};
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

%% ------------------------------------------------------------------
%% Classification

classify(ListenerPid, Datagram, IP, PortNum, State = #{local := Local}) ->
    Bik = maps:get(intro_key, Local),
    case i2p_ssu2:open_long(Datagram, Bik, Bik) of
        {ok, <<ConnId:64/big-unsigned-integer, _/binary>>} ->
            route_or_handshake(ListenerPid, ConnId, Datagram, IP, PortNum, State);
        error ->
            %% Shorter than ?MIN_PACKET, so not an SSU2 packet at all.
            i2p_log:debug({classify, ListenerPid, drop, {IP, PortNum}}, []),
            drop
    end.

%% Out-of-session PeerTest (type 7). Route to a live session by nonce-derived
%% connection id when one matches (Alice-role: the datagram is for one of our
%% initiated tests); otherwise handle it directly as the tested peer
%% (Charlie-role responder).
route_peertest(ConnId, Datagram, IP, PortNum, State) ->
    case ets:lookup(i2p_ssu2_sessions, ConnId) of
        [{_Id, Pid}] ->
            i2p_log:debug({route_peertest, session, ConnId}, []),
            Pid ! {ssu2_packet, Datagram},
            ok;
        [] ->
            i2p_log:debug({route_peertest, charlie_responder, ConnId}, []),
            charlie_peertest(Datagram, IP, PortNum, State)
    end.

%% Charlie-role responder: this router is the tested peer. On an inbound
%% Alice->Charlie message 6, replay a Charlie->Alice message 7 to the source
%% endpoint, carrying no hash/signature and echoing Alice's nonce/timestamp/
%% port/IP. Signature and hash are optional out-of-session (see docs).
charlie_peertest(Datagram, IP, PortNum, #{local := Local}) ->
    Bik = maps:get(intro_key, Local),
    case i2p_ssu2:decode_peertest(Bik, Datagram) of
        {ok, #{blocks := Blocks}} ->
            case lists:keyfind(peertest, 1, Blocks) of
                {peertest, 6, _Code, _Flags, _Hash, _Ver, Nonce, Ts, Port, Ip, _Sig} ->
                    i2p_log:debug({charlie_msg7_reply, {IP, PortNum}}, []),
                    Reply = i2p_peertest:block(7, 0, 0, <<>>, 2, Nonce, Ts, Port, Ip, <<>>),
                    Dst = i2p_peertest:dst_conn_id(Nonce),
                    Src = i2p_peertest:src_conn_id(Nonce),
                    {ok, Packet} = i2p_ssu2:encode_peertest(Bik, 0, Dst, Src, [Reply]),
                    i2p_ssu2_listener:send(self(), Packet, {IP, PortNum}),
                    ok;
                _Other ->
                    i2p_log:debug(charlie_peertest_other, []),
                    drop
            end;
        _NotPeertest ->
            i2p_log:debug(charlie_peertest_decode_error, []),
            drop
    end.

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
route_or_handshake(ListenerPid, ConnId, Datagram, IP, PortNum, State) ->
    case ets:lookup(i2p_ssu2_sessions, ConnId) of
        [{_Id, Pid}] ->
            i2p_log:debug({route_or_handshake, session, ConnId}, []),
            Pid ! {ssu2_packet, Datagram},
            ok;
        [] ->
            case ets:lookup(i2p_ssu2_pending, {IP, PortNum}) of
                [{_Ep, PendingPid}] ->
                    i2p_log:debug({route_or_handshake, pending, {IP, PortNum}}, []),
                    PendingPid ! {ssu2_packet, Datagram},
                    ok;
                [] ->
                    route_unowned(ListenerPid, ConnId, Datagram, IP, PortNum, State)
            end
    end.

route_unowned(ListenerPid, ConnId, Datagram, IP, PortNum, State = #{local := Local}) ->
    Bik = maps:get(intro_key, Local),
    case i2p_ssu2:open_long(Datagram, Bik, Bik) of
        {ok, <<_:64/big-unsigned-integer, _Num:32, ?TYPE_PEER_TEST:8, _/binary>>} ->
            i2p_log:debug({classify, ListenerPid, peertest, ConnId}, []),
            route_peertest(ConnId, Datagram, IP, PortNum, State);
        _ ->
            i2p_log:debug({classify, ListenerPid, try_handshake, ConnId}, []),
            try_handshake(ConnId, Datagram, IP, PortNum, State)
    end.

try_handshake(ConnId, Datagram, IP, PortNum, State = #{local := Local}) ->
    Bik = maps:get(intro_key, Local),
    case i2p_ssu2:decode_token_request(Bik, Datagram) of
        {ok, _TokenReqInfo} ->
            i2p_log:debug({handshake, token_request, ConnId}, []),
            spawn_bob(ConnId, Datagram, IP, PortNum, Local, State);
        error ->
            case i2p_ssu2:open_long(Datagram, Bik, Bik) of
                {ok,
                    <<_:64, _Num:32, ?TYPE_SESSION_REQUEST:8, 2:8, 2:8, _:8, _:64, _Tok:64,
                        _/binary>>} ->
                    i2p_log:debug({handshake, session_request, ConnId}, []),
                    spawn_bob(ConnId, Datagram, IP, PortNum, Local, State);
                _NotAHandshake ->
                    i2p_log:debug({handshake, drop, ConnId}, []),
                    drop
            end
    end.

spawn_bob(
    ConnId,
    Datagram,
    IP,
    PortNum,
    Local,
    #{owner := Owner, peer_test_coordinator := Coordinator} = _State
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
            ok;
        _StartFailed ->
            ets:delete(i2p_ssu2_sessions, ConnId),
            drop
    end.

maybe_coordinator(Args, undefined) ->
    Args;
maybe_coordinator(Args, Coordinator) ->
    Args#{peer_test_coordinator => Coordinator}.
