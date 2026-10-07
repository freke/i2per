-module(i2p_ssu2_conn).

-moduledoc """
One SSU2 session process: the Noise handshake over UDP and the established data
phase.

Exactly one process owns one session's handshake state and packet numbers;
a bad peer can only kill its own session. Handshake failures are permanent:
a protocol violation or exhausted identical retransmissions ends the
process (`exit({protocol_error | handshake_timeout, Phase})`) — recovery is
the transport manager's job (`m:i2p_peer`), never this process's.

## Roles

* `alice` — started by `f:connect/5`; sends SessionRequest with a zero
  token, handles the Retry that grants one, then Created/Confirmed.
* `bob` — spawned by `m:i2p_ssu2_listener` with the first inbound
  SessionRequest; answers SessionCreated, validates Alice's RouterInfo
  against her decrypted static key, acknowledges packet zero.

Both roles register their connection ID in `i2p_ssu2_sessions` for routing,
exchange `{ssu2_packet, Datagram}` messages with the listener, and send
outbound datagrams through it because only the listener owns the socket.

## Messages to the owner

* `{ssu2_ready, Pid, Info, RemoteRI}` — established; `Info` carries the
  derived `t:i2p_ssu2:data_keys/0`, `RemoteRI` the unverified RouterInfo that
  dialed us (bob), or `undefined` (alice).
* `{ssu2_data, Pid, Blocks}` — decoded blocks from a Data datagram.
* `{ssu2_closed, Pid, Reason}` — peer sent Termination.
""".

-behaviour(gen_server).

-export([
    connect/4,
    connect/5,
    connect_via_introducer/5,
    dial_budget_ms/0,
    set_owner/2,
    send_i2np/4,
    send_peertest/2,
    send_router_info/3,
    send_relay/2,
    initiate_peertest/4,
    terminate_session/2,
    charlie_reply_block/7
]).
-export([
    start_link/1,
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-export_type([config/0, local_keys/0, remote_opts/0]).

-define(RETRY_MS, 1000).
%% Session-request retransmits before giving up. Session establishment over a
%% lossy path (or a stalled listener under load) retries every RETRY_MS; after
%% MAX_RESENDS unanswered retransmits the session exits
%% `{handshake_timeout, session_request}`. Defaults bound a ~10 s establishment
%% window (SSU2 has no fixed spec value; Java I2P/i2pd use comparable budgets).
%% Overridable per app via `i2per` env `handshake_retry_ms` /
%% `handshake_max_resends`.
-define(MAX_RESENDS, 9).
%% The indirect (introducer) leg's own bound: how long the redirect to a
%% firewalled Charlie is waited for before the dial gives up on her introducers
%% and falls back to NTCP2. Named and exported through `f:dial_budget_ms/0`
%% because it is the longest single thing an SSU2 dial can block on, and
%% `m:i2p_peer`'s deadline on `connecting` has to exceed it — a deadline written
%% as its own number here would be a second copy that drifts.
-define(REDIRECT_TIMEOUT_MS, 60000).
%% How many `{nack, ack}` range pairs a session's ACK blocks may carry. This is
%% a *policy* choice — the wire format would allow more — and it is deliberately
%% the single place the number is written down, because the receive window's
%% bound is derived from it: an ACK block cannot name a packet number further
%% than `?ACK_MAX + this * 2 * ?ACK_MAX` below the highest received, so this
%% value is also how far back `m:i2p_ssu2_recv` retains. Raising it widens the
%% window as a side effect; the two cannot be changed independently without the
%% window becoming wrong about what an ACK can still express. See #7GP4A4K.
-define(MAX_ACK_RANGES, 20).
%% How long after the in-session message 4 Alice waits before judging the
%% reachability result, so an absent but still-in-flight out-of-session
%% message 5 (or the 6->7 probe) has time to land (SSU2 spec: wait several
%% seconds after message 4). A longer window is a failure-detection bound
%% only: when Charlie's out-of-session message 5 arrives, the result is `ok`
%% and is judged immediately without waiting for the timer. Overridable per
%% app via `i2per` env `peertest_settle_ms`.
-define(PEERTEST_SETTLE_MS, 10000).
%% Out-of-session HolePunch (type 11): Charlie pre-opening a path to Alice
%% during an introducer relay. Inbound it is routed by the relay-nonce
%% connection ID and decoded with our own introduction key.
-define(TYPE_HOLE_PUNCH, 11).
%% Data-phase keepalive: a path_challenge (type 18) block is sent every
%% KEEPALIVE_INTERVAL_MS and the peer echoes it as a path_response (type 19).
%% Any received datagram refreshes the session's last-recv activity; if none
%% arrives for IDLE_TIMEOUT_MS the session is considered dead and stops with
%% `{idle_timeout, no_activity}`. Both are overridable per run via app env
%% `i2per` -> `keepalive_interval_ms` / `idle_timeout_ms`.
-define(KEEPALIVE_INTERVAL_MS, 60000).
-define(IDLE_TIMEOUT_MS, 120000).
%% Data-phase loss recovery for ack-eliciting packets. Every tracked outbound
%% packet stays in `out_pkts` until a peer ACK covers it, so a peer that has
%% not acknowledged one of them within DATA_RESEND_MS gets the whole unacked
%% set resent under fresh packet numbers (idempotent to a receiver: fragment
%% and message identity survives renumbering). Without this, recovery is
%% NACK-only and a single lost packet is unrecoverable once its NACK pair is
%% lost too. Overridable per run via app env `i2per` -> `data_resend_ms`.
-define(DATA_RESEND_MS, 2000).
-define(PATH_CHALLENGE_BYTES, 8).
-define(TYPE_PEER_TEST, 7).
-define(TYPE_SESSION_REQUEST, 0).
-define(MTU, 1472).
%% Bytes left for block data after the 16-byte header and 16-byte AEAD tag.
-define(MAX_PAYLOAD, ?MTU - 32).
%% Largest body a single fragment may carry, leaving room for the fragment
%% (or whole-I2NP) block overhead.
-define(MAX_FRAG_BODY, ?MAX_PAYLOAD - 12).
%% Upper bound on in-flight reassembly buffers for uncompleted fragments.
-define(MAX_REASSEMBLY, 128).

-doc """
Local SSU2 identity material: the X25519 static keypair plus the
introduction key published in our SSU2 RouterAddress.
""".
-type local_keys() :: #{
    static_priv := i2p_crypto:x25519_private_key(),
    static_pub := i2p_crypto:x25519_public_key(),
    intro_key := binary(),
    sign_seed => i2p_crypto:ed25519_seed(),
    sign_pub => i2p_crypto:ed25519_public_key(),
    hash => i2p_crypto:hash(),
    ri => i2p_router_info:router_info()
}.

-doc """
Dial-out address options for a remote SSU2 router, as produced by
`f:i2p_router_info:ssu2_address_options/1` plus a `peer_test` flag. The
`peer_test` key is carried through the session but not consumed by the
Alice-side handshake; it is a hint that the remote advertises the `B`
(peer-test capable) capability.
""".
-type remote_opts() :: #{
    host := binary(),
    port := 1..65535,
    static_key := binary(),
    intro_key := binary(),
    peer_test := boolean()
}.

-doc """
Session start configuration. `alice` additionally needs `remote` (decoded
address options from `f:i2p_router_info:ssu2_address_options/1`), `ri_block`
(her encoded type-2 RouterInfo block for SessionConfirmed) and `listener`;
`bob` instead receives `first_packet` + `endpoint` + `listener` from
`m:i2p_ssu2_listener`.

`peer_test_role` is optional and holds the router's explicit peer-test intent
for this session — `alice` (the test target), `bob` (the introducer) or
`charlie` (the tested peer). When absent, the default inference from the
handshake role and the block message number applies.

`peer_test_coordinator` is optional and names an external coordinator (a
separate process) that owns the routing of this session's peer-test blocks.
When set on a `bob` session, the session no longer auto-answers an inbound
message 1 with the deterministic "no Charlie available" reject; instead it
forwards the block to the owner (the coordinator), which decides whether to
relay it to a Charlie session or reply with the reject itself.
""".
-type config() :: #{
    role := alice | bob,
    owner := pid(),
    local := local_keys(),
    listener := pid(),
    remote => remote_opts(),
    ri_block => binary(),
    first_packet => binary(),
    endpoint => {inet:ip_address(), 0..65535},
    peer_test_role => alice | bob | charlie,
    peer_test_coordinator => pid(),
    %% Indirec-dial (requester) overrides, set by `f:connect_via_introducer/6`
    %% and the redirect session it spawns.
    src_conn_id => i2p_ssu2:conn_id(),
    dst_conn_id => i2p_ssu2:conn_id(),
    token => i2p_ssu2:token(),
    relay_role => requester,
    %% Requester relay material: the introducer's placement, the target
    %% charlie's RouterInfo (keys + signing pub) and our asserted endpoint.
    relay => #{
        bob_hash := binary(),
        charlie_hash := binary(),
        charlie_ri := i2p_router_info:router_info(),
        tag := pos_integer(),
        our_port := 0..65535,
        our_ip := binary(),
        sign_seed := i2p_crypto:ed25519_seed()
    }
}.

%% ------------------------------------------------------------------
%% API

-doc """
Connect out to a remote SSU2 router; blocks until the handshake completes.

Input: local keys; remote address options; the encoded RouterInfo block to
carry in SessionConfirmed; the listener pid owning our UDP socket.
Output: `{ok, Pid, Info}` once established, `{error, Reason}` when the
session dies before that.
""".
-spec connect(i2p_ssu2_conn:local_keys(), i2p_ssu2_conn:remote_opts(), binary(), pid()) ->
    {ok, pid(), i2p_ssu2:data_keys()} | {error, term()}.
connect(LocalKeys, RemoteOpts, RIBlock, Listener) ->
    connect(LocalKeys, RemoteOpts, RIBlock, Listener, undefined).

-doc """
Connect out, optionally tagging the session with an explicit peer-test role
(`alice` the test target, `bob` the introducer, `charlie` the tested peer).
Passing `undefined` (the default) leaves the session untagged, so its
peer-test behavior is inferred as before.
""".
-spec connect(
    i2p_ssu2_conn:local_keys(),
    i2p_ssu2_conn:remote_opts(),
    binary(),
    pid(),
    alice | bob | charlie | undefined
) ->
    {ok, pid(), i2p_ssu2:data_keys()} | {error, term()}.
connect(LocalKeys, RemoteOpts, RIBlock, Listener, PeerTestRole) ->
    Args0 =
        #{
            role => alice,
            owner => self(),
            local => LocalKeys,
            remote => RemoteOpts,
            ri_block => RIBlock,
            listener => Listener
        },
    Args = maybe_tag_peertest_role(Args0, PeerTestRole),
    case i2p_ssu2_sup:start_session(i2p_ssu2_sup:session_child(Args)) of
        {ok, Pid} ->
            await_ssu2_connection(Pid, 20000);
        {ok, Pid, _Extra} ->
            await_ssu2_connection(Pid, 20000);
        {error, Reason} ->
            {error, Reason}
    end.

-spec await_ssu2_connection(pid(), timeout()) ->
    {ok, pid(), i2p_ssu2:data_keys()} | {error, term()}.
await_ssu2_connection(Pid, Timeout) ->
    MRef = erlang:monitor(process, Pid),
    receive
        {ssu2_ready, Pid, Info, _RemoteRI} ->
            erlang:demonitor(MRef, [flush]),
            {ok, Pid, Info};
        {'DOWN', MRef, process, Pid, Info} ->
            {error, Info}
    after Timeout ->
        exit(Pid, kill),
        {error, timeout}
    end.

-doc """
Dial a firewalled router (Charlie) indirectly, through one of her introducers
(Bob).

Input: local keys; Bob's SSU2 `remote_opts()` (a normal published address);
our RouterInfo block; the listener pid; and the relay material, a
map with `bob_hash` (Bob's router hash), `charlie_hash` (Charlie's),
`charlie_ri` (Charlie's full RouterInfo — she publishes no usable address,
only her keys and introducers), `tag` (the
relay tag Charlie published in her introducer address), `our_port`/`our_ip`
(our own asserted endpoint, which Charlie's HolePunch targets), and
`sign_seed` (used to sign the RelayRequest).

Flow: establish a session with Bob, send block 7 (RelayRequest), wait for the
RelayResponse (block 8) Charlie's tagged session answers with — the accept
carries her endpoint and a session token — then spawn the redirect session to
Charlie reusing the same connection IDs and starting with the granted token.
Output: `{ok, BobPid, CharliePid, Keys}` — the introducer leg, the established
redirect session, and its data keys — or `{error, Reason}` when the relay is
rejected, the redirect fails, or either session dies before that.
""".
-spec connect_via_introducer(
    i2p_ssu2_conn:local_keys(),
    i2p_ssu2_conn:remote_opts(),
    binary(),
    pid(),
    map()
) ->
    {ok, pid(), pid(), i2p_ssu2:data_keys()} | {error, term()}.
connect_via_introducer(LocalKeys, BobOpts, RIBlock, Listener, Relay) ->
    Config =
        #{
            role => alice,
            owner => self(),
            local => LocalKeys,
            remote => BobOpts,
            ri_block => RIBlock,
            listener => Listener,
            relay_role => requester,
            relay => Relay
        },
    case i2p_ssu2_sup:start_session(i2p_ssu2_sup:session_child(Config)) of
        {ok, Pid} ->
            await_ssu2_redirect(Pid, ?REDIRECT_TIMEOUT_MS);
        {ok, Pid, _Extra} ->
            await_ssu2_redirect(Pid, ?REDIRECT_TIMEOUT_MS);
        {error, Reason} ->
            {error, Reason}
    end.

-doc """
The longest a single SSU2 leg of one outbound dial can block, in milliseconds.

Two legs exist and they are bounded differently: a direct handshake by its
retransmit count (`f:handshake_retry_ms/0` times `f:handshake_max_resends/0`),
and the indirect one through an introducer by a flat wait. The longer of the two
is what a caller bounding the *whole* dial needs, so it is asked for here rather
than restated — and it moves when an operator retunes the retransmit settings,
which a number written down in the caller would not follow.
""".
-spec dial_budget_ms() -> pos_integer().
dial_budget_ms() ->
    max(?REDIRECT_TIMEOUT_MS, handshake_retry_ms() * handshake_max_resends()).

-spec await_ssu2_redirect(pid(), timeout()) ->
    {ok, pid(), pid(), i2p_ssu2:data_keys()} | {error, term()}.
await_ssu2_redirect(Pid, Timeout) ->
    MRef = erlang:monitor(process, Pid),
    receive
        {i2p_ssu2_redirect, Pid, RedirectPid, Keys} ->
            erlang:demonitor(MRef, [flush]),
            {ok, Pid, RedirectPid, Keys};
        {'DOWN', MRef, process, Pid, Reason} ->
            {error, Reason}
    after Timeout ->
        exit(Pid, kill),
        {error, timeout}
    end.

maybe_tag_peertest_role(Args, undefined) ->
    Args;
maybe_tag_peertest_role(Args, Role) ->
    Args#{peer_test_role => Role}.

-doc """
Hand an established session to a new owner.

Input: `Pid` — an established session; `Owner` — the pid that will receive the
session's `{ssu2_data, Pid, Blocks}` / keepalive / peer-test messages from then
on.

Output: `ok`.

A dial completes its blocking handshake with `f:connect/5` while the caller
(the spawned dial process) owns the session; the router must hand ownership to
the peer manager afterwards so live data reaches it. `f:i2p_peer` does exactly
this, mirroring NTCP2 where the connection is born owned by the manager.
""".
-spec set_owner(pid(), pid()) -> ok.
set_owner(Pid, Owner) ->
    gen_server:cast(Pid, {set_owner, Owner}).

-doc "Send one complete I2NP message as an I2NP block in a Data datagram.".
send_i2np(Pid, Type, MsgId, Body) when is_binary(Body) ->
    gen_server:cast(Pid, {i2np, Type, MsgId, Body}).

-doc """
Send a peer-test block outbound on an established session so it travels
in-session (messages 1-4 of the Alice/Bob/Charlie peer test).

Input: the session pid and an SSU2 peer-test `block()` (see `m:i2p_peertest`).
The Bob introducer uses this to forward message 2 to Charlie and message 4
back to Alice; a test harness uses it to drive the Charlie responder.
""".
-spec send_peertest(pid(), i2p_ssu2:block()) -> ok.
send_peertest(Pid, Block) ->
    gen_server:cast(Pid, {peertest, Block}).

-doc """
Send a router_info block outbound on an established session so it travels
in-session. The Bob introducer uses this to relay Charlie's RouterInfo
back to Alice before message 4 (see `docs/protocol.md` PeerTest rules).

Input: the session pid; `Flag` byte (bit 0 flood request, bit 1 gzip);
`RIData` is the RouterInfo body (binary).
""".
-spec send_router_info(pid(), byte(), binary()) -> ok.
send_router_info(Pid, Flag, RIData) ->
    gen_server:cast(Pid, {router_info, Flag, RIData}).

-doc """
Send an introducer-relay block outbound on an established session so it
travels in-session (blocks 7/8/9 and the 15/16 relay-tag exchange).

Input: the session pid and an SSU2 relay `block()` (see `m:i2p_relay`). The
Bob introducer coordinator (`m:i2p_relay_coord`) uses this to issue a relay
tag (block 16) and relay block 8 back to the requester; a requester sends a
RelayRequest (block 7) or a relay-tag request (block 15) with it. Like
`f:send_peertest/2`, the block is ack-eliciting and tracked for loss
recovery (`f:ack_eliciting/1`).
""".
-spec send_relay(pid(), i2p_ssu2:block()) -> ok.
send_relay(Pid, Block) ->
    gen_server:cast(Pid, {relay, Block}).

-doc """
Initiate an SSU2 peer test from the Alice (test-target) side.

Builds and signs the message-1 request, sends it in-session to the introducer,
and records the test nonce so the eventual in-session message-4 reject can be
validated against it before any `{peertest_result, _AddrType, _Result}` event
is emitted.

Input: the session pid (an established Alice-role session); `BobHash` — the
32-byte introducer router hash; `Port` and `Ip` — the endpoint Alice asserts
reachable. The nonce is chosen fresh here; the caller need not supply one.
Automatic NetDb-driven Charlie selection is not part of this release.
Output: `ok`.
""".
-spec initiate_peertest(pid(), binary(), 0..65535, binary()) -> ok.
initiate_peertest(Pid, BobHash, Port, Ip) ->
    gen_server:cast(Pid, {initiate_peertest, BobHash, Port, Ip}).

-doc "Close the session by sending a Termination block.".
terminate_session(Pid, ReasonCode) ->
    gen_server:cast(Pid, {terminate, ReasonCode}).

%% ------------------------------------------------------------------
%% gen_server

-spec start_link(config()) -> {ok, pid()} | {error, term()}.
start_link(Config = #{role := Role}) when Role =:= alice; Role =:= bob ->
    gen_server:start_link(?MODULE, Config, []).

%% Alice: pick connection IDs, register, open with a zero-token
%% SessionRequest (Bob answers Retry granting a token).
init(Config = #{role := alice}) ->
    %% A redirect session (requester leg) reuses the original dial's connection
    %% IDs and starts the SessionRequest with the relay token instead of a zero
    %% token; a fresh direct dial keeps the random pair.
    SrcConnId = maps:get(src_conn_id, Config, rand_conn_id()),
    DstConnId = maps:get(dst_conn_id, Config, rand_conn_id(SrcConnId)),
    Remote = maps:get(remote, Config),
    State0 =
        i2p_ssu2:alice_init(
            maps:get(static_key, Remote),
            maps:get(intro_key, Remote),
            maps:get(static_priv, maps:get(local, Config)),
            maps:get(static_pub, maps:get(local, Config))
        ),
    Listener = maps:get(listener, Config),
    true = ets:insert(i2p_ssu2_sessions, {SrcConnId, self()}),
    erlang:monitor(process, Listener),
    {ok, Endpoint} =
        endpoint(maps:get(host, Remote), maps:get(port, Remote)),
    gen_server:cast(Listener, {register_pending, self(), Endpoint}),
    State =
        #{
            hs => State0,
            src_conn_id => SrcConnId,
            dst_conn_id => DstConnId,
            listener => Listener,
            endpoint => Endpoint
        },
    {State1, SRPacket} = new_session_request(State, maps:get(token, Config, 0)),
    Timer = arm_timer(),
    {ok, State1#{
        config => Config,
        phase => session_request,
        sr_packet => SRPacket,
        timer_ref => Timer,
        resends => 0,
        pkt_out => 0,
        seen_in => i2p_ssu2_recv:new()
    }};
%% Bob: consume the listener's first SessionRequest immediately.
init(Config = #{role := bob}) ->
    #{
        first_packet := SRPacket,
        endpoint := Endpoint,
        local := Local,
        listener := Listener
    } =
        Config,
    State0 =
        i2p_ssu2:bob_init(
            maps:get(static_priv, Local),
            maps:get(static_pub, Local),
            maps:get(intro_key, Local)
        ),
    Res = i2p_ssu2:receive_session_request(State0, SRPacket),
    case Res of
        {ok, SRInfo, State1} ->
            %% Bob is addressed by the Destination Connection ID Alice
            %% chose for him, which lands in our dst_conn_id slot.
            true =
                ets:insert(
                    i2p_ssu2_sessions,
                    {maps:get(dst_conn_id, State1), self()}
                ),
            erlang:monitor(process, Listener),
            case answer_session_created(State1, Listener, Endpoint) of
                {ok, HS2, SCPacket} ->
                    {ok, #{
                        hs => HS2,
                        config => Config,
                        phase => confirmed_wait,
                        fragments => [],
                        endpoint => Endpoint,
                        listener => Listener,
                        sr_info => SRInfo,
                        last_packet => SCPacket,
                        timer_phase => created_sent,
                        resends => 0,
                        pkt_out => 0,
                        seen_in => i2p_ssu2_recv:new()
                    }}
            end;
        error ->
            exit({protocol_error, session_request})
    end.

handle_call(_Other, _From, State) ->
    {noreply, State}.

handle_cast({i2np, Type, MsgId, Body}, State = #{phase := established}) ->
    {noreply, send_blocks([{i2np, Type, MsgId, unix_now(), Body}], State)};
handle_cast({peertest, Block}, State = #{phase := established}) ->
    {noreply, send_blocks([Block], State)};
handle_cast({router_info, Flag, RIData}, State = #{phase := established}) ->
    {noreply, send_blocks([{router_info, Flag, RIData}], State)};
handle_cast({relay, Block}, State = #{phase := established}) ->
    {noreply, send_blocks([Block], State)};
handle_cast(
    {initiate_peertest, BobHash, Port, Ip},
    State = #{phase := established, pending_test := undefined}
) ->
    {noreply, do_initiate_peertest(BobHash, Port, Ip, State)};
handle_cast(
    {initiate_peertest, _BobHash, _Port, _Ip},
    State = #{phase := established, pending_test := Pending}
) when Pending =/= undefined ->
    %% A peer test is already in flight; a second initiation is silently
    %% ignored until the outstanding one resolves.
    {noreply, State};
handle_cast({terminate, Reason}, State = #{phase := established}) ->
    _ = send_termination(Reason, State),
    {stop, normal, State};
handle_cast({set_owner, Owner}, State) ->
    Config = maps:get(config, State),
    {noreply, State#{config := Config#{owner := Owner}}};
handle_cast(_Other, State) ->
    {noreply, State}.

handle_info({ssu2_packet, Packet}, State) ->
    Phase = maps:get(phase, State, undefined),
    i2p_log:debug({ssu2_packet, byte_size(Packet), Phase}, role(State)),
    try
        {noreply, on_packet(Packet, State)}
    catch
        exit:{protocol_error, _} = Exit ->
            {stop, Exit, State}
    end;
handle_info(retransmit, State = #{phase := established}) ->
    %% Stale handshake timer after establishment: ignore.
    {noreply, State};
handle_info(data_resend, State = #{phase := established}) ->
    %% Data-phase loss recovery: resend every packet that has gone
    %% unacknowledged for `data_resend_ms` under fresh packet numbers.
    {noreply, resend_unacked(State)};
handle_info(data_resend, State) ->
    %% Defensive: a data-resend timer must not outlive the established phase.
    {noreply, State};
handle_info(peertest_judge, State = #{pending_test := Pending}) when Pending =/= undefined ->
    {noreply, judge_peertest(State)};
handle_info(peertest_judge, State) ->
    {noreply, State};
handle_info(keepalive, State = #{phase := established}) ->
    State1 = send_keepalive(State),
    {noreply, arm_keepalive_timer(State1)};
handle_info(idle_timeout, State = #{phase := established}) ->
    {stop, {idle_timeout, no_activity}, State};
handle_info(retransmit, State = #{resends := N}) ->
    case N >= handshake_max_resends() of
        true ->
            Phase = maps:get(timer_phase, State, established),
            exit({handshake_timeout, Phase}),
            {stop, shutdown, State};
        false ->
            case maps:get(last_packet, State, undefined) of
                undefined ->
                    {noreply, State};
                Pkt ->
                    i2p_ssu2_listener:send(
                        maps:get(listener, State),
                        Pkt,
                        maps:get(endpoint, State)
                    ),
                    Timer = arm_timer(),
                    {noreply, State#{resends => N + 1, timer_ref => Timer}}
            end
    end;
%% The redirect session (spawned after Charlie's RelayResponse) established:
%% the requester leg reports it to its caller, who adopts it and terminates
%% this Bob leg.
handle_info(
    {ssu2_ready, RedirectPid, Keys, _RemoteRI},
    State = #{redirect_pid := RedirectPid}
) ->
    Owner = maps:get(owner, maps:get(config, State)),
    i2p_log:debug({relay, redirect_ready, pid, RedirectPid}, role(State)),
    _ = Owner ! {i2p_ssu2_redirect, self(), RedirectPid, Keys},
    {noreply, State};
%% The redirect session died before establishing: the relay served nothing; end
%% this leg with the redirect's reason so the caller falls back.
handle_info(
    {'DOWN', _Ref, process, RedirectPid, Reason},
    State = #{redirect_pid := RedirectPid}
) ->
    i2p_log:debug({relay, redirect_down, pid, RedirectPid, reason, Reason}, role(State)),
    {stop, {redirect_failed, Reason}, State};
handle_info(
    {'DOWN', _Ref, process, Listener, _},
    State =
        #{listener := Listener}
) ->
    exit(listener_down),
    {stop, shutdown, State};
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_timer_field(keepalive_ref, State),
    cancel_timer_field(idle_ref, State),
    cancel_timer_field(data_resend_ref, State),
    %% Drop the relay-nonce routing row if the leg dies mid-relay; on success
    %% `clear_relay_nonce` already removed it and the redirect is owned here.
    case maps:get(relay_pending, State, undefined) of
        #{nonce := Nonce} ->
            _ = ets:delete(i2p_ssu2_sessions, i2p_relay:dst_conn_id(Nonce));
        _ ->
            ok
    end,
    ok.

%% ------------------------------------------------------------------
%% Inbound datagram dispatch

on_packet(Packet, State = #{phase := session_request}) ->
    Bik = bik(State),
    case i2p_ssu2:decode_retry(Bik, Packet) of
        {ok, #{token := Token}} when Token =/= 0 ->
            %% Retry granted: fresh SessionRequest carrying the token.
            {State1, SRPacket} = new_session_request(State, Token),
            resend_now(State1#{sr_packet => SRPacket}),
            State1#{timer_ref => arm_timer()};
        _Other ->
            %% Retry rejected (token 0) or not a Retry: keep waiting.
            maybe_created(Packet, State)
    end;
on_packet(Packet, State = #{phase := session_created_wait}) ->
    maybe_created(Packet, State);
on_packet(Packet, State = #{phase := confirmed_wait}) ->
    %% A retransmitted SessionRequest for THIS session (same connection IDs)
    %% means the SessionCreated we already sent was lost in transit. Per SSU2
    %% the responder re-answers a duplicate SessionRequest by resending the
    %% SessionCreated, so the dial recovers within one retransmit interval
    %% instead of stranding until the budget expires. It also must NOT enter
    %% the SessionConfirmed fragment buffer below: one stray SessionRequest
    %% there would poison reassembly permanently.
    Bik = bik(State),
    case i2p_ssu2:open_long(Packet, Bik, Bik) of
        {ok, <<_:64, _Num:32, ?TYPE_SESSION_REQUEST:8, 2:8, 2:8, _:8, _:64, _/binary>>} ->
            i2p_log:debug({reanswer_created, byte_size(Packet)}, role(State)),
            resend_now(State),
            State;
        _ ->
            Fragments = [Packet | maps:get(fragments, State)],
            i2p_log:debug({fragment_buffer, byte_size(Packet), length(Fragments)}, role(State)),
            case i2p_ssu2:receive_session_confirmed(hs(State), Fragments) of
                {ok, Info, HS1} ->
                    establish(HS1, Info, State#{fragments => Fragments});
                error ->
                    %% Keep buffering until every fragment has arrived.
                    maps:put(fragments, Fragments, State)
            end
    end;
on_packet(Packet, State = #{phase := established}) ->
    State1 = refresh_idle(State),
    case peek_peertest(Packet, State1) of
        true ->
            %% An out-of-session PeerTest is only legitimate as a reply on an
            %% outstanding test. If the peek claimed one but the handler did not
            %% consume the datagram (no matching nonce), it was actually an
            %% in-session Data packet the listener mis-routed; do not drop it.
            case out_of_session_peertest(Packet, State1) of
                State1 -> data_packet(Packet, State1);
                State2 -> State2
            end;
        false ->
            case peek_holepunch(Packet, State1) of
                true ->
                    %% An out-of-session HolePunch (type 11) to a relayed-out
                    %% connection ID: Charlie pre-opening a path for our
                    %% redirect dial. Only honoured while a relay is pending —
                    %% the long-header mask can coincide with a Data packet
                    %% otherwise.
                    holepunch(Packet, State1);
                false ->
                    data_packet(Packet, State1)
            end
    end.

%% Peek whether an inbound datagram to an established session is an
%% out-of-session PeerTest (long header, type 7) rather than a Data packet.
%% The listener routes both to this session keyed on the connection ID; only
%% the type-7 messages are PeerTest. `open_long` de-obfuscates the header so
%% the type byte at offset 12 is readable. A short-header Data packet has no
%% long-header mask: opening it with our intro key yields garbage, which can
%% coincidentally match `?TYPE_PEER_TEST`; such a datagram must still be
%% handled as Data, so type-7 peeking is only honoured while a test is
%% outstanding and the handler must consume the datagram to count as one.
peek_peertest(Packet, State = #{pending_test := Pending}) when Pending =/= undefined ->
    own_type7(Packet, State);
peek_peertest(Packet, State) ->
    case own_type7(Packet, State) of
        true -> i2p_log:debug({peek_gated_pending_undefined}, role(State));
        false -> ok
    end,
    false.

own_type7(Packet, State) ->
    OwnIntro = maps:get(intro_key, maps:get(local, maps:get(config, State))),
    case i2p_ssu2:open_long(Packet, OwnIntro, OwnIntro) of
        {ok, <<_Dst:64/big-unsigned-integer, _Num:32, ?TYPE_PEER_TEST:8, _/binary>>} -> true;
        _ -> false
    end.

%% Peek whether an inbound datagram to an established session is an
%% out-of-session HolePunch (long header, type 11) rather than a Data packet.
%% Like the peer-test peek, a short-header Data packet can coincidentally
%% de-obfuscate to type 11, so the peek is only honoured while a relay is
%% pending.
peek_holepunch(Packet, State = #{relay_pending := Pending}) when Pending =/= undefined ->
    own_type11(Packet, State);
peek_holepunch(Packet, State) ->
    case own_type11(Packet, State) of
        true -> i2p_log:debug({peek_gated_holepunch_pending_undefined}, role(State));
        false -> ok
    end,
    false.

own_type11(Packet, State) ->
    OwnIntro = maps:get(intro_key, maps:get(local, maps:get(config, State))),
    case i2p_ssu2:open_long(Packet, OwnIntro, OwnIntro) of
        {ok, <<_Dst:64/big-unsigned-integer, _Num:32, ?TYPE_HOLE_PUNCH:8, _/binary>>} -> true;
        _ -> false
    end.

%% Handle an inbound out-of-session HolePunch (type 11) for the pending
%% relay: Charlie (the tagged peer) pre-opening a path to our asserted
%% endpoint so the redirect dial lands. Decoded with our own intro key and
%% surfaced to the owner so the relay flow is observable; it carries the
%% RelayResponse Charlie signed for us (block 8) in its payload.
holepunch(Packet, State) ->
    OwnIntro = maps:get(intro_key, maps:get(local, maps:get(config, State))),
    case i2p_ssu2:decode_holepunch(OwnIntro, Packet) of
        {ok, Info} ->
            i2p_log:debug({holepunch, received}, role(State)),
            Owner = maps:get(owner, maps:get(config, State)),
            _ = Owner ! {holepunch, self(), Info},
            State;
        error ->
            i2p_log:debug(holepunch_decode_error, role(State)),
            State
    end.

%% Handle an inbound out-of-session PeerTest message (5 or 7, Charlie->Alice)
%% for one of our initiated tests. The message is encrypted under our intro
%% key and routed here by the nonce-derived connection ID. Match the echoed
%% nonce against the outstanding test and feed the result state machine.
out_of_session_peertest(Packet, State = #{pending_test := Pending}) when Pending =/= undefined ->
    OwnIntro = maps:get(intro_key, maps:get(local, maps:get(config, State))),
    case i2p_ssu2:decode_peertest(OwnIntro, Packet) of
        {ok, #{blocks := Blocks}} ->
            case lists:keyfind(peertest, 1, Blocks) of
                {peertest, 5, _Code, _Flags, _Hash, _Ver, Nonce, _Ts, _Port, _Ip, _Sig} ->
                    i2p_log:debug({oos, 5}, role(State)),
                    maybe_seen5(Nonce, State);
                {peertest, 7, _Code, _Flags, _Hash, _Ver, Nonce, _Ts, _Port, _Ip, _Sig} ->
                    i2p_log:debug({oos, 7}, role(State)),
                    maybe_seen7(Nonce, State);
                _Other ->
                    State
            end;
        error ->
            i2p_log:debug(oos_decode_error, role(State)),
            State
    end;
out_of_session_peertest(_Packet, State) ->
    State.

%% Mark the out-of-session message 5 as received for the matching test. When
%% the nonce does not match an outstanding test the datagram is ignored.
%% Message 5 is Charlie proving he can reach us directly (message 7 is our
%% echo of his message 6): its arrival alone resolves the test to `ok`, so the
%% settle timer is short-circuited and the result emitted immediately.
maybe_seen5(Nonce, #{pending_test := #{nonce := Nonce} = PT} = State) ->
    State1 = State#{pending_test => PT#{seen5 => true}},
    cancel_judge_timer(maps:get(judge_ref, PT)),
    judge_peertest(State1);
maybe_seen5(_Nonce, State) ->
    State.

%% Mark the out-of-session message 7 as received for the matching test.
maybe_seen7(Nonce, #{pending_test := #{nonce := Nonce} = PT} = State) ->
    State#{pending_test => PT#{seen7 => true}};
maybe_seen7(_Nonce, State) ->
    State.

%% Alice: SessionCreated arrived.
maybe_created(Packet, State) ->
    case i2p_ssu2:receive_session_created(hs(State), Packet) of
        {ok, _CreatedInfo, HS1} ->
            RIData = maps:get(ri_block, maps:get(config, State)),
            MaxPkt = 1472,
            {ok, SCPackets, Keys, HS2} =
                i2p_ssu2:create_session_confirmed(
                    HS1,
                    [{router_info, 0, RIData}],
                    MaxPkt
                ),
            send_all(SCPackets, State),
            become_established(HS2, Keys, State#{
                last_packet => lists:last(SCPackets),
                last_packet_kind => confirmed,
                resends => 0,
                timer_ref => arm_timer()
            });
        error ->
            exit({protocol_error, created_decode})
    end.

%% Bob: full SessionConfirmed assembled; verify RI against Alice's key.
establish(HS1, Info, State) ->
    Apk = maps:get(static_key, Info),
    [{router_info, _Flag, RIData} | _] = maps:get(blocks, Info),
    case i2p_router_info:decode(RIData) of
        {ok, RI} ->
            Identity = i2p_router_info:identity(RI),
            PeerIntro =
                case i2p_router_info:ssu2_address_options(RI) of
                    {ok, Opts} -> maps:get(intro_key, Opts);
                    error -> undefined
                end,
            establish_key(
                HS1,
                Info,
                maps:get(crypto_key, Identity),
                Apk,
                State#{peer_intro => PeerIntro, remote_ri => RI}
            );
        {error, _Reason} ->
            exit({protocol_error, router_info})
    end.

establish_key(HS1, Info, Apk, Apk, State) ->
    Keys = maps:get(keys, Info),
    %% Established first so the ACK below can use the data keys.
    State1 = become_established(HS1, Keys, State#{resends => 0}),
    ack_packet_zero(Keys, State1);
establish_key(_HS1, _Info, _FromRI, _Apk, _State) ->
    exit({protocol_error, static_key_mismatch}).

become_established(HS, Keys, State) ->
    case maps:get(relay_role, maps:get(config, State), undefined) of
        requester ->
            %% The introducer (Bob) leg of an indirect dial: the callers owns
            %% the requester flow, not a session they can mark ready, so no
            %% `ssu2_ready` reaches the owner here — the redirect session
            %% (spawned after Charlie's RelayResponse) is signalled instead.
            begin_relay(become_established_common(HS, Keys, State));
        _ ->
            Owner = maps:get(owner, maps:get(config, State)),
            RemoteRI = maps:get(remote_ri, State, undefined),
            _ = Owner ! {ssu2_ready, self(), Keys, RemoteRI},
            become_established_common(HS, Keys, State)
    end.

become_established_common(HS, Keys, State) ->
    case maps:get(timer_ref, State, undefined) of
        undefined ->
            ok;
        Ref ->
            _ = erlang:cancel_timer(Ref),
            ok
    end,
    State1 =
        State#{
            phase => established,
            hs => HS,
            keys => Keys,
            timer_phase => established,
            last_packet => undefined,
            resends => 0,
            out_pkts => #{},
            reassembly => #{},
            pending_test => undefined,
            pt_target => undefined,
            %% The handshake's inbound reassembly buffer. It only ever holds
            %% SessionConfirmed fragments, and by here they have all been
            %% consumed, so leaving it resident would keep the last fragment's
            %% payload alive for the whole session. It was also the one field
            %% this transition forgot, which is why a session's heap depended on
            %% what the handshake happened to leave behind rather than on its
            %% data phase.
            fragments => [],
            sr_info => undefined
        },
    State2 = arm_keepalive_timer(arm_idle_timer(State1)),
    case role(State2) of
        %% Alice's SessionConfirmed already consumed packet zero; her first
        %% Data packet must be numbered one (spec: Alice 0 = Session
        %% Confirmed, Bob 0 = ACK of it).
        alice -> State2#{pkt_out => 1};
        bob -> State2
    end.

%% ------------------------------------------------------------------
%% Data phase

data_packet(Packet, State = #{keys := Keys}) ->
    RecvDir =
        case role(State) of
            alice -> ba;
            bob -> ab
        end,
    OwnIntro = maps:get(intro_key, maps:get(local, maps:get(config, State))),
    case i2p_ssu2:decode_data(Keys, RecvDir, OwnIntro, Packet) of
        {ok, #{pkt_num := Num, immediate_ack := ImmediateAck, blocks := Blocks}} ->
            on_data(Num, Blocks, ImmediateAck, RecvDir, State);
        error ->
            i2p_log:debug({recv, RecvDir, decode_error}, role(State)),
            State
    end.

%% Classify an inbound Data packet number against the receive window, then
%% deliver its blocks. The three outcomes differ only in what happens to the
%% window and to the telemetry -- the blocks are delivered either way, because
%% an out-of-window packet is still a real, authenticated packet carrying data
%% this router has not processed, and dropping it would lose traffic to save
%% bookkeeping. Block handling is idempotent by message identity, so delivering
%% a duplicate we could not recognise costs work rather than correctness.
on_data(Num, Blocks, ImmediateAck, RecvDir, State = #{seen_in := SeenIn}) ->
    case i2p_ssu2_recv:add(Num, SeenIn, ?MAX_ACK_RANGES) of
        {new, SeenIn1} ->
            i2p_log:debug(
                {recv, RecvDir, Num, new, [block_kind(B) || B <- Blocks]}, role(State)
            ),
            deliver(Num, Blocks, ImmediateAck, State#{seen_in => SeenIn1});
        duplicate ->
            i2p_log:debug({recv, RecvDir, Num, duplicate}, role(State)),
            State;
        stale ->
            %% Too old to be nameable in any ACK we could send, so it cannot be
            %% recorded — see `m:i2p_ssu2_recv`. Counted rather than silently
            %% treated as new, because a peer doing this routinely is
            %% retransmitting numbers the spec says it must not reuse.
            i2p_stats:add(ssu2_stale_packets, 1),
            i2p_log:debug(
                {recv, RecvDir, Num, out_of_window, [block_kind(B) || B <- Blocks]},
                role(State)
            ),
            deliver(Num, Blocks, ImmediateAck, State)
    end.

deliver(Num, Blocks, ImmediateAck, State) ->
    State1 = handle_blocks(Blocks, State),
    maybe_ack(Num, Blocks, ImmediateAck, State1).

block_kind({i2np, Type, _MsgId, _Exp, _Body}) ->
    {i2np, Type};
block_kind({first_fragment, _Type, _MsgId, _Exp, _Body}) ->
    fragment;
block_kind({follow_on_fragment, _FragNum, _IsLast, _MsgId, _Body}) ->
    fragment;
block_kind({peertest, N, _Code, _Flags, _Hash, _Ver, _Nonce, _Ts, _Port, _Ip, _Sig}) ->
    {peertest, N};
block_kind({relay_request, _Flag, Nonce, _Tag, _Ts, _Ver, _Port, _Ip, _Sig}) ->
    {relay_request, Nonce};
block_kind({relay_response, _Flag, Code, Nonce, _Ts, _Ver, _Port, _Ip, _Sig, _Token}) ->
    {relay_response, Code, Nonce};
block_kind({relay_intro, _Flag, _AliceHash, Nonce, _Tag, _Ts, _Ver, _Port, _Ip, _Sig}) ->
    {relay_intro, Nonce};
block_kind(relay_tag_request) ->
    relay_tag_request;
block_kind({relay_tag, Tag}) ->
    {relay_tag, Tag};
block_kind({router_info, Flag, _RIData}) ->
    {router_info, Flag};
block_kind({ack, _AT, _Acnt, _Ranges}) ->
    ack;
block_kind({path_challenge, _Data}) ->
    path_challenge;
block_kind({path_response, _Data}) ->
    path_response;
block_kind({termination, _Soon, _ConnId, _Reason}) ->
    termination;
block_kind(_) ->
    other.

peertest_msg_num({peertest, N, _Code, _Flags, _Hash, _Ver, _Nonce, _Ts, _Port, _Ip, _Sig}) ->
    N;
peertest_msg_num(_) ->
    0.

%% A packet is ack-eliciting when it carries blocks the peer needs to know
%% arrived: I2NP messages, fragments, peer-test and introducer-relay blocks
%% (7/8/9), router-info replies, or termination. Pure ACK/padding keepalive
%% blocks are not, so we never build a feedback loop of pure-ACK replies.
ack_eliciting(Blocks) ->
    lists:any(
        fun(B) ->
            case B of
                {i2np, _, _, _, _} -> true;
                {first_fragment, _, _, _, _} -> true;
                {follow_on_fragment, _, _, _, _} -> true;
                {termination, _, _, _} -> true;
                {peertest, _, _, _, _, _, _, _, _, _, _} -> true;
                {relay_request, _, _, _, _, _, _, _, _} -> true;
                {relay_response, _, _, _, _, _, _, _, _, _} -> true;
                {relay_intro, _, _, _, _, _, _, _, _, _} -> true;
                {router_info, _, _} -> true;
                _ -> false
            end
        end,
        Blocks
    ).

%% Timely ACK: sending an ACK block without delay for ack-eliciting packets
%% (or an explicit immediate-ack request), as one ACK-only Data packet in
%% response — the spec forbids more than one ACK-only packet per received
%% ack-eliciting packet. Every received packet feeds the ACK, so
%% non-ack-eliciting packets are acknowledged opportunistically too.
maybe_ack(_Num, Blocks, ImmediateAck, State) ->
    case ack_eliciting(Blocks) orelse ImmediateAck of
        true -> send_ack(State);
        false -> State
    end.

send_ack(State = #{seen_in := SeenIn}) ->
    AckBlock = i2p_ssu2:build_ack(SeenIn, ?MAX_ACK_RANGES),
    send_packet([AckBlock], State, false).

%% ------------------------------------------------------------------
%% Outbound: fragment oversized I2NP messages and send each block as one
%% Data packet, tracking ack-eliciting packets for NACK-driven
%% retransmission.
%% ------------------------------------------------------------------

%% Send data blocks (an I2NP message, typically) to the peer, fragmenting
%% any message that exceeds the per-packet budget and recording ack-eliciting
%% packets so a peer NACK (or a data resend) can retransmit them under fresh
%% packet numbers. Non-ack-eliciting blocks (path_response, path_challenge)
%% are never recorded: they are pure liveness exchanges and must not be
%% rescheduled by the data-resend timer.
send_blocks(Blocks0, State) ->
    Frags = expand_fragments(Blocks0, State),
    lists:foldl(
        fun(Block, St) -> send_packet([Block], St, ack_eliciting([Block])) end,
        State,
        Frags
    ).

%% Replace oversized whole-I2NP blocks with SSU2 fragment blocks; leave
%% everything else (small I2NP, ACK, termination) untouched.
expand_fragments(Blocks0, State) ->
    MaxBody = max_frag_body(State),
    lists:flatmap(
        fun
            ({i2np, Type, MsgId, ShortExp, Body}) when byte_size(Body) + 9 =< MaxBody ->
                [{i2np, Type, MsgId, ShortExp, Body}];
            ({i2np, Type, MsgId, ShortExp, Body}) ->
                i2p_ssu2:fragment_i2np(Type, MsgId, ShortExp, Body, MaxBody);
            (Other) ->
                [Other]
        end,
        Blocks0
    ).

max_frag_body(_State) ->
    ?MAX_FRAG_BODY.

%% Build, seal and send one Data datagram carrying `Blocks` using the next
%% outbound packet number. When `Track` is true the packet is recorded in
%% `out_pkts` so a peer NACK -- or the data-resend timer, if unacknowledged
%% for too long -- can retransmit it; ACK-only and pure-keepalive packets are
%% not tracked (per spec, pure ACKs are not retransmitted).
send_packet(Blocks, State = #{keys := Keys, pkt_out := Num}, Track) ->
    Dir =
        case role(State) of
            alice -> ab;
            bob -> ba
        end,
    RemoteIntro = remote_intro(State),
    Header = i2p_ssu2:short_header_data(dst_id(State), Num, 0),
    Payload = i2p_ssu2:ensure_min_payload(i2p_ssu2:encode_blocks(Blocks)),
    {KOwn, KH2Own} = dir_keys(Keys, Dir),
    {CT, MAC} = i2p_crypto:chacha20_poly1305_encrypt(
        KOwn,
        data_nonce(Num),
        Payload,
        Header
    ),
    Plain = <<Header/binary, CT/binary, MAC/binary>>,
    Datagram = seal_data(Plain, RemoteIntro, KH2Own),
    i2p_ssu2_listener:send(
        maps:get(listener, State),
        Datagram,
        maps:get(endpoint, State)
    ),
    i2p_log:debug({send, Num, Track, [block_kind(B) || B <- Blocks]}, role(State)),
    Out =
        case Track of
            true -> maps:put(Num, Blocks, maps:get(out_pkts, State));
            false -> maps:get(out_pkts, State)
        end,
    maybe_arm_data_resend(State#{pkt_out => Num + 1, out_pkts => Out}).

%% ------------------------------------------------------------------
%% Inbound: consume ACK blocks (drop ack'd, retransmit nack'd), reassemble
%% fragments into whole I2NP messages, and forward complete messages (and
%% termination) to the owner.
%% ------------------------------------------------------------------

handle_blocks(
    Blocks,
    State = #{relay_pending := Pending, phase := established}
) when
    Pending =/= undefined
->
    %% Requester waiting on Charlie's RelayResponse (block 8): absorb the ACK
    %% so the retransmission map drains (block 7 is ack-eliciting), then act
    %% on the response itself instead of forwarding it to the owner. Any other
    %% block still follows the default routing.
    State1 = handle_ack(Blocks, State),
    case lists:keyfind(relay_response, 1, Blocks) of
        false ->
            handle_termination(
                Blocks,
                handle_forward(Blocks, handle_keepalive(Blocks, State1))
            );
        Response ->
            requester_relay_response(Response, State1)
    end;
handle_blocks(Blocks, State) ->
    default_handle_blocks(Blocks, State).

default_handle_blocks(Blocks, State) ->
    handle_peertest(
        Blocks,
        handle_termination(
            Blocks, handle_ack(Blocks, handle_forward(Blocks, handle_keepalive(Blocks, State)))
        )
    ).

%% Data-phase keepalive: a peer's path_challenge (type 18) is answered with a
%% path_response (type 19) echoing the block data, and a peer's path_response is
%% merely a liveness signal — the session's last-recv refresh in
%% `f:refresh_idle/1` already re-arms the idle timer on any datagram, so nothing
%% else is needed. Neither block carries sidestate.
handle_keepalive(Blocks, State) ->
    case lists:keyfind(path_challenge, 1, Blocks) of
        {path_challenge, Data} ->
            send_blocks([{path_response, Data}], State);
        false ->
            State
    end.

%% The SSU2 PeerTest (transport-level reachability probe) carried as a block
%% (type 10) inside Data messages for messages 1-4 (see `m:i2p_peertest` and
%% `docs/protocol.md`). In-session responses and explicit Alice initiation are
%% implemented. Automatic NetDb-driven Charlie selection is not implemented in
%% this release. The dispatch keys off the session's peer-test discriminator
%% (`f:peertest_discriminator/2`): an explicit peer-test role when the session
%% carries one, otherwise the default handshake-role-and-message inference.
handle_peertest(Blocks, State) ->
    Block = lists:keyfind(peertest, 1, Blocks),
    case {peertest_discriminator(Block, State), Block} of
        {bob, {peertest, 1, _Code, _Flags, _Hash, _Ver, Nonce, Ts, Port, Ip, _Sig}} ->
            %% We are the introducer (Bob) and Alice asked us to test her.
            %% When a peer-test coordinator (a separate process) owns this
            %% session, the block is left for it to route — it forwards Alice's
            %% request to a Charlie session, or replies with the deterministic
            %% reject itself if no Charlie is reachable. Without a coordinator,
            %% Charlie selection is not wired, so reply with the deterministic
            %% Bob-side reject "no Charlie available" (code 2).
            case is_coordinator_owned(State) of
                true ->
                    i2p_log:debug({pt_dispatch, bob, 1, defer_coordinator}, role(State)),
                    State;
                false ->
                    i2p_log:debug({pt_dispatch, bob, 1, reject}, role(State)),
                    reply_peertest_reject(Nonce, Ts, Port, Ip, State)
            end;
        {charlie, {peertest, 2, _Code, _Flags, AliceHash, _Ver, Nonce, Ts, Port, Ip, _Sig}} ->
            %% We are the tested peer (Charlie): Bob (our session peer) relayed
            %% Alice's request in-session. When we have Alice's SSU2 address
            %% (from her forwarded RouterInfo) we also send the out-of-session
            %% message 5 to her; then reply message 3 signed with our own key,
            %% echoing Alice's nonce/timestamp/port/IP.
            i2p_log:debug({pt_dispatch, charlie, 2, charlie_reply}, role(State)),
            State1 = send_charlie_msg5(Nonce, Ts, Port, Ip, State),
            charlie_reply(AliceHash, Nonce, Ts, Port, Ip, State1);
        {alice, {peertest, 4, Code, _Flags, _Hash, _Ver, Nonce, _Ts, _Port, Ip, _Sig}} ->
            %% We are the test target (Alice) and the introducer relayed a
            %% message 4 back in-session: either a reject or Charlie's response.
            %% An explicitly `alice`-tagged session (an outbound initiator)
            %% validates the reject against the nonce of the test it originated
            %% and reports the result; an untagged session uses the conservative
            %% FIREWALLED result from message 4 alone.
            case is_explicit_alice(State) of
                true ->
                    case i2p_peertest:is_reject(Code) of
                        true ->
                            i2p_log:debug({pt_dispatch, alice, 4, reject_concluded}, role(State)),
                            conclude_peertest_reject(Nonce, State);
                        false ->
                            %% Message 4 accepted: Charlie is reachable.
                            %% Record it and trigger the out-of-session
                            %% message 6 probe to Charlie's address when we
                            %% have his endpoint cached; otherwise
                            %% `forward_block` will do so when his
                            %% RouterInfo arrives.
                            i2p_log:debug({pt_dispatch, alice, 4, accepted}, role(State)),
                            maybe_seen4_accept(Nonce, Ip, State)
                    end;
                false ->
                    i2p_log:debug({pt_dispatch, alice, 4, legacy_firewalled}, role(State)),
                    i2p_events:notify({peertest_result, addr_type(Ip), firewalled}),
                    State
            end;
        _ ->
            i2p_log:debug(
                {pt_dispatch, peertest_discriminator(Block, State), peertest_msg_num(Block),
                    passthrough},
                role(State)
            ),
            State
    end.

is_explicit_alice(State) ->
    maps:get(peer_test_role, maps:get(config, State), undefined) =:= alice.

%% Is this session owned by an external peer-test coordinator (a separate
%% process that routes peer-test blocks to a Charlie session)? When it is, the
%% session defers the deterministic message-1 reject to the coordinator.
is_coordinator_owned(State) ->
    maps:is_key(peer_test_coordinator, maps:get(config, State)).

%% Resolve an in-session message 4 reject against Alice's outstanding peer
%% test. The message must be a reject (`m:i2p_peertest:is_reject/1`) and its
%% nonce must match the one Alice chose when she initiated (message 1); only
%% then is the pending test concluded with the spec result (`firewalled` from
%% message 4 alone) and `pending_test` cleared. Unsolicited, mismatched, or
%% non-reject message 4s are ignored so a stale or forged block can neither
%% conclude a test nor emit a spurious result.
conclude_peertest_reject(Nonce, State) ->
    case maps:get(pending_test, State, undefined) of
        #{nonce := Nonce, addr_type := AddrType, judge_ref := JudgeRef} ->
            cancel_judge_timer(JudgeRef),
            i2p_events:notify({peertest_result, AddrType, firewalled}),
            State1 = clear_peertest(State),
            _ = unregister_peertest_conn_ids(Nonce),
            State1;
        _ ->
            State
    end.

%% An accepted in-session message 4 (Charlie reachable). Mark it seen, and as
%% soon as Charlie's out-of-session address is cached, probe him with message
%% 6 and start the settle timer after which the 4/5/7 result is judged.
maybe_seen4_accept(Nonce, Ip, State) ->
    case maps:get(pending_test, State, undefined) of
        #{nonce := Nonce} = PT ->
            State1 = State#{pending_test => PT#{seen4 => true, addr_type => addr_type(Ip)}},
            maybe_probe_charlie(State1);
        _ ->
            State
    end.

%% Send message 6 to Charlie and arm the result-settle timer once both the
%% message 4 has been accepted and Charlie's out-of-session address is known.
maybe_probe_charlie(State = #{pending_test := #{seen4 := true} = PT, pt_target := Target}) when
    Target =/= undefined
->
    case maps:is_key(sent6, PT) of
        true ->
            State;
        false ->
            State1 = send_msg6(Target, PT, State),
            State2 = arm_judge_timer(State1#{pending_test := PT#{sent6 => true}}),
            State2
    end;
maybe_probe_charlie(State) ->
    State.

%% Send the out-of-session Alice->Charlie message 6, addressed to Charlie's
%% address and encrypted under his intro key. The connection IDs are the
%% nonce-derived pair with dst/src swapped (message 6 is the reverse
%% direction of messages 5/7); the block re-asserts Alice's reachable
%% endpoint, as in the message-1 request. Signature is optional out-of-session.
send_msg6(Target, #{nonce := Nonce, aport := Port, aip := Ip}, State) ->
    Msg6 = i2p_peertest:block(6, 0, 0, <<>>, 2, Nonce, unix_now(), Port, Ip, <<>>),
    send_out_of_session(Target, Nonce, Msg6, State).

%% Send an out-of-session (type 7) PeerTest message addressed to `Target`
%% (`#{host, port, intro_key}`) and encrypted under its intro key.
send_out_of_session(Target, Nonce, Block, State) ->
    Dst = i2p_peertest:src_conn_id(Nonce),
    Src = i2p_peertest:dst_conn_id(Nonce),
    Bik = maps:get(intro_key, Target),
    {ok, Packet} = i2p_ssu2:encode_peertest(Bik, 0, Dst, Src, [Block]),
    {ok, {IP, Port}} = endpoint(maps:get(host, Target), maps:get(port, Target)),
    i2p_ssu2_listener:send(maps:get(listener, State), Packet, {IP, Port}),
    State.

%% Arm the settle timer; when it fires the result is judged from whichever of
%% messages 4/5/7 have arrived (the SSU2 "wait several seconds after message
%% 4" rule).
arm_judge_timer(State = #{pending_test := #{judge_ref := OldRef} = PT}) ->
    case OldRef of
        undefined ->
            ok;
        _ ->
            _ = erlang:cancel_timer(OldRef),
            ok
    end,
    NewRef = erlang:send_after(peertest_settle_ms(), self(), peertest_judge),
    State#{pending_test => PT#{judge_ref => NewRef}}.

cancel_judge_timer(undefined) ->
    ok;
cancel_judge_timer(Ref) ->
    _ = erlang:cancel_timer(Ref),
    ok.

%% Judge the completed test: resolve the 4/5/7 matrix, emit the result, and
%% release the test's state and nonce-derived connection IDs.
judge_peertest(
    State = #{
        pending_test := #{
            addr_type := AddrType, seen4 := S4, seen5 := S5, seen7 := S7, nonce := Nonce
        }
    }
) ->
    Result = i2p_peertest:result(S4, S5, S7),
    i2p_events:notify({peertest_result, AddrType, Result}),
    _ = unregister_peertest_conn_ids(Nonce),
    clear_peertest(State).

clear_peertest(State) ->
    State#{pending_test => undefined}.

unregister_peertest_conn_ids(Nonce) ->
    _ = ets:delete(i2p_ssu2_sessions, i2p_peertest:dst_conn_id(Nonce)),
    ok.

reply_peertest_reject(Nonce, Ts, Port, Ip, State) ->
    Reject = i2p_peertest:block(4, 2, 0, <<0:256>>, 2, Nonce, Ts, Port, Ip, <<>>),
    send_blocks([Reject], State).

%% Charlie-side in-session reply (message 3) to a message 2 relay from Bob.
%% The signature covers `bhash` (Bob, our session peer) and `ahash` (Alice,
%% carried in the message 2 hash field); the block itself omits both hash
%% fields (message 3 carries none).
charlie_reply(AliceHash, Nonce, Ts, Port, Ip, State) ->
    Local = maps:get(local, maps:get(config, State)),
    BobHash = peer_hash(State),
    Reply = charlie_reply_block(AliceHash, Nonce, Ts, Port, Ip, Local, BobHash),
    send_blocks([Reply], State).

%% Build the signed message-3 block Charlie replies with. Exposed as a pure
%% function so it can be verified independently of a live session.
charlie_reply_block(AliceHash, Nonce, Ts, Port, Ip, Local, BobHash) ->
    Sig = i2p_peertest:sign(
        BobHash, AliceHash, 2, Nonce, Ts, Port, Ip, maps:get(sign_seed, Local)
    ),
    i2p_peertest:block(3, 0, 0, <<>>, 2, Nonce, Ts, Port, Ip, Sig).

%% Charlie's out-of-session message 5 to Alice. Sent once Charlie is the
%% tested peer (message 2 received) and Alice's SSU2 address is known (her
%% forwarded RouterInfo). The connection IDs are the nonce-derived pair with
%% dst = `dst_conn_id(Nonce)` (Charlie->Alice direction); the signature is
%% optional out-of-session, so we omit it as the message-7 responder does.
send_charlie_msg5(Nonce, Ts, Port, Ip, State = #{pt_target := Target}) when Target =/= undefined ->
    Msg5 = i2p_peertest:block(5, 0, 0, <<>>, 2, Nonce, Ts, Port, Ip, <<>>),
    Dst = i2p_peertest:dst_conn_id(Nonce),
    Src = i2p_peertest:src_conn_id(Nonce),
    Bik = maps:get(intro_key, Target),
    {ok, Packet} = i2p_ssu2:encode_peertest(Bik, 0, Dst, Src, [Msg5]),
    {ok, {IP, TPort}} = endpoint(maps:get(host, Target), maps:get(port, Target)),
    i2p_ssu2_listener:send(maps:get(listener, State), Packet, {IP, TPort}),
    State;
send_charlie_msg5(_Nonce, _Ts, _Port, _Ip, State) ->
    State.

%% Alice-outbound initiation (message 1): choose a fresh nonce, build and sign
%% the request to the introducer, send it in-session, and remember the nonce
%% so the in-session message-4 reject can be validated against it later.
do_initiate_peertest(BobHash, Port, Ip, State) ->
    %% The peer-test nonce is a 4-byte wire field, so clamp the random value to
    %% 32 bits; a wider nonce would be truncated on encode and fail to match
    %% the echoed value when the message-4 reject comes back.
    Nonce = rand_conn_id() band 16#FFFFFFFF,
    Local = maps:get(local, maps:get(config, State)),
    Ts = unix_now(),
    Sig = i2p_peertest:sign(
        BobHash, undefined, 2, Nonce, Ts, Port, Ip, maps:get(sign_seed, Local)
    ),
    Msg1 = i2p_peertest:block(1, 0, 0, <<0:256>>, 2, Nonce, Ts, Port, Ip, Sig),
    State1 = send_blocks([Msg1], State),
    %% Register the nonce-derived connection IDs so the listener routes the
    %% out-of-session messages 5 and 7 (Charlie -> Alice) to this session.
    _ = ets:insert(i2p_ssu2_sessions, {i2p_peertest:dst_conn_id(Nonce), self()}),
    State1#{
        pending_test =>
            #{
                nonce => Nonce,
                addr_type => addr_type(Ip),
                aport => Port,
                aip => Ip,
                seen4 => false,
                seen5 => false,
                seen7 => false,
                judge_ref => undefined
            }
    }.

%% ----------------------------------------------------------------------
%% Indirect dial (requester role), see `f:connect_via_introducer/6`

%% The introducer leg established: sign and send the RelayRequest (block 7)
%% and register the nonce-derived connection IDs so the listener routes
%% Charlie's out-of-session HolePunch (type 11) to this session.
begin_relay(State) ->
    Relay = maps:get(relay, maps:get(config, State)),
    Nonce = rand32(),
    #{
        bob_hash := BobHash,
        charlie_hash := CharlieHash,
        tag := Tag,
        our_port := Port,
        our_ip := Ip,
        sign_seed := Seed
    } = Relay,
    Ts = unix_now(),
    Sig = i2p_relay:sign_request(BobHash, CharlieHash, 2, Nonce, Tag, Ts, Port, Ip, Seed),
    Block7 = i2p_relay:request_block(2, Nonce, Tag, Ts, Port, Ip, Sig),
    State1 = send_blocks([Block7], State),
    _ = ets:insert(i2p_ssu2_sessions, {i2p_relay:dst_conn_id(Nonce), self()}),
    i2p_log:debug({relay, request_sent, nonce, Nonce}, role(State1)),
    State1#{relay_pending => #{nonce => Nonce}}.

%% Charlie's RelayResponse (block 8) arrived in-session. Verify her signature
%% (the block is signed by her, relayed unmodified by Bob), then on accept
%% spawn the redirect dial toward her endpoint carrying the granted token; a
%% reject from either side ends the leg so the caller falls back.
requester_relay_response(
    {relay_response, _Flag, Code, Nonce, Ts, Ver, Port, Ip, Sig, Token}, State
) ->
    Relay = maps:get(relay, maps:get(config, State)),
    #{bob_hash := BobHash, charlie_ri := CharlieRI} = Relay,
    Pub = i2p_keys:signing_key(i2p_router_info:identity(CharlieRI)),
    case i2p_relay:verify_response(BobHash, Ver, Nonce, Ts, Port, Ip, Sig, Pub) of
        true when Code =:= 0, is_integer(Token) ->
            i2p_log:debug({relay, response_ok, nonce, Nonce}, role(State)),
            spawn_redirect(Port, Ip, Token, clear_relay_nonce(State));
        true ->
            i2p_log:debug({relay, rejected, code, Code}, role(State)),
            exit({relay_rejected, Code});
        false ->
            exit({relay_bad_response_sig, Nonce})
    end.

%% The relay is done either way: drop the pending marker and the
%% nonce-derived routing row (the HolePunch routing no longer applies).
clear_relay_nonce(State) ->
    #{nonce := Nonce} = maps:get(relay_pending, State),
    _ = ets:delete(i2p_ssu2_sessions, i2p_relay:dst_conn_id(Nonce)),
    maps:remove(relay_pending, State).

%% Spawn the redirect session to Charlie: an ordinary alice dial at her
%% asserted endpoint, reusing this leg's connection IDs and starting the
%% SessionRequest with Charlie's relay token. The session is owned by this
%% leg; when it establishes it reports back as `{i2p_ssu2_redirect, ...}`.
spawn_redirect(Port, Ip, Token, State) ->
    Config = maps:get(config, State),
    Relay = maps:get(relay, Config),
    CharlieRI = maps:get(charlie_ri, Relay),
    {ok, COpts} = i2p_router_info:ssu2_address_options(CharlieRI),
    RemoteC =
        #{
            host => iolist_to_binary(inet:ntoa(ip_tuple(Ip))),
            port => Port,
            static_key => maps:get(static_key, COpts),
            intro_key => maps:get(intro_key, COpts),
            peer_test => false
        },
    RedirectConfig =
        (maps:remove(relay, maps:remove(relay_role, Config)))#{
            owner => self(),
            remote => RemoteC,
            src_conn_id => maps:get(src_conn_id, State),
            dst_conn_id => maps:get(dst_conn_id, State),
            token => Token
        },
    case i2p_ssu2_sup:start_session(i2p_ssu2_sup:session_child(RedirectConfig)) of
        {ok, RedirectPid} ->
            _ = erlang:monitor(process, RedirectPid),
            i2p_log:debug({relay, redirect_spawned, pid, RedirectPid}, role(State)),
            State#{redirect_pid => RedirectPid};
        {ok, RedirectPid, _Extra} ->
            _ = erlang:monitor(process, RedirectPid),
            i2p_log:debug({relay, redirect_spawned, pid, RedirectPid}, role(State)),
            State#{redirect_pid => RedirectPid};
        {error, Reason} ->
            exit({session_admission_failed, Reason})
    end.

%% Relay block endpoints arrive as raw IPv4/IPv6 byte strings; the redirect
%% needs them as an IP tuple for its host string.
ip_tuple(Ip) ->
    list_to_tuple(binary_to_list(Ip)).

peer_hash(State) ->
    case maps:get(remote_ri, State, undefined) of
        #{identity := Identity} -> i2p_keys:hash(Identity);
        _ -> <<0:256>>
    end.

addr_type(Ip) when byte_size(Ip) == 16 -> ipv6;
addr_type(_Ip) -> ipv4.

handle_termination(Blocks, State) ->
    Owner = maps:get(owner, maps:get(config, State)),
    case lists:keyfind(termination, 1, Blocks) of
        {termination, _Valid, Reason, _Addl} ->
            _ = Owner ! {ssu2_closed, self(), Reason},
            ok;
        false ->
            ok
    end,
    State.

handle_ack(Blocks, State) ->
    case lists:keyfind(ack, 1, Blocks) of
        {ack, AT, Acnt, Ranges} ->
            process_ack({ack, AT, Acnt, Ranges}, State);
        false ->
            State
    end.

%% A received ACK/NACK block: drop fully-acked packets from the retransmit
%% map and retransmit NACKed packets' fragments under fresh packet numbers.
%% NACKed entries are dropped too: they are superseded by the fresh numbers
%% the retransmission uses, so the data-resend timer must not keep them alive.
process_ack({ack, AT, Acnt, Ranges}, State = #{out_pkts := Out}) ->
    {Acked, Nacked} = i2p_ssu2:ack_expand({ack, AT, Acnt, Ranges}),
    AckedSet = sets:from_list(Acked),
    NackedSet = sets:from_list(Nacked),
    Gone =
        fun(Num) ->
            sets:is_element(Num, AckedSet) orelse sets:is_element(Num, NackedSet)
        end,
    Out1 = maps:filter(fun(Num, _) -> not Gone(Num) end, Out),
    Retransmit = [maps:get(N, Out) || N <- Nacked, maps:is_key(N, Out)],
    State1 = State#{out_pkts => Out1},
    State2 = lists:foldl(fun(Blocks, St) -> send_blocks(Blocks, St) end, State1, Retransmit),
    maybe_arm_data_resend(State2).

%% Fold incoming blocks, feeding fragments into the reassembly buffer and
%% collecting complete I2NP messages to hand to the owner in one
%% `{ssu2_data, self(), ...}` message.
handle_forward(Blocks, State) ->
    {Forward, State1} = lists:foldl(fun forward_block/2, {[], State}, Blocks),
    Owner = maps:get(owner, maps:get(config, State)),
    case Forward of
        [] ->
            ok;
        _ ->
            i2p_log:debug({forwarded, [block_kind(B) || B <- Forward]}, role(State)),
            _ = Owner ! {ssu2_data, self(), lists:reverse(Forward)},
            ok
    end,
    State1.

forward_block(B, {Acc, State}) ->
    case B of
        {i2np, Type, MsgId, ShortExp, Body} ->
            {[{i2np, Type, MsgId, ShortExp, Body} | Acc], State};
        {first_fragment, Type, MsgId, ShortExp, Body} ->
            frag_forward({first_fragment, Type, MsgId, ShortExp, Body}, Acc, State);
        {follow_on_fragment, FragNum, IsLast, MsgId, Body} ->
            frag_forward(
                {follow_on_fragment, FragNum, IsLast, MsgId, Body},
                Acc,
                State
            );
        {peertest, _, _, _, _, _, _, _, _, _, _} = Peertest ->
            %% Peer-test blocks (messages 1-4) are forwarded to the owner so
            %% an introducer Bob can relay Charlie's message 3 back to Alice
            %% (and the responder can react to messages 1 and 2).
            {[Peertest | Acc], State};
        {relay_request, _, _, _, _, _, _, _, _} = RelayRequest ->
            %% Introducer-relay blocks (7/8/9) and the relay-tag exchange
            %% (15/16) travel in Data messages and are forwarded to the owner
            %% so an introducer Bob (`m:i2p_relay_coord`) can route the
            %% relay between his two sessions, and a requester or tagged peer
            %% observes its own leg of the exchange.
            {[RelayRequest | Acc], State};
        {relay_response, _, _, _, _, _, _, _, _, _} = RelayResponse ->
            {[RelayResponse | Acc], State};
        {relay_intro, _, _, _, _, _, _, _, _, _} = RelayIntro ->
            {[RelayIntro | Acc], State};
        relay_tag_request ->
            {[relay_tag_request | Acc], State};
        {relay_tag, _} = RelayTag ->
            {[RelayTag | Acc], State};
        {router_info, _Flag, RIData} = Ri ->
            %% RouterInfo blocks are forwarded to the owner so Bob can relay
            %% Charlie's RouterInfo back to Alice before message 4. We also
            %% cache the relayed peer's SSU2 address so this session can send
            %% it the out-of-session PeerTest messages (Alice->Charlie
            %% message 6, or Charlie->Alice message 5): the forwarded
            %% RouterInfo is the tested peer's own, carrying its intro key.
            State1 = cache_pt_target(RIData, State),
            {[Ri | Acc], State1};
        {path_challenge, _} = Challenge ->
            %% Keepalive probes are forwarded to the owner so it can observe
            %% the liveness exchange; the reply is sent by `handle_keepalive/2`.
            {[Challenge | Acc], State};
        {path_response, _} = Response ->
            {[Response | Acc], State};
        _ ->
            {Acc, State}
    end.

%% Cache the SSU2 address of a peer tested via an out-of-session PeerTest
%% message, learned from a forwarded RouterInfo. Alice caches Charlie (for
%% message 6); a Charlie-role session caches Alice (for message 5). When the
%% peer-test block has already arrived, re-trigger the now-possible probe.
cache_pt_target(RIData, State = #{pt_target := undefined}) ->
    case i2p_router_info:decode(RIData) of
        {ok, RI} ->
            case i2p_router_info:ssu2_address_options(RI) of
                {ok, Opts} ->
                    State1 = State#{pt_target => Opts},
                    probe_pending_peertest(State1);
                error ->
                    State
            end;
        _ ->
            State
    end;
cache_pt_target(_RIData, State) ->
    State.

%% A cached out-of-session peer address may unlock a pending action: Alice's
%% message 6 (when she already accepted message 4) or Charlie's message 5
%% (when he already received message 2). Dispatch on the session's role.
probe_pending_peertest(State) ->
    case maps:get(pending_test, State, undefined) of
        #{seen4 := true} -> maybe_probe_charlie(State);
        _ -> State
    end.

frag_forward(Frag, Acc, State) ->
    {Completed, State1} = reassemble_fragment(Frag, State),
    {lists:reverse(Completed) ++ Acc, State1}.

%% Buffer a fragment for `MsgId`; when a complete message is assembled
%% return it (as whole-I2NP blocks) and drop it from the buffer.
reassemble_fragment({first_fragment, Type, MsgId, ShortExp, Body}, State = #{reassembly := Reas}) ->
    E = maps:get(MsgId, Reas, empty_reassembly()),
    Reas1 = maps:put(MsgId, E#{first => {Type, ShortExp, Body}}, Reas),
    complete_msg(MsgId, State#{reassembly => capped(Reas1)});
reassemble_fragment(
    {follow_on_fragment, FragNum, IsLast, MsgId, Body},
    State = #{reassembly := Reas}
) ->
    E = maps:get(MsgId, Reas, empty_reassembly()),
    Parts = maps:get(parts, E),
    PendingTotal = maps:get(total, E),
    Total =
        case IsLast of
            true -> FragNum;
            false -> PendingTotal
        end,
    Parts1 = maps:put(FragNum, Body, Parts),
    Reas1 = maps:put(MsgId, E#{parts => Parts1, total => Total}, Reas),
    complete_msg(MsgId, State#{reassembly => capped(Reas1)}).

empty_reassembly() ->
    #{first => undefined, parts => #{}, total => undefined}.

%% Cap the reassembly buffer so a malicious or broken peer that never
%% completes a message cannot grow memory without bound. The oldest (by
%% arbitrary key order) incomplete message is dropped.
capped(Reas) when map_size(Reas) > ?MAX_REASSEMBLY ->
    case maps:keys(Reas) of
        [Oldest | _] -> maps:remove(Oldest, Reas);
        [] -> Reas
    end;
capped(Reas) ->
    Reas.

%% When every fragment of `MsgId` is present, assemble the body and return
%% it as a whole-I2NP block for the owner.
complete_msg(MsgId, State = #{reassembly := Reas}) ->
    case maps:get(MsgId, Reas, undefined) of
        #{first := {Type, ShortExp, FirstBody}, parts := Parts, total := Total} when
            Total =/= undefined
        ->
            case has_all_parts(Total, Parts) of
                true ->
                    Body = build_body(FirstBody, Total, Parts),
                    Reas1 = maps:remove(MsgId, Reas),
                    {[{i2np, Type, MsgId, ShortExp, Body}], State#{reassembly => Reas1}};
                false ->
                    {[], State}
            end;
        _ ->
            {[], State}
    end.

has_all_parts(Total, Parts) ->
    lists:all(fun(N) -> maps:is_key(N, Parts) end, lists:seq(1, Total)).

build_body(First, Total, Parts) ->
    Rest = [maps:get(N, Parts) || N <- lists:seq(1, Total)],
    iolist_to_binary([First | Rest]).

seal_data(Packet, ReceiverIntroKey, KH2Own) ->
    Len = byte_size(Packet),
    M1 = i2p_ssu2:header_mask(
        ReceiverIntroKey,
        binary:part(Packet, Len - 24, 12)
    ),
    M2 = i2p_ssu2:header_mask(KH2Own, binary:part(Packet, Len - 12, 12)),
    <<First:8/binary, Second:8/binary, Rest/binary>> = Packet,
    <<
        (crypto:exor(First, M1))/binary,
        (crypto:exor(Second, M2))/binary,
        Rest/binary
    >>.

dir_keys(#{k_ab := Kab, kh2_ab := KH2Ab}, ab) -> {Kab, KH2Ab};
dir_keys(#{k_ba := Kba, kh2_ba := KH2Ba}, ba) -> {Kba, KH2Ba}.

data_nonce(N) -> <<0:32, N:64/little>>.

send_termination(Reason, State) ->
    send_blocks([{termination, 0, Reason, <<>>}], State).

ack_packet_zero(_Keys, State = #{seen_in := SeenIn}) ->
    %% Alice's SessionConfirmed is her data-phase packet zero; record its
    %% receipt and ACK it with Bob's first Data packet (spec: Bob 0 = ACK).
    {new, SeenIn1} = i2p_ssu2_recv:add(0, SeenIn, ?MAX_ACK_RANGES),
    State1 = State#{seen_in => SeenIn1},
    AckBlock = i2p_ssu2:build_ack(SeenIn1, ?MAX_ACK_RANGES),
    send_packet([AckBlock], State1, false).

%% ------------------------------------------------------------------
%% Handshake helpers

hs(State) -> maps:get(hs, State).

role(State) -> maps:get(role, maps:get(config, State)).

%% The router's peer-test discriminator for an inbound peer-test block: the
%% session's explicit `peer_test_role` when it carries one, otherwise the
%% default inference from the handshake role and block message number. A
%% handshake-`bob` session is the introducer on message 1 but the tested peer
%% (Charlie) on message 2, so the untagged fallback stays message-sensitive.
peertest_discriminator(Block, State) ->
    case maps:get(peer_test_role, maps:get(config, State), undefined) of
        undefined -> legacy_peertest_role(role(State), Block);
        Role -> Role
    end.

legacy_peertest_role(_Role, {peertest, 1, _Code, _Flags, _Hash, _Ver, _N, _Ts, _P, _IP, _Sig}) ->
    bob;
legacy_peertest_role(_Role, {peertest, 2, _Code, _Flags, _AliceHash, _Ver, _N, _Ts, _P, _IP, _Sig}) ->
    charlie;
legacy_peertest_role(_Role, {peertest, 4, _Code, _Flags, _Hash, _Ver, _N, _Ts, _P, _IP, _Sig}) ->
    alice;
legacy_peertest_role(_Role, _Other) ->
    undefined.

bik(State) -> maps:get(bik, hs(State)).

dst_id(State) ->
    case role(State) of
        alice -> maps:get(dst_conn_id, hs(State));
        bob -> maps:get(src_conn_id, hs(State))
    end.

remote_intro(State) ->
    case role(State) of
        alice ->
            maps:get(intro_key, maps:get(remote, maps:get(config, State)));
        bob ->
            %% Learned from Alice's RouterInfo during the handshake.
            maps:get(peer_intro, State)
    end.

new_session_request(State, Token) ->
    EphPriv = fresh_ephemeral(),
    RandNum = rand32(),
    %% Reinitialize the noise state from scratch.  When i2pd's Bob receives
    %% the first SessionRequest with token=0 he replies Retry *without*
    %% advancing the Noise state, so Alice must not carry forward the
    %% state from the first (failed) attempt either.
    HS0 = maps:get(hs, State),
    FreshHS = i2p_ssu2:alice_init(
        maps:get(bpk, HS0),
        maps:get(bik, HS0),
        maps:get(my_static_priv, HS0),
        maps:get(my_static_pub, HS0)
    ),
    {ok, SRPacket, HS1} =
        i2p_ssu2:create_session_request(
            FreshHS,
            EphPriv,
            maps:get(dst_conn_id, State),
            maps:get(src_conn_id, State),
            Token,
            RandNum,
            [{datetime, unix_now()}, {padding, <<0, 0, 0, 0, 0>>}]
        ),
    i2p_ssu2_listener:send(
        maps:get(listener, State),
        SRPacket,
        maps:get(endpoint, State)
    ),
    {
        State#{
            hs => HS1,
            last_packet => SRPacket,
            resends => 0,
            timer_phase => session_request
        },
        SRPacket
    }.

answer_session_created(HS1, Listener, Endpoint) ->
    BeskPriv = fresh_ephemeral(),
    SCBlocks =
        [
            {datetime, unix_now()},
            {address, element(2, Endpoint), ip_bin(Endpoint)}
        ],
    {ok, SCPacket, HS2} = i2p_ssu2:create_session_created(HS1, BeskPriv, rand32(), SCBlocks),
    _ = i2p_ssu2_listener:send(Listener, SCPacket, Endpoint),
    {ok, HS2, SCPacket}.

send_all([Packet], State) ->
    i2p_ssu2_listener:send(
        maps:get(listener, State),
        Packet,
        maps:get(endpoint, State)
    );
send_all([Packet | Rest], State) ->
    i2p_ssu2_listener:send(
        maps:get(listener, State),
        Packet,
        maps:get(endpoint, State)
    ),
    send_all(Rest, State).

resend_now(State = #{last_packet := Pkt}) ->
    i2p_ssu2_listener:send(
        maps:get(listener, State),
        Pkt,
        maps:get(endpoint, State)
    ).

arm_timer() ->
    erlang:send_after(handshake_retry_ms(), self(), retransmit).

%% Send a fresh path_challenge probe: 8 random bytes per spec. The block is
%% sent as one (untracked is fine) Data packet; the peer's path_response echo
%% refreshes our idle timer.
send_keepalive(State) ->
    send_blocks([{path_challenge, crypto:strong_rand_bytes(?PATH_CHALLENGE_BYTES)}], State).

%% Any datagram proves peer liveness: record the timestamp and re-arm the idle
%% deadline.
refresh_idle(State) ->
    State1 = State#{last_recv => erlang:system_time(second)},
    cancel_timer_field(idle_ref, State1),
    State1#{idle_ref => erlang:send_after(idle_timeout_ms(), self(), idle_timeout)}.

%% Re-arm the keepalive probe timer so it fires every interval, cancelling any
%% pending one first.
arm_keepalive_timer(State) ->
    cancel_timer_field(keepalive_ref, State),
    State#{keepalive_ref => erlang:send_after(keepalive_interval_ms(), self(), keepalive)}.

%% Arm the idle timer without touching last_recv (used at establishment).
arm_idle_timer(State) ->
    State#{
        last_recv => erlang:system_time(second),
        idle_ref => erlang:send_after(idle_timeout_ms(), self(), idle_timeout)
    }.

cancel_timer_field(Key, State) ->
    case maps:get(Key, State, undefined) of
        undefined ->
            ok;
        Ref ->
            _ = erlang:cancel_timer(Ref),
            ok
    end.

%% Arm a single data-resend timer while any packet awaits an ACK, and drop it
%% the moment none does. Arming only on the empty-to-non-empty transition keeps
%% at most one timer in flight and lets an idling session (no tracked packets)
%% stay timer-free, so `idle_timeout` remains authoritative for death.
maybe_arm_data_resend(State = #{out_pkts := Out}) ->
    case map_size(Out) of
        0 ->
            cancel_timer_field(data_resend_ref, State),
            State#{data_resend_ref => undefined};
        _ ->
            case maps:get(data_resend_ref, State, undefined) of
                undefined ->
                    State#{
                        data_resend_ref => erlang:send_after(data_resend_ms(), self(), data_resend)
                    };
                _ ->
                    State
            end
    end.

%% Repair path: re-send every unacked packet set. Each block re-enters
%% `out_pkts` under a fresh packet number (arming a new timer), while the
%% superseded entries that fired this resend are dropped first so they cannot
%% be rescheduled forever.
resend_unacked(State = #{out_pkts := Out}) ->
    Pending = maps:to_list(Out),
    i2p_log:debug({data_resend_pending, length(Pending)}, role(State)),
    Empty = State#{out_pkts => #{}, data_resend_ref => undefined},
    lists:foldl(fun({_Num, Blocks}, St) -> send_blocks(Blocks, St) end, Empty, Pending).

keepalive_interval_ms() ->
    case application:get_env(i2per, keepalive_interval_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?KEEPALIVE_INTERVAL_MS
    end.

idle_timeout_ms() ->
    case application:get_env(i2per, idle_timeout_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?IDLE_TIMEOUT_MS
    end.

handshake_retry_ms() ->
    case application:get_env(i2per, handshake_retry_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?RETRY_MS
    end.

handshake_max_resends() ->
    case application:get_env(i2per, handshake_max_resends) of
        {ok, N} when is_integer(N), N > 0 -> N;
        _ -> ?MAX_RESENDS
    end.

data_resend_ms() ->
    case application:get_env(i2per, data_resend_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?DATA_RESEND_MS
    end.

peertest_settle_ms() ->
    case application:get_env(i2per, peertest_settle_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?PEERTEST_SETTLE_MS
    end.

fresh_ephemeral() ->
    {_Pub, Priv} = i2p_crypto:x25519_keygen(),
    Priv.

rand_conn_id() ->
    <<N:64/big-unsigned-integer>> = crypto:strong_rand_bytes(8),
    N.

rand_conn_id(Exclude) ->
    case rand_conn_id() of
        Exclude -> rand_conn_id(Exclude);
        Other -> Other
    end.

rand32() ->
    <<N:32/big-unsigned-integer>> = crypto:strong_rand_bytes(4),
    N.

unix_now() ->
    os:system_time(second).

endpoint(HostBin, Port) ->
    case inet:parse_address(binary_to_list(HostBin)) of
        {ok, IP} -> {ok, {IP, Port}};
        Error -> Error
    end.

ip_bin(Endpoint) ->
    case element(1, Endpoint) of
        {A, B, C, D} -> <<A, B, C, D>>;
        {A, B, C, D, E, F, G, H} -> <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>
    end.
