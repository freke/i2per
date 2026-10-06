-module(i2p_ntcp2_conn).

-moduledoc """
One process per NTCP2 connection, owning its socket.

This is the NTCP2 connection driver. A process in this module owns exactly one TCP
socket and its full state: the Noise XK handshake (via `m:i2p_ntcp2`) and the
data-phase framing (via `m:i2p_framing` and `m:i2p_stream`). It is started as a
`temporary` child of `m:i2p_ntcp2_sup` by `i2p_ntcp2_conn:connect/3` (initiator,
Alice) or by `m:i2p_ntcp2_listener` (responder, Bob).

The process is written to let protocol/session failures die:

- handshake timeout → `exit(timeout)`;
- protocol violation, MAC failure or malformed frame →
  `exit({protocol_error, Reason})`;
- socket close or error (`{tcp_closed, _}` / `{tcp_error, _, _}`) → the process
  dies;
- an unavailable endpoint or a non-published remote address reports
  `connect_failed` to the owner and exits normally, allowing bounded discovery
  to skip that candidate without generating a supervisor crash.

Its death closes the socket and reclaims the state; the supervisor never
restarts it and the listener and every sibling connection are unaffected.

## The send path, and why no caller waits on it

`f:send/2` is a cast, and the data-phase socket cannot block this process. Both
are load-bearing together, and both exist because of who the caller is.

The caller is `m:i2p_peer`, one `gen_server` for the whole router, through which
every inbound message from every connection passes. It used to call
`f:send/2`, which handed the payload over and then waited for a `{send_done, Ref}`
reply with **no timeout clause** — so one peer that was slow rather than dead, a
burst of AEAD or a socket write against a shut TCP window, stopped I2NP for
every other peer. The wait had no bound to hit. The same call had a second,
narrower unbounded wait: it monitored nothing, so a connection that died between
the caller's liveness check and its own message was a caller that never came back.

Serialisation is the reason the framing cannot simply move to the caller. NTCP2's
data phase is a stateful cipher stream — the message number and the SipHash IV
advance with every frame in a direction — so the frames have to be encrypted in
one process, in order, by whoever owns that state. What serialisation does *not*
require is the caller waiting for it. The caller hands the frame over and
returns, exactly as `m:i2p_ssu2_conn:send_i2np/4` does; the two transports are
now symmetric on the send path, so "make the busy one slower to fix" is no longer
a reason to leave a defect in one of them.

Making the caller wait-free is only half of it, because a process that never
returns from `f:send/2` is not much better than one that blocks: the connection
would still be stuck, and the frames would still queue. So the data-phase socket
is set `{delay_send, true}` with a `send_timeout`, which turns the socket write
from a wait into a question with a deadline. A peer that has stopped reading now
produces `{error, timeout}` in a known time, which `f:send_payload/3` turns into
a named exit and a bus announcement rather than an indefinite hang.

**What a stall costs, and where it ends.** The bound is the wire's, not a tuning
number: the driver accepts a finite queue before the send has to wait, so a peer
that never reads runs out of room after a fixed amount of undrained data and the
connection ends with `{send_stalled, socket_blocked}` and one
`{peer_send_stalled, _, socket_blocked}` on the bus. The peer manager observes
that as a disconnect and its existing backoff takes over; it does not re-announce
the reason, because the bus already carries it and ADR 0002 says a fact is
recorded once, on one instrument.

**Head-of-line, and the bound that holds it.** A send is serviced in mailbox
order, so it waits behind whatever is already queued. That is at most one
inbound socket message, because the socket is driven `{active, once}` and
re-armed only after the message in hand has been processed — an invariant of this
loop rather than a number someone chose, and the reason a burst of inbound
traffic cannot delay an outbound frame without bound. Inbound and outbound
frames must share one queue: the framing state they depend on is this process's,
and a second queue would mean two owners of one message number.

**What is deliberately not here.** Nothing bounds the *caller's* send rate to one
peer, so a connection that stays alive but stops draining its mailbox — wedged
somewhere this module cannot see — would accumulate frames until it recovered.
That costs this router memory on one connection and nothing else, because the
caller no longer waits on it, which is the property this is here to buy; the
socket bound above ends the case where the peer is the one not reading. A sweep
over connection queue lengths in the peer manager would close the remainder, and
is not worth a per-connection timer until a send rate makes it matter.

## The message counter, and why a session is not capped at 65536 frames

NTCP2's data phase holds one direction key for the life of the connection and
gives each frame a counter nonce: 4 zero bytes plus the message number as an
8-byte little-endian integer (`m:i2p_crypto:es_nonce/1`). **That counter is 64
bits wide**, so it runs `0..2^64 - 2` and the specification's rule for it is
*"Connection must be dropped and restarted after it reaches that value"* — not a
rekey. There is no key schedule partway through an NTCP2 session to ratchet
into, and none is needed: a nonce under a fixed key is unique for as long as the
counter does not repeat, and a strictly incrementing counter over 64 bits does
not repeat.

This matters here because **both** directions walk one such counter, and they
walk it independently: the send side seeds `msg => 0` here when the data phase
starts and increments per frame in `send_payload/4`, and the receive side is the
inbound half of the same counter, held by `m:i2p_stream`. So the two are one
change and one case — `i2p_ntcp2_conn_SUITE`'s
`a_session_is_alive_and_speaking_at_frame_70000/1` floods a live pair past the
boundary in both directions at once, and asserts both ends are still alive at a
frame far beyond it.

This module used to bound that counter at 65535 by way of the nonce function,
and the consequence was a connection process dying with a `function_clause`
raised out of a crypto helper on the 65536th frame. It was not a visible crash:
the peer manager observed a disconnect and backed off, so a healthy router looked
like one that had dropped a peer. **A counter that reached the specified maximum
still raises**, in `i2p_crypto:es_nonce/1` — the forbidden value is the one that
function exists to keep off the wire — and it raises rather than announcing,
because a counter at 2^64 - 1 is a defect in whatever increments it and not a
runtime condition to instrument. That is 2^48 times further off than the bound
this defect had.

## Usage

```erlang
%% Initiator — connect to a peer from its published RouterInfo.
Local = #{static_priv := P, static_pub := Q, hash := H, iv := I, ri := RI},
{ok, Conn} = i2p_ntcp2_conn:connect(PeerRI, Local, #{}),

%% Hand a framed payload (blocks) to the connection and receive
%% {ntcp2_frame, Conn, Payload} when it comes back the other way.
ok = i2p_ntcp2_conn:send(Conn, i2p_framing:encode_block(254, <<>>)),
receive {ntcp2_frame, Conn, Payload} -> Payload after 5000 -> timeout end.
```
""".

%% A connection is never started with start_link directly; the supervisor child
%% spec is built by i2p_ntcp2_sup.
-export([
    connect/3,
    send/2,
    stop/1
]).
-export([start_link/1, init/1]).

-doc """
The local node's NTCP2 identity material, shared by the initiator and the
responder: the X25519 static keypair, the router hash (SHA-256 of the
RouterIdentity, the AES-CBC key) and the published NTCP2 IV, plus the node's
own signed RouterInfo (the msg3 payload block).
""".
-type local_keys() :: #{
    static_priv := i2p_crypto:x25519_private_key(),
    static_pub := i2p_crypto:x25519_public_key(),
    hash := i2p_crypto:hash(),
    iv := i2p_crypto:aes_iv(),
    ri := i2p_router_info:router_info()
}.
-export_type([local_keys/0]).

-doc """
Connection configuration: `role` is `alice` (initiator, opens the TCP
connection to `remote_ri`'s published NTCP2 address) or `bob` (responder, owns
the accepted `sock`); `local` is the node's `t:local_keys/0`; `owner` is the
process that receives `{ntcp2_ready, Pid, RemoteRI}` (with the peer's decoded
RouterInfo, announced by both roles) and `{ntcp2_frame, Pid, Payload}`;
`handshake_timeout` bounds the handshake (default 15 seconds).
""".
-type config() :: #{
    role := alice | bob,
    remote_ri => i2p_router_info:router_info(),
    sock => gen_tcp:socket(),
    local := local_keys(),
    owner := pid(),
    handshake_timeout => pos_integer()
}.
-export_type([config/0]).

-doc """
Why a connection stopped accepting sends, as carried on the `m:i2p_events` bus
and in this process's exit reason.

`socket_blocked` — the socket would not take the frame. The data phase is
`{delay_send, true}` with a `send_timeout`, so the question has a deadline, and
a peer that has stopped reading answers it in a known time. That is the whole
vocabulary today; a reason not modelled here is a socket error this module does
not expect, and it crashes the connection rather than being given a name it has
not earned.
""".
-type send_stalled_reason() :: socket_blocked.
-export_type([send_stalled_reason/0]).

-define(DEFAULT_TIMEOUT, 15000).
%% Data-phase idle reaping: a connection that receives no frames for this
%% long is considered dead and the connection process exits with
%% `{idle_timeout, no_activity}`. A datetime heartbeat is sent every
%% `ntcp2_keepalive_interval_ms` so a healthy quiet session is refreshed rather
%% than mistaken for a dead peer. Overridable per run via app env `i2per` ->
%% `idle_timeout_ms` / `ntcp2_keepalive_interval_ms`; OS-level TCP keepalive
%% remains as the slower safety net.
-define(IDLE_TIMEOUT_MS, 120000).
-define(KEEPALIVE_INTERVAL_MS, 60000).
%% How long the data-phase socket write may hold this process when the peer has
%% stopped reading. The data phase is `{delay_send, true}`, so without this the
%% send is a wait with no deadline and a peer that never reads wedges the
%% connection exactly as an unbounded caller-side wait wedged the peer manager.
%% Generous, because a burst is not a fault: the point is that the wait ends,
%% not that it ends quickly. Overridable per run via app env `i2per` ->
%% `ntcp2_send_timeout_ms`.
-define(SEND_TIMEOUT_MS, 30000).
%% How long `f:stop/1` waits for a graceful close before killing the process.
%% A connection that cannot answer a close request cannot be closed gracefully,
%% and an exported function with an unbounded wait is the defect this module just
%% removed from its send path.
-define(STOP_TIMEOUT_MS, 1000).

-doc """
Establish a connection to a peer as the initiator.

Input: `RemoteRI` — the peer's RouterInfo with a published NTCP2 address (its
address, static key and hash drive the handshake); `Local` — this node's
`t:local_keys/0`;
`Opts` — `#{owner => pid(), timeout => ms()}` (defaults: calling process,
15s).
Output: `{ok, Pid}` once the handshake is complete and the connection is in the
data phase, or `{error, Reason}` if the connection process died during the
handshake. The caller also receives `{ntcp2_frame, Pid, Payload}` for each
decrypted frame.
""".
-spec connect(i2p_router_info:router_info(), local_keys(), map()) ->
    {ok, pid()} | {error, term()}.
connect(RemoteRI, Local, Opts) ->
    Owner = maps:get(owner, Opts, self()),
    Timeout = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    Args = #{
        role => alice,
        remote_ri => RemoteRI,
        local => Local,
        owner => Owner
    },
    case i2p_ntcp2_sup:start_connection(i2p_ntcp2_sup:conn_child(Args)) of
        {ok, Pid} ->
            await_connection(Pid, Timeout);
        {ok, Pid, _Extra} ->
            await_connection(Pid, Timeout);
        {error, Reason} ->
            {error, Reason}
    end.

-spec await_connection(pid(), timeout()) -> {ok, pid()} | {error, term()}.
await_connection(Pid, Timeout) ->
    MRef = erlang:monitor(process, Pid),
    receive
        {ntcp2_ready, P, _RemoteRI} when P =:= Pid ->
            erlang:demonitor(MRef, [flush]),
            {ok, Pid};
        {'DOWN', MRef, process, Pid, Reason} ->
            {error, Reason}
    after Timeout ->
        erlang:demonitor(MRef, [flush]),
        {error, timeout}
    end.

-doc """
Hand one data-phase frame carrying `Payload` (a concatenation of encoded
blocks) to the peer.

Input: `Conn` — a connection process in the data phase; `Payload` — the blocks
to frame and write. Output: `ok`, as soon as the frame is queued to the
connection. **This returns before the frame has been encrypted, framed or
written**, and a connection that cannot take it never says so here.

That is the whole contract, and it is what makes the caller safe. The caller is
`m:i2p_peer` — one process for the whole router, through which every inbound
message from every connection passes — and this function used to wait for a
`{send_done, Ref}` reply with no timeout clause, so one wedged peer stopped I2NP
for all of them. It is a cast now, the same shape as
`m:i2p_ssu2_conn:send_i2np/4`; see the module doc for why the framing cannot move
to the caller and why the caller does not have to follow it.

Frames are written in the order they are handed over, which is what the cipher
state requires. The cost of that is head-of-line within the connection, bounded
at one inbound socket message by `{active, once}`; the module doc says what that
bound rests on.

The other consequence worth stating: a frame handed to a connection that dies
before reading its mailbox is lost. The caller monitors the connection, so the
loss surfaces as a disconnect and the peer's queued work is re-sent on reconnect
— the recovery a send that failed for any other reason already gets.
""".
-spec send(pid(), binary()) -> ok.
send(Conn, Payload) ->
    Conn ! {send, Payload},
    ok.

-doc """
Close the connection gracefully: the process exits `normal` and the socket
closes with it. The supervisor's `temporary` restart policy leaves it dead.
Returns `ok` even if the connection already died on its own (e.g. the peer
closed the socket), and also if it is alive but never answers — after
`?STOP_TIMEOUT_MS` the process is killed, because a connection that cannot be
closed gracefully should not be left holding a socket, and this function's wait
is bounded for the same reason `f:send/2`'s caller no longer waits at all.
""".
-spec stop(pid()) -> ok.
stop(Conn) ->
    Ref = make_ref(),
    MRef = erlang:monitor(process, Conn),
    Conn ! {stop, self(), Ref},
    receive
        {stopped, Ref} ->
            erlang:demonitor(MRef, [flush]),
            ok;
        {'DOWN', MRef, process, Conn, _} ->
            ok
    after ?STOP_TIMEOUT_MS ->
        erlang:demonitor(MRef, [flush]),
        _ = catch exit(Conn, shutdown),
        ok
    end.

-doc false.
-spec start_link(config()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    proc_lib:start_link(?MODULE, init, [Args]).

%% Runs the handshake, then the data-phase loop. The ack is sent before the
%% handshake so the supervisor never blocks on a peer that is itself waiting for
%% this same supervisor to spawn the other side of the connection.
init(#{role := alice} = Args) ->
    proc_lib:init_ack({ok, self()}),
    run_handshake(alice, Args);
init(#{role := bob} = Args) ->
    proc_lib:init_ack({ok, self()}),
    run_handshake(bob, Args).

run_handshake(alice, #{
    remote_ri := RemoteRI, local := Local, owner := Owner, handshake_timeout := Timeout
}) ->
    Timer = handshake_timer(Timeout),
    case alice_handshake(RemoteRI, Local) of
        {Keys, Sock, ab, ba} ->
            enter_data_phase(Owner, Sock, Keys, ab, ba, Timer, RemoteRI);
        {error, Reason} ->
            _ = erlang:cancel_timer(Timer),
            %% The reason travels with the failure. It used to be dropped here, so
            %% the connection manager knew a connect had failed and not why, and
            %% the only honest thing it could report was that a peer was in
            %% backoff — which is the same figure for a timeout, a rejected
            %% handshake, and a key mismatch.
            Owner ! {connect_failed, i2p_router_info:hash(RemoteRI), {handshake, Reason}},
            exit(normal);
        error ->
            %% A protocol error is still a failed connect, and it is the one case
            %% that previously left no failure at all: the process exits, the
            %% manager sees a DOWN for a peer that never connected, and reports it
            %% as a disconnect. Announced here, where the cause is still known.
            Owner ! {connect_failed, i2p_router_info:hash(RemoteRI), protocol_error},
            exit({protocol_error, handshake})
    end;
run_handshake(bob, #{sock := Sock, local := Local, owner := Owner, handshake_timeout := Timeout}) ->
    ok = inet:setopts(Sock, [{active, false}]),
    Timer = handshake_timer(Timeout),
    case bob_handshake(Sock, Local) of
        {Keys, ba, ab, RemoteRI} ->
            enter_data_phase(Owner, Sock, Keys, ba, ab, Timer, RemoteRI);
        error ->
            exit({protocol_error, handshake})
    end.

handshake_timer(Timeout) ->
    erlang:send_after(Timeout, self(), handshake_timeout).

enter_data_phase(Owner, Sock, Keys, SendDir, RecvDir, Timer, RemoteRI) ->
    _ = erlang:cancel_timer(Timer),
    #{k_ab := KAb, k_ba := KBa, sip_ab := SipAb, sip_ba := SipBa} = Keys,
    {SendKey, SendSip, RecvKey, RecvSip} =
        case {SendDir, RecvDir} of
            {ab, ba} -> {KAb, SipAb, KBa, SipBa};
            {ba, ab} -> {KBa, SipBa, KAb, SipAb}
        end,
    Owner ! {ntcp2_ready, self(), RemoteRI},
    ok = inet:setopts(Sock, data_phase_opts()),
    data_loop(
        Owner,
        Sock,
        #{key => SendKey, sip => SendSip, msg => 0},
        i2p_stream:new(RecvKey, RecvSip),
        i2p_router_info:hash(RemoteRI),
        arm_idle_timer(),
        arm_keepalive_timer()
    ).

%% The data-phase socket is driven by this process and nothing else, so it must
%% not be able to stop this process.
%%
%% `{active, once}` is what bounds head-of-line on the send path: one inbound
%% socket message is in hand at a time, so a queued send waits behind at most
%% that one. The option is re-armed after the message in hand has been
%% processed, so the bound is this loop's own structure rather than a number
%% anyone chose.
%%
%% `{delay_send, true}` with a `send_timeout` is what bounds the write. Together
%% they turn `gen_tcp:send/2` from a wait into a question with a deadline: the
%% driver takes the frame and returns, and when the peer has stopped reading the
%% queue fills and the send comes back `{error, timeout}` in a known time. Either
%% option alone is not a bound — with `delay_send` and no `send_timeout` the send
%% waits for driver room indefinitely, which is the same unbounded wait one level
%% down from the one removed from the caller.
%%
%% `sndbuf` is offered and **not defaulted**: the kernel's own autotuning is left
%% in charge unless an operator sets `i2per` -> `ntcp2_sndbuf`, because how much
%% undrained data one peer may cost this router is a memory-budget decision for
%% whoever runs it, and picking the number for them is not this module's call.
%% Setting it has a second effect worth knowing: the queue the driver can fill
%% before it refuses is a function of it, so a smaller buffer brings the stall
%% above sooner as well as bounding what it costs.
data_phase_opts() ->
    [
        {active, once},
        {delay_send, true},
        {send_timeout, send_timeout_ms()}
        | sndbuf_opt()
    ].

sndbuf_opt() ->
    case application:get_env(i2per, ntcp2_sndbuf) of
        {ok, Bytes} when is_integer(Bytes), Bytes > 0 -> [{sndbuf, Bytes}];
        _ -> []
    end.

data_loop(Owner, Sock, Send, Recv, RemoteHash, IdleRef, KeepaliveRef) ->
    receive
        {tcp, Sock, Data} ->
            %% Counted on arrival, before the framing is touched. `Data` is the
            %% raw socket read, so it may hold a partial frame or several of
            %% them and either way it is exactly the bytes that arrived. Charging
            %% it before the parse also means a frame this connection rejects as
            %% malformed is still counted: it crossed the wire, and a counter
            %% that quietly excluded bytes the router received would be harder to
            %% reconcile against anything.
            ok = i2p_stats:add(ntcp2_bytes_in, byte_size(Data)),
            case i2p_stream:push(Recv, Data) of
                {ok, Recv1, Payloads} ->
                    lists:foreach(
                        fun(P) -> Owner ! {ntcp2_frame, self(), P} end,
                        Payloads
                    ),
                    ok = inet:setopts(Sock, [{active, once}]),
                    data_loop(
                        Owner,
                        Sock,
                        Send,
                        Recv1,
                        RemoteHash,
                        rearm_idle_timer(IdleRef),
                        KeepaliveRef
                    );
                error ->
                    exit({protocol_error, malformed_frame})
            end;
        {send, Payload} ->
            %% Serviced in mailbox order, which the framing state requires and the
            %% socket's send timeout bounds. No reply: the sender is not waiting,
            %% and a reply here is what made every caller a waiter.
            Send1 = send_payload(Sock, Send, Payload, RemoteHash),
            data_loop(
                Owner,
                Sock,
                Send1,
                Recv,
                RemoteHash,
                rearm_idle_timer(IdleRef),
                KeepaliveRef
            );
        {stop, From, Ref} ->
            _ = erlang:cancel_timer(IdleRef),
            _ = erlang:cancel_timer(KeepaliveRef),
            From ! {stopped, Ref},
            exit(normal);
        {tcp_closed, Sock} ->
            exit(closed);
        {tcp_error, Sock, Reason} ->
            exit({tcp_error, Reason});
        handshake_timeout ->
            exit(timeout);
        idle_timeout ->
            exit({idle_timeout, no_activity});
        keepalive ->
            Send1 = send_payload(Sock, Send, keepalive_payload(), RemoteHash),
            data_loop(
                Owner,
                Sock,
                Send1,
                Recv,
                RemoteHash,
                rearm_idle_timer(IdleRef),
                arm_keepalive_timer()
            )
    end.

send_payload(Sock, Send, Payload, RemoteHash) ->
    #{key := Key, sip := Sip, msg := Msg} = Send,
    {Frame, Sip1} = i2p_framing:encrypt_frame(Key, Msg, Payload, Sip),
    Wire = i2p_framing:frame_bytes(Frame),
    write_frame(Sock, Wire, RemoteHash),
    %% Charged after the write, not before. The counter's claim is that it reports
    %% what this router handed to the socket, and a frame the socket refused is
    %% not that — and refusing is now an outcome the process can reach and name
    %% rather than a crash, so counting ahead of the write would be counting bytes
    %% this router did not send.
    ok = i2p_stats:add(ntcp2_bytes_out, byte_size(Wire)),
    Send#{sip => Sip1, msg => Msg + 1}.

%% The socket would not take the frame, which on a `{delay_send, true}` socket
%% means the peer's window has been shut for longer than `send_timeout`. There
%% is no partial send to recover and no queue worth draining: the connection is
%% dead, and letting the peer manager rediscover that through a monitor and a
%% backoff is the recovery that already exists for a closed socket.
%%
%% The announcement is the whole report (ADR 0002: a fact is recorded once, on
%% one instrument). The peer manager deliberately does not repeat the reason when
%% it observes the disconnect — a busy consumer would read the same fact twice,
%% and the log line that would be the tempting second copy is exactly what the
%% rule is about.
%%
%% `closed` is not a stall and is not matched here: a closed socket raises, and
%% the loop's own `{tcp_closed, Sock}` clause names a disconnect as a disconnect.
%% Any other send error is likewise unmodelled, so it crashes the connection
%% rather than being given a reason `t:send_stalled_reason/0` has not earned.
write_frame(Sock, Wire, RemoteHash) ->
    case gen_tcp:send(Sock, Wire) of
        ok ->
            ok;
        {error, timeout} ->
            i2p_events:notify({peer_send_stalled, RemoteHash, socket_blocked}),
            exit({send_stalled, socket_blocked})
    end.

keepalive_payload() ->
    Now = erlang:system_time(second) band 16#FFFFFFFF,
    i2p_framing:encode_block(0, <<Now:32/big>>).

%% Arm the idle-reap timer; re-arm (cancelling the previous one) after any
%% inbound frame.
arm_idle_timer() ->
    erlang:send_after(idle_timeout_ms(), self(), idle_timeout).

rearm_idle_timer(IdleRef) ->
    _ = erlang:cancel_timer(IdleRef),
    arm_idle_timer().

arm_keepalive_timer() ->
    erlang:send_after(keepalive_interval_ms(), self(), keepalive).

keepalive_interval_ms() ->
    case application:get_env(i2per, ntcp2_keepalive_interval_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?KEEPALIVE_INTERVAL_MS
    end.

%% How long the data-phase socket write may hold this process. Read once, at the
%% transition into the data phase, so a change mid-connection cannot leave the
%% socket with a timeout this loop does not know about.
send_timeout_ms() ->
    case application:get_env(i2per, ntcp2_send_timeout_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?SEND_TIMEOUT_MS
    end.

idle_timeout_ms() ->
    case application:get_env(i2per, idle_timeout_ms) of
        {ok, Ms} when is_integer(Ms), Ms > 0 -> Ms;
        _ -> ?IDLE_TIMEOUT_MS
    end.

%% Alice (initiator): open the TCP connection, run the XK handshake and derive
%% the data-phase keys.
alice_handshake(RemoteRI, Local) ->
    case i2p_router_info:ntcp2_connector(RemoteRI) of
        {error, Reason} ->
            {error, {no_reachable_ntcp2, Reason}};
        {ok, Endpoint} ->
            #{host := Host, port := Port} = Endpoint,
            case
                gen_tcp:connect(
                    binary_to_list(Host),
                    Port,
                    [binary, {packet, raw}, {active, false}, {nodelay, true}, {keepalive, true}],
                    10000
                )
            of
                {error, Reason} ->
                    {error, {connect_failed, Reason}};
                {ok, Sock} ->
                    alice_handshake_socket(RemoteRI, Local, Endpoint, Sock)
            end
    end.

alice_handshake_socket(
    RemoteRI,
    #{static_priv := Priv, static_pub := Pub, ri := LocalRI},
    #{static := Static, iv := IV},
    Sock
) ->
    RemoteHash = i2p_router_info:hash(RemoteRI),
    S0 = i2p_ntcp2:alice_init(Static, RemoteHash, IV, Priv, Pub),
    Recv = recv_fun(Sock),
    Pad = random_pad(),
    Payload = i2p_router_info:m3p2_block(LocalRI),
    Opts = #{padlen => byte_size(Pad), m3p2len => byte_size(Payload) + 16, ts => now_ts()},
    {ok, Msg1, S1} = i2p_ntcp2:create_msg1(S0, ephemeral(), Opts, Pad),
    ok = gen_tcp:send(Sock, Msg1),
    case i2p_ntcp2:receive_msg2_stream(S1, Recv) of
        {ok, _Opts2, S2} ->
            {ok, Msg3, S3} = i2p_ntcp2:create_msg3(S2, Payload),
            ok = gen_tcp:send(Sock, Msg3),
            {i2p_ntcp2:data_phase_keys(S3), Sock, ab, ba};
        error ->
            error
    end.

%% Bob (responder): run the XK handshake on the accepted socket.
%% Output: `{Keys, ba, ab, RemoteRI}` — the data-phase keys, the send/recv
%% directions, and Alice's RouterInfo recovered from her msg3 payload.
bob_handshake(Sock, #{static_priv := Priv, static_pub := Pub, hash := Hash, iv := IV}) ->
    S0 = i2p_ntcp2:bob_init(Priv, Pub, Hash, IV),
    Recv = recv_fun(Sock),
    case i2p_ntcp2:receive_msg1_stream(S0, Recv) of
        {ok, _Opts1, S1} ->
            Pad = random_pad(),
            {ok, Msg2, S2} = i2p_ntcp2:create_msg2(S1, ephemeral(), Pad, now_ts()),
            ok = gen_tcp:send(Sock, Msg2),
            case i2p_ntcp2:receive_msg3_stream(S2, Recv) of
                {ok, Payload, S3} ->
                    RemoteRI = remote_ri_from_payload(Payload),
                    {i2p_ntcp2:data_phase_keys(S3), ba, ab, RemoteRI};
                error ->
                    error
            end;
        error ->
            error
    end.

%%%%%%% %%% Internal %%%%%%%

%% Alice's msg3 payload is the type-2 (RouterInfo) block she wrapped around her
%% signed RouterInfo (see `i2p_router_info:m3p2_block/1`): type byte, 16-bit
%% size (including the flags byte), zero flags byte, then the RouterInfo bytes.
%% Recover and verify the RouterInfo; a peer that fails to produce a valid one
%% is a protocol violation and ends the connection.
remote_ri_from_payload(<<2:8, Size:16/big, _Flags:8, Bin:(Size - 1)/binary>>) ->
    case i2p_router_info:decode(Bin) of
        {ok, RI} -> RI;
        {error, _} -> exit({protocol_error, invalid_routerinfo})
    end;
remote_ri_from_payload(_) ->
    exit({protocol_error, invalid_routerinfo}).

%% gen_tcp-backed byte source for the stream handshake readers. A zero-length
%% read must return immediately (gen_tcp:recv/3 would block waiting for data).
recv_fun(Sock) ->
    fun
        (0) ->
            {ok, <<>>};
        (N) ->
            case gen_tcp:recv(Sock, N, 10000) of
                {ok, Data} -> {ok, Data};
                {error, _} -> error
            end
    end.

random_pad() ->
    crypto:strong_rand_bytes(rand:uniform(33) - 1).

ephemeral() ->
    {Priv, _} = i2p_crypto:x25519_keygen(),
    Priv.

now_ts() ->
    erlang:system_time(second).
