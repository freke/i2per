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

## Usage

```erlang
%% Initiator — connect to a peer from its published RouterInfo.
Local = #{static_priv := P, static_pub := Q, hash := H, iv := I, ri := RI},
{ok, Conn} = i2p_ntcp2_conn:connect(PeerRI, Local, #{}),

%% Send a framed payload (blocks) and receive {ntcp2_frame, Conn, Payload}.
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
Send one data-phase frame carrying `Payload` (a concatenation of encoded
blocks) to the peer.

Returns `ok` once the frame has been handed to the socket. The message number
and SipHash IV advance with every frame in this direction.
""".
-spec send(pid(), binary()) -> ok.
send(Conn, Payload) ->
    Ref = make_ref(),
    Conn ! {send, self(), Ref, Payload},
    receive
        {send_done, Ref} -> ok
    end.

-doc """
Close the connection gracefully: the process exits `normal` and the socket
closes with it. The supervisor's `temporary` restart policy leaves it dead.
Returns `ok` even if the connection already died on its own (e.g. the peer
closed the socket).
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
        {error, _Reason} ->
            _ = erlang:cancel_timer(Timer),
            Owner ! {connect_failed, i2p_router_info:hash(RemoteRI)},
            exit(normal);
        error ->
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
    ok = inet:setopts(Sock, [{active, once}]),
    data_loop(
        Owner,
        Sock,
        #{key => SendKey, sip => SendSip, msg => 0},
        i2p_stream:new(RecvKey, RecvSip),
        arm_idle_timer(),
        arm_keepalive_timer()
    ).

data_loop(Owner, Sock, Send, Recv, IdleRef, KeepaliveRef) ->
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
                        rearm_idle_timer(IdleRef),
                        KeepaliveRef
                    );
                error ->
                    exit({protocol_error, malformed_frame})
            end;
        {send, From, Ref, Payload} ->
            Send1 = send_payload(Sock, Send, Payload),
            From ! {send_done, Ref},
            data_loop(
                Owner,
                Sock,
                Send1,
                Recv,
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
            Send1 = send_payload(Sock, Send, keepalive_payload()),
            data_loop(
                Owner,
                Sock,
                Send1,
                Recv,
                rearm_idle_timer(IdleRef),
                arm_keepalive_timer()
            )
    end.

send_payload(Sock, Send, Payload) ->
    #{key := Key, sip := Sip, msg := Msg} = Send,
    {Frame, Sip1} = i2p_framing:encrypt_frame(Key, Msg, Payload, Sip),
    Wire = i2p_framing:frame_bytes(Frame),
    ok = i2p_stats:add(ntcp2_bytes_out, byte_size(Wire)),
    ok = gen_tcp:send(Sock, Wire),
    Send#{sip => Sip1, msg => Msg + 1}.

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
