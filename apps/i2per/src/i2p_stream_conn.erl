-module(i2p_stream_conn).

-moduledoc """
Streaming connection state machine: one process per end-to-end stream,
implementing TCP-like reliable ordered delivery on top of unreliable garlic
Data cloves.

Each side picks one random nonzero stream ID at creation. Every outgoing
packet carries `sendStreamId = peer's ID` and `receiveStreamId = my ID`;
an initiator does not know the peer's ID yet, so its SYN sends
`sendStreamId = 0` and adopts the peer's ID from the SYN reply. Incoming
packets are matched by our own ID arriving in the sendStreamId field —
the demux key the owning session dispatches on (mirrors i2pd's
`Streaming.cpp`). SYNCHRONIZE packets carry the recipient's destination
hash in the eight-NACK replay-prevention form and are Ed25519-signed, as
are CLOSE and RESET. The packet codec allows options to be absent, so peer-offer
handling matches I2P Java: a missing offer falls back to 1730 bytes and a
positive offer below 512 bytes is raised to 512. An explicit zero offer is a
protocol error because it cannot carry payload. This connection includes its
positive local offer unchanged in both the SYN and SYN-ACK, then limits outbound
data to the smaller local and normalized peer values.

Reliability model: a fixed-size window of
unacked packets, cumulative `ackThrough` acknowledgements, immediate plain
ACKs (sequenceNum 0), NACK-driven fast retransmit when a sequence number
arrives NACKed twice, a periodic retransmission round resending all
unacked packets plus an unanswered CLOSE, and a give-up after
`?MAX_RESEND_ROUNDS` silent rounds — the owner is notified with
`{stream_reset, Conn}` and the process dies. Recovery lives above the
connection.

Let-it-crash: malformed packets, bad signatures, replay-hash mismatches
and identity mismatches raise `{protocol_error, _}`. The supervisor leaves
the dead connection dead; the owning SAM session and sibling streams are
unaffected.

## Usage

```erlang
{ok, Conn} = i2p_stream_conn:start_link(#{
    role => connect, owner => self(),
    send_fn => fun(Wire) -> wrap_and_inject(Wire) end,
    local_seed => SignSeed, local_dest_bin => MyDest,
    local_dest_hash => MyHash,
    remote_dest_bin => TargetDest, remote_dest_hash => TargetHash}),
receive {stream_established, Conn, _PeerHash} -> ok after 15000 -> timeout end,
ok = i2p_stream_conn:send(Conn, <<"GET / HTTP/1.0", "\r\n\r\n">>),
receive {stream_data, Conn, Bytes} -> ok end,
ok = i2p_stream_conn:close(Conn).
```
""".
-behaviour(gen_server).

-export([
    start_link/1,
    send/2,
    close/1,
    handle_packet/2
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export_type([opts/0]).

-define(DEFAULT_WINDOW, 8).
-define(DEFAULT_MTU, 1730).
-define(MIN_PEER_MTU, 512).
%% Seconds advertised in the resendDelay byte; also the retransmit period.
-define(RESEND_MS, 1000).
-define(MAX_RESEND_ROUNDS, 15).
-define(CONNECT_TIMEOUT_MS, 15000).

-doc """
Start options.

`role` selects the handshake direction: `connect` sends the SYN, `accept`
consumes an already-decoded inbound SYN supplied in `syn`. `send_fn`
transmits one encoded streaming packet toward the peer (the caller wraps
it into garlic and injects it into a tunnel). The local fields describe
THIS destination; the remote fields are mandatory for `connect` (the
resolved dial target) and forbidden for `accept`, which learns the peer
from the SYN's FROM option. The optional `window` and `mtu` values are used as
supplied; `mtu` is the positive local payload limit advertised unchanged and
defaults to 1730 bytes. Peer-offer normalization happens during the handshake.
""".
-type opts() :: #{
    role := connect | accept,
    owner := pid(),
    send_fn := fun((binary()) -> ok),
    local_seed := i2p_crypto:ed25519_seed(),
    local_dest_bin := binary(),
    local_dest_hash := i2p_crypto:hash(),
    remote_dest_bin => binary(),
    remote_dest_hash => i2p_crypto:hash(),
    syn => i2p_streaming:packet(),
    window => pos_integer(),
    mtu => pos_integer()
}.

-doc "Internal connection state.".
-type state() :: #{
    owner := pid(),
    send_fn := fun((binary()) -> ok),
    seed := i2p_crypto:ed25519_seed(),
    dest_bin := binary(),
    dest_hash := i2p_crypto:hash(),
    my_id := 1..16#FFFFFFFF,
    peer_id => 1..16#FFFFFFFF,
    peer_pub => i2p_crypto:ed25519_public_key(),
    peer_hash => i2p_crypto:hash(),
    mtu := pos_integer(),
    window := pos_integer(),
    status := connecting | established | closing | closed,
    send_seq := 0..16#FFFFFFFF,
    inflight := #{0..16#FFFFFFFF => binary()},
    out_buf := binary(),
    resend_round := 0,
    resend_armed := boolean(),
    close_requested := boolean(),
    close_wire => binary(),
    recv_contig := -1..16#FFFFFFFF,
    reorder := #{0..16#FFFFFFFF => binary()},
    nack_counts := #{0..16#FFFFFFFF => non_neg_integer()},
    syn_wire => binary()
}.

%%%%%%% %%% API %%%%%%%

-doc """
Start a streaming connection process.

Input: `Opts` — see `t:opts/0`; `accept` roles additionally require the
decoded inbound `syn` packet.
Output: `{ok, Pid}` of a process linked to the caller (production paths
start it under the SAM dynamic supervisor).
""".
-spec start_link(opts()) -> {ok, pid()}.
start_link(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

-doc """
Queue application bytes for ordered delivery to the peer.

Bytes are buffered until the handshake completes, then chunked to the
negotiated MTU under the send window; backpressure is the window.
""".
-spec send(pid(), binary()) -> ok.
send(Conn, Data) ->
    gen_server:cast(Conn, {send, Data}).

-doc """
Request a graceful close: flush queued data, then exchange signed CLOSE
packets with the peer. The owner receives `{stream_closed, Conn}` when the
peer's CLOSE arrives (or `{stream_reset, Conn}` if it never does).
""".
-spec close(pid()) -> ok.
close(Conn) ->
    gen_server:cast(Conn, close).

-doc """
Deliver one raw streaming packet (already unwrapped from garlic) to the
connection. The owning session calls this for every packet whose demux key
matches this stream.
""".
-spec handle_packet(pid(), binary()) -> ok.
handle_packet(Conn, WireBin) ->
    Conn ! {packet, WireBin},
    ok.

%%%%%%% %%% gen_server callbacks %%%%%%%

-spec init(opts()) -> {ok, state()}.
init(#{role := connect} = Opts) ->
    S = base_state(Opts),
    %% First owner message: announces the demux key (our stream ID).
    maps:get(owner, S) ! {stream_started, self(), maps:get(my_id, S)},
    SynWire = i2p_streaming:signed(syn_packet(S), maps:get(seed, S)),
    transmit(SynWire, S),
    erlang:send_after(?CONNECT_TIMEOUT_MS, self(), connect_timeout),
    {ok,
        ensure_resend_timer(S#{
            status => connecting,
            send_seq => 1,
            inflight => #{0 => SynWire},
            syn_wire => SynWire
        })};
init(#{role := accept, syn := Pkt} = Opts) ->
    S = base_state(Opts),
    maps:get(owner, S) ! {stream_started, self(), maps:get(my_id, S)},
    {ok, S1} = verify_syn(Pkt, S),
    SynAckWire = i2p_streaming:signed(syn_ack_packet(S1), maps:get(seed, S1)),
    %% The SYN-ACK keeps our local offer; `mtu` becomes the outbound limit.
    S2 = negotiate_outbound_mtu(Pkt, S1),
    transmit(SynAckWire, S2),
    maps:get(owner, S2) !
        {stream_established, self(), maps:get(peer_hash, S2)},
    case i2p_streaming:payload(Pkt) of
        <<>> ->
            ok;
        Payload ->
            maps:get(owner, S2) ! {stream_data, self(), Payload},
            ok
    end,
    {ok,
        ensure_resend_timer(S2#{
            status => established,
            send_seq => 1,
            recv_contig => 0,
            syn_wire => SynAckWire
        })}.

-spec handle_call(term(), {pid(), term()}, state()) ->
    {reply, term(), state()}.
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast({send, <<>>}, State) ->
    {noreply, State};
handle_cast({send, Data}, #{status := connecting, out_buf := Buf} = State) ->
    %% Handshake still in flight — buffer only, nothing can be sent yet
    %% because the peer's stream ID is unknown.
    {noreply, State#{out_buf => <<Buf/binary, Data/binary>>}};
handle_cast({send, Data}, #{status := established, out_buf := Buf} = State) ->
    {noreply, flush_out(State#{out_buf => <<Buf/binary, Data/binary>>})};
handle_cast({send, _Data}, State) ->
    {noreply, State};
handle_cast(close, #{status := established} = State) ->
    {noreply, maybe_send_close(State#{close_requested => true})};
handle_cast(close, #{status := connecting} = State) ->
    {noreply, State#{close_requested => true}};
handle_cast(close, State) ->
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) ->
    {noreply, state()} | {stop, normal, state()}.
handle_info({packet, WireBin}, State) ->
    case i2p_streaming:decode(WireBin) of
        {ok, Pkt} ->
            handle_pkt(Pkt, State);
        {error, Reason} ->
            exit({protocol_error, {malformed_packet, Reason}})
    end;
handle_info(resend_tick, State) ->
    {noreply, resend_tick(State)};
handle_info(connect_timeout, #{status := connecting, owner := Owner} = State) ->
    Owner ! {stream_connect_failed, self()},
    {stop, normal, State};
handle_info(connect_timeout, State) ->
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

%%%%%%% %%% Inbound packet processing %%%%%%%

-spec handle_pkt(i2p_streaming:packet(), state()) ->
    {noreply, state()} | {stop, normal, state()}.
handle_pkt(Pkt, #{status := connecting} = State) ->
    handle_syn_reply(Pkt, State);
handle_pkt(_Pkt, #{status := closed} = State) ->
    {noreply, State};
handle_pkt(Pkt, #{status := Status} = State) when
    Status =:= established; Status =:= closing
->
    case i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize()) of
        true ->
            %% Retransmitted SYN: answer again so a lost SYN-ACK heals.
            transmit(maps:get(syn_wire, State), State),
            {noreply, State};
        false ->
            State1 = process_ack(Pkt, State),
            {Changed, State2} = ingest_data(Pkt, State1),
            State3 =
                case Changed of
                    true -> send_plain_ack(State2);
                    false -> State2
                end,
            %% Freed window space may unblock buffered outbound data;
            %% flush_out early-exits when there is nothing to do.
            State4 = flush_out(State3),
            handle_control(Pkt, State4)
    end.

%% handle_syn_reply — validate the peer's SYN-ACK on an outbound connection
%% and move to established.
-spec handle_syn_reply(i2p_streaming:packet(), state()) ->
    {noreply, state()} | {stop, normal, state()}.
handle_syn_reply(Pkt, #{status := connecting} = State) ->
    case i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize()) of
        false ->
            %% Follow-on data before the SYN-ACK is legal (spec 0-RTT);
            %% the peer repeats under its window, so waiting costs nothing.
            {noreply, State};
        true ->
            ok = expect(
                i2p_streaming:send_id(Pkt),
                maps:get(my_id, State),
                syn_ack_wrong_stream_id
            ),
            PeerId = expect_nonzero(i2p_streaming:recv_id(Pkt)),
            {ok, S1} = verify_signature_and_from(Pkt, State),
            Negotiated = negotiate_outbound_mtu(Pkt, S1),
            State1 = process_ack(Pkt, Negotiated),
            Established = State1#{
                status => established,
                peer_id => PeerId,
                recv_contig => 0
            },
            maps:get(owner, Established) !
                {stream_established, self(), maps:get(peer_hash, Established)},
            case i2p_streaming:payload(Pkt) of
                <<>> ->
                    ok;
                Payload ->
                    maps:get(owner, Established) !
                        {stream_data, self(), Payload},
                    ok
            end,
            State2 = flush_out(Established),
            {noreply, maybe_send_close(State2)}
    end.

%% ingest_data — ordered delivery with duplicate suppression and a reorder
%% buffer. Returns whether any new bytes were consumed or staged.
-spec ingest_data(i2p_streaming:packet(), state()) -> {boolean(), state()}.
ingest_data(Pkt, State) ->
    Seq = i2p_streaming:seq_num(Pkt),
    IsPlainAck =
        Seq =:= 0 andalso
            not i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize()),
    Payload = i2p_streaming:payload(Pkt),
    Contig = maps:get(recv_contig, State),
    Reorder = maps:get(reorder, State),
    Seen = maps:is_key(Seq, Reorder),
    cond_ingest(IsPlainAck, Payload, Seq, Contig, Seen, Reorder, State).

cond_ingest(true, _Payload, _Seq, _Contig, _Seen, _Reorder, State) ->
    {false, State};
cond_ingest(_Plain, <<>>, _Seq, _Contig, _Seen, _Reorder, State) ->
    {false, State};
cond_ingest(_Plain, _Payload, Seq, Contig, _Seen, _Reorder, State) when
    Seq =< Contig
->
    %% Retransmit duplicate: ack fields were already processed.
    {false, State};
cond_ingest(_Plain, _Payload, _Seq, _Contig, true, _Reorder, State) ->
    {false, State};
cond_ingest(_Plain, Payload, Seq, Contig, false, Reorder, State) when
    Seq =:= Contig + 1
->
    %% Payload belongs to sequence Seq; anything already buffered at
    %% Seq+1, Seq+2, ... now becomes deliverable too.
    {InOrder, Reorder1} = drain_from(Seq + 1, Reorder, [Payload]),
    maps:get(owner, State) !
        {stream_data, self(), iolist_to_binary(InOrder)},
    {true, State#{
        recv_contig => Contig + length(InOrder),
        reorder => Reorder1
    }};
cond_ingest(_Plain, Payload, Seq, _Contig, false, Reorder, State) ->
    {true, State#{reorder => Reorder#{Seq => Payload}}}.

drain_from(Next, Reorder, Acc) ->
    case maps:take(Next, Reorder) of
        {Payload, Rest} -> drain_from(Next + 1, Rest, Acc ++ [Payload]);
        error -> {Acc, Reorder}
    end.

%% handle_control — CLOSE/RESET termination flags, applied after data.
-spec handle_control(i2p_streaming:packet(), state()) ->
    {noreply, state()} | {stop, normal, state()}.
handle_control(Pkt, State) ->
    Flags = i2p_streaming:flags(Pkt),
    ResetBit = i2p_streaming:flag_reset(),
    CloseBit = i2p_streaming:flag_close(),
    if
        Flags band ResetBit =/= 0 ->
            require_signed(Pkt, State),
            maps:get(owner, State) ! {stream_reset, self()},
            {stop, normal, State};
        Flags band CloseBit =/= 0 ->
            require_signed(Pkt, State),
            maps:get(owner, State) ! {stream_closed, self()},
            case maps:get(status, State) of
                closing ->
                    {stop, normal, State#{status => closed}};
                established ->
                    %% Answer the FIN so the peer sees a complete close.
                    CloseWire = i2p_streaming:signed(
                        control_packet(i2p_streaming:flag_close(), State),
                        maps:get(seed, State)
                    ),
                    transmit(CloseWire, State),
                    {stop, normal, State#{status => closed}}
            end;
        true ->
            {noreply, State}
    end.

%% send_plain_ack — cumulative acknowledgement with current gap NACKs.
-spec send_plain_ack(state()) -> state().
send_plain_ack(#{peer_id := PeerId} = State) ->
    P0 = i2p_streaming:new(
        PeerId,
        maps:get(my_id, State),
        0,
        maps:get(recv_contig, State)
    ),
    P =
        case current_gaps(State) of
            [] -> P0;
            Gaps -> i2p_streaming:with_nacks(P0, Gaps)
        end,
    transmit(i2p_streaming:encode(P), State),
    State.

current_gaps(#{recv_contig := Contig, reorder := Reorder}) ->
    MaxSeen = lists:max([Contig | maps:keys(Reorder)]),
    [S || S <- lists:seq(Contig + 1, MaxSeen), not maps:is_key(S, Reorder)].

%%%%%%% %%% Acknowledgement processing %%%%%%%

%% process_ack — retire cumulatively-acked packets (minus NACKs) and honour
%% double-NACK fast-retransmit requests. NACK counts accumulate across
%% packets in `nack_counts`; a sequence asked-for twice triggers an
%% immediate retransmit and a fresh count.
-spec process_ack(i2p_streaming:packet(), state()) -> state().
process_ack(Pkt, State) ->
    case i2p_streaming:has_flag(Pkt, i2p_streaming:flag_no_ack()) of
        true ->
            State;
        false ->
            AckThrough = i2p_streaming:ack_through(Pkt),
            Nacked = i2p_streaming:nacks(Pkt),
            #{inflight := Inflight} = State,
            Kept = maps:filter(
                fun(Seq, _) ->
                    Seq > AckThrough orelse lists:member(Seq, Nacked)
                end,
                Inflight
            ),
            Counts0 = maps:get(nack_counts, State),
            Counts1 = maps:filter(fun(Seq, _) -> Seq > AckThrough end, Counts0),
            Counts = lists:foldl(
                fun(S, M) -> M#{S => maps:get(S, M, 0) + 1} end,
                Counts1,
                Nacked
            ),
            fast_resend(Counts, State#{
                inflight => Kept,
                nack_counts => Counts
            })
    end.

fast_resend(Counts, #{inflight := Inflight} = State) ->
    Doubles = [
        S
     || {S, N} <- maps:to_list(Counts),
        N >= 2,
        maps:is_key(S, Inflight)
    ],
    lists:foldl(
        fun(Seq, Acc) ->
            case maps:get(Seq, maps:get(inflight, Acc), undefined) of
                undefined ->
                    Acc;
                Wire ->
                    transmit(Wire, Acc),
                    Acc#{
                        inflight =>
                            (maps:get(inflight, Acc))#{Seq => Wire},
                        nack_counts =>
                            (maps:get(nack_counts, Acc))#{Seq => 0}
                    }
            end
        end,
        State,
        Doubles
    ).

%% resend_tick — one retransmission round: resend everything unacked (or the
%% unanswered CLOSE), give up after too many silent rounds. Disarms itself
%% while nothing is outstanding.
-spec resend_tick(state()) -> state().
resend_tick(#{inflight := Inflight} = State) ->
    Idle = map_size(Inflight) =:= 0 andalso not maps:is_key(close_wire, State),
    case {Idle, maps:get(resend_armed, State)} of
        {true, _} ->
            State#{resend_round => 0, resend_armed => false};
        {false, false} ->
            State;
        {false, true} ->
            resend_round(State)
    end.

resend_round(#{inflight := Inflight, status := Status} = State) ->
    Round = maps:get(resend_round, State) + 1,
    case Round > ?MAX_RESEND_ROUNDS of
        true ->
            maps:get(owner, State) ! {stream_reset, self()},
            erlang:error(gave_up_after_resend_rounds);
        false ->
            [transmit(Wire, State) || Wire <- maps:values(Inflight)],
            case maps:get(close_wire, State, undefined) of
                undefined -> ok;
                CloseWire -> transmit(CloseWire, State)
            end,
            case Status of
                closed ->
                    State;
                _ ->
                    ensure_resend_timer(
                        State#{resend_round => Round, resend_armed => false}
                    )
            end
    end.

ensure_resend_timer(#{resend_armed := false} = State) ->
    erlang:send_after(?RESEND_MS, self(), resend_tick),
    State#{resend_armed => true};
ensure_resend_timer(State) ->
    State.

%%%%%%% %%% Outbound %%%%%%%

%% flush_out — chunk the buffer to the negotiated MTU while the window has
%% room; each transmitted chunk joins the inflight set under a resend timer.
-spec flush_out(state()) -> state().
flush_out(#{inflight := Inflight, window := Window} = State) when
    map_size(Inflight) >= Window
->
    maybe_send_close(State);
flush_out(#{out_buf := <<>>} = State) ->
    maybe_send_close(State);
flush_out(#{out_buf := Buf, mtu := MTU} = State) ->
    Size = min(MTU, byte_size(Buf)),
    <<Chunk:Size/binary, Rest/binary>> = Buf,
    Seq = maps:get(send_seq, State),
    Pkt = data_packet(Seq, Chunk, State),
    Wire = i2p_streaming:encode(Pkt),
    transmit(Wire, State),
    State1 = State#{
        out_buf => Rest,
        send_seq => Seq + 1,
        inflight => (maps:get(inflight, State))#{Seq => Wire}
    },
    flush_out(ensure_resend_timer(State1)).

%% maybe_send_close — once asked to close and everything flushed, emit the
%% signed CLOSE and await the peer's.
-spec maybe_send_close(state()) -> state().
maybe_send_close(
    #{
        close_requested := true,
        out_buf := <<>>,
        status := established
    } = State
) ->
    CloseWire = i2p_streaming:signed(
        control_packet(i2p_streaming:flag_close(), State),
        maps:get(seed, State)
    ),
    transmit(CloseWire, State),
    ensure_resend_timer(
        State#{status => closing, close_wire => CloseWire}
    );
maybe_send_close(State) ->
    State.

%%%%%%% %%% Packet builders %%%%%%%

-spec negotiate_outbound_mtu(i2p_streaming:packet(), state()) -> state().
negotiate_outbound_mtu(Pkt, #{mtu := LocalMTU} = State) ->
    State#{mtu => min(LocalMTU, normalized_peer_mtu(Pkt))}.

normalized_peer_mtu(Pkt) ->
    normalize_peer_mtu(i2p_streaming:max_packet_size(Pkt)).

normalize_peer_mtu(undefined) ->
    ?DEFAULT_MTU;
normalize_peer_mtu(PeerMTU) when is_integer(PeerMTU), PeerMTU > 0 ->
    max(PeerMTU, ?MIN_PEER_MTU);
normalize_peer_mtu(_PeerMTU) ->
    exit({protocol_error, invalid_max_packet_size}).

base_state(Opts) ->
    Base = #{
        owner => maps:get(owner, Opts),
        send_fn => maps:get(send_fn, Opts),
        seed => maps:get(local_seed, Opts),
        dest_bin => maps:get(local_dest_bin, Opts),
        dest_hash => maps:get(local_dest_hash, Opts),
        my_id => rand_stream_id(),
        mtu => maps:get(mtu, Opts, ?DEFAULT_MTU),
        window => maps:get(window, Opts, ?DEFAULT_WINDOW),
        status => connecting,
        send_seq => 0,
        inflight => #{},
        out_buf => <<>>,
        resend_round => 0,
        resend_armed => false,
        close_requested => false,
        recv_contig => -1,
        reorder => #{},
        nack_counts => #{}
    },
    %% The dialed peer identity exists only on the connect role; accept
    %% learns it from the SYN's FROM option.
    case maps:find(remote_dest_hash, Opts) of
        {ok, RemoteHash} ->
            Base#{
                remote_dest_bin => maps:get(remote_dest_bin, Opts),
                remote_dest_hash => RemoteHash
            };
        error ->
            Base
    end.

rand_stream_id() ->
    <<ID:32>> = crypto:strong_rand_bytes(4),
    expect_nonzero(ID).

syn_packet(S) ->
    P0 = i2p_streaming:new(0, maps:get(my_id, S), 0, 0),
    Flags =
        i2p_streaming:flag_synchronize() bor
            i2p_streaming:flag_from_included() bor
            i2p_streaming:flag_max_packet_size_included() bor
            i2p_streaming:flag_no_ack(),
    P1 = i2p_streaming:with_flags(P0, Flags),
    %% Replay prevention binds the SYN to the RECIPIENT's destination hash.
    P2 = i2p_streaming:with_from(P1, maps:get(dest_bin, S)),
    P3 = i2p_streaming:with_max_packet_size(P2, maps:get(mtu, S)),
    i2p_streaming:with_nacks(
        P3,
        i2p_streaming:syn_replay_nacks(maps:get(remote_dest_hash, S))
    ).

syn_ack_packet(S) ->
    %% Our outgoing sendStreamId field carries the PEER's ID (which arrived
    %% in their SYN's receiveStreamId); receiveStreamId is ours.
    P0 = i2p_streaming:new(maps:get(peer_id, S), maps:get(my_id, S), 0, 0),
    Flags =
        i2p_streaming:flag_synchronize() bor
            i2p_streaming:flag_from_included() bor
            i2p_streaming:flag_max_packet_size_included(),
    P1 = i2p_streaming:with_flags(P0, Flags),
    P2 = i2p_streaming:with_from(P1, maps:get(dest_bin, S)),
    i2p_streaming:with_max_packet_size(P2, maps:get(mtu, S)).

data_packet(Seq, Chunk, State) ->
    P0 = i2p_streaming:new(
        maps:get(peer_id, State),
        maps:get(my_id, State),
        Seq,
        maps:get(recv_contig, State)
    ),
    P1 = i2p_streaming:with_resend_delay(P0, ?RESEND_MS div 1000),
    P2 = i2p_streaming:with_payload(P1, Chunk),
    case current_gaps(State) of
        [] -> P2;
        Gaps -> i2p_streaming:with_nacks(P2, Gaps)
    end.

control_packet(FlagBit, State) ->
    P0 = i2p_streaming:new(
        maps:get(peer_id, State),
        maps:get(my_id, State),
        0,
        maps:get(recv_contig, State)
    ),
    i2p_streaming:with_flags(P0, FlagBit).

%%%%%%% %%% Verification %%%%%%%

%% verify_syn — accept-role handshake validation: the SYN must carry the
%% replay-prevention hash bound to this destination and a signature from the
%% FROM identity. Raises protocol_error on any mismatch.
-spec verify_syn(i2p_streaming:packet(), state()) -> {ok, state()}.
verify_syn(Pkt, S) ->
    ok = expect(
        i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize()),
        syn_without_synchronize
    ),
    case i2p_streaming:replay_hash(Pkt) of
        {ok, Hash} ->
            ok = expect(Hash, maps:get(dest_hash, S), replay_hash_mismatch);
        error ->
            exit({protocol_error, syn_missing_replay_hash})
    end,
    {ok, S1} = verify_signature_and_from(Pkt, S),
    PeerId = expect_nonzero(i2p_streaming:recv_id(Pkt)),
    {ok, S1#{peer_id => PeerId}}.

%% verify_signature_and_from — parse the FROM destination, verify the
%% packet signature under its Ed25519 key; on the connect role the FROM must
%% equal the dialed destination.
verify_signature_and_from(Pkt, S) ->
    FromBin =
        case i2p_streaming:from(Pkt) of
            undefined -> exit({protocol_error, missing_from_option});
            F -> F
        end,
    Id = expect_ok(i2p_keys:parse(FromBin), unparsable_destination),
    Pub = i2p_keys:signing_key(Id),
    Hash = i2p_keys:hash(Id),
    ok = expect(i2p_streaming:verify(Pkt, Pub), invalid_packet_signature),
    case maps:find(remote_dest_hash, S) of
        {ok, ExpectedHash} ->
            ok = expect(Hash, ExpectedHash, peer_identity_mismatch);
        error ->
            ok
    end,
    {ok, S#{peer_pub => Pub, peer_hash => Hash}}.

require_signed(Pkt, S) ->
    ok = expect(
        i2p_streaming:has_flag(Pkt, i2p_streaming:flag_signature_included()) andalso
            i2p_streaming:verify(Pkt, maps:get(peer_pub, S)),
        unsigned_or_invalid_control_packet
    ).

%%%%%%% %%% Internal %%%%%%%

transmit(Wire, #{send_fn := Fn} = _S) ->
    Fn(Wire),
    ok.

expect(Value, Value, _Reason) -> ok;
expect(_Got, _Want, Reason) -> exit({protocol_error, Reason}).

expect(true, _Reason) -> ok;
expect(false, Reason) -> exit({protocol_error, Reason}).

expect_nonzero(0) -> exit({protocol_error, zero_stream_id});
expect_nonzero(ID) -> ID.

expect_ok({ok, V}, _Reason) -> V;
expect_ok({error, Why}, Reason) -> exit({protocol_error, {Reason, Why}}).
