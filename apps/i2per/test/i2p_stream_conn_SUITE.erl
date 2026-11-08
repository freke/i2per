%% Streaming connection state-machine tests. Two live `i2p_stream_conn`
%% processes are wired through a controllable wire that can deliver, drop,
%% duplicate, or reorder packets. The cases cover the SYN/SYN-ACK handshake,
%% stream-ID direction and replay-hash binding, ordered data across MTU chunks
%% and window refills, out-of-order reassembly, NACK-driven retransmission,
%% duplicate-SYN healing, CLOSE, and SYN authentication failures.
%%
%% Each case owns its processes and timers. Frame collection stops after a
%% bounded quiet window, and event waits use deadlines rather than fixed
%% sleeps.

-module(i2p_stream_conn_SUITE).

-include_lib("eunit/include/eunit.hrl").

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    handshake_and_bidirectional_data/1,
    peer_max_packet_size_limits_outbound_mtu/1,
    missing_peer_max_packet_size_uses_java_default/1,
    low_peer_max_packet_size_is_clamped/1,
    zero_peer_max_packet_size_is_rejected/1,
    missing_syn_max_packet_size_uses_java_default/1,
    low_syn_max_packet_size_is_clamped/1,
    zero_syn_max_packet_size_is_rejected/1,
    chunked_transfer_across_window/1,
    out_of_order_reassembly/1,
    loss_fast_retransmit/1,
    duplicate_syn_gets_reanswered/1,
    close_handshake_notifies_both_owners/1,
    malformed_packet_kills_connection/1,
    unsigned_close_is_refused/1,
    wrong_replay_hash_syn_refused/1,
    tampered_syn_refused/1,
    owner_death_stops_connection/1
]).

-define(TIMEOUT, 10000).
%% Load-safe quiet window: how long `collect_data/1` observes no further
%% packet before deciding a burst has ended. Never a point-in-time sleep.
-define(QUIET_MS, 50).

suite() ->
    [].

all() ->
    [
        handshake_and_bidirectional_data,
        peer_max_packet_size_limits_outbound_mtu,
        missing_peer_max_packet_size_uses_java_default,
        low_peer_max_packet_size_is_clamped,
        zero_peer_max_packet_size_is_rejected,
        missing_syn_max_packet_size_uses_java_default,
        low_syn_max_packet_size_is_clamped,
        zero_syn_max_packet_size_is_rejected,
        chunked_transfer_across_window,
        out_of_order_reassembly,
        loss_fast_retransmit,
        duplicate_syn_gets_reanswered,
        close_handshake_notifies_both_owners,
        malformed_packet_kills_connection,
        unsigned_close_is_refused,
        wrong_replay_hash_syn_refused,
        tampered_syn_refused,
        owner_death_stops_connection
    ].

init_per_testcase(_Case, Config) ->
    %% The conns are linked to the case process; trap exits so `await_exit/1`
    %% can observe a conn that crashes or closes.
    process_flag(trap_exit, true),
    put(stream_conn_pids, []),
    [{timetrap, ?TIMEOUT} | Config].

end_per_testcase(_Case, _Config) ->
    %% Reap any conns a scenario left running, so no resend_tick timer or
    %% mailbox outlives the case. Scenarios that already close or crash their
    %% conns find the list empty or already-exited here.
    lists:foreach(fun(P) -> try_exit(P) end, get(stream_conn_pids)).

try_exit(Pid) ->
    MRef = erlang:monitor(process, Pid),
    case is_process_alive(Pid) of
        true ->
            exit(Pid, kill),
            receive
                {'DOWN', MRef, process, Pid, _} -> ok
            after 1000 ->
                ok
            end;
        false ->
            ok
    end.

track(Pid) ->
    put(stream_conn_pids, [Pid | get(stream_conn_pids)]),
    Pid.

%% ---------------------------------------------------------------------------
%% Harness
%% ---------------------------------------------------------------------------

make_dest() ->
    #{identity := Id, sign_priv := Seed} = i2p_keys:generate_with_privkeys(),
    #{
        dest_bin => i2p_keys:to_binary(Id),
        dest_hash => i2p_keys:hash(Id),
        seed => Seed
    }.

%% pair/1 and pair/2 open a connected A->B pair; every outgoing packet of
%% side a/b lands in the test mailbox as {wire, TagA|TagB, Bin} under unique tags.
pair(ExtraA) ->
    pair(ExtraA, #{}).

pair(ExtraA, ExtraB) ->
    A = make_dest(),
    B = make_dest(),
    Self = self(),
    TagA = {wire, erlang:unique_integer()},
    TagB = {wire, erlang:unique_integer()},
    {ok, ConnA} = i2p_stream_conn:start_link(
        maps:merge(
            #{
                role => connect,
                owner => Self,
                send_fn => fun(Bin) -> Self ! {TagA, Bin} end,
                local_seed => maps:get(seed, A),
                local_dest_bin => maps:get(dest_bin, A),
                local_dest_hash => maps:get(dest_hash, A),
                remote_dest_bin => maps:get(dest_bin, B),
                remote_dest_hash => maps:get(dest_hash, B)
            },
            ExtraA
        )
    ),
    track(ConnA),
    %% The connect role emits its SYN synchronously during init, so the frame
    %% is already in the mailbox; no settle needed to reach it.
    [SynAB] = await_frames(TagA, 1),
    {ok, SynPkt} = i2p_streaming:decode(SynAB),
    {ok, ConnB} = i2p_stream_conn:start_link(
        maps:merge(
            #{
                role => accept,
                syn => SynPkt,
                owner => Self,
                send_fn => fun(Bin) -> Self ! {TagB, Bin} end,
                local_seed => maps:get(seed, B),
                local_dest_bin => maps:get(dest_bin, B),
                local_dest_hash => maps:get(dest_hash, B)
            },
            ExtraB
        )
    ),
    track(ConnB),
    %% Accept-side SYN-ACK and stream_established are both emitted during
    %% init. Await the SYN-ACK wire frame first: await_frames's selective
    %% receive leaves the control message queued, so neither wait consumes
    %% the other's message.
    SynAcks = await_frames(TagB, 1),
    {ConnB, HashA} = await_established(ConnB),
    ?assertEqual(maps:get(dest_hash, A), HashA),
    deliver(ConnA, SynAcks),
    {ConnA, HashB} = await_established(ConnA),
    ?assertEqual(maps:get(dest_hash, B), HashB),
    %% Discard any leftover on A's wire (a resend would only appear after
    %% ~1s, far beyond this proto's lifetime).
    _ = drain(TagA),
    #{
        a => ConnA,
        b => ConnB,
        ta => TagA,
        tb => TagB,
        a_dest => A,
        b_dest => B,
        syn_wire => SynAB
    }.

modified_syn_ack_pair(ExtraA, Modify) ->
    A = make_dest(),
    B = make_dest(),
    Self = self(),
    TagA = {wire, erlang:unique_integer()},
    TagB = {wire, erlang:unique_integer()},
    ConnAOpts = maps:merge(
        #{
            role => connect,
            owner => Self,
            send_fn => fun(Bin) -> Self ! {TagA, Bin} end,
            local_seed => maps:get(seed, A),
            local_dest_bin => maps:get(dest_bin, A),
            local_dest_hash => maps:get(dest_hash, A),
            remote_dest_bin => maps:get(dest_bin, B),
            remote_dest_hash => maps:get(dest_hash, B)
        },
        ExtraA
    ),
    {ok, ConnA} = i2p_stream_conn:start_link(ConnAOpts),
    track(ConnA),
    [SynAB] = await_frames(TagA, 1),
    {ok, SynPkt} = i2p_streaming:decode(SynAB),
    {ok, ConnB} = i2p_stream_conn:start_link(#{
        role => accept,
        syn => SynPkt,
        owner => Self,
        send_fn => fun(Bin) -> Self ! {TagB, Bin} end,
        local_seed => maps:get(seed, B),
        local_dest_bin => maps:get(dest_bin, B),
        local_dest_hash => maps:get(dest_hash, B)
    }),
    track(ConnB),
    [SynAckWire] = await_frames(TagB, 1),
    {ok, SynAckPkt} = i2p_streaming:decode(SynAckWire),
    ModifiedWire = i2p_streaming:signed(Modify(SynAckPkt), maps:get(seed, B)),
    {ConnA, ConnB, ModifiedWire, TagA}.

%% Build an accept-role pair whose initial SYN is modified and re-signed
%% before ConnB verifies it. The responder's SYN-ACK is consumed here so its
%% tag contains only application frames after the helper returns.
modified_syn_pair(ExtraA, ExtraB, Modify) ->
    A = make_dest(),
    B = make_dest(),
    Self = self(),
    TagA = {wire, erlang:unique_integer()},
    TagB = {wire, erlang:unique_integer()},
    ConnAOpts = maps:merge(
        #{
            role => connect,
            owner => Self,
            send_fn => fun(Bin) -> Self ! {TagA, Bin} end,
            local_seed => maps:get(seed, A),
            local_dest_bin => maps:get(dest_bin, A),
            local_dest_hash => maps:get(dest_hash, A),
            remote_dest_bin => maps:get(dest_bin, B),
            remote_dest_hash => maps:get(dest_hash, B)
        },
        ExtraA
    ),
    {ok, ConnA} = i2p_stream_conn:start_link(ConnAOpts),
    track(ConnA),
    [SynWire] = await_frames(TagA, 1),
    {ok, SynPkt} = i2p_streaming:decode(SynWire),
    ModifiedSynWire = i2p_streaming:signed(Modify(SynPkt), maps:get(seed, A)),
    {ok, ModifiedSyn} = i2p_streaming:decode(ModifiedSynWire),
    ConnBOpts = maps:merge(
        #{
            role => accept,
            syn => ModifiedSyn,
            owner => Self,
            send_fn => fun(Bin) -> Self ! {TagB, Bin} end,
            local_seed => maps:get(seed, B),
            local_dest_bin => maps:get(dest_bin, B),
            local_dest_hash => maps:get(dest_hash, B)
        },
        ExtraB
    ),
    case i2p_stream_conn:start_link(ConnBOpts) of
        {ok, ConnB} ->
            track(ConnB),
            [_SynAckWire] = await_frames(TagB, 1),
            {ConnB, _} = await_established(ConnB),
            {ok, ConnB, TagB};
        Error ->
            Error
    end.

remove_max_packet_size(Pkt) ->
    Flags =
        i2p_streaming:flags(Pkt) band
            bnot i2p_streaming:flag_max_packet_size_included(),
    maps:remove(max_packet_size, Pkt#{flags => Flags}).

%% Grab anything already queued for Tag (never blocks).
drain(Tag) -> drain(Tag, []).

drain(Tag, Acc) ->
    receive
        {Tag, Bin} -> drain(Tag, [Bin | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.

%% Await exactly N frames for Tag, then drain any stragglers, so the caller
%% can both assert the count and consume the full burst. Event-driven: waits
%% on the frames themselves; the deadline is a hang guard, not a sleep.
await_frames(Tag, N) ->
    case await_frames_acc(Tag, N, []) of
        {ok, Acc} -> lists:reverse(Acc) ++ drain(Tag);
        timeout -> error({await_frames_timeout, Tag, N})
    end.

await_frames_acc(_Tag, 0, Acc) ->
    {ok, Acc};
await_frames_acc(Tag, N, Acc) ->
    receive
        {Tag, Bin} -> await_frames_acc(Tag, N - 1, [Bin | Acc])
    after ?TIMEOUT ->
        timeout
    end.

deliver(_To, []) ->
    ok;
deliver(To, [Wire | Rest]) ->
    i2p_stream_conn:handle_packet(To, Wire),
    deliver(To, Rest).

await_established(Conn) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({stream_established, P, Hash}) when P =:= Conn -> {true, {P, Hash}};
            (_) -> false
        end,
        ?TIMEOUT
    ).

collect_data(Conn) -> collect_data(Conn, <<>>).

collect_data(Conn, Acc) ->
    receive
        {stream_data, Conn, Bytes} ->
            collect_data(Conn, <<Acc/binary, Bytes/binary>>)
    after ?QUIET_MS ->
        Acc
    end.

await_closed(Conn) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({stream_closed, P}) when P =:= Conn -> {true, Conn};
            (_) -> false
        end,
        ?TIMEOUT
    ).

await_exit(Pid) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({'EXIT', P, Reason}) when P =:= Pid -> {true, Reason};
            (_) -> false
        end,
        ?TIMEOUT
    ).

%% ---------------------------------------------------------------------------
%% Handshake and data
%% ---------------------------------------------------------------------------

handshake_and_bidirectional_data(_Config) ->
    S = pair(#{}),
    ConnA = maps:get(a, S),
    ConnB = maps:get(b, S),
    i2p_stream_conn:send(ConnA, <<"hello from A">>),
    deliver(ConnB, await_frames(maps:get(ta, S), 1)),
    ?assertEqual(<<"hello from A">>, collect_data(ConnB)),
    %% Receiving A's data made B ack it back on its wire; drop that stale ack
    %% so the B->A data frame is the next one we collect.
    _ = drain(maps:get(tb, S)),
    i2p_stream_conn:send(ConnB, <<"hi A, this is B">>),
    deliver(ConnA, await_frames(maps:get(tb, S), 1)),
    ?assertEqual(<<"hi A, this is B">>, collect_data(ConnA)).

peer_max_packet_size_limits_outbound_mtu(_Config) ->
    PeerMTU = 600,
    S = pair(#{mtu => 1024}, #{mtu => PeerMTU}),
    ConnA = maps:get(a, S),
    TagA = maps:get(ta, S),

    i2p_stream_conn:send(ConnA, crypto:strong_rand_bytes(700)),
    [FirstWire, LastWire] = await_frames(TagA, 2),
    {ok, FirstPacket} = i2p_streaming:decode(FirstWire),
    ?assertEqual(PeerMTU, byte_size(i2p_streaming:payload(FirstPacket))),
    {ok, LastPacket} = i2p_streaming:decode(LastWire),
    ?assertEqual(100, byte_size(i2p_streaming:payload(LastPacket))).

missing_peer_max_packet_size_uses_java_default(_Config) ->
    {ConnA, _ConnB, SynAckWire, TagA} = modified_syn_ack_pair(
        #{mtu => 2000}, fun remove_max_packet_size/1
    ),
    i2p_stream_conn:handle_packet(ConnA, SynAckWire),
    {ConnA, _} = await_established(ConnA),
    _ = drain(TagA),
    i2p_stream_conn:send(ConnA, crypto:strong_rand_bytes(1800)),
    [FirstWire, LastWire] = await_frames(TagA, 2),
    {ok, FirstPacket} = i2p_streaming:decode(FirstWire),
    ?assertEqual(1730, byte_size(i2p_streaming:payload(FirstPacket))),
    {ok, LastPacket} = i2p_streaming:decode(LastWire),
    ?assertEqual(70, byte_size(i2p_streaming:payload(LastPacket))).

low_peer_max_packet_size_is_clamped(_Config) ->
    {ConnA, _ConnB, SynAckWire, TagA} = modified_syn_ack_pair(
        #{mtu => 1024},
        fun(Pkt) -> Pkt#{max_packet_size => 32} end
    ),
    i2p_stream_conn:handle_packet(ConnA, SynAckWire),
    {ConnA, _} = await_established(ConnA),
    _ = drain(TagA),
    i2p_stream_conn:send(ConnA, crypto:strong_rand_bytes(600)),
    [FirstWire, LastWire] = await_frames(TagA, 2),
    {ok, FirstPacket} = i2p_streaming:decode(FirstWire),
    ?assertEqual(512, byte_size(i2p_streaming:payload(FirstPacket))),
    {ok, LastPacket} = i2p_streaming:decode(LastWire),
    ?assertEqual(88, byte_size(i2p_streaming:payload(LastPacket))).

zero_peer_max_packet_size_is_rejected(_Config) ->
    {ConnA, _ConnB, SynAckWire, _TagA} = modified_syn_ack_pair(#{}, fun(Pkt) ->
        Pkt#{max_packet_size => 0}
    end),
    i2p_stream_conn:handle_packet(ConnA, SynAckWire),
    {protocol_error, invalid_max_packet_size} = await_exit(ConnA).

missing_syn_max_packet_size_uses_java_default(_Config) ->
    {ok, ConnB, TagB} = modified_syn_pair(
        #{mtu => 2000}, #{mtu => 2000}, fun remove_max_packet_size/1
    ),
    i2p_stream_conn:send(ConnB, crypto:strong_rand_bytes(1800)),
    [FirstWire, LastWire] = await_frames(TagB, 2),
    {ok, FirstPacket} = i2p_streaming:decode(FirstWire),
    ?assertEqual(1730, byte_size(i2p_streaming:payload(FirstPacket))),
    {ok, LastPacket} = i2p_streaming:decode(LastWire),
    ?assertEqual(70, byte_size(i2p_streaming:payload(LastPacket))).

low_syn_max_packet_size_is_clamped(_Config) ->
    {ok, ConnB, TagB} = modified_syn_pair(
        #{},
        #{mtu => 1024},
        fun(Pkt) -> Pkt#{max_packet_size => 32} end
    ),
    i2p_stream_conn:send(ConnB, crypto:strong_rand_bytes(600)),
    [FirstWire, LastWire] = await_frames(TagB, 2),
    {ok, FirstPacket} = i2p_streaming:decode(FirstWire),
    ?assertEqual(512, byte_size(i2p_streaming:payload(FirstPacket))),
    {ok, LastPacket} = i2p_streaming:decode(LastWire),
    ?assertEqual(88, byte_size(i2p_streaming:payload(LastPacket))).

zero_syn_max_packet_size_is_rejected(_Config) ->
    {error, {protocol_error, invalid_max_packet_size}} = modified_syn_pair(
        #{}, #{}, fun(Pkt) -> Pkt#{max_packet_size => 0} end
    ).

chunked_transfer_across_window(_Config) ->
    Payload = crypto:strong_rand_bytes(300),
    S = pair(#{mtu => 64, window => 4}),
    ConnA = maps:get(a, S),
    ConnB = maps:get(b, S),
    i2p_stream_conn:send(ConnA, Payload),
    %% Window holds only 4 chunks at first; acks flowing back refill it.
    pump(S, 7000),
    ?assertEqual(Payload, collect_data(ConnB)).

out_of_order_reassembly(_Config) ->
    Payload = crypto:strong_rand_bytes(180),
    S = pair(#{mtu => 60}),
    ConnB = maps:get(b, S),
    i2p_stream_conn:send(maps:get(a, S), Payload),
    Chunks = await_frames(maps:get(ta, S), 3),
    ?assertEqual(3, length(Chunks)),
    %% Deliver last chunk first: it must wait in the reorder buffer.
    Reordered =
        [lists:last(Chunks) | lists:sublist(Chunks, length(Chunks) - 1)],
    deliver(ConnB, Reordered),
    ?assertEqual(Payload, collect_data(ConnB)).

loss_fast_retransmit(_Config) ->
    Payload = crypto:strong_rand_bytes(120),
    S = pair(#{mtu => 40}),
    ConnA = maps:get(a, S),
    ConnB = maps:get(b, S),
    i2p_stream_conn:send(ConnA, Payload),
    [_Lost, Second, Third] = await_frames(maps:get(ta, S), 3),
    %% Lose the first chunk entirely; the two later arrivals each carry a NACK
    %% for sequence 1, and the second triggers fast retransmit.
    deliver(ConnB, [Second, Third]),
    %% Return B's acknowledgement traffic to A so the double-NACK lands.
    deliver(ConnA, await_frames(maps:get(tb, S), 1)),
    Resent = await_frames(maps:get(ta, S), 1),
    ?assertNotEqual([], Resent),
    deliver(ConnB, Resent),
    ?assertEqual(Payload, collect_data(ConnB)).

duplicate_syn_gets_reanswered(_Config) ->
    S = pair(#{}),
    ConnB = maps:get(b, S),
    i2p_stream_conn:handle_packet(ConnB, maps:get(syn_wire, S)),
    ?assertNotEqual([], await_frames(maps:get(tb, S), 1)).

%% ---------------------------------------------------------------------------
%% Close, reset and authentication
%% ---------------------------------------------------------------------------

close_handshake_notifies_both_owners(_Config) ->
    S = pair(#{}),
    ConnA = maps:get(a, S),
    ConnB = maps:get(b, S),
    ok = i2p_stream_conn:close(ConnA),
    Closes1 = await_frames(maps:get(ta, S), 1),
    ?assertNotEqual([], Closes1),
    deliver(ConnB, Closes1),
    %% B emits, in order: stream_closed, its CloseWire, then exits. Collect
    %% each before the next wait so no draining waiter consumes a sibling.
    ?assertEqual(ConnB, await_closed(ConnB)),
    BClose = await_frames(maps:get(tb, S), 1),
    normal = await_exit(ConnB),
    deliver(ConnA, BClose),
    ?assertEqual(ConnA, await_closed(ConnA)),
    normal = await_exit(ConnA).

malformed_packet_kills_connection(_Config) ->
    S = pair(#{}),
    ConnA = maps:get(a, S),
    i2p_stream_conn:handle_packet(ConnA, <<1, 2, 3>>),
    {protocol_error, {malformed_packet, truncated_header}} = await_exit(ConnA).

unsigned_close_is_refused(_Config) ->
    S = pair(#{}),
    ConnA = maps:get(a, S),
    ConnB = maps:get(b, S),
    %% Send a genuine signed CLOSE from A, then rebuild its wire form without
    %% SIGNATURE_INCLUDED: B must refuse the forged control packet.
    ok = i2p_stream_conn:close(ConnA),
    [CloseWire | _] = await_frames(maps:get(ta, S), 1),
    {ok, Pkt} = i2p_streaming:decode(CloseWire),
    Forged = i2p_streaming:encode(Pkt#{
        flags => i2p_streaming:flag_close()
    }),
    i2p_stream_conn:handle_packet(ConnB, Forged),
    {protocol_error, unsigned_or_invalid_control_packet} = await_exit(ConnB).

wrong_replay_hash_syn_refused(_Config) ->
    A = make_dest(),
    B = make_dest(),
    Self = self(),
    OtherHash = crypto:strong_rand_bytes(32),
    {ok, _ConnA} = i2p_stream_conn:start_link(#{
        role => connect,
        owner => Self,
        send_fn => fun(_) -> ok end,
        local_seed => maps:get(seed, A),
        local_dest_bin => maps:get(dest_bin, A),
        local_dest_hash => maps:get(dest_hash, A),
        remote_dest_bin => maps:get(dest_bin, B),
        remote_dest_hash => maps:get(dest_hash, B)
    }),
    {error, {protocol_error, replay_hash_mismatch}} =
        refused_syn(A, B, OtherHash, Self).

tampered_syn_refused(_Config) ->
    A = make_dest(),
    B = make_dest(),
    Self = self(),
    Tag = {syn_wire_tamper},
    {ok, ConnA} = i2p_stream_conn:start_link(#{
        role => connect,
        owner => Self,
        send_fn => fun(Bin) -> Self ! {Tag, Bin} end,
        local_seed => maps:get(seed, A),
        local_dest_bin => maps:get(dest_bin, A),
        local_dest_hash => maps:get(dest_hash, A),
        remote_dest_bin => maps:get(dest_bin, B),
        remote_dest_hash => maps:get(dest_hash, B)
    }),
    track(ConnA),
    [SynAB] = await_frames(Tag, 1),
    %% Flip a byte inside the FROM option region (22-byte header + 32-byte
    %% replay hash => FROM starts at offset 54).
    <<Pre:60/binary, Byte, Post/binary>> = SynAB,
    Tampered = <<Pre/binary, (Byte bxor 16#FF), Post/binary>>,
    {ok, TamperedPkt} = i2p_streaming:decode(Tampered),
    {error, {protocol_error, invalid_packet_signature}} =
        i2p_stream_conn:start_link(#{
            role => accept,
            syn => TamperedPkt,
            owner => Self,
            send_fn => fun(_) -> ok end,
            local_seed => maps:get(seed, B),
            local_dest_bin => maps:get(dest_bin, B),
            local_dest_hash => maps:get(dest_hash, B)
        }).

%% A connection whose owner has died has nobody to deliver to, so it stops
%% instead of holding a stream and its timers alive.
owner_death_stops_connection(_Config) ->
    A = make_dest(),
    B = make_dest(),
    Owner = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    {ok, Conn} = i2p_stream_conn:start_link(#{
        role => connect,
        owner => Owner,
        send_fn => fun(_) -> ok end,
        local_seed => maps:get(seed, A),
        local_dest_bin => maps:get(dest_bin, A),
        local_dest_hash => maps:get(dest_hash, A),
        remote_dest_bin => maps:get(dest_bin, B),
        remote_dest_hash => maps:get(dest_hash, B)
    }),
    track(Conn),
    ?assert(is_process_alive(Conn)),
    MRef = erlang:monitor(process, Conn),
    exit(Owner, kill),
    receive
        {'DOWN', MRef, process, Conn, _} -> ok
    after ?TIMEOUT -> ?assert(false)
    end.

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

refused_syn(A, B, ReplayHash, Self) ->
    Tag = {syn_wire_refused},
    {ok, ConnA} = i2p_stream_conn:start_link(#{
        role => connect,
        owner => Self,
        send_fn => fun(Bin) -> Self ! {Tag, Bin} end,
        local_seed => maps:get(seed, A),
        local_dest_bin => maps:get(dest_bin, A),
        local_dest_hash => maps:get(dest_hash, A),
        remote_dest_bin => maps:get(dest_bin, B),
        remote_dest_hash => maps:get(dest_hash, B)
    }),
    track(ConnA),
    [SynAB] = await_frames(Tag, 1),
    {ok, SynPkt} = i2p_streaming:decode(SynAB),
    %% Re-sign the SYN so the signature is valid but bound to a different
    %% destination hash than B's: the replay check must refuse it.
    Resigned = i2p_streaming:signed(
        SynPkt#{nacks => i2p_streaming:syn_replay_nacks(ReplayHash)},
        maps:get(seed, A)
    ),
    {ok, ResignedPkt} = i2p_streaming:decode(Resigned),
    i2p_stream_conn:start_link(#{
        role => accept,
        syn => ResignedPkt,
        owner => Self,
        send_fn => fun(_) -> ok end,
        local_seed => maps:get(seed, B),
        local_dest_bin => maps:get(dest_bin, B),
        local_dest_hash => maps:get(dest_hash, B)
    }).

%% pump/2 alternates deliveries in both directions until both wires have
%% stayed quiet for several consecutive cadence samples or a wall-clock
%% deadline passes. The quiet detect samples on a short 25ms cadence bounded
%% by the deadline — the same convention as `i2p_ct_helpers:await/2` — never a
%% fixed-total blind sleep. Each settle lets an asynchronous `cast`/ack
%% round-trip through the peer's gen_server mailbox before the next drain.
pump(S, TimeoutMs) ->
    pump(S, erlang:monotonic_time(millisecond) + TimeoutMs, 0).

pump(_S, _Deadline, Quiet) when Quiet >= 4 ->
    ok;
pump(S, Deadline, Quiet) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            ok;
        false ->
            WA = drain(maps:get(ta, S)),
            WB = drain(maps:get(tb, S)),
            case WA =:= [] andalso WB =:= [] of
                false ->
                    deliver(maps:get(b, S), WA),
                    deliver(maps:get(a, S), WB),
                    pump(S, Deadline, 0);
                true ->
                    Settle =
                        erlang:min(
                            25,
                            erlang:max(
                                0,
                                Deadline - erlang:monotonic_time(millisecond)
                            )
                        ),
                    receive
                    after Settle -> ok
                    end,
                    pump(S, Deadline, Quiet + 1)
            end
    end.
