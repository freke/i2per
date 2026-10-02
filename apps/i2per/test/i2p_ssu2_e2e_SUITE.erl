%% SSU2 end-to-end session and data-path tests. Each case owns its process,
%% mailbox, application lifecycle, and network fixtures. Every wait drains
%% non-matching messages through `i2p_ct_helpers`.
%%
%% The suite covers session establishment, bidirectional I2NP delivery,
%% keepalive and idle handling, fragmentation, and malformed-datagram
%% tolerance. Deterministic handshake-recovery cases live in
%% `i2p_ssu2_handshake_SUITE`; they inject delayed and lost SessionCreated
%% replies and verify the public connection result without a test-level retry.

-module(i2p_ssu2_e2e_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    full_handshake_and_data/1,
    transport_bytes_are_counted/1,
    keepalive_roundtrip/1,
    idle_reaps_silent_session/1,
    large_fragmented_message_reassembled/1,
    garbage_datagram_survives/1,
    receive_window_does_not_grow_with_traffic/1
]).

-define(APP, i2per).
-define(DATA_WINDOW, 15000).
-define(RELAY_WINDOW, 20000).
%% The session's ACK range budget, which is also the bound on its receive
%% window. Mirrored rather than read from `i2p_ssu2_conn` so that the assertion
%% is against the documented bound rather than against whatever the module
%% under test currently believes. See #7GP4A4K.
-define(MAX_ACK_RANGES, 20).
%% The deepest packet number an ACK block can name: `acnt` carries at most 255
%% consecutive, and each of the range pairs two more bytes of at most 255. This
%% is the format's arithmetic, not a measured figure, and it is what the receive
%% window is allowed to retain.
-define(ACK_REACH, 255 + ?MAX_ACK_RANGES * 2 * 255).
%% The receive window case pushes 20,000 real datagrams through a live session,
%% each one encrypted and each answered. A hang guard rather than a
%% synchronisation -- the barrier is the messages themselves -- so it is set well
%% above what the run needs even with the whole suite competing for the CPU.
-define(TRAFFIC_WINDOW, 120000).
%% How many packets are queued before the owner drains the far end. Small enough
%% that the listener's socket does not overflow, large enough that the drain is
%% not the whole cost of the run.
-define(TRAFFIC_CHUNK, 200).

suite() ->
    [].

all() ->
    [
        full_handshake_and_data,
        transport_bytes_are_counted,
        keepalive_roundtrip,
        idle_reaps_silent_session,
        large_fragmented_message_reassembled,
        garbage_datagram_survives,
        receive_window_does_not_grow_with_traffic
    ].

%% ---------------------------------------------------------------------------
%% Per-case lifecycle: env must be set before the app (and its SSU2 sup) come
%% up; app stop tears down the SSU2 session/listener tree (all `temporary`
%% children of i2p_ssu2_sup), so nothing leaks into the next testcase.
%% ---------------------------------------------------------------------------

init_per_testcase(full_handshake_and_data, Config) ->
    start_app(Config, 60000);
init_per_testcase(keepalive_roundtrip, Config) ->
    ok = application:set_env(?APP, keepalive_interval_ms, 300),
    ok = application:set_env(?APP, idle_timeout_ms, 60000),
    start_app(Config, 120000);
init_per_testcase(idle_reaps_silent_session, Config) ->
    ok = application:set_env(?APP, idle_timeout_ms, 1000),
    ok = application:set_env(?APP, keepalive_interval_ms, 60000),
    start_app(Config, 30000);
init_per_testcase(transport_bytes_are_counted, Config) ->
    %% No interval needs pinning here, and that is the point of the case's shape:
    %% it stands up a listener with **no sessions on it**, so there are no
    %% keepalives, no acknowledgements and no path probes to interleave — the only
    %% datagrams that exist are the ones this case sends. The earlier version of
    %% this case used a live peer pair, where all three could, which is what made
    %% its assertions a hope rather than a synchronisation.
    start_app(Config, 30000);
init_per_testcase(large_fragmented_message_reassembled, Config) ->
    start_app(Config, 60000);
init_per_testcase(garbage_datagram_survives, Config) ->
    start_app(Config, 30000);
init_per_testcase(receive_window_does_not_grow_with_traffic, Config) ->
    %% No keepalive, no idle reap, and a long loss-recovery period: this case is
    %% about the receive window, and a session that ends early -- or a resend
    %% timer firing mid-run -- would stop the traffic that exercises it.
    ok = application:set_env(?APP, keepalive_interval_ms, 600000),
    ok = application:set_env(?APP, idle_timeout_ms, 600000),
    ok = application:set_env(?APP, data_resend_ms, 600000),
    %% **No frame capture**, unlike every other case here. It logs a line per
    %% packet on both sessions, and this case pushes tens of thousands of them:
    %% the trace itself would dominate the runtime and fill the log with more
    %% than a hundred thousand lines. Nothing in this case reads the trace.
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, 300000} | Config].

start_app(Config, Timetrap) ->
    i2p_ct_helpers:start_ssu2_trace(),
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, Timetrap} | Config].

end_per_testcase(keepalive_roundtrip, _Config) ->
    teardown();
end_per_testcase(idle_reaps_silent_session, _Config) ->
    teardown();
end_per_testcase(receive_window_does_not_grow_with_traffic, _Config) ->
    %% No trace was started for this case, so none is stopped here -- and the
    %% env it set is unset, because `application:stop/1` does not clear it and
    %% the next case would inherit a 10-minute keepalive.
    ok = application:unset_env(?APP, keepalive_interval_ms),
    ok = application:unset_env(?APP, idle_timeout_ms),
    ok = application:unset_env(?APP, data_resend_ms),
    application:stop(?APP),
    ok;
end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    i2p_ct_helpers:stop_ssu2_trace(),
    ok.

teardown() ->
    ok = application:unset_env(?APP, keepalive_interval_ms),
    ok = application:unset_env(?APP, idle_timeout_ms),
    application:stop(?APP),
    i2p_ct_helpers:stop_ssu2_trace(),
    ok.

%% ---------------------------------------------------------------------------
%% Session + data path
%% ---------------------------------------------------------------------------

%% Full loopback handshake (Retry token grant, SessionConfirmed RouterInfo
%% validation, Bob's ACK of packet zero) then data both directions and a clean
%% termination observed at the peer.
full_handshake_and_data(_Config) ->
    {APid, BPid} = establish_pair(),
    MsgBody = <<"hello over ssu2">>,
    i2p_ssu2_conn:send_i2np(APid, 6, 4242, MsgBody),
    ok = wait_i2np(BPid, 4242, MsgBody),
    Reply = <<"reply from bob">>,
    i2p_ssu2_conn:send_i2np(BPid, 6, 4243, Reply),
    ok = wait_i2np(APid, 4243, Reply),
    i2p_ssu2_conn:terminate_session(APid, 0),
    ok = wait_closed(BPid, 0).

%% Bytes counted at the SSU2 transport boundary.
%%
%% The listener owns the socket and every outbound datagram funnels through
%% `m:i2p_ssu2_listener:send/3` — data, keepalives, the handshake resend and the
%% data-phase `resend_unacked` alike — so that is the one place a byte can be
%% charged once.
%%
%% **Why this case stands up its own listener with no sessions on it.** An earlier
%% version of it ran against a live peer pair and compared the inbound and
%% outbound totals for equality. That is not a synchronisation, it is a hope: SSU2
%% interleaves acknowledgements and path probes with data, so two router-wide
%% readings a few milliseconds apart differ by whatever control traffic landed in
%% between. It passed when the suite ran alone and failed in the full gate, and I
%% "fixed" it by widening the assertion to a tolerance. That was the wrong repair —
%% a tolerance is a flake with extra steps, and it stops the test from being able to
%% fail.
%%
%% A session-less listener has no peer, so no control traffic exists to intrude. And
%% each measurement is taken against a datagram the test is *holding*, which makes
%% it a barrier rather than a poll:
%%
%%   - **inbound**: the charge happens before the datagram is classified, and an
%%     out-of-session PeerTest is answered. Receiving that answer proves the charge
%%     already happened, so the inbound total can be compared for exact equality
%%     against the size of the packet that was sent.
%%   - **outbound**: the charge happens before `gen_udp:send/4`, so the reply
%%     arriving on the test's own socket proves that charge happened too, and the
%%     outbound total equals the size of the reply that arrived.
%%
%% Both directions are therefore exact equalities against bytes the test can name,
%% with no window, no deadline and no tolerance.
transport_bytes_are_counted(_Config) ->
    %% One keypair, bound once. The Charlie responder signs its reply with
    %% `static_priv`, so a pub and priv drawn from two separate generations would
    %% make the reply unverifiable and the case would pass for the wrong reason.
    {CPub, CPriv} = i2p_crypto:x25519_keygen(),
    Bik = crypto:strong_rand_bytes(32),
    CharlieLocal = #{static_priv => CPriv, static_pub => CPub, intro_key => Bik},
    {ok, Listener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, CharlieLocal, self()),
    Port = i2p_ssu2_listener:port(Listener),
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    try
        #{ssu2_bytes_in := In0, ssu2_bytes_out := Out0} = i2p_stats:snapshot(),

        %% An out-of-session PeerTest, which a session-less listener answers.
        %% Receiving the answer is the barrier for both charges.
        Packet = peertest_packet(Bik, 16#12345678, 4567),
        ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, Packet),
        Reply = await_datagram(Sock),
        true = (byte_size(Packet) =:= ssu2_bytes_in() - In0),
        true = (byte_size(Reply) =:= ssu2_bytes_out() - Out0),
        %% An answer really was produced, or the barrier is not a barrier.
        true = (byte_size(Reply) > 0),
        %% A packet of tens of bytes charged as its exact length is already more
        %% than a per-datagram counter would produce, and the 700-byte payload
        %% below is a second, very different size measured the same way. Together
        %% they are what separates byte-counting from message-counting — no
        %% tolerance and no second round trip needed.

        %% And an outbound datagram of a size this test chose, sent straight
        %% through the funnel, is charged exactly its own length.
        Out1 = Out0 + byte_size(Reply),
        Payload = crypto:strong_rand_bytes(700),
        %% The endpoint is a two-tuple `{IP, Port}`. `i2p_ssu2_listener:send/3`
        %% matches `{_IP, _Port}`, and an Erlang tuple pattern matches exact
        %% arity — so the five-element `{127,0,0,1,Port}` form that `gen_udp:send/4`
        %% wants raises `function_clause` here. Easy to get wrong, and the failure
        %% names the wrong function.
        ok = i2p_ssu2_listener:send(Listener, Payload, {{127, 0, 0, 1}, my_port(Sock)}),
        true = (Payload =:= await_datagram(Sock)),
        true = (byte_size(Payload) =:= ssu2_bytes_out() - Out1)
    after
        ok = gen_udp:close(Sock),
        ok = i2p_ssu2_listener:stop(Listener)
    end.

%% A well-formed out-of-session PeerTest, which a session-less listener answers
%% with a Charlie reply. Shaped exactly as `i2p_ssu2_peertest_SUITE` builds it.
peertest_packet(Bik, Nonce, PeerPort) ->
    peertest_packet(Bik, Nonce, PeerPort, <<>>).

peertest_packet(Bik, Nonce, PeerPort, RouterHash) ->
    Block =
        i2p_peertest:block(
            6, 0, 0, RouterHash, 2, Nonce, 1_700_000_000, PeerPort, <<127, 0, 0, 1>>, <<>>
        ),
    {ok, Packet} =
        i2p_ssu2:encode_peertest(
            Bik,
            0,
            i2p_peertest:src_conn_id(Nonce),
            i2p_peertest:dst_conn_id(Nonce),
            [Block]
        ),
    Packet.

%% The test's own socket: a receive is the proof the listener has finished with
%% the datagram, so no deadline is needed to say "it has been processed".
await_datagram(Sock) ->
    receive
        {udp, S, _IP, _Port, Datagram} when S =:= Sock ->
            Datagram
    end.

my_port(Sock) ->
    {ok, Port} = inet:port(Sock),
    Port.

ssu2_bytes_in() ->
    maps:get(ssu2_bytes_in, i2p_stats:snapshot()).

ssu2_bytes_out() ->
    maps:get(ssu2_bytes_out, i2p_stats:snapshot()).

%% Data-phase keepalive: with a short keepalive interval the session sends a
%% path_challenge (type 18) probe and the peer echoes it as a path_response
%% (type 19). Two full exchanges prove the cadence keeps firing; the echoed
%% data must match the challenge byte-for-byte.
%%
%% The capture is one pass over both sessions' block streams so a block is
%% never dropped by a competing wait. The response echo is cross-checked by
%% set membership against the challenges actually captured: both ends probe on
%% the same 300ms cadence and loopback echo is effectively in-order, but a
%% challenge captured seconds after its echo already hit the peer's mailbox
%% can make pairwise sequence ordering unreliable. The single receive loop keeps
%% both directions observable.
keepalive_roundtrip(_Config) ->
    {APid, BPid} = establish_pair(),
    {Cs, Rs} = capture_exchanges(BPid, APid, 2),
    true = lists:all(fun(D) -> byte_size(D) =:= 8 end, Cs),
    true = lists:all(fun(R) -> lists:member(R, Cs) end, Rs),
    true = is_process_alive(APid),
    true = is_process_alive(BPid).

%% Consume `N` path_challenges seen by `ChPid` and `N` path_responses seen by
%% `ResPid` in one receive loop, so no block is lost to a sibling wait and no
%% message is consumed twice. Blocks of the other tag on either session are
%% ignored, not drained-and-lost.
capture_exchanges(ChPid, ResPid, N) ->
    capture_exchanges(ChPid, ResPid, N, [], []).

capture_exchanges(_ChPid, _ResPid, N, Cs, Rs) when length(Cs) >= N, length(Rs) >= N ->
    {lists:reverse(Cs), lists:reverse(Rs)};
capture_exchanges(ChPid, ResPid, N, Cs, Rs) ->
    receive
        {ssu2_data, ChPid, Blocks} ->
            NewCs = append_blocks(Cs, path_challenge, Blocks, N),
            capture_exchanges(ChPid, ResPid, N, NewCs, Rs);
        {ssu2_data, ResPid, Blocks} ->
            NewRs = append_blocks(Rs, path_response, Blocks, N),
            capture_exchanges(ChPid, ResPid, N, Cs, NewRs)
    after ?RELAY_WINDOW ->
        erlang:error({keepalive_exchange_incomplete, length(Cs), length(Rs)})
    end.

append_blocks(Acc, Tag, Blocks, N) when length(Acc) < N ->
    Taken = [D || {T, D} <- Blocks, T =:= Tag],
    lists:sublist(Acc ++ Taken, N);
append_blocks(Acc, _Tag, _Blocks, _N) ->
    Acc.

%% Idle reap: with a short idle timeout and keepalive far away, a quiet
%% established session reaps itself — both ends exit `{idle_timeout,
%% no_activity}`.
idle_reaps_silent_session(_Config) ->
    {APid, BPid} = establish_pair(),
    expect_idle_exit([APid, BPid]).

%% A large I2NP message exceeds the per-packet budget and is fragmented across
%% several Data packets; the peer reassembles the exact body.
large_fragmented_message_reassembled(_Config) ->
    {APid, BPid} = establish_pair(),
    BigBody = crypto:strong_rand_bytes(6000),
    MsgId = 9000,
    i2p_ssu2_conn:send_i2np(APid, 6, MsgId, BigBody),
    ok = wait_i2np(BPid, MsgId, BigBody).

%% A random (non-session) datagram reaching the listener must never kill it:
%% the listener survives garbage and still answers.
garbage_datagram_survives(_Config) ->
    {_BPub, BPriv} = i2p_crypto:x25519_keygen(),
    Local =
        #{
            static_priv => BPriv,
            static_pub => crypto:strong_rand_bytes(32),
            intro_key => crypto:strong_rand_bytes(32)
        },
    {ok, Listener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, Local, self()),
    Port = i2p_ssu2_listener:port(Listener),
    {ok, Sock} = gen_udp:open(0, [binary]),
    ok =
        gen_udp:send(
            Sock,
            {127, 0, 0, 1},
            Port,
            crypto:strong_rand_bytes(120)
        ),
    ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, <<1, 2, 3>>),
    Port = i2p_ssu2_listener:port(Listener),
    gen_udp:close(Sock),
    ok.

%% The receive window does not grow with traffic (#7GP4A4K).
%%
%% This is the live half of a pair whose unit half is
%% `m:i2p_ssu2_recv_tests`, and it exists because the unit test can only see the
%% window term in isolation. Here a **real session process** receives tens of
%% thousands of real packets over loopback, and the window is read back out of
%% the live process afterwards. The old structure held one entry per packet for
%% the life of the session, so this is the case that could not have existed
%% before.
%%
%% **The subject is the receiving session.** The receiver's window is what is on
%% trial, and it sends nothing but ACK-only packets, which are never tracked --
%% so its `out_pkts` is empty and its `reassembly` never fills (the messages are
%% 8 bytes, far below the fragment threshold). The *sender* is the opposite:
%% its `out_pkts` holds every unacknowledged packet, so measuring it would
%% report the resend map rather than the window, and would make any comparison a
%% race.
%%
%% **Each round gets its own pair.** Reusing one session would carry the first
%% round's state into the second, and the sender's queue would still be draining
%% when the second round began.
%%
%% **What is asserted is the ceiling, not equality between the two rounds.** The
%% first round leaves the window not yet full (2,001 numbers after 2,000
%% packets) and the second leaves it full at exactly the reach (10,456 after
%% 20,000), so the two readings are *supposed* to differ: the window fills and
%% then stops. Comparing them for equality would assert that it never fills,
%% which is not the claim and would be false. The claim is that ten times the
%% traffic does not cost ten times the memory -- which the ceiling states as a
%% number, and the old structure could not have met it at any scale.
%%
%% **The retained packet count, and not the process's heap.** An earlier version
%% compared the session's total heap and flaked at 8,864 / 13,824 / 13,888 words
%% while the window sat unchanged in every run; the difference was `remote_ri`,
%% a RouterInfo a handshake leaves resident, and what the collector happened to
%% be holding. Comparing two such readings is a tolerance, and a tolerance is a
%% flake that has given up the ability to fail. The heap is still bounded below,
%% but by a stated ceiling rather than by comparison -- so it can catch a
%% regression without being able to fail spuriously.
%%
%% The range count is asserted against the **structural bound** rather than
%% against exactly one. UDP drops datagrams under this much load, and a real gap
%% is a real range; demanding a perfect stream would be asserting the network
%% rather than the code.
receive_window_does_not_grow_with_traffic(_Config) ->
    {Short, ShortHeap} = drive_traffic(2000),
    {Long, LongHeap} = drive_traffic(20000),
    ct:pal("window ~p -> ~p; receiver heap ~p -> ~p words", [
        Short, Long, ShortHeap, LongHeap
    ]),
    true = maps:get(ranges, Long) =< ?MAX_ACK_RANGES + 1,
    Retained = maps:get(packets, Long),
    true = Retained =< ?ACK_REACH + 1,
    %% The old structure would have retained all 20,000. The floor is the point
    %% as much as the ceiling: the window is not empty, and not so full that it
    %% has stopped remembering anything.
    true = Retained > 2000,
    %% And a ceiling on the process itself, stated as a number rather than
    %% measured against the session. The old representation held 20,000 packet
    %% numbers in a flat list, and packet numbers here are boxed bignums rather
    %% than immediates, so each cost a cons cell (2 words) plus its box (2
    %% words): 80,000 words, before anything else the session holds. The
    %% session's own steady-state cost is under 9,000, so this sits an order of
    %% magnitude below what the old code could not avoid and an order of
    %% magnitude above the real figure -- a bound rather than a fit to the
    %% measurement.
    OldFlatListWords = 20000 * 4,
    true = LongHeap < OldFlatListWords div 2.

%% Stand up a pair, push `N` messages one way, and return the receiving
%% session's live heap and window size once the whole run has been processed.
%%
%% **Sent in chunks, with the receiver drained between them.** This is
%% backpressure rather than bookkeeping: the owner of both sessions is this
%% process, so while it is queueing sends it is not receiving, and a burst large
%% enough to overflow the listener's socket is dropped by the kernel and never
%% recovered -- the resend timer is deliberately parked for this case, so a lost
%% datagram would simply never arrive and the wait would never finish. Draining a
%% chunk before sending the next keeps both queues bounded, and it is still a
%% barrier rather than a sleep: the receiver forwards only after decrypting,
%% numbering and folding a packet into its window, so a drained chunk is a
%% processed chunk.
drive_traffic(N) ->
    {Sender, Receiver} = establish_pair(),
    lists:foreach(
        fun(Chunk) ->
            lists:foreach(
                fun(I) -> i2p_ssu2_conn:send_i2np(Sender, 6, I, <<"traffic">>) end,
                Chunk
            ),
            ok = wait_for_received(Receiver, length(Chunk))
        end,
        chunks(lists:seq(1, N), ?TRAFFIC_CHUNK)
    ),
    drain(Receiver),
    #{seen_in := Window} = sys:get_state(Receiver),
    Reading = {
        #{
            ranges => i2p_ssu2_recv:range_count(Window),
            packets => length(i2p_ssu2_recv:to_list(Window))
        },
        live_heap(Receiver)
    },
    true = is_process_alive(Sender),
    true = is_process_alive(Receiver),
    Reading.

chunks([], _Size) ->
    [];
chunks(List, Size) ->
    {Chunk, Rest} = lists:split(min(Size, length(List)), List),
    [Chunk | chunks(Rest, Size)].

wait_for_received(_To, 0) ->
    ok;
wait_for_received(To, N) ->
    receive
        {ssu2_data, To, _Blocks} -> wait_for_received(To, N - 1)
    after ?TRAFFIC_WINDOW ->
        erlang:error({traffic_incomplete, N})
    end.

%% The session's live heap in words, after a full collection so the reading is
%% the data it holds rather than whatever the collector has not swept.
live_heap(Pid) ->
    erlang:garbage_collect(Pid),
    {memory, Words} = process_info(Pid, memory),
    Words.

%% Read the session's own view of itself. `sys:get_state/1` is a synchronous
%% call into the process, so what comes back is a state it has already reached.
%% These are the receive window's own figures -- the structure the ticket bounds,
%% which do not move with unrelated session state.

%% Everything the session forwarded while the traffic ran, so the reading is
%% taken from an empty mailbox rather than an inherited one.
drain(To) ->
    receive
        {ssu2_data, To, _Blocks} -> drain(To)
    after 0 ->
        ok
    end.

%% ---------------------------------------------------------------------------
%% Helpers for the session pair and wire assertions.
%% ---------------------------------------------------------------------------

%% Stand up an Alice and a Bob session over two loopback listeners, with both
%% owners confirmed and the derived direction keys checked to agree.
establish_pair() ->
    {BPub, BPriv} = i2p_crypto:x25519_keygen(),
    Bik = crypto:strong_rand_bytes(32),
    BobLocal = #{static_priv => BPriv, static_pub => BPub, intro_key => Bik},
    {ok, BobListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    BobPort = i2p_ssu2_listener:port(BobListener),
    {ALocal, RIBlock} = alice_local(),
    {ok, AliceListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, ALocal, self()),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => BobPort,
            static_key => BPub,
            intro_key => Bik
        },
    {ok, APid, KeysA} = i2p_ssu2_conn:connect(ALocal, RemoteOpts, RIBlock, AliceListener),
    #{k_ab := KAbA, k_ba := KBaA} = KeysA,
    BPid =
        i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_ready, P, KeysB, _RemoteRI}) ->
                    #{k_ab := KAbB, k_ba := KBaB} = KeysB,
                    KAbA = KAbB,
                    KBaA = KBaB,
                    {true, P};
                (_) ->
                    false
            end,
            ?DATA_WINDOW
        ),
    unlink(APid),
    unlink(BPid),
    {APid, BPid}.

%% Wait until `FromPid`'s session delivers the I2NP message `MsgId`/`Body`.
%% Non-matching session messages are drained; a premature close of the awaited
%% session fails the wait (closed_early).
wait_i2np(FromPid, MsgId, Body) ->
    Result =
        i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_data, P, Blocks}) when P =:= FromPid ->
                    case lists:keyfind(i2np, 1, Blocks) of
                        {i2np, _, MsgId, _, Body} -> {true, ok};
                        _ -> false
                    end;
                ({ssu2_closed, P, _Reason}) when P =:= FromPid ->
                    erlang:error(closed_early);
                (_) ->
                    false
            end,
            ?DATA_WINDOW
        ),
    ok = Result.

%% Wait for the peer session to announce a clean termination with `Reason`.
wait_closed(Pid, Reason) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_closed, P, R}) when P =:= Pid, R =:= Reason -> {true, ok};
            (_) -> false
        end,
        ?DATA_WINDOW
    ).

%% Assert every pid exits with `{idle_timeout, no_activity}` within the window.
%% All monitors are armed before any is awaited so the two sessions' exits
%% (which may be microseconds apart) cannot be missed as a `noproc` DOWN.
expect_idle_exit(Pids) ->
    Refs = [{erlang:monitor(process, Pid), Pid} || Pid <- Pids],
    lists:foreach(
        fun({MRef, Pid}) ->
            receive
                {'DOWN', MRef, process, Pid, {idle_timeout, no_activity}} ->
                    ok;
                {'DOWN', MRef, process, Pid, Other} ->
                    erlang:error({unexpected_exit, Pid, Other})
            after 5000 ->
                erlang:error({not_idle_reaped, Pid})
            end
        end,
        Refs
    ).

alice_local() ->
    {APub, APriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(APub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19150, APub, IntroKey),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI =
        i2p_router_info:build(
            Identity,
            erlang:system_time(millisecond),
            [Addr],
            Opts,
            Seed
        ),
    ALocal = #{static_priv => APriv, static_pub => APub, intro_key => IntroKey},
    {ALocal#{sign_seed => Seed, sign_pub => SignPub}, maps:get(binary, RI)}.
