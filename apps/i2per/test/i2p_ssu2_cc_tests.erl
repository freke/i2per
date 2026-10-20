%% The SSU2 data-phase congestion control and RTT estimator: the arithmetic
%% itself, not the transport around it.
%%
%% #RC68AGE shipped 197 lines of this with no test, and it is the one part of
%% 0.5.0 that can ship a silent numerical bug. Everything here is pure window
%% arithmetic on byte counts and millisecond timers, so a transposed
%% coefficient or an off-by-one in the gate does not crash -- it produces
%% plausible numbers and a throughput regression nobody can attribute, with no
%% oracle to compare against. That is the risk these cases retire.
%%
%% Expected values are derived from `f:mtu/0` rather than restating 1472. The
%% window is counted in MTUs, so a hardcoded constant here would be a second
%% copy of a define that gates the send path.
%%
%% **Nothing here opens a socket.** The cases drive the state map directly,
%% which is only possible because the pure half of the estimator is exported
%% (see the export list in `m:i2p_ssu2_conn`) and because `f:update_rtt_at/4`
%% takes the clock as a parameter. `update_rtt/3` reads
%% `erlang:monotonic_time/1` internally, and with the clock inside, the only
%% thing a test could observe about a sample is that one happened -- the whole
%% Jacobson/Karels estimator would be unreachable.

-module(i2p_ssu2_cc_tests).

-include_lib("eunit/include/eunit.hrl").

-define(MTU, i2p_ssu2_conn:mtu()).

%%% --------------------------------------------------------------------------
%%% RTT estimation (Jacobson/Karels)
%%% --------------------------------------------------------------------------

%% The first sample seeds the estimator rather than averaging into it. A
%% first-sample bias of 1/8 would start srtt below the true RTT and take eight
%% acknowledgements to recover, which is most of a session's short-lived life.
first_sample_seeds_the_estimator_test() ->
    State = i2p_ssu2_conn:apply_rtt_sample(#{}, 250),
    ?assertEqual(true, maps:get(rtt_initialized, State)),
    ?assertEqual(250, maps:get(srtt_ms, State)),
    ?assertEqual(125, maps:get(rttvar_ms, State)).

%% RFC 6298: alpha 1/8, beta 1/4. Both weights are asserted by their effect on
%% a sample that is not a fixed point, so a transposed numerator (7 and 3
%% swapped) or a beta of 1/2 instead of 1/4 fails here rather than drifting.
%%
%% srtt: (7*100 + 200) / 8 = 900/8 = 112.5 -> 112
%% rttvar: (3*50 + |100-200|) / 4 = (150 + 100)/4 = 62.5 -> 62
subsequent_sample_uses_the_rfc_6298_weights_test() ->
    State = #{rtt_initialized => true, srtt_ms => 100, rttvar_ms => 50},
    State1 = i2p_ssu2_conn:apply_rtt_sample(State, 200),
    ?assertEqual(112, maps:get(srtt_ms, State1)),
    ?assertEqual(62, maps:get(rttvar_ms, State1)).

%% The floor is load-bearing. rttvar decays multiplicatively toward a jitter
%% that never reaches zero; without a floor it hits 0 and the estimator can no
%% longer detect a genuine delay increase, which is the one thing it is for.
rttvar_never_falls_below_one_test() ->
    State = #{rtt_initialized => true, srtt_ms => 100, rttvar_ms => 1},
    State1 = i2p_ssu2_conn:apply_rtt_sample(State, 100),
    ?assertEqual(1, maps:get(rttvar_ms, State1)).

%% A steady stream must reach an exact fixed point, not an asymptote. (7S+R)/8
%% with R = S is S for every S, so any drift here is a truncation bug.
rtt_converges_exactly_on_a_steady_stream_test() ->
    State0 = i2p_ssu2_conn:apply_rtt_sample(#{}, 250),
    State1 = lists:foldl(
        fun(_, S) -> i2p_ssu2_conn:apply_rtt_sample(S, 250) end, State0, lists:seq(1, 20)
    ),
    ?assertEqual(250, maps:get(srtt_ms, State1)).

%% `rtt`, `rtt_ms`, `srtt` and `srtt_ms` are four names for two numbers, kept
%% in step so an observer reading either pair sees the same estimate. The
%% status page reads `rtt`, the session state carries `srtt`.
rtt_keeps_both_spellings_in_step_test() ->
    State0 = i2p_ssu2_conn:apply_rtt_sample(#{}, 250),
    State1 = i2p_ssu2_conn:apply_rtt_sample(State0, 400),
    #{rtt := Rtt, rtt_ms := RttMs, srtt := Srtt, srtt_ms := SrttMs} = State1,
    ?assertEqual(Rtt, RttMs),
    ?assertEqual(Srtt, SrttMs),
    ?assertEqual(SrttMs, RttMs).

%%% --------------------------------------------------------------------------
%%% RTT sample selection
%%% --------------------------------------------------------------------------

%% update_rtt_at/4 with the clock supplied, so the sample is the number the
%% test chose rather than however long the machine took.
acked_packet_contributes_a_sample_test() ->
    Out = #{1 => {[], ?MTU, 1000, false}},
    State = i2p_ssu2_conn:update_rtt_at(#{}, [1], Out, 1250),
    ?assertEqual(250, maps:get(srtt_ms, State)).

%% Karn's algorithm. A retransmitted packet's RTT sample includes the delay the
%% peer's own retransmit timer added, so folding it in biases the estimate
%% upward precisely when the link is worst. The `Retransmitted` flag is the only
%% thing distinguishing the two, so it has to be honoured.
retransmitted_packets_do_not_contribute_a_sample_test() ->
    Out = #{1 => {[], ?MTU, 1000, true}},
    State = i2p_ssu2_conn:update_rtt_at(#{}, [1], Out, 1250),
    ?assertNot(maps:is_key(rtt_initialized, State)).

%% An ACK naming a packet number we never sent -- reordered after a
%% retransmission renumbered it, or forged. No map entry, so no sample, and no
%% crash on the `maps:get/3` default either.
unknown_packet_numbers_are_ignored_test() ->
    Out = #{1 => {[], ?MTU, 1000, false}},
    State = i2p_ssu2_conn:update_rtt_at(#{}, [99], Out, 1250),
    ?assertNot(maps:is_key(rtt_initialized, State)).

%% A clock that reads behind a send time gives a negative sample. The guard
%% exists because monotonic time is per-node and a resumed or migrated session
%% can observe one; without it srtt drifts negative and every later comparison
%% against rttvar is meaningless.
negative_samples_are_discarded_test() ->
    Out = #{1 => {[], ?MTU, 2000, false}},
    State = i2p_ssu2_conn:update_rtt_at(#{}, [1], Out, 1000),
    ?assertNot(maps:is_key(rtt_initialized, State)).

%% One ACK covering several packets folds each in turn, in ACK order.
%% 1: sample 250 -> srtt 250, rttvar 125
%% 2: sample 350 -> srtt (7*250+350)/8 = 2100/8 = 262.5 -> 262
%%    rttvar (3*125 + |250-350|)/4 = (375+100)/4 = 475/4 = 118.75 -> 118
%% The order is the list's, which is why the expectation is written out rather
%% than derived -- a fold that reversed it would land elsewhere, and the
%% difference is small enough to pass a tolerance.
multiple_acked_packets_fold_in_ack_order_test() ->
    Out = #{
        1 => {[], ?MTU, 1000, false},
        2 => {[], ?MTU, 900, false}
    },
    State = i2p_ssu2_conn:update_rtt_at(#{}, [1, 2], Out, 1250),
    ?assertEqual(262, maps:get(srtt_ms, State)),
    ?assertEqual(118, maps:get(rttvar_ms, State)).

%%% --------------------------------------------------------------------------
%%% Window growth
%%% --------------------------------------------------------------------------

%% Slow start: the window grows by everything acknowledged, one byte per byte.
slow_start_grows_by_the_acked_bytes_test() ->
    State = i2p_ssu2_conn:apply_cc_ack(#{cwnd => 1000, ssthresh => 65535}, 500),
    ?assertEqual(1500, maps:get(cwnd, State)).

%% ssthresh is inclusive. `Cwnd =< Ssthresh` means a session sitting exactly at
%% the threshold still grows by the full amount; one byte over and it drops to
%% the avoidance increment. This is the off-by-one the window turns on.
ssthresh_is_inclusive_test() ->
    At = i2p_ssu2_conn:apply_cc_ack(#{cwnd => 65535, ssthresh => 65535}, 500),
    ?assertEqual(66035, maps:get(cwnd, At)),
    Over = i2p_ssu2_conn:apply_cc_ack(#{cwnd => 65536, ssthresh => 65535}, ?MTU),
    ?assertNotEqual(65536 + 500, maps:get(cwnd, Over)).

%% Congestion avoidance: MTU * AckedBytes / Cwnd per ACK -- roughly one MTU per
%% RTT, which is the whole point of the phase. 1472 * 1472 / 100000 = 21.
congestion_avoidance_grows_by_one_mtu_per_rtt_test() ->
    State = i2p_ssu2_conn:apply_cc_ack(#{cwnd => 100000, ssthresh => 1000}, ?MTU),
    ?assertEqual(100021, maps:get(cwnd, State)).

%% The avoidance increment floors at 1. Without it, a window large enough that
%% MTU*AckedBytes/Cwnd rounds to zero stops growing entirely -- the session
%% never recovers throughput after the congestion it just backed off from.
congestion_avoidance_never_stalls_at_zero_test() ->
    State = i2p_ssu2_conn:apply_cc_ack(#{cwnd => 100000000, ssthresh => 1}, 1),
    ?assertEqual(100000001, maps:get(cwnd, State)).

%% An ACK acknowledging nothing -- every packet it named was NACKed, or it
%% covered only packets already dropped as superseded. Growing on it would open
%% the window for no reason.
zero_acked_bytes_leaves_the_window_alone_test() ->
    State = #{cwnd => 1000, ssthresh => 65535},
    ?assertEqual(State, i2p_ssu2_conn:apply_cc_ack(State, 0)).

%%% --------------------------------------------------------------------------
%%% Loss and timeout
%%% --------------------------------------------------------------------------

%% A NACK halves the window and pins ssthresh to the new value, so the next
%% ACK re-enters congestion avoidance at the reduced rate rather than slow
%% start.
loss_halves_the_window_and_pins_ssthresh_test() ->
    State = i2p_ssu2_conn:on_cc_loss(#{cwnd => 10000}),
    ?assertEqual(5000, maps:get(cwnd, State)),
    ?assertEqual(5000, maps:get(ssthresh, State)).

%% Halving floors at one MTU. A window below one MTU cannot carry a packet, so
%% without the floor a second consecutive loss would drive it to 736 and the
%% session would never send again.
loss_floors_at_one_mtu_test() ->
    State = i2p_ssu2_conn:on_cc_loss(#{cwnd => 2000}),
    ?assertEqual(?MTU, maps:get(cwnd, State)),
    ?assertEqual(?MTU, maps:get(ssthresh, State)).

%% A resend timeout is a stronger signal than a NACK: the window goes to a
%% single packet, while ssthresh only halves. The two phases are deliberately
%% not symmetric -- timeout means we have heard nothing at all.
timeout_resets_the_window_and_halves_only_ssthresh_test() ->
    State = i2p_ssu2_conn:on_cc_timeout(#{cwnd => 10000}),
    ?assertEqual(?MTU, maps:get(cwnd, State)),
    ?assertEqual(5000, maps:get(ssthresh, State)).

timeout_ssthresh_floors_at_one_mtu_test() ->
    State = i2p_ssu2_conn:on_cc_timeout(#{cwnd => 2000}),
    ?assertEqual(?MTU, maps:get(cwnd, State)),
    ?assertEqual(?MTU, maps:get(ssthresh, State)).

%% Same input, different outcome. Loss halves from 10000 to 5000; timeout sends
%% it to one MTU. A test asserting only "the window shrank" would pass on a
%% build where both handlers did the same thing.
loss_and_timeout_are_not_the_same_handler_test() ->
    In = #{cwnd => 10000},
    ?assertNotEqual(
        maps:get(cwnd, i2p_ssu2_conn:on_cc_loss(In)),
        maps:get(cwnd, i2p_ssu2_conn:on_cc_timeout(In))
    ).

%%% --------------------------------------------------------------------------
%%% In-flight accounting and the window gate
%%% --------------------------------------------------------------------------

%% The in-flight total is what the window is compared against, summed over
%% every tracked packet still awaiting an ACK. An empty map is zero, which the
%% gate below treats as "send anything".
inflight_sums_every_tracked_packet_test() ->
    ?assertEqual(
        1972,
        i2p_ssu2_conn:inflight_bytes(#{
            out_pkts => #{
                0 => {[], 1472, 0, false},
                1 => {[], 500, 0, false}
            }
        })
    ),
    ?assertEqual(0, i2p_ssu2_conn:inflight_bytes(#{out_pkts => #{}})).

%% The gate, through the one branch of the drain that needs no socket: with the
%% window already full, a queued packet must stay queued.
%%
%% 1472 in flight against a 1472 window: 1472 + 1472 > 1472, so blocked.
drain_holds_a_packet_while_the_window_is_full_test() ->
    State = #{
        cwnd => ?MTU,
        out_pkts => #{0 => {[], ?MTU, 0, false}},
        send_queue => queue:from_list([packet(queued)])
    },
    State1 = i2p_ssu2_conn:drain_send_queue(State),
    ?assertEqual([packet(queued)], queue:to_list(maps:get(send_queue, State1))).

%% A blocked drain leaves the queue in the order it was offered.
%% `drain_send_queue/1` pops the head, finds the window closed, and pushes it
%% back with `queue:in_r/2` -- which puts an item at the far end of the
%% storage, so it is the next one out again. That is both how the function
%% terminates instead of spinning on a full window, and why a momentary stall
%% reorders nothing: packets still leave in the order they were offered.
drain_preserves_order_when_the_window_is_full_test() ->
    State = #{
        cwnd => ?MTU,
        out_pkts => #{0 => {[], ?MTU, 0, false}},
        send_queue => queue:from_list([packet(first), packet(second)])
    },
    State1 = i2p_ssu2_conn:drain_send_queue(State),
    ?assertEqual(
        [packet(first), packet(second)],
        queue:to_list(maps:get(send_queue, State1))
    ).

%% An empty queue is a no-op regardless of how full the window is.
drain_on_an_empty_queue_is_a_no_op_test() ->
    State = #{
        cwnd => ?MTU,
        out_pkts => #{0 => {[], ?MTU, 0, false}},
        send_queue => queue:new()
    },
    ?assertEqual(State, i2p_ssu2_conn:drain_send_queue(State)).

%% The gate refuses whenever under one MTU of headroom remains, and it refuses
%% at exactly that threshold: `send_packet/3` queues at `Inflight + MTU > Cwnd`
%% and the drain admits at `Inflight + MTU =< Cwnd`, exact complements over
%% integers, so a window of 2*MTU against 2*MTU in flight is already full.
%% The admitting side is covered below, where a stand-in listener makes the
%% sealed datagram land in the test's own mailbox.
window_gate_holds_below_one_mtu_of_headroom_test() ->
    Cwnd = 2 * ?MTU,
    Held = fun(InFlight) ->
        State = #{
            cwnd => Cwnd,
            out_pkts => #{0 => {[], InFlight, 0, false}},
            send_queue => queue:from_list([packet(queued)])
        },
        ?assertEqual(
            [packet(queued)],
            queue:to_list(
                maps:get(
                    send_queue,
                    i2p_ssu2_conn:drain_send_queue(State)
                )
            )
        )
    end,
    ok = Held(?MTU + 1),
    ok = Held(Cwnd),
    ok = Held(10 * ?MTU).

%%% --------------------------------------------------------------------------
%%% Loss does not reopen the window
%%% --------------------------------------------------------------------------

%% A NACK halves the window but changes no in-flight bytes -- the ACKed packets
%% are still awaiting their ACK. So a session that just halved its window is
%% still blocked, and stays blocked until acknowledged bytes reopen it through
%% `apply_cc_ack/2`. Anything that read `on_cc_loss/1` as "and now we can send
%% again" would invert the whole recovery loop, and the in-flight total not
%% moving is the reason it cannot.
loss_does_not_by_itself_reopen_the_window_test() ->
    Blocked = #{
        cwnd => ?MTU,
        out_pkts => #{0 => {[], ?MTU, 0, false}},
        send_queue => queue:from_list([packet(queued)])
    },
    AfterLoss = i2p_ssu2_conn:on_cc_loss(Blocked),
    ?assertEqual(?MTU, maps:get(cwnd, AfterLoss)),
    ?assertEqual(
        [packet(queued)],
        queue:to_list(
            maps:get(
                send_queue,
                i2p_ssu2_conn:drain_send_queue(AfterLoss)
            )
        )
    ).

%%% --------------------------------------------------------------------------
%%% The reported congestion state
%%% --------------------------------------------------------------------------
%%
%% A session pushes its RTT and window into a public ETS table and the status
%% service reads the aggregate from there, so no reader ever blocks on a
%% session process. What is asserted below is that aggregation: which rows
%% count, which are skipped, and which are thrown away.
%%
%% The supervisor is started per test and stopped again, rather than once for
%% the module, because the registered name is node-global: `i2p_ssu2_sup` is
%% visible to every other eunit module on `nonode@nohost`, and a suite that
%% left one running would decide whether the no-supervisor case below passes.

%% The status service may run where SSU2 was never started. Reading congestion
%% state there must be a zero, not a crash.
rtt_summary_is_zero_without_a_supervisor_test() ->
    ok = stop_sup(),
    ?assertEqual(undefined, whereis(i2p_ssu2_sup)),
    ?assertEqual(#{sessions => 0, rtt_ms => 0, cwnd => 0}, i2p_ssu2_sup:rtt_summary()).

%% Two live sessions, averaged. The aggregate is the mean of the sessions that
%% have an RTT sample, integer-divided.
rtt_summary_averages_rtt_across_live_sessions_test() ->
    with_sup(fun() ->
        Session = live_session(),
        ok = i2p_ssu2_sup:update_metrics(self(), 100, true, 1000, established),
        ok = i2p_ssu2_sup:update_metrics(Session, 200, true, 2000, established),
        ?assertMatch(#{rtt_ms := 150, cwnd := 3000}, i2p_ssu2_sup:rtt_summary()),
        Session ! stop
    end).

%% A session that has not taken a sample yet pushes rtt_init = false with an
%% rtt_ms of 0. Folding that zero into the average would halve every reading
%% on the status page, which looks like a fast link that is not fast.
%%
%% The second session's own 100 is what makes this a test rather than a
%% tautology: with the filter, the mean is 100; without it, (100 + 0) / 2 = 50.
%% Asserting the unfiltered mean against a lone 0 would pass either way.
rtt_summary_skips_uninitialised_rtts_in_the_average_test() ->
    with_sup(fun() ->
        Session = live_session(),
        ok = i2p_ssu2_sup:update_metrics(self(), 100, true, 1000, established),
        ok = i2p_ssu2_sup:update_metrics(Session, 0, false, 5000, established),
        %% Its window still counts -- 6000, not 1000 -- because the window is
        %% measured from the first packet, while the RTT is not.
        ?assertMatch(#{rtt_ms := 100, cwnd := 6000}, i2p_ssu2_sup:rtt_summary()),
        Session ! stop
    end).

%% Only an established session's window is a congestion measurement. One still
%% handshaking carries the default window, and summing those would report a
%% total larger than anything any of those sessions could actually send.
rtt_summary_counts_only_established_windows_test() ->
    with_sup(fun() ->
        Session = live_session(),
        ok = i2p_ssu2_sup:update_metrics(Session, 100, true, 9999, handshake),
        ?assertMatch(#{rtt_ms := 100, cwnd := 0}, i2p_ssu2_sup:rtt_summary()),
        Session ! stop
    end).

%% A session process that exited without clearing its row leaves a stale entry
%% behind, and `remove_metrics/1` only runs on a clean terminate. The read
%% prunes it: an unreclaimed row is a permanent overstatement of both figures.
rtt_summary_prunes_rows_whose_session_is_gone_test() ->
    with_sup(fun() ->
        Gone = dead_session(),
        ok = i2p_ssu2_sup:update_metrics(Gone, 999, true, 999, established),
        ?assertMatch(#{rtt_ms := 0, cwnd := 0}, i2p_ssu2_sup:rtt_summary()),
        ?assertEqual([], ets:lookup(i2p_ssu2_metrics, Gone))
    end).

%% A session tearing down releases its row eagerly, so the aggregate drops it
%% without waiting for the next read to notice the process is gone.
remove_metrics_releases_the_row_test() ->
    with_sup(fun() ->
        Session = live_session(),
        ok = i2p_ssu2_sup:update_metrics(Session, 100, true, 1000, established),
        ?assertEqual(1, length(ets:lookup(i2p_ssu2_metrics, Session))),
        ok = i2p_ssu2_sup:remove_metrics(Session),
        ?assertEqual([], ets:lookup(i2p_ssu2_metrics, Session)),
        Session ! stop
    end).

%%% --------------------------------------------------------------------------
%%% The admitting side of the gate
%%% --------------------------------------------------------------------------
%%
%% `m:i2p_ssu2_listener:send/3` is a `gen_server:cast/2` to whatever pid the
%% session state names, so standing in a listener for `self()` puts the sealed
%% datagram in this process's mailbox. That reaches the branch the refused
%% cases cannot: `send_packet_now/5` needs keys, an intro key and a
%% connection id, and nothing here needs a socket or an i2pd to supply them.

%% A packet the window admits is sealed, cast, and spends its packet number.
an_admitted_packet_is_sent_and_spends_its_number_test() ->
    ok = clean_mailbox(),
    State = session_state(),
    State1 = i2p_ssu2_conn:drain_send_queue(
        State#{send_queue => queue:from_list([packet(i2np_block(1))])}
    ),
    ?assertEqual(queue:new(), maps:get(send_queue, State1)),
    ?assertEqual(8, maps:get(pkt_out, State1)),
    [Datagram] = take_sends(),
    ?assert(is_binary(Datagram)),
    %% Recorded for retransmission, so the ACK can still find it.
    ?assertEqual(1, maps:size(maps:get(out_pkts, State1))).

%% The queue is not one-per-tick. Whatever headroom the window has, the drain
%% spends it in one pass and leaves the rest queued -- so a window reopened by
%% a single ACK lets go of every packet that now fits, not just the next one.
drain_spends_the_whole_window_at_once_test() ->
    ok = clean_mailbox(),
    Queue = queue:from_list([packet(i2np_block(N)) || N <- [1, 2, 3, 4, 5]]),
    State1 = i2p_ssu2_conn:drain_send_queue((session_state())#{send_queue => Queue}),
    ?assertEqual(queue:new(), maps:get(send_queue, State1)),
    ?assertEqual(12, maps:get(pkt_out, State1)),
    ?assertEqual(5, length(take_sends())).

%% An ACK block is not ack-eliciting, so `send_blocks/2` sends it with
%% `Track = false` -- and `send_packet/3` gates only on `Track`. A pure ACK
%% therefore goes out against a full window and is never queued.
%%
%% Deliberate, and worth pinning. Throttling an ACK would stop the peer hearing
%% about the packets it already sent, its own window would close further, and
%% the congestion would compound from both ends: the one packet that must
%% never be queued is the one that repairs it. The contrast is the assertion --
%% the same full window, an ack-eliciting block, goes to the queue instead.
ack_only_packets_bypass_a_full_window_test() ->
    ok = clean_mailbox(),
    Full = #{cwnd => ?MTU, out_pkts => #{0 => {[], ?MTU, 0, false}}},
    State = maps:merge(session_state(), Full),
    Ack = i2p_ssu2_conn:send_packet([{ack, 0, 1, [{0, 0}]}], State, false),
    ?assertEqual(1, length(take_sends())),
    ?assertEqual(queue:new(), maps:get(send_queue, Ack)),
    %% Still only the pre-existing tracked packet: an ACK is never
    %% retransmitted, so recording it would strand it in `out_pkts` forever.
    ?assertEqual(1, maps:size(maps:get(out_pkts, Ack))),
    Data = i2p_ssu2_conn:send_packet([i2np_block(1)], State, true),
    ?assertEqual(queue:from_list([packet(i2np_block(1))]), maps:get(send_queue, Data)),
    ?assertEqual(0, length(take_sends())).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

%% The minimum a session state carries to seal and cast one Data packet: the
%% alice direction's two keys, a 32-byte remote intro key to seal against, a
%% connection id for the short header, a listener and an endpoint for the
%% cast, and a packet number to spend. A window wide enough that nothing
%% queues.
%%
%% The listener is `self()`, so the sealed datagram lands in this process's
%% mailbox -- which is what makes the cast assertable without a socket.
session_state() ->
    #{
        config => #{
            role => alice,
            remote => #{intro_key => <<1:256>>}
        },
        hs => #{dst_conn_id => 42},
        keys => #{k_ab => <<2:256>>, kh2_ab => <<3:256>>},
        listener => self(),
        endpoint => {{127, 0, 0, 1}, 0},
        pkt_out => 7,
        cwnd => 1024 * 1024,
        out_pkts => #{},
        send_queue => queue:new(),
        data_resend_ref => undefined,
        retransmitting => false
    }.

i2np_block(MsgId) ->
    {i2np, 20, MsgId, 0, <<0:256>>}.

%% **One queue entry is a packet, so a list of blocks -- not a bare block.**
%% `send_packet/3` queues the `Blocks` argument whole, and every caller passes
%% a one-element list. `ack_eliciting/1` then receives a list; hand it a bare
%% tuple and `lists:any/2` tuple-dispatches it into the branch for
%% function/2, which surfaces as a `case_clause` on the tuple with the frames
%% pointing at the drain rather than at the mistake.
packet(Blocks) when is_list(Blocks) ->
    Blocks;
packet(Block) ->
    [Block].

%% Counts the datagrams the stand-in listener was handed. `send/3` is a
%% `gen_server:cast/2`, so the datagram arrives wrapped in the cast envelope --
%% matching on the bare `{send, _, _}` tuple finds nothing and the cases that
%% assert on a send silently pass.
%%
%% Every eunit module's cases share one process and therefore one mailbox, so
%% a datagram a previous case did not account for would be counted here as
%% this case's own. `f:clean_mailbox/0` is the guard against that; these three
%% cases call it first.
take_sends() ->
    receive
        {'$gen_cast', {send, Datagram, _Endpoint}} -> [Datagram | take_sends()];
        _Other -> take_sends()
    after 0 ->
        []
    end.

clean_mailbox() ->
    _ = take_sends(),
    ok.

%% The metrics table is a named public ETS table, so it is node-global and its
%% rows outlive the test that wrote them: eunit runs a module's tests in one
%% process, so the table created by the first `start_link/0` is still there --
%% and still holding that test's rows -- for the next one. Every case here
%% reads the aggregate whole, so a leftover row would be a phantom session in
%% someone else's average. Hence the wipe, after the table exists and before
%% the case runs.
with_sup(Fun) ->
    {ok, _Sup} = i2p_ssu2_sup:start_link(),
    try
        ets:delete_all_objects(i2p_ssu2_metrics),
        Fun()
    after
        stop_sup()
    end.

%% Wait for the DOWN rather than firing and returning: the registered name is
%% released as part of the exit, and a later `start_link/0` would otherwise
%% race the unregistration and answer `{error, {already_started, _}}`.
stop_sup() ->
    case whereis(i2p_ssu2_sup) of
        undefined ->
            ok;
        Pid ->
            Ref = monitor(process, Pid),
            unlink(Pid),
            exit(Pid, shutdown),
            receive
                {'DOWN', Ref, process, Pid, _} -> ok
            end
    end.

%% A session stands in for a live process only in that it is alive and holds
%% an ETS row; the aggregate reads no session state beyond `is_process_alive/1`.
live_session() ->
    spawn(fun() ->
        receive
            stop -> ok
        end
    end).

dead_session() ->
    Pid = spawn(fun() -> ok end),
    Ref = monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _} -> Pid
    end.
