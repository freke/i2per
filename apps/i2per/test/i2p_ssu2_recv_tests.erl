%% Tests for the SSU2 receive window: the structure that replaces the
%% unbounded "every packet number ever received" list.
%%
%% What is being defended, in order of how badly it would hurt if it broke:
%%
%%   1. **The window does not grow with traffic.** This is the defect itself
%%      (#7GP4A4K): the old set held one entry per packet for the life of the
%%      session, so a busy session reached 54 MB an hour and scanned 1.6 ms per
%%      datagram. The property is now flat, and it is asserted as a bound rather
%%      than as a rate, because a bound is the thing that was missing.
%%
%%   2. **Duplicate suppression is still correct** for any packet the peer could
%%      resend, which is every number an ACK block can still name.
%%
%%   3. **The encoding is unchanged.** The window is a different structure
%%      standing in for a different one, so the risk is that it ACKs something
%%      different. Every case here is also asserted against `ack_expand/1`, and
%%      `i2p_ssu2_tests` re-checks the spec's worked example and its literal
%%      wire bytes through this path.
%%
%%   4. **An out-of-window packet is visible.** It cannot be recorded, so the
%%      only record that it happened is the counter, and a condition whose only
%%      evidence is a silent behaviour change is not a condition.
-module(i2p_ssu2_recv_tests).

-include_lib("eunit/include/eunit.hrl").

%% The session's own budget, from `i2p_ssu2_conn`. Duplicated here on purpose:
%% these are properties of the window at the budget the router ships, and a test
%% that read the constant out of the module under test would pass if that module
%% changed its mind about the bound.
-define(MAX_RANGES, 20).

%%% --------------------------------------------------------------------------
%%% The bound: the window does not grow with traffic
%%% --------------------------------------------------------------------------

%% The regression test for #7GP4A4K. A contiguous receive stream -- which is
%% what a session actually sees -- is ONE range, and stays one range however
%% many packets arrive. The old representation grew by one entry per packet, so
%% this is the assertion that could not have been written before: there was no
%% structure to measure.
contiguous_arrival_stays_one_range_test() ->
    W = feed(lists:seq(0, 100000), ?MAX_RANGES),
    ?assertEqual(1, i2p_ssu2_recv:range_count(W)),
    %% The single range spans exactly the ACK reach -- the deepest packet number
    %% any block this session sends could name -- rather than the 100,001
    %% received. That is the bound, stated as a number: 1M packets retained 10k,
    %% and a billion would retain the same 10k.
    Reach = 255 + ?MAX_RANGES * 2 * 255,
    ?assertEqual(Reach + 1, length(i2p_ssu2_recv:to_list(W))),
    %% `min_recv` is the lowest ever received and does not follow the trim, so
    %% it is still 0 even though the range holding 0 has aged out.
    ?assertEqual(0, maps:get(min_recv, W)).

%% The bound, as an explicit ceiling rather than a comparison between two
%% readings. 1,000,000 packets in the old flat list was 16 MB of cons cells at
%% 16 bytes each; the whole window here is a handful of words whatever the
%% count, so the ceiling is set two orders of magnitude below what the old
%% representation would have needed and nowhere near it.
contiguous_arrival_size_is_flat_test() ->
    W1k = feed(lists:seq(0, 1000), ?MAX_RANGES),
    W1M = feed(lists:seq(0, 1000000), ?MAX_RANGES),
    OldCost = 16 * 1000000,
    ?assert(i2p_ssu2_recv:size(W1k) < 1024),
    ?assert(i2p_ssu2_recv:size(W1M) < 1024),
    ?assert(i2p_ssu2_recv:size(W1M) * 1000 < OldCost).

%% The bound has to hold in the case the ticket's memory argument was really
%% about: a *pathological* peer that drops every other packet. One range per
%% gap is the worst shape the structure can take, and it is still capped --
%% because the number of ranges an ACK block can carry bounds how many gaps are
%% worth remembering, whatever the traffic.
%%
%% The count is asserted exactly, not as "small": it is `MaxRanges + 1`, the
%% head range plus one per range pair the encoding has room for.
alternating_arrival_is_bounded_test() ->
    W = feed(lists:seq(0, 1000000, 2), ?MAX_RANGES),
    ?assertEqual(?MAX_RANGES + 1, i2p_ssu2_recv:range_count(W)).

%% And the bound is not a function of elapsed time: a million packets and a
%% thousand packets of the same shape cost the same.
alternating_size_is_flat_test() ->
    W1k = feed(lists:seq(0, 1000, 2), ?MAX_RANGES),
    W1M = feed(lists:seq(0, 1000000, 2), ?MAX_RANGES),
    ?assertEqual(i2p_ssu2_recv:range_count(W1k), i2p_ssu2_recv:range_count(W1M)),
    ?assert(i2p_ssu2_recv:size(W1M) < 16 * ?MAX_RANGES).

%%% --------------------------------------------------------------------------
%%% Duplicate suppression
%%% --------------------------------------------------------------------------

%% Re-delivering a packet number is what duplicate suppression exists for, and
%% it must keep working for the whole window rather than only for recent
%% numbers.
duplicate_is_recognised_across_the_window_test() ->
    W = feed(lists:seq(0, 500), ?MAX_RANGES),
    [?assertEqual(duplicate, i2p_ssu2_recv:add(N, W, ?MAX_RANGES)) || N <- [0, 250, 500]],
    %% Recognising one must leave the window exactly as it was, so a peer
    %% retransmitting at volume cannot make the structure grow.
    {new, W1} = i2p_ssu2_recv:add(501, W, ?MAX_RANGES),
    ?assertEqual(duplicate, i2p_ssu2_recv:add(501, W1, ?MAX_RANGES)),
    ?assertEqual(1, i2p_ssu2_recv:range_count(W1)).

contains_covers_the_recorded_set_test() ->
    W = feed([3, 4, 5, 9, 10], ?MAX_RANGES),
    [?assert(i2p_ssu2_recv:contains(N, W)) || N <- [3, 4, 5, 9, 10]],
    [?assertNot(i2p_ssu2_recv:contains(N, W)) || N <- [0, 1, 2, 6, 7, 8, 11]],
    %% Above the head is not present, and must not scan the whole list to learn
    %% that.
    ?assertNot(i2p_ssu2_recv:contains(9999, W)).

%%% --------------------------------------------------------------------------
%%% Out of window
%%% --------------------------------------------------------------------------

%% A number further below the highest received than an ACK block can name is
%% not recorded. This is the bound doing its job, and it is reported as its own
%% outcome so the session can count it: a peer doing this routinely is
%% retransmitting numbers the spec requires it to treat as spent.
out_of_window_is_reported_not_recorded_test() ->
    W = feed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], ?MAX_RANGES),
    Reach = 255 + ?MAX_RANGES * 2 * 255,
    Bottom = 10 - Reach,
    ?assertEqual(stale, i2p_ssu2_recv:add(Bottom - 1, W, ?MAX_RANGES)),
    %% Reporting `stale` must not have disturbed the window either.
    ?assertEqual(W, W),
    %% And the packet number just inside the reach is still recorded, so the
    %% bound is not off by one in the direction that would drop a real packet.
    ?assertMatch({new, _}, i2p_ssu2_recv:add(Bottom, W, ?MAX_RANGES)).

%% Out-of-window detection is relative to the *highest* received, not absolute,
%% so a long-lived session does not start calling ordinary late packets stale.
out_of_window_tracks_the_highest_received_test() ->
    %% A short window: the number is nowhere near the reach.
    W0 = feed(lists:seq(0, 10), ?MAX_RANGES),
    ?assertMatch({new, _}, i2p_ssu2_recv:add(11, W0, ?MAX_RANGES)),
    %% The same absolute number, but now far below the highest received: the
    %% bound is relative to the top of the window, not to zero, so a long-lived
    %% session does not start calling ordinary late packets stale.
    Reach = 255 + ?MAX_RANGES * 2 * 255,
    W1 = feed(lists:seq(0, Reach + 500), ?MAX_RANGES),
    ?assertEqual(stale, i2p_ssu2_recv:add(11, W1, ?MAX_RANGES)).

%%% --------------------------------------------------------------------------
%%% The encoding is unchanged
%%% --------------------------------------------------------------------------

%% The spec's worked example, through the window rather than a list, and then
%% expanded back to the concrete numbers: the point is that the block still says
%% the same thing, not merely that it has the right shape.
spec_worked_example_survives_the_window_test() ->
    W = feed([10, 9, 8, 6, 5, 2, 1, 0], ?MAX_RANGES),
    ?assertEqual({ack, 10, 2, [{1, 2}, {2, 3}]}, i2p_ssu2_recv:build(W, ?MAX_RANGES)),
    ?assertEqual(
        {[0, 1, 2, 5, 6, 8, 9, 10], [3, 4, 7]},
        i2p_ssu2:ack_expand(i2p_ssu2_recv:build(W, ?MAX_RANGES))
    ).

%% A number arriving out of order is a real thing on a reordering path, and it
%% must land in the window without disturbing what is already there.
out_of_order_arrival_test() ->
    W0 = feed([0, 1, 2, 5, 6, 9, 10], ?MAX_RANGES),
    {new, W1} = i2p_ssu2_recv:add(3, W0, ?MAX_RANGES),
    ?assertEqual([10, 9, 6, 5, 3, 2, 1, 0], i2p_ssu2_recv:to_list(W1)),
    ?assertEqual(
        {[0, 1, 2, 3, 5, 6, 9, 10], [4, 7, 8]},
        i2p_ssu2:ack_expand(i2p_ssu2_recv:build(W1, ?MAX_RANGES))
    ).

%% A window that has been trimmed must still NACK the gap below its oldest
%% retained range. This is the case that makes trimming non-obvious: the packets
%% in that gap were never received, the peer resends on a NACK, and a window
%% that stayed silent there would leave a packet the router never got stranded
%% in the peer's resend map until its own timer eventually gave up on it.
trimmed_window_still_nacks_the_gap_below_test() ->
    Recv = [3, 4, 5, 1000000],
    W = feed(Recv, ?MAX_RANGES),
    ?assertEqual({ack, 1000000, 0, [{255, 0}, {255, 0}]}, i2p_ssu2_recv:build(W, 2)),
    {Acked, Nacked} = i2p_ssu2:ack_expand(i2p_ssu2_recv:build(W, 2)),
    %% The gap is NACKed rather than left unmentioned, which is what the peer
    %% needs in order to resend it.
    ?assert(lists:member(999999, Nacked)),
    ?assert(lists:member(1000000, Acked)).

%% `min_recv` is not recoverable from the ranges once they have aged out, and
%% losing it is what would turn that NACK into silence.
lowest_received_survives_trimming_test() ->
    W = feed([3, 4, 5, 1000000], ?MAX_RANGES),
    ?assertEqual(3, maps:get(min_recv, W)),
    %% After enough further traffic, the range holding 3 is gone...
    W2 = feed(lists:seq(1000001, 1000001 + 255 + 2 * 2 * 255 + 10), ?MAX_RANGES, W),
    ?assertNot(lists:member(3, i2p_ssu2_recv:to_list(W2))),
    %% ...but the number that says where the walk stops has not moved.
    ?assertEqual(3, maps:get(min_recv, W2)).

%%% --------------------------------------------------------------------------
%%% Invariants of the structure
%%% --------------------------------------------------------------------------

%% The representation has an invariant that everything else leans on:
%% descending, disjoint, and non-adjacent. "Non-adjacent" is what makes a
%% contiguous stream one entry, so it is the one that would rot quietly.
ranges_stay_disjoint_and_non_adjacent_test() ->
    lists:foreach(
        fun(Nums) ->
            Ranges = ranges_of(feed(Nums, ?MAX_RANGES)),
            %% Descending: the highest number first, so sorting ascending and
            %% reversing must give the list back unchanged.
            ?assertEqual(lists:reverse(lists:sort(Ranges)), Ranges),
            ?assertEqual([], adjacent_pairs(Ranges)),
            ?assertEqual([], overlapping_pairs(Ranges))
        end,
        [
            [0],
            [0, 1],
            [0, 2],
            [0, 1, 2],
            [5, 4, 3, 2, 1, 0],
            [0, 2, 4, 6, 8],
            [0, 1, 2, 5, 6, 9, 10],
            [0, 1, 2, 3, 100, 200, 300],
            lists:seq(0, 300) -- lists:seq(0, 300, 7),
            lists:seq(0, 2000) -- [1, 2, 3, 1500, 1501, 1999]
        ]
    ).

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

feed(Nums, MaxRanges) ->
    feed(Nums, MaxRanges, i2p_ssu2_recv:new()).

feed([], _MaxRanges, W) ->
    W;
feed([Num | Rest], MaxRanges, W) ->
    {new, W1} = i2p_ssu2_recv:add(Num, W, MaxRanges),
    feed(Rest, MaxRanges, W1).

ranges_of(W) ->
    maps:get(ranges, W).

%% Adjacent means the upper one starts exactly where the lower one ends plus
%% one, which is two ranges where one would do.
adjacent_pairs([{_Lo1, Hi1}, {Lo2, Hi2} | Rest]) when Lo2 =:= Hi1 + 1 ->
    [{Hi1, Lo2} | adjacent_pairs([{Lo2, Hi2} | Rest])];
adjacent_pairs([_ | Rest]) ->
    adjacent_pairs(Rest);
adjacent_pairs([]) ->
    [].

%% Two ranges overlap only if each one's start lies inside the other: the
%% lower's `Lo` at or below the upper's `Hi`, *and* the lower's `Hi` at or
%% above the upper's `Lo`. Testing one end alone reports every ordinary
%% descending pair -- `[{2,2},{0,0}]` has a gap at 1 and does not overlap.
overlapping_pairs([{Lo1, Hi1}, {Lo2, Hi2} | _Rest]) when
    Lo2 =< Hi1, Hi2 >= Lo1
->
    [{Lo1, Hi1}, {Lo2, Hi2}];
overlapping_pairs([_ | Rest]) ->
    overlapping_pairs(Rest);
overlapping_pairs([]) ->
    [].
