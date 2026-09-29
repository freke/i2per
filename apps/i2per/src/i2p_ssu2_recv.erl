%% The set of Data packet numbers an SSU2 session has received.
%%
%% A session needs this set for two things: to recognise a retransmission, and
%% to build the ACK block that tells the peer what to stop resending. The
%% obvious representation -- a flat list of every number ever seen, prepended
%% on each packet -- satisfies both and is wrong, because it is never pruned.
%% The set grows by one entry per packet for the life of the session and the
%% membership test is a linear scan of it, so the cost of receiving a datagram
%% rises with the number of datagrams already received. At 1,000 packets per
%% second that is 16 bytes of heap per packet forever: about 54 MB an hour on
%% one session, with the scan measured at 1.6 ms per datagram after a million
%% packets.
%%
%% So the set is held as **ranges**: a descending list of disjoint,
%% non-adjacent inclusive `{Lo, Hi}` pairs. Contiguous arrival -- the normal
%% case, and what a session actually sees -- collapses to a single range, so
%% the structure is O(1) for a healthy session however long it runs, and
%% membership scans a handful of ranges rather than every packet ever
%% received. Memory becomes proportional to the number of *gaps* in the
%% receive stream rather than to its length.
%%
%% The bound is not chosen, it is read off the wire format. An ACK block names
%% at most `?ACK_MAX` consecutive packets in its `acnt` field plus `MaxRanges`
%% `{nack, ack}` pairs of one byte each, so it cannot name a packet number
%% further than `?ACK_MAX + MaxRanges * 2 * ?ACK_MAX` below `AckThrough`.
%% Anything deeper is unnameable in any ACK this session could send, so
%% retaining it cannot change a byte on the wire -- and dropping it is what
%% bounds the structure in the pathological case too, where a peer that loses
%% every other packet would otherwise leave one range per gap.
%%
%% The **lowest number ever received** is carried separately from the ranges,
%% because it is not the same thing as the lowest retained range and the
%% distinction is load-bearing. A session that has received packets 3, 4, 5 and
%% 1,000,000 retains only the last of those, but the numbers below it were
%% still never received, and the ACK block says so with a NACK the peer acts
%% on. `m:i2p_ssu2:build_ack/2` stops its walk at that number, so a window
%% that forgot it would turn a NACK into silence -- which is exactly how a peer
%% concludes we want nothing resent.
%%
%% See #7GP4A4K.
-module(i2p_ssu2_recv).

-moduledoc """
The bounded set of Data packet numbers an SSU2 session has received.

One session holds one of these. It is the input to `m:i2p_ssu2:build_ack/2` and
the authority on whether an inbound packet number is a retransmission. See the
module documentation for why it is a range list rather than a flat one, why the
bound is derived from the ACK block's own reach rather than picked, and why the
lowest number ever received is kept separately from the ranges.
""".

-export([new/0, add/3, contains/2, build/2, to_list/1, range_count/1, size/1]).

-export_type([window/0]).

%% The largest count a single `nack`/`ack` byte pair can express. This is the
%% format's limit, not ours, and it is why the receive window's reach is finite.
-define(ACK_MAX, 255).

-doc """
A session's received-packet window.

`ranges` is a descending list of disjoint, non-adjacent inclusive
`{Lo, Hi}` packet-number ranges, so the head holds the highest number received.
Disjoint and non-adjacent is an invariant, not an accident: two ranges one
apart are one range, and that is what keeps a contiguous receive stream at a
single entry.

`min_recv` is the lowest number **ever** received, which is not necessarily in
`ranges` -- it may have aged out below the retained reach. It is where the ACK
walk stops, so it cannot be recovered from the ranges and is stored.
""".
-type window() :: #{
    ranges := [{non_neg_integer(), non_neg_integer()}],
    min_recv := non_neg_integer()
}.

-doc """
An empty receive window.

Input: none. Output: a `t:window/0` holding nothing, which is what a session
starts with before packet zero.
""".
%% The spec names the exact empty term rather than the general `window()` type,
%% because the type is a superset of what this returns and a wider spec is an
%% underspec: it would promise callers a `min_recv` they cannot rely on and let
%% dialyzer miss a caller that assumed otherwise.
-spec new() -> #{ranges := [], min_recv := 0}.
new() ->
    #{ranges => [], min_recv => 0}.

-doc """
Whether `Num` has already been received, and so is a retransmission.

Input: a packet number and a `t:window/0`. Output: a boolean.

A number that has aged out of the retained ranges reads as not-received. That
is the safe direction to be wrong in: such a packet is a duplicate the peer has
already moved past, and block handling is idempotent by message identity, so
re-processing it costs a little work rather than corrupting state. `f:add/3`
reports these as `stale` so they are visible rather than silent.
""".
-spec contains(non_neg_integer(), window()) -> boolean().
contains(Num, #{ranges := Ranges}) ->
    in_ranges(Num, Ranges).

%% The recursion walks the range list rather than a rebuilt window: the
%% membership test never needs `min_recv`, and carrying the whole window through
%% each step would put a field on the path that the test does not read.
in_ranges(_Num, []) ->
    false;
in_ranges(Num, [{Lo, Hi} | _]) when Num >= Lo, Num =< Hi ->
    true;
in_ranges(Num, [{_Lo, Hi} | _]) when Num > Hi ->
    %% Above the head, hence above every retained range.
    false;
in_ranges(Num, [_ | Rest]) ->
    in_ranges(Num, Rest).

-doc """
Record `Num` as received.

Input: `Num` -- the packet number; `Window` -- a `t:window/0`; `MaxRanges` --
the ACK range budget this session sends, which is what fixes the reach.
Output: `{new, Window1}` if the number was not already recorded, `duplicate` if
it was, and `stale` if it falls below the retained reach.

`duplicate` and `stale` are both "do not record this", and they are kept apart
because they mean different things to an operator. A duplicate is the network
or the peer doing something ordinary. `stale` is a real case rather than an
error: a number more than `?ACK_MAX + MaxRanges * 2 * ?ACK_MAX` below the
highest received cannot appear in any ACK this session sends, so recording it
would grow the window without changing a byte on the wire. The caller counts
it, which is what makes an out-of-window retransmit visible instead of silently
processed as new.
""".
-spec add(non_neg_integer(), window(), non_neg_integer()) ->
    {new, window()} | duplicate | stale.
add(Num, #{ranges := []} = Window, _MaxRanges) ->
    {new, Window#{ranges => [{Num, Num}], min_recv => Num}};
add(Num, #{ranges := Ranges, min_recv := MinRecv} = Window, MaxRanges) ->
    case contains(Num, Window) of
        true ->
            duplicate;
        false ->
            Top = element(2, hd(Ranges)),
            case Num < Top - reach(MaxRanges) of
                true ->
                    stale;
                false ->
                    %% `min_recv` only ever falls: it is the lowest number this
                    %% session has seen, and the ACK walk stops there even after
                    %% the range holding it has aged out.
                    Trimmed = trim(insert(Num, Ranges), min(Num, MinRecv), MaxRanges),
                    {new, Trimmed}
            end
    end.

%% How far below `AckThrough` an ACK block can still name a packet number: the
%% `acnt` field's ?ACK_MAX consecutive, then each of `MaxRanges` pairs carrying
%% up to two more. The format's limit, not a tuning knob.
reach(MaxRanges) ->
    ?ACK_MAX + MaxRanges * 2 * ?ACK_MAX.

%% Insert `Num` into the descending, disjoint, non-adjacent range list. The
%% caller has already established that `Num` is not present, so the only cases
%% are above a range, adjacent to one, or in a gap between two.
insert(Num, []) ->
    [{Num, Num}];
insert(Num, [{_Lo, Hi} = Head | Rest]) when Num > Hi + 1 ->
    %% Above the head with a gap between them: a range of its own.
    [{Num, Num}, Head | Rest];
insert(Num, [{Lo, Hi} | Rest]) when Num =:= Hi + 1 ->
    %% Immediately above the head: widen it upwards. Keeping adjacent numbers
    %% in one range is what makes a contiguous receive stream one entry.
    [{Lo, Num} | Rest];
insert(Num, [{Lo, Hi} | Rest]) when Num =:= Lo - 1 ->
    %% Immediately below the head: widen it downwards.
    [{Num, Hi} | Rest];
insert(Num, [{_Lo, _Hi} = Head | Rest]) ->
    %% Below the head across a gap wider than one packet, so widening cannot
    %% reach it: it belongs to a lower range, or starts a new one.
    [Head | insert(Num, Rest)].

%% Drop what the ACK block can no longer name, and bound the number of ranges
%% retained to the ones a block can carry.
trim(Ranges, MinRecv, MaxRanges) ->
    Top = element(2, hd(Ranges)),
    Floor = Top - reach(MaxRanges),
    #{ranges => depth_trim(lists:sublist(Ranges, MaxRanges + 1), Floor), min_recv => MinRecv}.

%% Retain every range reaching at or above `Floor`, and clip the lowest
%% survivor's low end up to it. A range straddling the floor is retained, not
%% dropped: it still names received packets inside the window.
depth_trim(Ranges, Floor) ->
    case lists:takewhile(fun({_Lo, Hi}) -> Hi >= Floor end, Ranges) of
        [{Lo, Hi}] when Lo < Floor ->
            [{Floor, Hi}];
        Kept ->
            Kept
    end.

-doc """
The ACK block describing what has been received.

Input: a `t:window/0` and `MaxRanges`, the range budget to encode within.
Output: a `t:m:i2p_ssu2:ack_block/0`.

Building it here rather than in `m:i2p_ssu2:build_ack/2` is what keeps the
receive path cheap: the block is derived by walking the handful of retained
ranges, not by materialising every packet number the session ever received. The
two are the same function -- `build_ack/2` on a list delegates here -- so there
is one implementation and one place where the wire format is decided.
""".
-spec build(window(), non_neg_integer()) -> tuple().
build(#{ranges := []}, _MaxRanges) ->
    {ack, 0, 0, []};
build(#{ranges := [{Lo, Top} | _] = Ranges, min_recv := MinRecv}, MaxRanges) ->
    Acnt = min(?ACK_MAX, Top - Lo),
    Rest =
        case Top - Acnt - 1 >= Lo of
            true -> [{Lo, Top - Acnt - 1} | tl(Ranges)];
            false -> tl(Ranges)
        end,
    {ack, Top, Acnt, walk(Rest, Top - Acnt - 1, MinRecv, MaxRanges, [])}.

%% Walk down from `Low`, emitting one `{nack, ack}` pair per gap-and-run. Runs
%% wider than ?ACK_MAX take several pairs, because that is the width of the
%% field that carries them; `MaxRanges` is the only thing that stops the walk,
%% which is why it stops where it does rather than at the lowest range.
walk(_Rest, _Low, _MinRecv, 0, Acc) ->
    lists:reverse(Acc);
walk(_Rest, Low, MinRecv, _MaxRanges, Acc) when Low < MinRecv ->
    lists:reverse(Acc);
walk([], Low, MinRecv, MaxRanges, Acc) ->
    %% Nothing further was received, and the numbers between here and the
    %% lowest ever received never arrived: a NACK, not silence.
    gap_walk(Low, MinRecv, MaxRanges, Acc);
walk([{Lo, Hi} = Range | Rest], Low, MinRecv, MaxRanges, Acc) ->
    Gap = Low - Hi,
    case Gap > ?ACK_MAX of
        true ->
            walk([Range | Rest], Low - ?ACK_MAX, MinRecv, MaxRanges - 1, [
                {?ACK_MAX, 0} | Acc
            ]);
        false ->
            RunLen = Hi - Lo + 1,
            case RunLen > ?ACK_MAX of
                true ->
                    walk(
                        [{Lo, Hi - ?ACK_MAX} | Rest],
                        Hi - ?ACK_MAX,
                        MinRecv,
                        MaxRanges - 1,
                        [{Gap, ?ACK_MAX} | Acc]
                    );
                false ->
                    walk(Rest, Lo - 1, MinRecv, MaxRanges - 1, [{Gap, RunLen} | Acc])
            end
    end.

%% A tail of NACK-only pairs covering the gap down to the lowest received.
gap_walk(_Low, _MinRecv, 0, Acc) ->
    lists:reverse(Acc);
gap_walk(Low, MinRecv, _MaxRanges, Acc) when Low < MinRecv ->
    lists:reverse(Acc);
gap_walk(Low, MinRecv, MaxRanges, Acc) ->
    Gap = min(?ACK_MAX, Low - MinRecv + 1),
    gap_walk(Low - Gap, MinRecv, MaxRanges - 1, [{Gap, 0} | Acc]).

-doc """
Every packet number the window still records, as a flat list.

Input: a `t:window/0`. Output: the numbers, highest first.

Exponential in the number of ranges, so this is for tests and diagnostics and
never for a packet path -- the packet path uses `f:build/2`, which walks the
ranges. It exists so a test can assert on the set rather than on the structure
holding it.
""".
-spec to_list(window()) -> [non_neg_integer()].
to_list(#{ranges := Ranges}) ->
    %% `lists:seq/2` only counts upwards, so each run is built ascending and
    %% reversed -- the output is highest-first, matching the ranges' own order.
    lists:append([lists:reverse(lists:seq(Lo, Hi)) || {Lo, Hi} <- Ranges]).

-doc """
How many ranges the window holds.

Input: a `t:window/0`. Output: a count.

This is the number that was previously unbounded in the packet count, so it is
what a test asserts on to show the structure no longer grows with traffic.
""".
-spec range_count(window()) -> non_neg_integer().
range_count(#{ranges := Ranges}) ->
    length(Ranges).

-doc """
The size of the window in heap words.

Input: a `t:window/0`. Output: the term's own size.

Asserting the structure is cheaper than asserting process memory and catches
the regression directly; `erlang:external_size/1` is the coarse companion for
the case where something else on the same state map is what grew.
""".
-spec size(window()) -> non_neg_integer().
size(Window) ->
    erlang:external_size(Window).
