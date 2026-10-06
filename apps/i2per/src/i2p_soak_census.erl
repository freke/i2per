-module(i2p_soak_census).

-moduledoc """
The instrument half of `m:i2p_soak`: snapshot every process on the node, compare
two snapshots, and turn the comparison into a verdict.

Kept apart from `m:i2p_soak` so the arithmetic is a pure function of two maps.
That is what makes the self-checks in `m:i2p_soak` possible at all — they feed
this module a census it has deliberately broken and ask whether the verdict
notices. An instrument that cannot be shown to notice is not an instrument.

## Why each of these functions is shaped the way it is

Every rule below exists because a version of this harness produced a
**confident wrong answer** rather than an error. That is the mode that costs the
most: a measurement reporting no problems because it is broken is worse than no
measurement, because it is believed.

**1. `f:census/0` pairs each pid with the item list it asked for, and
`f:snapshot/0` refuses an empty census.**

**No form of `erlang:process_info/1,2` returns the pid alongside the readings.**
Measured on OTP 28.5: the no-item form returns a bare proplist (`is_list` true,
`is_tuple` false), the item-list form returns a bare proplist, and only the
single-item form returns a `{Key, Value}` pair. So a comprehension matching on
`{Pid, Info}` finds nothing **in either form** and yields an empty census for the
whole run, silently. Measured here: 43 processes, 0 entries.

So `f:census/0` builds the pairing itself, from `erlang:processes/0` and the pid
it already holds. There is nothing to mis-match, and the hazard is gone rather
than avoided. An empty census is then a hard error (`empty_census`), not a run
that found nothing.

**2. `f:delta/2` never treats an absent pid as zero, and `f:top_consumers/2`
ranks only survivors.**

The old accessor defaulted a missing pid to `0`, so a process that died between
two snapshots scored `0 - 20941606` — the largest "consumption" in the run — and
sorted to the top of a table headed *top consumers*. A corpse is not a consumer,
and the absence of a reading is not a reading of zero. `f:delta/2` returns three
disjoint sets (`survivors`, `arrived`, `departed`), and only `survivors` holds a
comparable pair of readings.

**3. `f:words_mb/1` renders a negative delta as negative.**

The old formatter printed every negative delta as exactly `0.00`, so a 7 GB
*drop* was reported as `raw 0.00` and read as no change. Sign is information: a
drop and a flat line are different findings.

## What a verdict may and may not say

`f:verdict/2` is deliberately unable to call anything a leak. A slope is a
slope: to call it a leak you need to know the structure has no bound, and two
snapshots cannot show that. What the verdict can do is separate the two causes
that look identical in a single window — see `f:verdict/2`.
""".

-export([census/0, snapshot/0, delta/2, verdict/3, top_consumers/2, top_mailboxes/2]).
-export([words_mb/1, bytes_mb/1, require_non_empty/1, format_table/1]).

-export_type([census/0, sample/0, growth/0, delta/0, verdict/0, retention/0, row/0]).

%% %%%%% %%% Types %%%%% %%%

-doc "One process's readings at one instant, in the units named in each key.".
-type sample() :: #{
    module := module(),
    mailbox := non_neg_integer(),
    heap_words := non_neg_integer(),
    binary_bytes := non_neg_integer(),
    reductions := integer()
}.

-doc """
The signed change in each reading of `t:sample/0`.

Every value here is a difference between two readings **of the same pid**. There
is no way to build one without both, which is why the arrived and departed sets
in `t:delta/0` carry a `t:sample/0` and not a `t:growth/0`.
""".
-type growth() :: #{
    mailbox := integer(),
    heap_words := integer(),
    binary_bytes := integer(),
    reductions := integer()
}.

-doc """
Every readable process at one instant, keyed by pid.

A process that died between `erlang:processes/0` and its `process_info/2` call is
absent rather than present with zero readings, so `map_size/1` counts processes
that were actually read.
""".
-type census() :: #{pid() => sample()}.

-doc """
The comparison of two censuses, split so a value cannot be computed across a pid
that was not in both.

- `survivors` — pids in both, with the module they were running and their signed
  `growth`.
- `arrived` — in `After` only. Growth is **unknown, not zero**: there is no
  earlier reading to difference against.
- `departed` — in `Before` only. Nothing to rank.
""".
-type delta() :: #{
    survivors := #{pid() => #{module := module(), growth := growth()}},
    arrived := #{pid() => sample()},
    departed := #{pid() => sample()}
}.

-doc """
Why a structure grew, as far as two snapshots plus an offered-load figure can
tell.

- `traffic_proportional` — grew under load and gave it back when load stopped.
- `traffic_independent` — grew with no traffic offered, so something other than
  the offered work filled it. A real finding, and still not a leak: a bounded
  cache filling once looks identical.
- `inconclusive` — the window was too short or the load too small to say.
""".
-type retention() :: traffic_proportional | traffic_independent | inconclusive.

-doc """
What the numbers support, and what they do not.

`t:retention/0` is the classification; `slope_words` is the raw arithmetic with no
attribution attached. There is no `leak` key, and there cannot be one — see the
module doc.
""".
-type verdict() :: #{
    retention := retention(),
    slope_words := integer(),
    recovered_words := integer(),
    offered_events := non_neg_integer(),
    note := binary()
}.

-doc "One ranked entry: who it was, and how much it grew.".
-type row() :: #{pid := pid(), module := module(), growth := growth()}.

%% %%%%% %%% The census %%%%% %%%

%% `process_info/2`'s item-list form. Named once so the reading set is a single
%% fact rather than a list repeated per call site — and so adding a reading is
%% one edit that cannot leave a caller reading a key nobody sets.
%% **`binary` is on that list because `total_heap_size` cannot see the thing this
%% harness most needs to see.** Measured on this build: a process holding a 4 MB
%% refc binary reports `total_heap_size` 233 words and
%% `erlang:process_info(Pid, memory)` 2624 bytes -- *neither counts the binary*.
%% `process_info(Pid, memory)` is a plain total, not a breakdown, and on OTP 28
%% the no-item form has no `memory` key at all; the per-category figure lives in
%% the `binary` item as `[{Address, Bytes, RefCount}]`.
%%
%% This is not a hypothetical blind spot: the first version of this harness drove
%% refc binaries to 11 GB in under ten seconds and the heap readings did not
%% move, so a census reading only `total_heap_size` would have called that run
%% clean. The leaky-process check found it, by failing against a 4 MB holder it
%% had seeded itself.
-define(ITEMS, [
    message_queue_len, total_heap_size, reductions, current_function, binary
]).

-doc """
Read every process on this node.

One `process_info/2` per pid in the **item-list** form (cheaper than the full
form), paired with **the pid this function already holds** — because no form of
`process_info` returns it. That pairing is the fix for the silent-empty-census
bug: there is nothing to mis-match.

Output: `{ok, Census}`.
""".
-spec census() -> {ok, census()}.
census() ->
    read(erlang:processes(), #{}).

-spec read([pid()], census()) -> {ok, census()}.
read([], Acc) ->
    {ok, Acc};
read([Pid | Rest], Acc) ->
    case erlang:process_info(Pid, ?ITEMS) of
        undefined ->
            %% Died between the enumeration and this read. Skipped rather than
            %% recorded as zeros: it is not a process with an empty mailbox, it
            %% is a process that was not there.
            read(Rest, Acc);
        Info ->
            read(Rest, Acc#{Pid => sample(Info)})
    end.

%% `maps:from_list/1` on the proplist, because `erlang:process_info/2` returns a
%% proplist in **both** forms. Reading it with `maps:get/2` raises `bad map` --
%% which is the one failure mode that announces itself, and worth having here
%% rather than a `proplists:get_value/2` that would quietly default to 0 on a
%% key the OTP stops sending. See the module doc for the bug this module exists
%% to make impossible: an absent reading silently becoming a zero.
-spec sample([{atom(), term()}]) -> sample().
sample(Proplist) ->
    Info = maps:from_list(Proplist),
    #{
        module => module_of(maps:get(current_function, Info, undefined)),
        mailbox => maps:get(message_queue_len, Info, 0),
        heap_words => maps:get(total_heap_size, Info, 0),
        binary_bytes => binary_bytes(maps:get(binary, Info, [])),
        reductions => maps:get(reductions, Info, 0)
    }.

%% The `binary` item is a list of `{Address, Bytes, RefCount}`. Summing the middle
%% element is the whole point: a process holding no refc binary reports `[]`, and
%% `maps:get(binary, Info, 0)` would raise on that. Both the empty case and an
%% OTP that reshapes the item land on 0 rather than on a crash, because a
%% reading this module cannot take must not be invented -- but the leaky-process
%% check is what proves the sum is working rather than merely silent.
-spec binary_bytes([{integer(), non_neg_integer(), pos_integer()}] | term()) -> non_neg_integer().
binary_bytes(Held) when is_list(Held) ->
    lists:sum([Bytes || {_Address, Bytes, _RefCount} <- Held]);
binary_bytes(_) ->
    0.

-spec module_of(term()) -> module().
module_of({Module, _Fun, _Arity}) when is_atom(Module) -> Module;
module_of(_) -> unknown.

-doc """
The census every other reading in this module is taken against.

Output: `{ok, Census}`, or `{error, empty_census}`.

The empty case is an **error, not an empty result**. Those two are the same thing
to every caller downstream, which is exactly how a broken instrument reports "no
problems found"; the branch is what separates them.

Input: nothing. Output: `{ok, t:census/0}` or `{error, empty_census}`.
""".
-spec snapshot() -> {ok, census()} | {error, empty_census}.
snapshot() ->
    require_non_empty(element(2, census())).

-doc """
Refuse an empty census.

Exported separately from `f:snapshot/0` so a self-check can assert the failure
path directly: given `#{}` it returns `{error, empty_census}`, which is what a run
must see rather than a clean bill of health.

Input: a `t:census/0`. Output: `{ok, Census}` or `{error, empty_census}`.
""".
-spec require_non_empty(census()) -> {ok, census()} | {error, empty_census}.
require_non_empty(Census) when map_size(Census) =:= 0 -> {error, empty_census};
require_non_empty(Census) -> {ok, Census}.

%% %%%%% %%% The comparison %%%%% %%%

-doc """
Compare two censuses.

Output: `t:delta/0`.

The survivor clause requires `#{Pid := _}` in **both** maps, so the missing-pid
case cannot reach the subtraction — there is no `maps:get/3` with a `0` default
anywhere in this function. That is the corpse-ranking fix, and it is structural
rather than a matter of being careful.

Input: `Before` and `After`, both `t:census/0`. Output: `t:delta/0`.
""".
-spec delta(census(), census()) -> delta().
delta(Before, After) ->
    #{
        survivors => survivors(Before, After, #{}),
        arrived => maps:with(maps:keys(After) -- maps:keys(Before), After),
        departed => maps:with(maps:keys(Before) -- maps:keys(After), Before)
    }.

%% The guard is the fix: a pid is only ever compared when `After` actually holds
%% a reading for it, so "absent" is settled before any subtraction happens.
-spec survivors(census(), census(), #{pid() => #{module := module(), growth := growth()}}) ->
    #{pid() => #{module := module(), growth := growth()}}.
survivors(Before, After, Acc) ->
    maps:fold(
        fun
            (Pid, _Sample0, Acc0) when is_map_key(Pid, After) ->
                #{module := Module} = Sample1 = maps:get(Pid, After),
                Acc0#{Pid => #{module => Module, growth => growth(Sample1, maps:get(Pid, Before))}};
            (_Pid, _Sample, Acc0) ->
                Acc0
        end,
        Acc,
        Before
    ).

-spec growth(sample(), sample()) -> growth().
growth(
    #{
        mailbox := M1,
        heap_words := H1,
        binary_bytes := B1,
        reductions := R1
    },
    #{mailbox := M0, heap_words := H0, binary_bytes := B0, reductions := R0}
) ->
    #{
        mailbox => M1 - M0,
        heap_words => H1 - H0,
        binary_bytes => B1 - B0,
        reductions => R1 - R0
    }.

-doc """
The processes that consumed the most reductions between two snapshots.

Only `survivors` are eligible, and a pid is in `survivors` only if it was read in
**both** snapshots. A pid that arrived or departed during the window has no
comparable pair, and letting it into this table is what put three corpses at the
top of it.

Input: `D` (`t:delta/0`) and `N`. Output: up to `N` `t:row/0`, largest first.
""".
-spec top_consumers(delta(), pos_integer()) -> [row()].
top_consumers(#{survivors := Survivors}, N) ->
    rank(Survivors, reductions, N).

-doc """
The processes whose mailboxes grew most between two snapshots.

Mailbox growth is the finding the original diagnostic run was looking for: a
process that stops reading accumulates. Input as `f:top_consumers/2`, ranked on
the mailbox reading.
""".
-spec top_mailboxes(delta(), pos_integer()) -> [row()].
top_mailboxes(#{survivors := Survivors}, N) ->
    rank(Survivors, mailbox, N).

%% Reverse *first*, then take N. `lists:sublist/2` on an ascending list returns
%% the N **smallest**, so reversing afterwards ranks the table's least
%% interesting entries at the top -- a table headed "top consumers" whose every
%% row is zero. Written the other way round it looks correct and reports
%% nothing, which is how the mailbox check below caught it.
-spec rank(
    #{pid() => #{module := module(), growth := growth()}}, mailbox | reductions, pos_integer()
) ->
    [row()].
rank(Survivors, Key, N) ->
    Descending = lists:reverse(
        lists:sort([
            {maps:get(Key, G), Pid}
         || {Pid, #{growth := G}} <- maps:to_list(Survivors)
        ])
    ),
    [
        #{
            pid => Pid,
            module => maps:get(module, Entry),
            growth => maps:get(growth, Entry)
        }
     || {_Growth, Pid} <- lists:sublist(Descending, N),
        Entry <- [maps:get(Pid, Survivors)]
    ].

%% %%%%% %%% The verdict %%%%% %%%

-doc """
What the numbers support.

**This function cannot return the word "leak", and that is the design.** A slope
is a slope: calling it a leak means asserting the structure is unbounded, and two
snapshots cannot show that. What it can do is separate the two causes that look
identical inside a single window:

- Grew under load and **gave memory back** once the load stopped →
  `traffic_proportional`. It retained in proportion to what it was given.
- Grew under load and **did not give anything back** →
  `traffic_independent`. Something other than the offered traffic filled it.
  That is a real finding and it is **not yet a leak**: a bounded cache filling
  once looks exactly the same, and telling those apart needs a longer window
  than a soak run has.
- Did not grow → `inconclusive`.

**It classifies on retained memory, not on reductions.** Reductions are cumulative
and monotonic -- a process that is merely alive keeps accruing them -- so "did it
give its consumption back" is not a question reductions can answer, and every run
classified `traffic_independent`. Retention is a property of memory, and memory
can fall, which is what makes the negative branch reachable at all. The reduction
slope is still worth having as `top_consumers/2` output, which is the figure that
answers *who did the work*; it just does not decide *why they kept it*.

The `note` states the three figures it reasoned from, so a reader can check the
classification rather than take it.

Input: `Loaded` (the delta across the load window), `Drained` (the delta across
the quiet window after the load stopped), and the number of events offered.
Output: `t:verdict/0`.
""".
-spec verdict(delta(), delta(), non_neg_integer()) -> verdict().
verdict(#{survivors := Loaded}, #{survivors := Drained}, Offered) ->
    Held = retained_words(Loaded),
    Released = retained_words(Drained),
    #{
        retention => classify(Held, Released),
        slope_words => Held,
        recovered_words => Released,
        offered_events => Offered,
        note => note(Held, Released, Offered)
    }.

%% Words retained, summed over the processes read in both snapshots.
%% `binary_bytes` is divided by 8 so it shares a unit with `heap_words`;
%% conflating the two would overstate every off-heap figure eightfold.
-spec retained_words(#{pid() => #{module := module(), growth := growth()}}) -> integer().
retained_words(Survivors) ->
    lists:sum([
        maps:get(heap_words, G) + maps:get(binary_bytes, G) div 8
     || {_, #{growth := G}} <- maps:to_list(Survivors)
    ]).

-spec classify(integer(), integer()) -> retention().
classify(Held, _Released) when Held =< 0 ->
    %% Nothing was retained across the load window, so there is nothing to
    %% attribute.
    inconclusive;
classify(_Held, Released) when Released < 0 ->
    traffic_proportional;
classify(_Held, _Released) ->
    traffic_independent.

-spec note(integer(), integer(), non_neg_integer()) -> binary().
note(Held, Released, Offered) ->
    list_to_binary(
        lists:flatten(
            io_lib:format(
                "words retained across the load window ~p, and across the quiet "
                "window after it ~p, for ~p events offered. A retained slope is "
                "not a leak: telling an unbounded structure from a cache that "
                "filled once needs a window longer than this run has.",
                [Held, Released, Offered]
            )
        )
    ).

%% %%%%% %%% Rendering %%%%% %%%

-doc """
Render a signed word count as megabytes, keeping the sign.

A negative delta is a **drop**, and printing it as `0.00` is how a 7 GB release
reads as no change. The sign is the finding.

Input: `Words`, signed. Output: a string like `"-54613.33 MB"`.
""".
-spec words_mb(integer()) -> string().
words_mb(Words) ->
    lists:flatten(io_lib:format("~.2f MB", [Words * 8 / 1048576.0])).

-doc """
Render a ranked table for the report.

Input: rows from `f:top_consumers/2` or `f:top_mailboxes/2`. Output: a list of
lines.

**Each row names its own module**, taken from the reading it was ranked from, so
this needs no second lookup — and there is therefore no way for a row to print a
bare pid, or for an unnamed process to reach the table at all. Both were the
corpse bug's shape.
""".
-spec format_table([row()]) -> [string()].
format_table(Rows) ->
    [format_row(Row) || Row <- Rows].

-spec format_row(row()) -> string().
format_row(#{pid := Pid, module := Module, growth := Growth}) ->
    lists:flatten(
        io_lib:format("  ~p ~-24s reductions +~s  mailbox ~+b  heap ~s  binary ~s", [
            Pid,
            Module,
            words_mb(maps:get(reductions, Growth)),
            maps:get(mailbox, Growth),
            words_mb(maps:get(heap_words, Growth)),
            bytes_mb(maps:get(binary_bytes, Growth))
        ])
    ).

-doc """
Render a signed **byte** count as megabytes, keeping the sign.

Split from `f:words_mb/1` because off-heap refc-binary memory is counted in
bytes by `erlang:process_info/2` and in words by `total_heap_size`, and
conflating the two would overstate every binary figure by eight.
""".
-spec bytes_mb(integer()) -> string().
bytes_mb(Bytes) ->
    lists:flatten(io_lib:format("~.2f MB", [Bytes / 1048576.0])).
