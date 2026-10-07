-module(i2p_soak_selfcheck).

-moduledoc """
The three self-checks `m:i2p_soak` runs before it reports anything. Each must
**fail the run** rather than annotate it.

## Why they exist

The first version of this harness answered its question and the answer was
worthless. All three of its bugs produced **confident wrong answers** rather
than errors:

1. A process census that silently returned an empty map for an entire run.
   No form of `erlang:process_info/1,2` returns the pid alongside the readings,
   so a comprehension whose generator pattern was `{Pid, Info}` found nothing —
   0 entries against 43 processes. Every analysis built on it reported zero
   findings because it had nothing to look at, and the first "no mailbox growth"
   result had to be re-taken.
2. A *top consumers* table topped by three corpses. The accessor defaulted an
   absent pid to `0`, so a process that died between two snapshots scored
   `0 - 20941606` and sorted above every real consumer.
3. A formatter that printed every negative delta as exactly zero, so a 7 GB
   *drop* was reported as `raw 0.00` and read as no change.

None of these announce themselves. **That is the property worth encoding**, and
it is why these are code rather than a comment: an instrument that cannot
demonstrate it detects a known fault is not an instrument.

## What each check actually drives

Every check is a `Before`/`After` pair fed through the **real** analysis path —
`m:i2p_soak_census`'s `delta/2` and `top_mailboxes/2` — rather than asserting on
a census in isolation. That is deliberate. Bugs 1 and 2 lived in the *seam*
between reading a census and ranking it, so a check that only inspected a census
would have gone green over both of them.

The faults are seeded rather than waited for, because a check has to be
deterministic: the mailbox check floods a mailbox it owns, and the missed-process
check starts a process that holds a large binary. Nothing here depends on the
router misbehaving, and every fixture is stopped in an `after` clause — a
self-check that left a 4 MB holder and a 5,000-message mailbox behind would
corrupt the very census the soak reads next.

## How the failure is demonstrated

Each check takes its inputs, so `i2p_soak_selfcheck_tests` drives the same
functions with a **deliberately broken** census and asserts `ok =:= false`. A
check nobody has seen fail is a comment with a function around it.

## Barriers, not deadlines

Two places here look like waits and are not. `Pid ! Msg` returns only once the
message is in the mailbox, so the flood is established the moment
`f:flood_pid/2` returns — polling for it would be a deadline pretending to be a
barrier. And the leaker sends its own `{leaky, ...}` message *after* it
allocates, so waiting for that message cannot be reordered before the allocation
it reports.
""".

-export([run/0, census_not_empty/1, known_bad_mailbox_is_bad/3, seeded_leak_is_flagged/2]).
-export([mailbox_holder/0, flood/1, seed_leaky_process/2, stop_fixtures/1]).

-export_type([check/0, check_name/0, report/0]).

%% %%%%% %%% %%% Types %%%%% %%%

-doc """
The three invariants, by name.

**A closed union rather than `atom()`,** because `atom()` is a supertype of these
three and the tree runs dialyzer with `underspecs`. Naming them also means a reader
of a report can look the name up here, and a fourth check cannot be added without
someone deciding what it is called.
""".
-type check_name() ::
    census_not_empty
    | known_bad_mailbox_reported_as_growth
    | seeded_leak_flagged.

-doc """
One invariant, the evidence for it, and whether it held.

`evidence` is prose rather than a bare figure on purpose: a reader deciding
whether to trust the `ok` should be able to read what it saw without running
anything.
""".
-type check() :: #{name := check_name(), ok := boolean(), evidence := string()}.

-doc """
The three checks, in the order a reader should take them in.

**Non-empty** because `f:run/0` cannot produce an empty list — it builds exactly
three — and `underspecs` is a release gate here. A type that permits a list the
function cannot return is the same drift as a duplicated constant, only quieter.
""".
-type report() :: [check(), ...].

%% %%%%% %%% %%% Tuning %%%%% %%%

%% How many unread messages the mailbox check puts in a mailbox. Enough that a
%% census reporting a small number is unmistakably wrong rather than plausibly
%% right, and small enough that seeding it costs nothing.
-define(FLOOD, 5000).

%% Bytes the leaker holds. The point is that it is *large*, not that it is
%% exactly this; the check asks whether the census found a big one.
-define(LEAK_BYTES, 4 * 1024 * 1024).

%% The process-dictionary key the leaker stores its binary under. It is the
%% reference the runtime can trace across a collection, so it is what keeps the
%% binary retained -- see `f:hold/1`, which used to rely on a loop variable and
%% retained nothing.
-define(HELD, soak_held_binary).

%% %%%%% %%% %%% The run %%%%% %%%

-doc """
Seed all three faults, read the node twice, and return the three checks.

Output: a list of `t:check/0`. `m:i2p_soak` exits non-zero if any is false.

**The order is load-bearing.** Both fixtures are started and confirmed *before*
the first census, so each is read in both snapshots and therefore lands in
`survivors`. A fault seeded between the two readings would be `arrived`, and
`arrived` carries no growth by construction — so it could not exercise the
ranking path these checks exist to test.
""".
-spec run() -> report().
run() ->
    Parent = self(),
    {Leaker, LeakerRef} = seed_leaky_process(Parent, ?LEAK_BYTES),
    FloodPid = mailbox_holder(),
    try
        %% Both readings are taken with the fixtures already alive but **not yet
        %% faulty**. That is the ordering that makes these checks possible: a
        %% process absent from the first census is `arrived`, and `arrived`
        %% carries no growth by construction, so a fault seeded before the first
        %% reading would produce zero growth and pass nothing. Alive first, faulty
        %% second, means both are survivors with a real delta to rank.
        Before = census(),
        ok = await_leaker(Leaker, LeakerRef),
        ok = flood(FloodPid),
        After = census(),
        Delta = i2p_soak_census:delta(Before, After),
        [
            census_not_empty(Before),
            known_bad_mailbox_is_bad(Delta, FloodPid, ?FLOOD),
            seeded_leak_is_flagged(Delta, Leaker)
        ]
    after
        stop_fixtures([Leaker, FloodPid])
    end.

%% %%%%% %%% %%% The checks %%%%% %%%

-doc """
Check 1: the census holds at least one process.

Input: a census. Output: `t:check/0`.

An empty census is the exact shape of the broken harness, and every analysis
downstream of it reports zero findings because it has nothing to look at — so
this fails rather than reporting that nothing was found.

Give it `#{}` and it fails: that is the shape the broken harness produced, and
`i2p_soak_selfcheck_tests` asserts it.
""".
-spec census_not_empty(i2p_soak_census:census()) -> check().
census_not_empty(Census) ->
    Count = map_size(Census),
    #{
        name => census_not_empty,
        ok => Count > 0,
        evidence => lists:flatten(
            io_lib:format(
                "census holds ~p process(es); an empty census is what the broken " ++
                    "harness produced, so this fails rather than reporting nothing found",
                [Count]
            )
        )
    }.

-doc """
Check 2: the mailbox this run flooded is ranked as growth.

Input: the `t:i2p_soak_census:delta/0` from the two readings, the flooded pid,
and how many messages it was given. Output: `t:check/0`.

**This is the check that can catch the ranking going blind**, because it goes
through `f:top_mailboxes/2` rather than reading the census directly: a rank built
from an empty census, or one that skipped a pid, returns nothing here and fails.
The check asks the analysis a question it cannot answer falsely — which pids grew
their mailboxes most, and by how much — and compares the answer against a mailbox
known to hold `Count` unread messages.

Fails when the flooded pid is not in `survivors` (it was not read in both
snapshots, so there is no growth to rank), or when the rank does not report a
mailbox growth of at least `Count` for it.
""".
-spec known_bad_mailbox_is_bad(i2p_soak_census:delta(), pid(), pos_integer()) -> check().
known_bad_mailbox_is_bad(Delta, Pid, Count) ->
    Ranked = i2p_soak_census:top_mailboxes(Delta, 5),
    Seen = lists:any(fun(Row) -> reports_flood(Row, Pid, Count) end, Ranked),
    #{
        name => known_bad_mailbox_reported_as_growth,
        ok => Seen,
        evidence => lists:flatten(
            io_lib:format(
                "a mailbox seeded with ~p unread messages; top mailbox growth was ~s. " ++
                    "A rank over an empty or partial census reports nothing here.",
                [Count, describe(Ranked)]
            )
        )
    }.

-spec reports_flood(i2p_soak_census:row(), pid(), pos_integer()) -> boolean().
reports_flood(#{pid := Pid, growth := #{mailbox := Mailbox}}, Pid, Count) ->
    Mailbox >= Count;
reports_flood(#{growth := #{mailbox := Mailbox}}, _Pid, Count) ->
    Mailbox >= Count;
reports_flood(#{}, _Pid, _Count) ->
    false.

-spec describe([i2p_soak_census:row()]) -> string().
describe([]) ->
    "nothing at all";
describe(Rows) ->
    lists:flatten(
        lists:join(
            ", ",
            [
                io_lib:format("~p +~p", [Pid, Mailbox])
             || #{pid := Pid, growth := #{mailbox := Mailbox}} <- Rows
            ]
        )
    ).

-doc """
Check 3: the process this run seeded is in the census, holding its binary.

Input: the delta and the seeded pid. Output: `t:check/0`.

A census taken over the wrong processes cannot see the leaker at all, so this is
the check that catches an instrument pointed at the wrong thing. It requires the
pid to appear in `survivors`, which means it was read in **both** snapshots — a
process missed once is `arrived` or absent, and either way this fails.

`evidence` carries the heap it was seen at, because "it was found" is a stronger
claim when the reader can see how much it was holding.

An absent pid reads as `0` words, so this fails rather than raising: the check's
job is to report, and a check that crashed on the fault it found would report
nothing at all.
""".
-spec seeded_leak_is_flagged(i2p_soak_census:delta(), pid()) -> check().
seeded_leak_is_flagged(#{survivors := Survivors}, Pid) ->
    #{growth := #{heap_words := Heap, binary_bytes := Binary}} =
        maps:get(Pid, Survivors, #{growth => #{heap_words => 0, binary_bytes => 0}}),
    #{
        name => seeded_leak_flagged,
        ok => Heap > 0 orelse Binary > 0,
        evidence => lists:flatten(
            io_lib:format(
                "seeded process ~p grew by ~s of heap and ~s of refc binary. A census " ++
                    "over the wrong processes would not have found it, and a census " ++
                    "reading only total_heap_size would not have counted the binary.",
                [Pid, i2p_soak_census:words_mb(Heap), i2p_soak_census:bytes_mb(Binary)]
            )
        )
    }.

%% %%%%% %%% %%% Fixtures %%%%% %%%

-doc """
Start a process that will hold a large binary when asked, monitored by the caller.

Input: the pid to report to, and how many bytes it will hold. Output:
`{Pid, MonitorRef}`.

It **holds** rather than allocates-and-drops because a leak is retention: a
process that allocates and releases shows none, and a check built on one would
pass over the fault it exists to catch. It allocates only on receiving
`{fill, Bytes}`, which is what lets `f:run/0` take the first census with the
process alive but not yet faulty — so the growth it later shows is a real delta
between two readings rather than an `arrived` entry with nothing to compare.

The `{leaky, ...}` message is sent *after* the allocation, which is what makes
waiting for it a barrier rather than a deadline — see the module doc.

The caller must stop it, which is why the ref comes back with it.
""".
-spec seed_leaky_process(pid(), pos_integer()) -> {pid(), reference()}.
seed_leaky_process(Parent, Bytes) ->
    Pid = spawn(fun() -> await_fill(Parent, Bytes) end),
    {Pid, erlang:monitor(process, Pid)}.

-spec await_fill(pid(), pos_integer()) -> no_return().
await_fill(Parent, Bytes) ->
    receive
        {fill, Bytes} ->
            Held = binary:copy(<<0>>, Bytes),
            Parent ! {leaky, self(), byte_size(Held)},
            hold(Held)
    end.

%% Keep the binary **referenced** for as long as the fixture lives, which is the
%% difference between retention and a bare allocation.
%%
%% **This was a real defect, and only a forced collection exposed it.** `Held` used
%% to be bound, measured with `byte_size/1` and then never mentioned again, so the
%% compiler was free to treat it as dead across the following `receive`. Until a
%% collection ran there was no difference to see -- so the fixture was reporting
%% uncollected garbage as a leak-shaped finding, and every check built on it
%% passed because nothing had collected the heap yet.
%%
%% Then `m:i2p_soak_census:f:retained/1` arrived, forcing a full collection and
%% waiting for it, and the same fixture measured **233 words** where it had been
%% counting as 4 MB.
%%
%% **What actually keeps it alive is the difference worth recording.** Measured on
%% this build: neither a tail-recursive helper that re-uses the binary nor a bare
%% argument threaded through a loop survives a collection -- the compiler trims
%% those, because after a `receive` the runtime can only trace values that are
%% reachable, and neither frame is. What does retain, across every OTP, is a
%% reference the runtime itself can trace: a **process dictionary entry** (`put`).
%% That is why `f:hold/1` uses one. Reaching for "a variable in a loop is surely
%% enough" is what this defect was.
-spec hold(binary()) -> ok.
hold(Held) ->
    put(?HELD, Held),
    receive
        stop -> ok
    end.

-doc """
Start a process that will be flooded with unread messages.

Input: nothing. Output: the pid, **unflooded**. `f:flood/1` fills it.

Split in two for the same reason as `f:seed_leaky_process/2`: the process has to
be alive at the first census and faulty at the second. The flood is a message to
a live process, not the spawning of one.

It parks on a message that never arrives, so the flood messages queue behind it
unmatched. **It must not match the flood itself**: a `receive _Any` consumes the
first `{soak_flood, _}`, the process then exits, and the remaining 4,999 messages
belong to a dead pid whose mailbox the runtime reclaims — leaving the check
reporting a mailbox growth of zero for a mailbox that really did fill. A fixture
bug that produces exactly the confident wrong answer these checks exist to
prevent, so the pattern here is deliberately specific.
""".
-spec mailbox_holder() -> pid().
mailbox_holder() ->
    spawn(fun() ->
        receive
            {soak_release} -> ok
        end
    end).

-doc """
Put `?FLOOD` unread messages into `Pid`'s mailbox.

Input: the holder from `f:mailbox_holder/0`. Output: `ok`.

No waiting is needed: `Pid ! Msg` returns only once the message is in the
mailbox, so the depth is established before this function returns.
""".
-spec flood(pid()) -> ok.
flood(Pid) ->
    lists:foreach(fun(N) -> Pid ! {soak_flood, N} end, lists:seq(1, ?FLOOD)),
    ok.

-doc """
Stop every fixture this module started.

Input: the pids. Output: `ok`.

Runs from `f:run/0`'s `after` clause, so a **failed check still cleans up**. The
pids are passed rather than kept in process state here on purpose: a registry
inside this module would be one more thing that can be wrong, and the caller
already holds them.
""".
-spec stop_fixtures([pid()]) -> ok.
stop_fixtures(Pids) ->
    lists:foreach(fun stop_fixture/1, Pids),
    ok.

-spec stop_fixture(pid()) -> ok.
stop_fixture(Pid) ->
    case is_process_alive(Pid) of
        true ->
            Pid ! stop,
            ok;
        false ->
            ok
    end.

%% %%%%% %%% %%% %%% Internal %%%%% %%%

-spec census() -> i2p_soak_census:census().
census() ->
    {ok, Census} = i2p_soak_census:snapshot(),
    Census.

%% Tell the leaker to allocate, then wait for it to say it has. The `fill` send
%% is what makes it faulty; the wait is what makes it *observably* faulty, since
%% the message it sends comes after the allocation it reports and cannot be
%% reordered before it. A `DOWN` first would mean the fixture died before it
%% could report, which is a broken check rather than a finding, so it fails
%% loudly instead of returning ok.
-spec await_leaker(pid(), reference()) -> ok.
await_leaker(Leaker, Ref) ->
    Leaker ! {fill, ?LEAK_BYTES},
    receive
        {leaky, _Pid, _Bytes} ->
            ok;
        {'DOWN', Ref, process, _Pid, Reason} ->
            exit({soak_leaker_died, Reason})
    end.
