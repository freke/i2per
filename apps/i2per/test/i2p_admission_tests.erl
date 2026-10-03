%% Tests that the connection cap is a cap, and that the `global` lock which used
%% to enforce it is gone.
%%
%% ## What was wrong
%%
%% All three supervisors admitted a child with `global:trans/2`, wrapping the
%% count and the `supervisor:start_child/2` in what reads as a mutex:
%%
%%     global:trans({?MODULE, connection_admission}, fun() -> ... end)
%%
%% **It is not a mutex.** `m:global:set_lock/3` documents the lock as shared:
%%
%%     The global name server keeps track of all processes sharing the same lock,
%%     that is, if two processes set the same lock, both processes must delete
%%     the lock.
%%
%% A lock id is `{ResourceId, LockRequesterId}` and the name server matches on the
%% *pair*, so a second process asking for an id that is already held is *added* to
%% the holder list and answered `true`. Twelve dialers sharing one id therefore all
%% run the body.
%%
%% It only looks exclusive when the body is quick. `set_lock/4` waits by retrying
%% through `random_sleep/1`, so a loser comes back while the holder is still inside
%% and is granted the lock then. Measured here, twelve processes on one id: one
%% process inside at a time when the body returns immediately, all twelve when it
%% sleeps 2 ms. The real body is a supervision-tree walk and a process start.
%%
%% **So the cap did not hold.** Reverting these three functions to the shape above
%% and running the three cap cases below, with a cap of 4 and 24 dials released
%% together: 8, 10 and 24 admitted for NTCP2, SSU2 and SAM. Those are three runs of
%% the same test, which is the point -- the number moves, because nothing is
%% synchronising it.
%%
%% ## The three properties, and why each is its own case
%%
%% **The cap holds under concurrency.** These are the cases that fail against the
%% old code, and the load-bearing ones in this module. Count-then-start is a race
%% unless the two halves are atomic, and a peer-set rebuild completes many
%% handshakes in the same instant -- the moment the count is most likely to be read
%% twice before either start lands. They use a *barrier*, not a sleep: every dialer
%% is confirmed waiting before any is released, so they race for real rather than
%% being staggered into not racing at all.
%%
%% **Admission does not consult a cluster-wide lock.** A behavioural case, not a
%% grep: it *takes* the old lock id and asserts an admission still returns promptly.
%% **What it does not catch, stated plainly, because the obvious reading of it is
%% wrong:** it passed against the old code too. That lock was shared, so holding
%% the id blocked nobody. It catches the other way the lock could come back -- an
%% *exclusive* one, which is what a per-process `LockRequesterId` or a
%% `global:register_name/3` mutex gives you -- and it costs four lines.
%%
%% **The three caps are independent.** A router refusing a ninth SAM session while
%% an NTCP2 connection is admitted is the ticket's open question, answered by
%% assertion rather than by a comment: a shared admission process, or a shared
%% counter, would make these one queue.
%%
%% ## What is *not* under test
%%
%% The child that gets admitted is a sleeper, not a connection or a session. The
%% property here is the cap, and building a real handshake for 24 processes would
%% test `i2p_ntcp2_conn` and `i2p_ssu2_conn` instead. What the sleeper does keep is
%% the part that matters: its child id carries the tag the count filters on, so a
%% count that stopped filtering on the right tag would report zero and leave the cap
%% unenforceable while every assertion here passed.

-module(i2p_admission_tests).

-moduledoc """
Tests that the connection cap is a cap under concurrent dials, that admitting a
child no longer takes a cluster-wide lock, and that the three caps are
independent of one another.
""".

-include_lib("eunit/include/eunit.hrl").

-define(APP, i2per).

%% The sleeper, which lives until its supervisor goes, so a count read back after
%% a race reflects the children the race admitted rather than children that
%% happened to still be starting. Both are exported because a child spec's `start`
%% is an MFA: the compiler cannot see the reference, and neither can anything else.
%% They live here rather than in `i2p_admission` so nothing in the core can start
%% one.
-export([sleeper_start_link/0, sleeper_init/0]).

%% Dials per case, and the cap they race for. The dials deliberately exceed the
%% cap by a wide margin: a case with exactly as many dials as slots would pass
%% against a check-then-start that was never atomic, because nothing would ever be
%% refused. The gap is what makes the assertion mean something.
-define(DIALS, 24).
-define(CAP, 4).

%% How long a dialer may take to arrive or answer before the case concludes
%% something is wrong. Generous against a loaded machine, and it is a bound rather
%% than a sleep: a case that hangs is a case that reports nothing.
-define(BOUND_MS, 2000).

%%% %%%%% %%% The cap holds under concurrent dials %%%%% %%%

%% Each of the three, as its own case rather than one case looping over a list.
%%
%% A parameterised case that failed would name no resource, and "the cap does not
%% hold" is not an actionable report when three caps exist. Three near-identical
%% bodies is the trade this project makes elsewhere for a failure message that
%% can be acted on.
ntcp2_cap_holds_under_concurrent_dials_test() ->
    assert_cap_holds(ntcp2_cap, i2p_ntcp2_sup, fun start_ntcp2/0, max_ntcp2_connections).

ssu2_cap_holds_under_concurrent_dials_test() ->
    assert_cap_holds(ssu2_cap, i2p_ssu2_sup, fun start_ssu2/0, max_ssu2_sessions).

sam_cap_holds_under_concurrent_dials_test() ->
    assert_cap_holds(sam_cap, i2p_sam_sup, fun start_sam/0, max_sam_sessions).

%%% %%%%% %%% No cluster-wide lock %%%%% %%%

%% **Narrower than it looks, and deliberately.** The three lock ids are the ones the
%% code used to take, written out rather than derived from a module — deriving them
%% would be a case looking for a lock to find. Each is held by this process for the
%% duration, and every admission below must still return.
%%
%% This does **not** fail against the code as it stood, and the module doc says why:
%% that lock was shared rather than exclusive, so holding the id blocked nobody. What
%% it does catch is the lock coming back in an exclusive form — a per-process
%% `LockRequesterId`, or a `global:register_name/3` used as a mutex, either of which
%% is the shape a well-meaning fix for the shared-lock bug would take. That is worth
%% four lines, and it is worth being explicit that it is not what pins the cap: the
%% three cases above are.
admission_does_not_consult_a_cluster_wide_lock_test() ->
    Locks = [
        {i2p_ntcp2_sup, connection_admission},
        {i2p_ssu2_sup, session_admission},
        {i2p_sam_sup, session_admission}
    ],
    lists:foreach(fun(Id) -> true = global:set_lock(Id, [node()]) end, Locks),
    try
        with_sups(
            fun() ->
                lists:foreach(
                    fun({Sup, Start}) ->
                        {ok, _Pid} = admit_within(Sup, Start)
                    end,
                    [
                        {i2p_ntcp2_sup, fun start_ntcp2/0},
                        {i2p_ssu2_sup, fun start_ssu2/0},
                        {i2p_sam_sup, fun start_sam/0}
                    ]
                )
            end
        )
    after
        lists:foreach(fun(Id) -> global:del_lock(Id, [node()]) end, Locks)
    end.

%%% %%%%% %%% Three caps, three queues %%%%% %%%

%% The ticket's open question, answered. A SAM session is a client connection an
%% operator is waiting on by hand; the bursts the peer caps exist for are floodfill
%% replication and post-restart peer-set rebuilds. Were these one admission
%% process, a wave of peer handshakes would queue in front of that session.
%%
%% Asserted by saturating one cap and admitting on the others, which is the shape a
%% shared lock or a shared counter would fail: the refusal here is on *SAM
%% sessions* and must not be the answer to a question about a peer connection.
the_three_caps_are_independent_test() ->
    with_caps(fun() ->
        with_sups(fun() ->
            set_cap(max_sam_sessions, 1),
            {ok, _} = start_sam(),
            ?assertMatch({error, session_limit}, start_sam()),
            %% SAM is at its one session, and the peer caps are untouched by that. Both
            %% read as 0 *with their supervisors up*, which is the part that matters: a
            %% count that answered 0 because nothing was running would agree with this
            %% assertion for the wrong reason.
            ?assertEqual(0, i2p_ntcp2_sup:connection_count()),
            ?assertEqual(0, i2p_ssu2_sup:session_count()),
            set_cap(max_ntcp2_connections, 0),
            ?assertMatch({error, connection_limit}, start_ntcp2()),
            %% ... and refusing a peer connection does not disturb the live SAM one.
            ?assertEqual(1, i2p_sam_sup:session_count())
        end)
    end).

%%% %%%%% %%% A refusal is counted %%%%% %%%

%% Before this a cap being hit was invisible. The refusal returned an atom a caller
%% could ignore and no caller logged, so a router at its connection limit looked
%% exactly like a router whose peers were refusing to answer.
a_refused_dial_is_counted_test() ->
    with_caps(fun() ->
        with_stats(fun() ->
            with_sup(i2p_ntcp2_sup, fun() ->
                set_cap(max_ntcp2_connections, 0),
                ?assertMatch({error, connection_limit}, start_ntcp2()),
                After = i2p_stats:snapshot(),
                ?assertEqual(
                    1, maps:get(ntcp2_connections_refused_limit, After)
                ),
                %% An admitted dial is not a refusal. The two are separate facts, and a
                %% counter that moved on both would be answering neither.
                set_cap(max_ntcp2_connections, 1),
                {ok, _} = start_ntcp2(),
                ?assertEqual(
                    After, i2p_stats:snapshot(), admitted_dial_must_not_be_counted_as_a_refusal
                )
            end)
        end)
    end).

%%% %%%%% %%% What the SAM cap counts %%%%% %%%

%% The cap moved from the ETS rows to the supervisor's children, and the reason is
%% a hole rather than a preference: a session writes its registry row *after*
%% `start_child` returns, so a row-based count is a later and smaller number than
%% the number of live session processes, and concurrent accepts could exceed the
%% cap by the number of sessions mid-registration.
%%
%% Pinned with a live child and no ETS row, which is the exact state the old count
%% read as zero. The other direction — a row with no child — is not reachable from
%% outside the session process, so it is not asserted.
sam_sessions_are_counted_by_child_not_by_ets_row_test() ->
    with_sup(i2p_sam_sup, fun() ->
        {ok, _} = start_sam(),
        ?assertEqual([], i2p_sam_sup:client_sessions()),
        ?assertEqual(1, i2p_sam_sup:session_count())
    end).

%%% %%%%% %%% Restarting the admission process %%%%% %%%

%% An admission process is a `permanent` child, so a crash is the supervisor's to
%% notice. What is worth asserting is what the restart costs: nothing, because
%% nothing is cached in it. Had a count been kept there, this case would be the one
%% that noticed a process enforcing a total it built before the children it counts
%% were started.
an_admission_process_is_restarted_after_dying_test() ->
    with_caps(fun() ->
        with_sup(i2p_ntcp2_sup, fun() ->
            set_cap(max_ntcp2_connections, ?CAP),
            Old = whereis(i2p_ntcp2_admission),
            ?assert(is_pid(Old)),
            exit(Old, kill),
            New = await_restart(i2p_ntcp2_admission, Old),
            ?assertNotEqual(Old, New),
            %% Still a cap after the restart, and still enforced by a live process
            %% rather than by whatever the dead one had decided. The same body the
            %% dedicated cap cases run, against the supervisor that is already up —
            %% nesting `with_sup/2` here would try to start a second one under the same
            %% registered name and fail on `{already_started, _}`.
            assert_cap_still_holds(ntcp2_cap, i2p_ntcp2_sup, fun start_ntcp2/0)
        end)
    end).

%%% %%%%% %%% The cap case, once %%%%% %%%

%% The whole concurrency case for one resource: start the supervisor, set the
%% cap, race. The three call sites differ in which supervisor, which start function
%% and which key — nothing else, and each of those three is a name rather than a
%% shape.
assert_cap_holds(Label, Sup, Start, CapKey) ->
    with_caps(fun() ->
        with_sup(Sup, fun() ->
            set_cap(CapKey, ?CAP),
            assert_cap_still_holds(Label, Sup, Start)
        end)
    end).

%% The assertions, for a supervisor that is already running with its cap set. Split
%% from the fixture so the restart case can re-run them without standing a second
%% supervisor up under a name the first one holds.
assert_cap_still_holds(Label, Sup, Start) ->
    Results = race_dials(Start),
    Admitted = [R || R <- Results, R =:= admitted],
    Denied = [R || R <- Results, R =:= refused],
    %% Every dialer answered. A dialer that hung would show up here as a missing
    %% answer rather than as a wrong count, which is the difference between "the
    %% cap let too many through" and "the cap never answered".
    ?assertEqual({Label, ?DIALS}, {Label, length(Results)}),
    %% The cap is the property the ticket is not negotiable on.
    ?assertEqual({Label, ?CAP}, {Label, length(Admitted)}),
    ?assertEqual({Label, ?DIALS - ?CAP}, {Label, length(Denied)}),
    %% Read back from the supervisor rather than from the tally above: the count
    %% admission used and the count an operator sees must be the same number, and
    %% only the supervisor knows the second one.
    ?assertEqual({Label, ?CAP}, {Label, count_of(Sup)}).

%%% %%%%% %%% Racing the dials %%%%% %%%

%% ?DIALS processes, all released together.
%%
%% The barrier is a counter in this process: each dialer announces itself, and none
%% is told to go until all ?DIALS have arrived. A sleep instead would leave the
%% dials staggered by however long the sleep was, which is the one thing a
%% count-then-start race needs to *not* be — so the arrival of the last dialer is
%% itself the event that starts the race.
%%
%% Answers are collected in dial order rather than as they come, because a refused
%% dial returns at once and an admitted one returns after a `start_child`. If the
%% first to answer won the tally position, the results would be ordered by how the
%% cap treated them — which is exactly the ordering that would let a broken cap
%% read as a working one.
race_dials(Start) ->
    Parent = self(),
    Dials = [
        spawn(fun() ->
            Parent ! {arrived, self()},
            receive
                go -> Parent ! {answered, self(), dial(Start)}
            end
        end)
     || _ <- lists:seq(1, ?DIALS)
    ],
    ok = await_arrivals(Dials),
    lists:foreach(fun(Pid) -> Pid ! go end, Dials),
    [await_answer() || _ <- lists:seq(1, ?DIALS)].

%% One dial, from a process with an empty mailbox, so admission is not competing
%% with this test's own traffic for the admission process.
dial(Start) ->
    case Start() of
        {error, _Refused} -> refused;
        {ok, _Pid} -> admitted;
        {ok, _Pid, _Extra} -> admitted
    end.

%% Every dialer waiting. The pid is the tag, so a dialer that died instead of
%% arriving cannot be mistaken for one that has not been scheduled yet.
await_arrivals([]) ->
    ok;
await_arrivals(Pids) ->
    receive
        {arrived, Pid} ->
            await_arrivals(Pids -- [Pid])
    after ?BOUND_MS ->
        erlang:error({dialers_never_all_arrived, length(Pids)})
    end.

await_answer() ->
    receive
        {answered, _Pid, Result} -> Result
    after ?BOUND_MS ->
        erlang:error(dial_never_answered)
    end.

%%% %%%%% %%% Admitting, and refusing to wait for it %%%%% %%%

%% For the lock case. The dial runs in a process of its own so the case can still
%% answer when it does not: an admission that blocks past the bound is reported
%% with the supervisor that waited, not left to hang.
admit_within(Sup, Start) ->
    Parent = self(),
    _Dialer = spawn(fun() -> Parent ! {answered, self(), Start()} end),
    receive
        {answered, _Pid, Result} -> Result
    after ?BOUND_MS ->
        erlang:error({admission_waited_on_something_it_should_not_have, Sup})
    end.

%% The supervisor restarts a `permanent` child, so the new pid exists as soon as
%% the old one is gone. Polled rather than assumed, because "restarted" and "the
%% name still points at a dead process" are different answers.
await_restart(Name, OldPid) ->
    case whereis(Name) of
        OldPid ->
            exit(OldPid, kill),
            await_restart(Name, OldPid);
        undefined ->
            timer:sleep(1),
            await_restart(Name, OldPid);
        Pid ->
            Pid
    end.

%%% %%%%% %%% Standing up a supervisor, and a child to admit %%%%% %%%

%% Each case owns its supervisor, so the caps cannot leak between them and the
%% admitted children are torn down with it. The three are started with the empty
%% `init/1` form, which brings up the admission process and nothing else: no
%% listener is bound and no port is taken.
%%
%% The link is dropped before the kill, and that is the whole reason this helper
%% exists rather than a bare `start_link/0` in each case. `start_link` links the
%% supervisor to this process, so killing it sends `killed` down that link — and a
%% case that tore down its own fixture that way would take the eunit test process
%% with it, which is reported as "unexpected termination of test process" and names
%% nothing. Unlinking first makes the teardown mean what it says.
with_sup(Sup, Fun) ->
    {ok, Pid} = Sup:start_link(),
    true = unlink(Pid),
    try
        Fun()
    after
        kill_and_wait(Sup, Pid)
    end.

%% Several at once, for the cases that cross resources. Started outermost-first and
%% therefore torn down innermost-first, so a case that needs a live count out of a
%% second supervisor has that supervisor genuinely running for as long as it does.
with_sups(Fun) ->
    with_sups(Fun, [i2p_ntcp2_sup, i2p_ssu2_sup, i2p_sam_sup]).

with_sups(Fun, []) ->
    Fun();
with_sups(Fun, [Sup | Rest]) ->
    with_sup(Sup, fun() -> with_sups(Fun, Rest) end).

%% `exit/2` is asynchronous and the registered name goes with the process, so
%% killing and immediately starting the next case can find the name still taken.
%% That shows up as `{already_started, <0.645.0>}` in whichever case lost the race
%% — a failure in a case that did nothing wrong, pointing at no code at all. The
%% `DOWN` is what makes the teardown ordered rather than merely requested.
kill_and_wait(Sup, Pid) ->
    MRef = erlang:monitor(process, Pid),
    exit(Pid, kill),
    receive
        {'DOWN', MRef, process, Pid, _Reason} -> ok
    after ?BOUND_MS ->
        %% A supervisor that did not die took its children with it, and the next
        %% case is about to fail on a name this one still holds. Named rather than
        %% left to the next case to trip over.
        erlang:error({supervisor_would_not_die, Sup, Pid})
    end.

%% A `temporary` sleeper under the tag the resource's count filters on. See the
%% module doc for why the admitted child is not a real connection. Three
%% functions rather than one over a tuple, so each resource's tag and entry point
%% sit next to each other and a mismatch is a visible pair rather than two
%% arguments that happen to line up.
start_ntcp2() ->
    i2p_ntcp2_sup:start_connection(sleeper_child(conn)).

start_ssu2() ->
    i2p_ssu2_sup:start_session(sleeper_child(ssu2_conn)).

start_sam() ->
    i2p_sam_sup:start_session(sleeper_child(session)).

sleeper_child(Tag) ->
    #{
        id => {Tag, erlang:unique_integer([positive, monotonic])},
        start => {?MODULE, sleeper_start_link, []},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [?MODULE]
    }.

sleeper_start_link() ->
    proc_lib:start_link(?MODULE, sleeper_init, []).

sleeper_init() ->
    proc_lib:init_ack({ok, self()}),
    timer:sleep(infinity).

%%% %%%%% %%% Reading a count back %%%%% %%%

%% Which read answers "how many are live" for a given supervisor. A function
%% rather than a fun applied at the call site, because `Fun:arity` is not
%% something Erlang can write — an applied fun needs a known arity at the call.
count_of(i2p_ntcp2_sup) -> i2p_ntcp2_sup:connection_count();
count_of(i2p_ssu2_sup) -> i2p_ssu2_sup:session_count();
count_of(i2p_sam_sup) -> i2p_sam_sup:session_count().

%%% %%%%% %%% Caps and the counter home %%%%% %%%

set_cap(Key, Value) ->
    ok = application:set_env(?APP, Key, Value),
    Value.

%% The three cap keys, and the fixture that puts them back.
%%
%% **Every one of these is on the `m:i2p_config` allowlist**, so a cap left set
%% shows up in `m:i2p_config:in_force/0` and the router's boot line. EUnit runs
%% every module in this directory in one node, so a case here that does not clean
%% up breaks `i2p_config_tests:in_force_reports_values_as_stored_test` — which
%% asserts the boot line is *exactly* two keys — with three extra ones and no hint
%% that the fault is two directories away. That is what this is for.
with_caps(Fun) ->
    Saved = [{Key, application:get_env(?APP, Key)} || Key <- cap_keys()],
    try
        Fun()
    after
        lists:foreach(fun restore_cap/1, Saved)
    end.

restore_cap({Key, {ok, Value}}) ->
    ok = application:set_env(?APP, Key, Value);
restore_cap({Key, undefined}) ->
    ok = application:unset_env(?APP, Key).

cap_keys() ->
    [max_ntcp2_connections, max_ssu2_sessions, max_sam_sessions].

%% **Stopped, not killed.** `i2p_stats:terminate/2` erases the `persistent_term`
%% entry holding the counter registry, and only a clean stop runs it. A `kill`
%% leaves a term pointing at a dead counter reference, which the next case in this
%% node would read as a live snapshot -- the same shape of leak as the cap keys
%% above, and it would surface in `i2per_status_tests` rather than here.
%%
%% Started only if absent and stopped either way, because a neighbouring case may
%% already own the counter home; this module must not take it away from one that
%% did not ask for it.
with_stats(Fun) ->
    Started = ensure_stats(),
    try
        Fun()
    after
        case Started of
            true -> ok = gen_server:stop(whereis(i2p_stats));
            false -> ok
        end
    end.

ensure_stats() ->
    case whereis(i2p_stats) of
        undefined ->
            {ok, _Pid} = i2p_stats:start_link(),
            true;
        _Pid ->
            false
    end.
