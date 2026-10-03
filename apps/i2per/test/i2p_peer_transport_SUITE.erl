%% Transport-selection and peer-backoff tests. Each case owns the application
%% lifecycle, the registered peer manager, listeners, and mailbox. The wire
%% assertions use the public transport-selection and status APIs.
%%
%% A stale message from a sibling case cannot be matched because every receive
%% drains non-matching mail through `i2p_ct_helpers:wait_msg/2`. Peer-status
%% and attempt-count polls are deadline-bounded. Discovery, answer, LeaseSet,
%% and floodfill-publish scenarios live in `i2p_peer_discovery_SUITE` and the
%% direct unit tests.
%%
%% Listeners bind at port 0 and close in `after` blocks. The slow fallback case
%% allows the SSU2 handshake budget before the NTCP2 leg appears; the backoff
%% case walks the configured retry windows. The two park cases do not: they arm
%% the retransmit schedule down, or answer on the first reply, so a park costs
%% milliseconds rather than the ten seconds it costs a real dial. The
%% read-during-a-park case arms it *up* instead, to a window wide enough to read
%% the peer from inside the park rather than only after it.

-module(i2p_peer_transport_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    transport_ntcp2_when_remote_is_ntcp2_only/1,
    transport_ntcp2_when_ssu2_disabled/1,
    transport_ssu2_when_available/1,
    transport_falls_back_to_ntcp2/1,
    ssu2_park_on_a_dead_port_is_reported_with_its_reason/1,
    ssu2_park_separates_silence_from_a_wrong_answer/1,
    a_peer_parked_on_ssu2_reports_ssu2_not_ntcp2/1,
    one_stalled_connection_does_not_stop_the_others/1,
    dead_peer_backs_off_then_recovers/1
]).

-include_lib("eunit/include/eunit.hrl").

-define(APP, i2per).
-define(TIMEOUT, 10000).

%% How many frames the wedged-connection case pushes at the silent peer, and how
%% long it then waits for that connection to be sitting in the socket write. The
%% frames are the largest legal NTCP2 payload, so a few hundred of them are
%% megabytes — comfortably past what a socket absorbs before it refuses, which
%% was measured on this tree at 45 frames of 60 kB. Both numbers are hang guards
%% on kernel and driver behaviour rather than claims about the router; reaching
%% either fails the case rather than passing it.
-define(FILL_FRAMES, 400).
-define(BLOCKED_WINDOW_MS, 15000).

%% The retransmit interval the park case arms, chosen so the dial it parks on is
%% over inside the case rather than after it. See `arm_handshake/1`.
-define(PARK_RETRY_MS, 20).

%% A wider retransmit interval, for the case that has to *observe* a park rather
%% than merely reach its end. See `arm_handshake/1`.
-define(OBSERVE_RETRY_MS, 125).

suite() ->
    [].

all() ->
    [
        transport_ntcp2_when_remote_is_ntcp2_only,
        transport_ntcp2_when_ssu2_disabled,
        transport_ssu2_when_available,
        transport_falls_back_to_ntcp2,
        ssu2_park_on_a_dead_port_is_reported_with_its_reason,
        ssu2_park_separates_silence_from_a_wrong_answer,
        a_peer_parked_on_ssu2_reports_ssu2_not_ntcp2,
        one_stalled_connection_does_not_stop_the_others,
        dead_peer_backs_off_then_recovers
    ].

%% ---------------------------------------------------------------------------
%% Per-case lifecycle: the `ssu2_enabled` switch must be set before the app
%% and its SSU2 supervisor come up. App stop and unset_env in
%% end_per_testcase leave a clean envelope for the next case. The fallback
%% scenario spends ~20s in the SSU2 handshake budget, so it gets a wider
%% timetrap.
%% ---------------------------------------------------------------------------

init_per_testcase(Case, Config) ->
    ok = arm_ssu2(Case),
    ok = arm_sndbuf(Case),
    ok = arm_handshake(Case),
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, timetrap_for(Case)} | Config].

%% A small per-connection send buffer, so the silent peer's socket fills in a few
%% frames rather than however many the kernel's autotuning would allow. This is
%% the same option an operator sets to bound what one non-reading peer costs, so
%% the case reaches the stall through a production lever rather than a private
%% mechanism. Read when a connection enters the data phase, which is after this.
arm_sndbuf(one_stalled_connection_does_not_stop_the_others) ->
    application:set_env(?APP, ntcp2_sndbuf, 4096);
arm_sndbuf(_Case) ->
    ok.

%% The SessionRequest retransmit schedule, taken down to about 40 ms.
%%
%% A dial that parks on a silent UDP port is parked by this budget -- nine
%% unanswered retransmits at 1 Hz, ~10 s -- and not by the 20 s ceiling above it,
%% so a case that leaves it alone is asserting against the slowest thing in the
%% suite for a fact that arrives the moment the budget expires. Both values are
%% app-env levers `docs/protocol.md` documents and an operator can set, which is
%% what makes this the same kind of lever as `arm_sndbuf/1` above rather than a
%% private mechanism added for the test.
%%
%% One retransmit is not zero: `f:handshake_max_resends/0` accepts only a
%% positive count, so the earliest budget a dial can be given is two timer
%% firings. At `?PARK_RETRY_MS` that is ~40 ms, and the assertion waits on the
%% event rather than on the clock either way.
arm_handshake(ssu2_park_on_a_dead_port_is_reported_with_its_reason) ->
    application:set_env(?APP, handshake_retry_ms, ?PARK_RETRY_MS),
    application:set_env(?APP, handshake_max_resends, 1);
%% The park window this case observes has to be *wider than the window it reads
%% in*, or the case is a race rather than a test. At `?PARK_RETRY_MS` (20ms) the
%% dial is parked for ~40ms and the read is a 25ms poll, so the poll can easily
%% straddle the whole park and never see it. Four resends at `?OBSERVE_RETRY_MS`
%% give a ~500ms park against the same 25ms poll — twenty samples inside the
%% window rather than one.
arm_handshake(a_peer_parked_on_ssu2_reports_ssu2_not_ntcp2) ->
    application:set_env(?APP, handshake_retry_ms, ?OBSERVE_RETRY_MS),
    application:set_env(?APP, handshake_max_resends, 4);
arm_handshake(_Case) ->
    ok.

arm_ssu2(transport_ntcp2_when_remote_is_ntcp2_only) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(transport_ssu2_when_available) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(transport_falls_back_to_ntcp2) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(ssu2_park_on_a_dead_port_is_reported_with_its_reason) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(ssu2_park_separates_silence_from_a_wrong_answer) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(a_peer_parked_on_ssu2_reports_ssu2_not_ntcp2) ->
    application:set_env(?APP, ssu2_enabled, true);
arm_ssu2(_Case) ->
    ok.

timetrap_for(transport_falls_back_to_ntcp2) ->
    60000;
timetrap_for(a_peer_parked_on_ssu2_reports_ssu2_not_ntcp2) ->
    60000;
timetrap_for(_Case) ->
    30000.

end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    ok = application:unset_env(?APP, ssu2_enabled),
    ok = application:unset_env(?APP, ntcp2_sndbuf),
    ok = application:unset_env(?APP, handshake_retry_ms),
    ok = application:unset_env(?APP, handshake_max_resends),
    ok.

%% ---------------------------------------------------------------------------
%% Transport selection: with SSU2 armed, an outbound dial takes NTCP2
%% only when the remote cannot do SSU2; takes SSU2 when both endpoints are
%% ready (and live messages cross the SSU2 session); and falls back to NTCP2
%% when the remote advertises an SSU2 address that answers nothing. The global
%% `ssu2_enabled` switch gates the whole preference, so a fully SSU2-capable
%% setup still dials NTCP2 while the switch is off.
%% ---------------------------------------------------------------------------

%% Remote advertises only NTCP2 (no SSU2 address): the SSU2 guard fails on the
%% remote side and the dial goes over NTCP2, with the switch fully armed.
transport_ntcp2_when_remote_is_ntcp2_only(_Config) ->
    {A, B, _C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    {AL, _APort} = ssu2_listener(A),
    try
        BRI = ri_at(listen_port(LB), B),
        BHash = i2p_router_info:hash(BRI),
        A2 = local(A, 4668),
        AHash = maps:get(hash, A2),
        start_peer(A2, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        {CB, {lookup, Exploratory}} = await_frame(),
        #{type := exploratory, key := AHash} = Exploratory,
        {store, _} = recv_db_store(CB),
        await_peer_status(BHash, connected),
        #{status := connected, transport := ntcp2} = peer_status(BHash),
        i2p_peer:stop()
    after
        i2p_ssu2_listener:stop(AL),
        i2p_ntcp2_listener:stop(LB)
    end.

%% The `ssu2_enabled` switch is off (the default): even though the remote
%% advertises SSU2 and this router would be SSU2-armed, the dial stays NTCP2.
transport_ntcp2_when_ssu2_disabled(_Config) ->
    {A, B, _C} = trio(),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        DeadPort = i2p_ct_helpers:free_port(),
        BRI = ssu2_ri_at(listen_port(LB), DeadPort, B),
        BHash = i2p_router_info:hash(BRI),
        start_peer(local(A, 4668), [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        {CB, {lookup, _}} = await_frame(),
        {store, _} = recv_db_store(CB),
        await_peer_status(BHash, connected),
        #{status := connected, transport := ntcp2} = peer_status(BHash),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB)
    end.

%% Both ends SSU2-ready and the remote reachable on SSU2 and NTCP2 alike: the
%% dial prefers SSU2 (transport=ssu2), and the queued exploratory lookup plus
%% the self-announcement actually cross the SSU2 session, so the selected
%% transport is fully functional — not just handshake-deep.
transport_ssu2_when_available(_Config) ->
    {A, B, _C} = trio(),
    {AL, APort} = ssu2_listener(A),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, _Self = self()),
    try
        ALocal = ssu2_local(A, i2p_ct_helpers:free_port(), APort),
        B0 = router(),
        {BL, BPort} = ssu2_listener(B0),
        BRI = ssu2_ri_at(listen_port(LB), BPort, B0),
        BHash = i2p_router_info:hash(BRI),
        start_peer(ALocal, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        %% B's SSU2 session (owned by the test) carries A's queued lookup and
        %% self-announcement as SSU2 Data blocks...
        Seen = await_ssu2_types([2, 1], 10),
        true = lists:member(1, Seen),
        true = lists:member(2, Seen),
        await_peer_status(BHash, connected),
        #{status := connected, transport := ssu2} = peer_status(BHash),
        i2p_peer:stop(),
        i2p_ssu2_listener:stop(BL)
    after
        i2p_ntcp2_listener:stop(LB),
        i2p_ssu2_listener:stop(AL)
    end.

%% The remote advertises an SSU2 address nothing answers. The SSU2 handshake
%% times out (the fixed ~20s connect budget), the dial falls back to NTCP2,
%% and the same queued work completes over TCP. Slow by design, hence the
%% explicit 60s timetrap on this scenario.
transport_falls_back_to_ntcp2(_Config) ->
    {A, B, _C} = trio(),
    {AL, APort} = ssu2_listener(A),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        ALocal = ssu2_local(A, i2p_ct_helpers:free_port(), APort),
        DeadPort = i2p_ct_helpers:free_port(),
        BRI = ssu2_ri_at(listen_port(LB), DeadPort, B),
        BHash = i2p_router_info:hash(BRI),
        AHash = maps:get(hash, ALocal),
        start_peer(ALocal, [BRI]),
        ok = i2p_peer:lookup(BHash, exploratory),
        %% ~20s of SSU2 handshake retries to the dead port, then the NTCP2
        %% dial over B's listener with the queued lookup intact.
        {CB, {lookup, Exploratory}} = await_frame(40000),
        #{type := exploratory, key := AHash} = Exploratory,
        {store, _} = recv_db_store(CB),
        %% 25 ms polls x 1600 = 40 s budget for the SSU2-attempt window.
        await_peer_status(BHash, connected, 1600),
        #{status := connected, transport := ntcp2} = peer_status(BHash),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB),
        i2p_ssu2_listener:stop(AL)
    end.

%% --------------------------------------------------------------------------
%% Why a dial was parked (the half above is that it parked; this is that we can
%% now say what happened)
%% --------------------------------------------------------------------------

%% The same fallback as above, against a silent UDP port, and the assertion is on
%% the *reason*: the park happened before the peer connected, so nothing about
%% the outcome differs from the case above -- what differs is that this one says
%% so.
%%
%% `{handshake_timeout, session_request}` is the silence case. We sent and nothing
%% came back. It is a real answer about the network -- and an operator-fixable one
%% -- because across peers a dial that always ends here while NTCP2 always
%% succeeds means the UDP is being dropped on our side, which nothing in this
%% router said before.
%%
%% Both halves of the claim are asserted, and neither alone would do: the counter
%% says a park was charged, and the event says what it was. A counter with no
%% reason answers "how often" and a reason with no counter answers "once, to
%% whom"; a stall has to be countable to be a rate and has to carry its reason to
%% be worth counting.
ssu2_park_on_a_dead_port_is_reported_with_its_reason(_Config) ->
    {A, B, _C} = trio(),
    {AL, APort} = ssu2_listener(A),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        ALocal = ssu2_local(A, i2p_ct_helpers:free_port(), APort),
        BRI = ssu2_ri_at(listen_port(LB), i2p_ct_helpers:free_port(), B),
        BHash = i2p_router_info:hash(BRI),
        start_peer(ALocal, [BRI]),
        Before = counter(ssu2_dials_parked),
        Events = i2p_ct_helpers:events_from(fun() ->
            ok = i2p_peer:lookup(BHash, exploratory),
            %% The NTCP2 leg runs only after the park, so reaching `connected`
            %% is the barrier for it.
            await_peer_status(BHash, connected, 1600)
        end),
        ?assertEqual(1, counter(ssu2_dials_parked) - Before),
        ?assertEqual([{handshake_timeout, session_request}], park_reasons(Events)),
        %% A park that then connects over TCP is not a failed connect:
        %% `peer_connect_failed` fires only once *both* legs are down, and this
        %% peer came up on the second one. Asserted because the two facts were
        %% previously the same absence -- neither reported -- and merging them
        %% the other way would make a working TCP dial read as a fault.
        ?assertEqual([], [R || {peer_connect_failed, _, R, _} <- Events]),
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB),
        i2p_ssu2_listener:stop(AL)
    end.

%% The comparison the whole reason vocabulary exists for, and it is the one a
%% single dial cannot make for itself: silence and a wrong answer are the same
%% fallback, the same counter, and the same peer status.
%%
%% The remote's SSU2 address answers, but wrongly: a datagram sealed under our
%% own intro key, routed to the waiting session by the connection id it chose,
%% and typed as something other than the SessionCreated it is waiting for (see
%% `wrong_answer/2`). So the session exits `{protocol_error, created_decode}` on
%% the first reply -- no retransmit budget spent, and therefore no timing in this
%% case at all.
%%
%% `{protocol_error, _}` against `{handshake_timeout, _}` is the load-bearing
%% pair. Something came back and was wrong is proof that UDP works in this
%% direction; nothing came back is not. Both are a fallback to NTCP2 and neither
%% differs from the case above in anything an operator could previously read.
ssu2_park_separates_silence_from_a_wrong_answer(_Config) ->
    {A, B, _C} = trio(),
    {AL, APort} = ssu2_listener(A),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    Answerer = wrong_answer(intro_key(B), intro_key(A)),
    {_AnswererPid, _AnswererSock, AnswererPort} = Answerer,
    try
        ALocal = ssu2_local(A, i2p_ct_helpers:free_port(), APort),
        BRI = ssu2_ri_at(listen_port(LB), AnswererPort, B),
        BHash = i2p_router_info:hash(BRI),
        start_peer(ALocal, [BRI]),
        Events = i2p_ct_helpers:events_from(fun() ->
            ok = i2p_peer:lookup(BHash, exploratory),
            await_peer_status(BHash, connected, 1600)
        end),
        ?assertEqual([{protocol_error, created_decode}], park_reasons(Events)),
        i2p_peer:stop()
    after
        wrong_answer_stop(Answerer),
        i2p_ntcp2_listener:stop(LB),
        i2p_ssu2_listener:stop(AL)
    end.

%% --------------------------------------------------------------------------
%% What the read API says *while* a dial is parked
%% --------------------------------------------------------------------------

%% The peer entry is created with `transport => ntcp2`, before any dial has
%% chosen anything -- it is the seed value, not a report. Before this case that
%% seed was also all the read API ever saw for the whole of an SSU2 park, so a
%% peer sitting in a ten-second (or sixty-second, through an introducer) SSU2
%% handshake reported `ntcp2`: the fallback, announced as though it had already
%% happened.
%%
%% The park here is the observable, not a timing accident. The endpoint is a UDP
%% socket that receives the SessionRequest and never answers, so the session
%% stays in its retransmit budget for the ~500ms `arm_handshake/1` set up — a
%% window twenty polls wide, against the 25ms poll interval. The case then reads
%% the peer *during* that window rather than after it, so it asserts what an
%% operator polling a page would have seen while the dial was stuck.
%%
%% Two things are asserted rather than one, because either alone is satisfiable
%% by the wrong fix. `ssu2` alone could be satisfied by a router that never
%% falls back; the counter proves the park was real and bounded, and the
%% `connected` wait afterwards proves the fallback still happened. And the
%% `ntcp2` assertion is the negative that the bug actually produced: it is the
%% value the read API returned for the entire duration of the defect.
a_peer_parked_on_ssu2_reports_ssu2_not_ntcp2(_Config) ->
    {A, B, _C} = trio(),
    {AL, APort} = ssu2_listener(A),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    Silent = silent_endpoint(),
    {_SilentPid, _SilentSock, SilentPort} = Silent,
    try
        ALocal = ssu2_local(A, i2p_ct_helpers:free_port(), APort),
        BRI = ssu2_ri_at(listen_port(LB), SilentPort, B),
        BHash = i2p_router_info:hash(BRI),
        start_peer(ALocal, [BRI]),
        Before = counter(ssu2_dials_parked),
        ok = i2p_peer:lookup(BHash, exploratory),
        %% The barrier is the park itself: a peer reported as attempting `ssu2`
        %% is a dial that has committed and not yet finished, which is exactly
        %% the interval the old code reported as `ntcp2`. Reaching the deadline
        %% without seeing it means the announcement never happened — which is
        %% what the bug looked like from here, the whole park reading `ntcp2`.
        ok = await_attempting_ssu2(BHash, 40),
        %% Matched rather than compared, so the failure names what it read: the
        %% assertion is that `transport` is the attempt and not the seed.
        #{status := connecting, transport := ssu2} = peer_status(BHash),
        %% `last_attempt` is the field that separates this from a fresh dial,
        %% which is what `attempts = 0` at `connecting` cannot do.
        #{attempts := 0, last_attempt := Started} = peer_status(BHash),
        true = is_integer(Started),
        true = Started =< erlang:system_time(second),
        %% The fallback still runs, and the transport follows it — the second
        %% half of the same lie, one transport later.
        await_peer_status(BHash, connected, 1600),
        #{status := connected, transport := ntcp2} = peer_status(BHash),
        %% Read *after* the park rather than during it, because that is when it
        %% is knowable: the counter is charged when the park ends. Asserted here
        %% so this case cannot pass by catching a dial a moment into one — the
        %% thing observed above is a bounded wait, not an instant.
        ?assertEqual(1, counter(ssu2_dials_parked) - Before),
        i2p_peer:stop()
    after
        silent_endpoint_stop(Silent),
        i2p_ntcp2_listener:stop(LB),
        i2p_ssu2_listener:stop(AL)
    end.

%% Wait until the peer reports a dial in flight over SSU2. A deadline-bounded
%% poll of a state predicate, which is a barrier in the sense the project's
%% testing rule allows: reaching the end of the window fails the case rather
%% than passing it.
await_attempting_ssu2(_Hash, 0) ->
    error({never_attempted_ssu2, i2p_peer:status()});
await_attempting_ssu2(Hash, N) ->
    case i2p_peer:status() of
        #{Hash := #{status := connecting, transport := ssu2}} ->
            ok;
        _ ->
            %% Documented load-safe window: 25ms poll backoff inside the
            %% deadline-bounded await loop — a state poll over
            %% `i2p_peer:status/0`, not a fixed sleep gating an assertion.
            timer:sleep(25),
            await_attempting_ssu2(Hash, N - 1)
    end.

%% A UDP endpoint that receives datagrams and answers none of them, so the dial
%% parks on it for its whole retransmit budget.
%%
%% Owned by a spawned process for the reason `f:wrong_answer/2` is: `gen_udp:open/2`
%% makes its caller the socket's controlling process, so an active-mode datagram
%% is delivered there however many other processes hold the port term.
silent_endpoint() ->
    Owner = self(),
    Pid = spawn_link(fun() -> silent_endpoint_open(Owner) end),
    receive
        {silent_endpoint_ready, Sock, Port} -> {Pid, Sock, Port}
    end.

silent_endpoint_open(Owner) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, once}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Sock),
    Owner ! {silent_endpoint_ready, Sock, Port},
    silent_endpoint_loop(Sock).

silent_endpoint_loop(Sock) ->
    receive
        {udp, Sock, _IP, _Port, _Datagram} ->
            ok = inet:setopts(Sock, [{active, once}]),
            silent_endpoint_loop(Sock);
        {silent_endpoint_stop, Owner} ->
            gen_udp:close(Sock),
            Owner ! {silent_endpoint_stopped, self()}
    end.

silent_endpoint_stop({Pid, _Sock, _Port}) ->
    Pid ! {silent_endpoint_stop, self()},
    receive
        {silent_endpoint_stopped, Pid} -> ok
    end.

%% The reasons this router reported a park, in the order it reported them, and
%% nothing else. Read through rather than matched inline so that a case asserting
%% "exactly one park, and here is why" says that in one expression.
park_reasons(Events) ->
    [Reason || {ssu2_dial_parked, _PeerHash, Reason} <- Events].

%% One counter by name. `f:snapshot/0` reports a registered counter whether or not
%% it has ever moved, so this cannot fail on the first read of a fresh router.
counter(Name) ->
    maps:get(Name, i2p_stats:snapshot(), 0).

%% A UDP endpoint that answers every datagram with a well-formed SSU2 long-header
%% packet addressed back to the sender -- one this router will classify as its own
%% and route to the waiting session -- carrying a type it is not asking for.
%%
%% **An echo cannot stand in for this, and why it cannot is the claim under test.**
%% Our listener opens a datagram's connection id under *our* intro key, so an echo
%% of our own SessionRequest -- sealed, as it must be, under the *remote's* -- is
%% never routed to the session and is dropped unread. It arrives, and reads as
%% silence: exactly the conflation this case exists to catch, arrived at by
%% accident. So the reply is sealed under ours instead, which is what makes it
%% something that came back rather than nothing did.
%%
%% Both keys are the production derivations, read out of the fixtures rather than
%% invented: the request is opened under the intro key published in the remote's
%% address, and the reply sealed under ours.
%%
%% **The socket is opened inside the answerer, not here and handed over.**
%% `gen_udp:open/2` makes its caller the socket's *controlling process*, and an
%% active-mode datagram goes to that process however many other processes hold
%% the port term -- so opening it here delivered every `{udp, ...}` to the test
%% process, where `f:events_from/1`'s drain discarded them, and the case read as
%% total silence from an endpoint that had answered every time. `{active, once}`
%% rather than a blocking `gen_udp:recv/3` keeps the loop idle between
%% datagrams: a zero-timeout poll would be a spin, and a blocking recv would sit
%% in the driver past the stop message.
wrong_answer(RemoteIntroKey, LocalIntroKey) ->
    Owner = self(),
    Pid = spawn_link(fun() -> wrong_answer_open(Owner, RemoteIntroKey, LocalIntroKey) end),
    receive
        {wrong_answer_ready, Sock, Port} -> {Pid, Sock, Port}
    end.

wrong_answer_open(Owner, RemoteIntroKey, LocalIntroKey) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, once}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Sock),
    Owner ! {wrong_answer_ready, Sock, Port},
    wrong_answer_loop(Sock, RemoteIntroKey, LocalIntroKey).

wrong_answer_stop({Pid, _Sock, _Port}) ->
    Pid ! {wrong_answer_stop, self()},
    receive
        {wrong_answer_stopped, Pid} -> ok
    end.

wrong_answer_loop(Sock, RemoteIntroKey, LocalIntroKey) ->
    receive
        {udp, Sock, IP, Port, Datagram} ->
            Reply = not_a_session_created(Datagram, RemoteIntroKey, LocalIntroKey),
            ok = gen_udp:send(Sock, IP, Port, Reply),
            ok = inet:setopts(Sock, [{active, once}]),
            wrong_answer_loop(Sock, RemoteIntroKey, LocalIntroKey);
        {wrong_answer_stop, Owner} ->
            gen_udp:close(Sock),
            Owner ! {wrong_answer_stopped, self()}
    end.

%% A long-header datagram for the connection id the request chose, sealed under
%% our intro key, typed 0 where `f:receive_session_created/2` is about to look for
%% a type 1.
%%
%% The 32 zero bytes stand in for the ciphertext and the last 16 for the Poly1305
%% tag, and both are zeros on purpose: the packet has to be *routable* and nothing
%% more. A correctly authenticated SessionCreated would be accepted rather than
%% failing, and then this would be a different case.
not_a_session_created(Datagram, RemoteIntroKey, LocalIntroKey) ->
    {ok, DstConnId} = i2p_ssu2:open_conn_id(Datagram, RemoteIntroKey, RemoteIntroKey),
    Header = i2p_ssu2:long_header(DstConnId, 0, 0, DstConnId, 0),
    i2p_ssu2:seal_long(
        <<Header/binary, 0:256, 0:128>>,
        LocalIntroKey,
        LocalIntroKey
    ).

%% --------------------------------------------------------------------------
%% One wedged connection does not stop the router
%% --------------------------------------------------------------------------

%% The whole point of the case, and the reason the send path was rebuilt.
%%
%% The manager is one `gen_server` that every inbound message from every
%% connection passes through, so a send that blocked on one connection stopped
%% I2NP for all of them. Two peers are connected here: one healthy, and one whose
%% far end completed a real NTCP2 handshake and then went silent
%% (`f:i2p_ct_helpers:silent_ntcp2_peer/1`), so its window shuts and the manager's
%% connection to it ends up blocked in a socket write. While that is true, a
%% message for the *healthy* peer still has to arrive.
%%
%% The conclusion the case draws is a barrier: the healthy peer's connection
%% delivers a real DatabaseLookup, which is an event the runtime ordered and not
%% a duration the case slept through. Under the old send the manager would be
%% inside `f:i2p_ntcp2_conn:send/2` waiting for a reply from the wedged
%% connection, and that frame would never arrive at all.
%%
%% Two things make the ordering honest rather than lucky. The wedged connection is
%% the manager's own, so "it is blocked in a socket write" is read off the live
%% process before the healthy send is issued; and the case then asserts that
%% connection is *still* blocked afterwards, so the healthy frame cannot have been
%% served before the stall rather than during it.
one_stalled_connection_does_not_stop_the_others(_Config) ->
    {A, B, Silent} = trio(),
    {LSilent, SilentPort, _Peer} = i2p_ct_helpers:silent_ntcp2_peer(Silent),
    {ok, LB} = i2p_ntcp2_listener:listen(0, B, self()),
    try
        %% Three distinct routers, and it has to be three: the RouterInfo hash
        %% covers the identity rather than the published addresses, so a second
        %% RouterInfo built from the same router would be the *same peer* with a
        %% different port, and the manager would have held one connection where
        %% this case needs two.
        BRI = ri_at(listen_port(LB), B),
        SilentRI = ri_at(SilentPort, Silent),
        BHash = i2p_router_info:hash(BRI),
        SilentHash = i2p_router_info:hash(SilentRI),
        start_peer(local(A, 4668), [BRI, SilentRI]),
        ok = i2p_peer:lookup(SilentHash, exploratory),
        ok = await_silent_peer(),
        await_peer_status(SilentHash, connected),
        await_peer_status(BHash, connected),
        Stalled = connection_of(SilentHash),
        %% Two keys minted here, neither of them a peer's, so neither can be a key
        %% the manager would have looked up by itself.
        StalledKey = crypto:strong_rand_bytes(32),
        ProbeKey = crypto:strong_rand_bytes(32),
        %% Push the silent peer's socket past what it will absorb, from a separate
        %% process so the feeding and the observation are not one loop. The frames
        %% are the largest legal payload, so this is megabytes rather than
        %% thousands of casts, and it happens fast.
        Filler = spawn(fun() -> flood(Stalled, ?FILL_FRAMES) end),
        try
            ok = await_blocked(Stalled),
            %% Everything the manager has already put on the wire is drained
            %% first. Connecting to a peer flushes its queued lookups, so a
            %% DatabaseLookup is sitting in this mailbox from before the stall
            %% began, and a case that waited for "a lookup" without clearing it
            %% would be satisfied by that stale frame whether or not the manager
            %% could still reach anybody — the assertion would be true in exactly
            %% the situation it exists to detect is fixed.
            ok = drain_frames(),
            %% Both of these are casts, so neither call can itself be what is
            %% being waited on. That is the property, visible in the shape of the
            %% calls that carry it: the manager reaches the second peer without
            %% returning from the first.
            ok = i2p_peer:send_when_ready(SilentHash, probe(StalledKey)),
            ok = i2p_peer:send_when_ready(BHash, probe(ProbeKey)),
            {CB, {lookup, Lookup}} = await_frame(),
            %% The key is the proof the frame is this probe and not a leftover:
            %% the manager never looks up a key it was not given, and this one was
            %% minted after the drain.
            ProbeKey = maps:get(key, Lookup),
            true = is_pid(CB),
            true = is_pid(Filler),
            %% Still wedged, so the healthy frame above was served during the
            %% stall rather than after it.
            {current_function, {prim_inet, send, _}} =
                erlang:process_info(Stalled, current_function)
        after
            exit(Filler, kill)
        end,
        i2p_peer:stop()
    after
        i2p_ntcp2_listener:stop(LB),
        gen_tcp:close(LSilent)
    end.

%% A DatabaseLookup, because that is the message the manager really sends for
%% outstanding work, and because the healthy peer's connection decodes it into a
%% `lookup` this case can recognise: the assertion is that a real message
%% crossed, not that bytes moved. The key is the caller's, so the frame can be
%% told apart from any lookup the manager sent on its own.
probe(Key) ->
    i2p_i2np:db_lookup(Key, Key, i2p_i2np:lookup_type_routerinfo(), []).

%% Discard every frame already delivered to the healthy peer's connection. Only
%% frames from the connection under test are drained, so a message belonging to
%% another case's connection is left alone rather than swallowed.
drain_frames() ->
    drain_frames(?TIMEOUT).

drain_frames(Timeout) ->
    receive
        {ntcp2_frame, _Conn, _Payload} -> drain_frames(Timeout)
    after Timeout ->
        ok
    end.

%% Whether the connection has stopped draining its mailbox by sitting in the
%% socket write — the state the whole case is about. This one is polled, because
%% a process does not announce that it has entered a NIF, and it says only that
%% the stall is in place before the barrier is set up; whether the manager kept
%% working is then answered by the frame. Reaching the deadline fails the case.
await_blocked(Conn) ->
    await_blocked(Conn, erlang:monotonic_time(millisecond) + ?BLOCKED_WINDOW_MS).

await_blocked(Conn, Deadline) ->
    case erlang:process_info(Conn, current_function) of
        {current_function, {prim_inet, send, _}} ->
            ok;
        _Other ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> erlang:error({connection_never_blocked, Conn});
                false -> await_blocked(Conn, Deadline)
            end
    end.

flood(_Conn, 0) ->
    ok;
flood(Conn, N) ->
    ok = i2p_ntcp2_conn:send(Conn, i2p_framing:encode_block(3, crypto:strong_rand_bytes(60_000))),
    flood(Conn, N - 1).

%% The silent peer's announcement that it has stopped reading. Its own barrier,
%% and it is needed rather than merely tidy: frames sent before the peer parks
%% would be drained, and the socket would never fill.
await_silent_peer() ->
    receive
        {silent_ntcp2_peer, _Peer} -> ok;
        {ntcp2_ready, _Conn, _RemoteRI} -> await_silent_peer()
    after ?TIMEOUT ->
        error(peer_never_went_silent)
    end.

%% The manager's connection pid for one peer. `f:i2p_peer:status/0` reports
%% status, attempts and transport, and the pid is none of those, so this reads
%% the manager's state through the documented introspection call rather than
%% adding an accessor to the module under test for one case's benefit.
connection_of(Hash) ->
    case sys:get_state(i2p_peer) of
        #{peers := Peers} -> maps:get(conn, maps:get(Hash, Peers));
        _Other -> erlang:error(peer_not_in_manager_state)
    end.

%% --------------------------------------------------------------------------
%% Let it crash: a dead peer (nothing listens) only ever produces exponential
%% backoff — a handful of attempts, no hot loop — and the manager recovers
%% once a listener appears on the same port.
%% --------------------------------------------------------------------------

%% The backoff windows (1s, 2s, 4s...) plus the recovery retry need ~8s in
%% total, so the scenario gets an explicit timetrap instead of the CT default.
dead_peer_backs_off_then_recovers(_Config) ->
    A = local(router(), 4668),
    D = local(router(), 4668),
    Port = i2p_ct_helpers:free_port(),
    DRI = ri_at(Port, D),
    DHash = i2p_router_info:hash(DRI),
    start_peer(A, [DRI]),
    ok = i2p_peer:lookup(DHash, exploratory),
    %% The connect fails (nothing listens) -> backoff after one attempt.
    await_peer_status(DHash, backoff),
    #{status := backoff, attempts := Attempts} = peer_status(DHash),
    true = Attempts >= 1,
    %% Let a few backoff windows elapse (1s then 2s): wait until the
    %% manager has retried a couple of times on the spread-out windows,
    %% proving the backoff is exponential — never a tight loop.
    Deadline = erlang:monotonic_time(millisecond) + 8000,
    Attempts2 = wait_for_attempts(DHash, 3, Deadline),
    true = Attempts2 >= 2 andalso Attempts2 =< 4,
    await_peer_status(DHash, backoff),
    %% Bring a listener up on the same port; the next retry must succeed.
    {ok, LD} = i2p_ntcp2_listener:listen(Port, D, self()),
    await_peer_status(DHash, connected),
    i2p_peer:stop(),
    i2p_ntcp2_listener:stop(LD).

%% ---------------------------------------------------------------------------
%% Transport-suite helpers. Wire receipts use `m:i2p_ct_helpers:wait_msg/2`.
%% ---------------------------------------------------------------------------

%% A router node: identity, static keypair, IV, signing seed.
router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        sign_pub => SignPub,
        iv => IV,
        seed => Seed,
        identity => Identity
    }.

%% The full local-keys map with a signed RouterInfo announcing NTCP2 on Port.
local(#{identity := Identity, static_pub := Pub, iv := IV, seed := Seed} = N, Port) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, now_ms(), [Addr], Opts, Seed),
    N#{sign_seed => Seed, hash => i2p_router_info:hash(RI), ri => RI}.

%% Three distinct router nodes (placeholder port 4668; listeners rebind via
%% ri_at/2 before use).
trio() ->
    {local(router(), 4668), local(router(), 4668), local(router(), 4668)}.

%% Re-sign a router's RouterInfo announcing the actual bound listener port.
ri_at(Port, #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed}) ->
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, Pub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, now_ms(), [Addr], Opts, Seed).

now_ms() ->
    erlang:system_time(millisecond).

%% --------------------------------------------------------------------------
%% SSU2 transport-selection fixtures
%% --------------------------------------------------------------------------

%% The SSU2 session intro key, derived from the router's static secret exactly
%% as `i2per_sup` does at boot (`i2p_identity:intro_key/1`).
intro_key(#{static_priv := Priv}) ->
    crypto:hash(sha256, <<Priv/binary, "i2p-ssu2-intro">>).

%% The full local-keys map of an SSU2-capable router: static keypair plus
%% derived intro key, and a signed RouterInfo announcing both NTCP2 on
%% NTCP2Port and SSU2 on SSU2Port. Mirrors `i2p_peer:ssu2_connect_ready/3`
%% expectations.
ssu2_local(
    #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed} = N, NTCP2Port, SSU2Port
) ->
    Addrs = [
        i2p_router_info:ntcp2_address(<<"127.0.0.1">>, NTCP2Port, Pub, IV),
        i2p_router_info:ssu2_address(<<"127.0.0.1">>, SSU2Port, Pub, intro_key(N))
    ],
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, now_ms(), Addrs, Opts, Seed),
    N#{
        sign_seed => Seed,
        intro_key => intro_key(N),
        hash => i2p_router_info:hash(RI),
        ri => RI
    }.

%% As `f:ssu2_local/3` but a plain RouterInfo (no full local map): a remote
%% router announcing NTCP2 on NTCP2Port and SSU2 on SSU2Port.
ssu2_ri_at(
    NTCP2Port, SSU2Port, #{identity := Identity, static_pub := Pub, iv := IV, seed := Seed} = N
) ->
    Addrs = [
        i2p_router_info:ntcp2_address(<<"127.0.0.1">>, NTCP2Port, Pub, IV),
        i2p_router_info:ssu2_address(<<"127.0.0.1">>, SSU2Port, Pub, intro_key(N))
    ],
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    i2p_router_info:build(Identity, now_ms(), Addrs, Opts, Seed).

%% Bind a loopback SSU2 listener for a router (session owner = the test
%% process), registering the `i2p_ssu2_listener` global name so the peer
%% manager's SSU2 guard sees it; return `{Listener, BoundPort}`.
ssu2_listener(#{static_priv := Priv, static_pub := Pub}) ->
    LocalKeys = #{
        static_priv => Priv,
        static_pub => Pub,
        intro_key => crypto:hash(sha256, <<Priv/binary, "i2p-ssu2-intro">>)
    },
    {ok, L} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, LocalKeys, self()),
    {L, i2p_ssu2_listener:port(L)}.

%% The next inbound SSU2 Data delivery to the (test-owned) Bob session,
%% draining any non-session mail (ready/close notices from earlier in the
%% case or from the boot listener) that a plain receive would leave behind.
await_ssu2() ->
    await_ssu2(?TIMEOUT).

await_ssu2(TimeoutMs) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, Pid, Blocks}) -> {true, {Pid, Blocks}};
            (_) -> false
        end,
        TimeoutMs
    ).

%% The I2NP block types carried in SSU2 Data blocks.
ssu2_block_types(Blocks) ->
    [Type || {i2np, Type, _MsgId, _ShortExp, _Body} <- Blocks].

%% Collect inbound SSU2 Data up to N messages until every I2NP type in `Want`
%% has been seen (datagrams may coalesce or split arbitrarily).
await_ssu2_types(Want, N) ->
    collect_ssu2(Want, [], N).

collect_ssu2(_Want, _Seen, 0) ->
    error(ssu2_types_timeout);
collect_ssu2(Want, Seen, N) ->
    {_, Blocks} = await_ssu2(),
    NewSeen = lists:usort(Seen ++ ssu2_block_types(Blocks)),
    case Want -- NewSeen of
        [] -> NewSeen;
        _ -> collect_ssu2(Want, NewSeen, N - 1)
    end.

%% Stop any previous manager (async, so wait for its death) and start a fresh
%% one linked to the test process.
start_peer(Local, Seeds) ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            i2p_peer:stop(),
            MRef = erlang:monitor(process, Pid),
            receive
                {'DOWN', MRef, process, Pid, _} -> ok
            after 5000 ->
                error(stop_timeout)
            end
    end,
    {ok, _} = i2p_peer:start_link(Local, Seeds),
    ok.

listen_port(Listener) ->
    i2p_ntcp2_listener:port(Listener).

%% Wait for the first data-phase frame (we own the bob-side connection), and
%% return the connection pid together with the decoded database message:
%% `{store, Map}` | `{lookup, Map}` | `{search_reply, Map}` |
%% `{delivery_status, MsgID, TimeMs}`.
await_frame() ->
    await_frame(?TIMEOUT).

%% As `f:await_frame/0` with an explicit timeout (the NTCP2 leg of the fallback
%% scenario only appears after the ~20s SSU2 handshake budget).
await_frame(TimeoutMs) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, Conn, Payload}) -> {true, {Conn, db_msg(decode_msg(Payload))}};
            (_) -> false
        end,
        TimeoutMs
    ).

decode_msg(Payload) ->
    {ok, Blocks} = i2p_framing:decode_blocks(Payload),
    [#{type := 3, data := Data}] = [B || #{type := 3} = B <- Blocks],
    {ok, Msg} = i2p_i2np:decode(Data),
    Msg.

db_msg(#{type := 1, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_store(Body),
    {store, M};
db_msg(#{type := 2, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_lookup(Body),
    {lookup, M};
db_msg(#{type := 3, body := Body}) ->
    {ok, M} = i2p_i2np:decode_db_search_reply(Body),
    {search_reply, M};
db_msg(#{type := 10, body := Body}) ->
    {ok, MsgID, TimeMs} = i2p_i2np:decode_delivery_status(Body),
    {delivery_status, MsgID, TimeMs}.

%% Documented load-safe window: 400 polls x 25ms = 10s wall-clock budget for
%% the peer manager to reach a status, which covers the SSU2->NTCP2 handshake
%% (~20s, see the 1600-iteration variant below). The poll is deadline-bounded;
%% the 40s variant exists for the slow fallback path.
await_peer_status(Hash, Status) ->
    await_peer_status(Hash, Status, 400).

await_peer_status(_Hash, _Status, 0) ->
    error({peer_not_in_status, i2p_peer:status()});
await_peer_status(Hash, Status, N) ->
    case i2p_peer:status() of
        #{Hash := #{status := Status}} ->
            ok;
        _ ->
            %% Documented load-safe window: 25ms poll backoff inside the
            %% deadline-bounded await_peer_status loop (see the window note
            %% above) — a state poll over i2p_peer:status(), not a fixed sleep
            %% gating an assertion.
            timer:sleep(25),
            await_peer_status(Hash, Status, N - 1)
    end.

peer_status(Hash) ->
    #{Hash := S} = i2p_peer:status(),
    S.

%% Poll the manager until the dial attempt count reaches MinAttempts — the
%% retries firing on the 1s/2s/4s backoff windows prove exponential backoff.
wait_for_attempts(_Hash, MinAttempts, _Deadline) when MinAttempts =< 0 ->
    i2p_peer:status();
wait_for_attempts(Hash, MinAttempts, Deadline) ->
    #{Hash := #{attempts := N}} = i2p_peer:status(),
    case N >= MinAttempts of
        true ->
            N;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    erlang:error({attempts_timeout, N});
                false ->
                    %% Documented load-safe window: 50ms poll backoff in a
                    %% deadline-bounded loop over i2p_peer:status() — a state
                    %% poll, not a fixed sleep gating an assertion.
                    timer:sleep(50),
                    wait_for_attempts(Hash, MinAttempts, Deadline)
            end
    end.

%% The I2NP message on Conn, decoded — the receive drains anything that is not
%% a frame from this exact connection.
recv_msg(Conn) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ntcp2_frame, P, Payload}) when P =:= Conn -> {true, decode_msg(Payload)};
            (_) -> false
        end,
        ?TIMEOUT
    ).

recv_db_store(Conn) ->
    #{type := 1, body := Body} = recv_msg(Conn),
    {ok, #{store_type := 0, data := Data}} = i2p_i2np:decode_db_store(Body),
    {ok, RIBytes} = i2p_i2np:parse_router_info_data(Data),
    {ok, RI} = i2p_router_info:decode(RIBytes),
    {store, RI}.
