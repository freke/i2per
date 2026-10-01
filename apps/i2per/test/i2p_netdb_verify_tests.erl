%% Tests that the NetDb read path is not behind signature verification.
%%
%% Storing a RouterInfo from the wire means verifying an Ed25519 signature, and
%% that verification measures 100.4 us against 1-3 us for the store itself. It
%% used to run inside `m:i2p_netdb_srv`, so a floodfill replication burst or a
%% 75-RouterInfo reseed bundle was a run of those in the one process every NetDb
%% read queues behind. `f:i2p_netdb_srv:store_binary/2` now decodes in the calling
%% process and hands the NetDb a parsed value.
%%
%% The property these cases assert is that a read is still served while stores
%% are in flight. That is deliberately not a timing assertion, because no
%% deadline is involved anywhere. A test that waited and checked "the read came
%% back fast enough" passes on an idle machine and fails on a loaded one, and
%% this project treats a deadline as a flake with better manners. What is
%% asserted instead is structural, namely that the NetDb process performs no
%% verification, which is the thing that would have to be true for a read to be
%% blocked, plus a functional check that a read issued from another process
%% during a burst is answered.

-module(i2p_netdb_verify_tests).

-moduledoc """
Tests that NetDb signature verification does not run in the process that
serves reads.
""".

-include_lib("eunit/include/eunit.hrl").

%% A reseed delivers 75 RouterInfos in one bundle, and a floodfill burst is
%% similar in shape. 75 is the reseed figure, so it is the number worth testing.
-define(BUNDLE, 75).

%%% --------------------------------------------------------------------------
%%% The property
%%% --------------------------------------------------------------------------

%% The structural assertion, and the one that catches a regression.
%%
%% Traced rather than timed: put the decode back inside the NetDb and this goes
%% red, with no deadline anywhere in it. The trace covers `decode/1` and
%% `parse/1` because either could be where a future change reintroduces the
%% verify, and it is filtered to the NetDb process so an unrelated decode in the
%% test process cannot mask a real one.
%%
%% Demonstrated red: moving `i2p_router_info:decode/1` back inside the
%% `handle_call` clause turns this case red and lists every decode the NetDb
%% performed, and it is green again on restore.
netdb_process_never_verifies_a_signature_test() ->
    with_netdb(
        fun(_Key) ->
            Traced = start_tracing(),
            try
                ?assertEqual(?BUNDLE, store_bundle()),
                ?assertEqual([], verifications_in(Traced, []))
            after
                stop_tracing(Traced)
            end
        end
    ).

%% A read from another process is answered while a burst of stores is still
%% being issued. The burst runs in its own process and is left in flight, and the
%% read is issued from this one.
%%
%% `f:start_storing/0` returns the moment the burst announces itself, before its
%% first store, so the read below genuinely overlaps the burst rather than
%% following it. The assertion is on the answer coming back, not on how long it
%% took.
read_is_served_while_a_bundle_is_being_stored_test() ->
    with_netdb(
        fun(Key) ->
            Ref = start_storing(),
            try
                ?assertMatch({ok, _}, i2p_netdb_srv:find(Key))
            after
                await_stores(Ref)
            end
        end
    ).

%% The same read on the existence check the relay path actually uses.
%% `has_router/1` is a table read and the cheapest read there is, so if that one
%% is blocked then so is everything.
relay_read_is_served_while_a_bundle_is_being_stored_test() ->
    with_netdb(
        fun(Key) ->
            Ref = start_storing(),
            try
                ?assertEqual(true, i2p_netdb_srv:has_router(Key))
            after
                await_stores(Ref)
            end
        end
    ).

%% Starts a burst of stores in its own process and returns once it is under way.
%%
%% The barrier is the `started` message the storer sends before its first store.
%% That is the point at which stores are certain to be in flight, so the read the
%% caller issues next genuinely overlaps the burst. Waiting for the burst to
%% finish instead would make the two sequential and the case would prove nothing.
%%
%% The monitor is taken here, where the process is created. Monitoring afterwards
%% races: a burst of 75 verifications can complete before the monitor exists, and
%% monitoring a dead pid answers `noproc` at once, which reads as a crash in the
%% storer rather than as the race it is.
start_storing() ->
    Parent = self(),
    {_Pid, Ref} = spawn_monitor(fun() -> start_storing_here(Parent) end),
    receive
        started -> Ref
    after 5000 ->
        erlang:error(storer_never_started)
    end.

%% Announces itself to `Parent` before the first store, so the parent's read is
%% issued while stores are certain to be in flight.
start_storing_here(Parent) ->
    Parent ! started,
    store_bundle().

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

%% Brings up a NetDb holding one RouterInfo, then hands the body that
%% RouterInfo's hash.
%%
%% Whatever this starts, it stops. `i2p_stats` and `i2p_netdb_srv` are
%% registered names inside the `i2per` application, and a bare `start_link/0`
%% leaves one registered that the application controller did not start, which the
%% next module that boots `i2per` reads as `already_started` and fails on.
with_netdb(Body) ->
    StartedNetdb = ensure_started(i2p_netdb_srv),
    StartedStats = ensure_started(i2p_stats),
    try
        Now = erlang:system_time(millisecond),
        RI = i2p_ct_helpers:floodfill_router_info(Now, <<"192.0.2.10">>),
        added = i2p_netdb_srv:store(RI, Now),
        Body(i2p_router_info:hash(RI))
    after
        stop_if_started(StartedStats),
        stop_if_started(StartedNetdb)
    end.

ensure_started(Mod) ->
    case whereis(Mod) of
        undefined ->
            {ok, Pid} = Mod:start_link(),
            Pid;
        _Running ->
            already_running
    end.

stop_if_started(already_running) ->
    ok;
stop_if_started(Pid) ->
    ok = gen_server:stop(Pid),
    ok.

%%% --------------------------------------------------------------------------
%%% The burst
%%% --------------------------------------------------------------------------

%% What a reseed or a floodfill burst delivers: signed bytes, not parsed values.
%% Handing over bytes rather than a parsed RouterInfo is the point, so the decode
%% really is on the path being tested.
%%
%% Returns how many were added, which is ?BUNDLE. Each entry is signed once here
%% and verified once per store inside `f:store_binary/2`, so the burst costs
%% ?BUNDLE verifications. Asserting the count is what stops a silently dropped
%% entry from turning this into a test that verifies nothing.
store_bundle() ->
    Now = erlang:system_time(millisecond),
    Bins = [
        i2p_router_info:to_binary(i2p_ct_helpers:floodfill_router_info(Now, host(N)))
     || N <- lists:seq(1, ?BUNDLE)
    ],
    Outcomes = [i2p_netdb_srv:store_binary(Bin, Now) || Bin <- Bins],
    length([added || {ok, added} <- Outcomes]).

%% Documentation-range addresses, one per fixture, so each RouterInfo is a
%% distinct key and the burst really does grow the store rather than colliding
%% on one entry.
host(N) ->
    list_to_binary("192.0.2." ++ integer_to_list(N)).

%% Waits for the burst to finish, so a case cannot leave stores in flight behind
%% it. A storer that died is a failure rather than a silent pass, since it means
%% the burst raised, which is the thing the read assertions would have hidden.
await_stores(Ref) ->
    receive
        {'DOWN', Ref, process, _Pid, Reason} when Reason =:= normal ->
            ok;
        {'DOWN', Ref, process, Pid, Reason} ->
            erlang:error({storer_died, Pid, Reason})
    after 30000 ->
        erlang:error({storer_stuck, Ref})
    end.

%%% --------------------------------------------------------------------------
%%% Tracing
%%% --------------------------------------------------------------------------

%% Trace the NetDb process's own calls to the two functions that can verify a
%% signature. `decode/1` is what `f:store_binary/2` calls today, and `parse/1` is
%% what it would call if someone reintroduced the verify inside the NetDb by
%% another route.
%%
%% The count \`erlang:trace_pattern/3\` returns has to be asserted. It returns 0
%% for a module that has not been loaded yet, and 0 matches means no trace
%% messages arrive, so an assertion built on them passes no matter what the code
%% under test does. Loading the module first and asserting the count turns a
%% silent no-op trace into a failure here rather than into a test that cannot fail
%% below. That is not hypothetical: it is what this case did until the count was
%% checked.
start_tracing() ->
    {module, i2p_router_info} = code:ensure_loaded(i2p_router_info),
    ?assertEqual(1, erlang:trace_pattern({i2p_router_info, decode, 1}, true, [local])),
    ?assertEqual(1, erlang:trace_pattern({i2p_router_info, parse, 1}, true, [local])),
    Netdb = whereis(i2p_netdb_srv),
    ?assertEqual(1, erlang:trace(Netdb, true, [call])),
    Netdb.

stop_tracing(Netdb) ->
    _ = erlang:trace_pattern({i2p_router_info, decode, 1}, false, [local]),
    _ = erlang:trace_pattern({i2p_router_info, parse, 1}, false, [local]),
    _ = erlang:trace(Netdb, false, [call]),
    ok.

%% Traced calls arrive as ordinary messages, so draining the mailbox is a
%% barrier: by the time this returns, every traced call the NetDb made has
%% returned and its message is already queued.
%%
%% The message is the 4-tuple `{trace, Pid, call, {M, F, Args}}`. Two details
%% matter and both fail silently if wrong. The args are the *third* element of
%% the MFA, not a nested `{M, F, A}` triple; and there is no return value,
%% because the `call` trace flag reports the call and not its result. A pattern
%% expecting a fifth element matches nothing, and an assertion built on a match
%% that cannot fire passes whatever the code under test does.
verifications_in(Netdb, Acc) ->
    receive
        {trace, Netdb, call, {i2p_router_info, decode, _Args}} ->
            verifications_in(Netdb, [decode | Acc]);
        {trace, Netdb, call, {i2p_router_info, parse, _Args}} ->
            verifications_in(Netdb, [parse | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.
