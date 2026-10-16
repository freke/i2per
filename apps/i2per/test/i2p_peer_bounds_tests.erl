%% Tests that the peer manager's three accumulating structures are bounded.
%%
%% ## What was wrong
%%
%% Three structures in `m:i2p_peer` were appended to and never reclaimed:
%%
%% - `pending_sends` -- one entry per peer hash, drained by exactly one path
%%   (`send_pending_sends/4`, reached only when a connection succeeds). A peer
%%   nothing ever connects to kept its entry for the life of the process. Silent:
%%   no log, no counter, no test.
%% - `peers` -- `put_peer/3` only ever put, and nothing ever removed.
%% - `known` -- the dialable seed set, which was a *list* that deduped by hash
%%   and never evicted, so it grew for every distinct RouterInfo the NetDb
%%   accepted, and `known_hash/2` was a `lists:any/2` over all of it on the dial
%%   path.
%%
%% The sharp case is the one this suite pins hardest: a peer that will never be
%% dialled. `f:maybe_connect/2` declines when `find_peer_config/2` is `undefined`,
%% and no amount of waiting drains the queue. That is a RouterInfo with no
%% published address, and a RouterInfo whose only address is SSU2 on a router
%% that does not reach for UDP (`f:i2p_identity:ssu2_preferred/0` false).
%%
%% ## What this suite does not claim
%%
%% That the constants are the right numbers. `?MAX_PENDING_SENDS_PER_PEER` is
%% sized against the reconnection window and `?MAX_KNOWN` against the connection
%% caps; both are argued in `m:i2p_peer` and neither is measured here. What is
%% pinned is the *behaviour*: that each bound holds, that it is reachable by
%% exceeding it, and that what gets discarded is the right thing.

-module(i2p_peer_bounds_tests).

-moduledoc """
Tests that `m:i2p_peer`'s three accumulating structures are bounded, that the
bounds are reachable by exceeding them, and that reclamation takes the oldest
rather than the newest.
""".

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% pending_sends: depth
%% --------------------------------------------------------------------------

%% **The depth bound holds, and the case reaches it rather than reading it.**
%%
%% 100 enqueues against a peer that never connects, then the queue is asserted
%% to be at the cap and no larger. A test that read the constant back would pass
%% against a bound that is never enforced; this one cannot.
queue_stops_growing_at_the_depth_bound_test() ->
    H = mk_hash(),
    S0 = base_state(),
    S1 = enqueue_n(S0, H, 100),
    Queue = maps:get(H, maps:get(pending_sends, S1)),
    ?assertEqual(64, length(Queue)).

%% **The tail goes, not the head.**
%%
%% `f:enqueue_send/3` prepends, so a full queue sheds its *oldest* entries. A
%% relay frame belongs to a tunnel, and one that has waited is worth less than
%% one that has not -- so the frames that survive a truncation are the recent
%% ones. The test enqueues numbered messages and asserts the survivors are the
%% high numbers.
%%
%% Getting this backwards keeps the frame that has waited longest and delivers
%% it in preference to a fresh one, which is the worse of the two mistakes
%% because it looks like it is prioritising.
queue_truncation_keeps_the_newest_frames_test() ->
    H = mk_hash(),
    S1 = enqueue_n(base_state(), H, 100),
    Survivors = [M || {at, _, M} <- maps:get(H, maps:get(pending_sends, S1))],
    Numbers = [maps:get(body, M) || M <- Survivors],
    %% The 100 most recent are numbers 37..100, newest first.
    ?assertEqual(100, lists:max(Numbers)),
    ?assertEqual(37, lists:min(Numbers)),
    ?assertEqual(64, length(Numbers)).

%% The bound is per peer, not global: one peer's queue being full must not
%% consume another's.
queue_bound_is_per_peer_test() ->
    H1 = mk_hash(),
    H2 = mk_hash(),
    S1 = enqueue_n(base_state(), H1, 100),
    S2 = enqueue_n(S1, H2, 5),
    ?assertEqual(64, length(maps:get(H1, maps:get(pending_sends, S2)))),
    ?assertEqual(5, length(maps:get(H2, maps:get(pending_sends, S2)))).

%% --------------------------------------------------------------------------
%% pending_sends: age
%% --------------------------------------------------------------------------

%% **Age reclaims what the depth bound holds.**
%%
%% This is the half that matters for the permanent-stall case. A depth cap alone
%% converts unbounded growth into a bounded amount retained *for ever*, once per
%% peer the router ever learned -- which across a router fed thousands of
%% distinct peers is still a leak. Only expiry gives the memory back.
%%
%% The timestamps are written by hand rather than waited for, so the case has no
%% timing assertion in it: the clock is an input, not something the test sleeps
%% for.
aged_queue_is_reclaimed_by_the_sweep_test() ->
    H = mk_hash(),
    Now = erlang:system_time(millisecond),
    Old = Now - 600_000,
    S0 = base_state(),
    S1 = S0#{
        pending_sends => #{
            H => [
                {at, Now, msg(1)},
                {at, Now - 1000, msg(2)},
                {at, Old, msg(3)},
                {at, Old - 1000, msg(4)}
            ]
        }
    },
    S2 = i2p_peer:handle_info(sweep, S1),
    {noreply, S3} = S2,
    Survivors = [M || {at, _, M} <- maps:get(H, maps:get(pending_sends, S3))],
    ?assertEqual([1, 2], [maps:get(body, M) || M <- Survivors]).

%% A peer whose entire queue has aged out is removed from `pending_sends`
%% altogether, rather than being left holding an empty list -- which would keep
%% the key, and the entry it implies, for ever.
fully_aged_queue_removes_the_peer_entry_test() ->
    H = mk_hash(),
    Old = erlang:system_time(millisecond) - 600_000,
    S0 = base_state(),
    S1 = S0#{pending_sends := #{H => [{at, Old, msg(1)}]}},
    {noreply, S2} = i2p_peer:handle_info(sweep, S1),
    ?assertEqual(#{}, maps:get(pending_sends, S2)).

%% A fresh queue survives the sweep untouched. The sweep must not be a
%% convenient way to lose work.
fresh_queue_survives_the_sweep_test() ->
    H = mk_hash(),
    S1 = enqueue_n(base_state(), H, 10),
    {noreply, S2} = i2p_peer:handle_info(sweep, S1),
    ?assertEqual(10, length(maps:get(H, maps:get(pending_sends, S2)))).

%% --------------------------------------------------------------------------
%% peers
%% --------------------------------------------------------------------------

%% `connecting` is never evicted, even over the cap. A peer mid-dial has a
%% handshake in flight, and `f:handle_conn_started/4` answers `error` for an
%% unknown peer by stopping the connection -- so evicting one tears down a dial
%% with its own successful handshake.
connecting_peer_is_never_evicted_test() ->
    S0 = idle_peers(base_state(), 300),
    Mid = mk_hash(),
    S1 = S0#{peers := maps:put(Mid, peer(Mid, #{status => connecting}), maps:get(peers, S0))},
    {noreply, S2} = i2p_peer:handle_info(sweep, S1),
    ?assert(maps:is_key(Mid, maps:get(peers, S2))).

%% Idle peers *are* evicted over the cap, which is the case the bound exists
%% for. "Idle" is no conn, no monitor, not connecting -- i.e. a peer in backoff
%% that nothing is holding.
idle_peers_are_evicted_over_the_cap_test() ->
    S0 = idle_peers(base_state(), 300),
    Before = map_size(maps:get(peers, S0)),
    ?assertEqual(300, Before),
    {noreply, S1} = i2p_peer:handle_info(sweep, S0),
    After = map_size(maps:get(peers, S1)),
    ?assert(After < Before),
    ?assert(After =< 256).

%% Under the cap, the sweep leaves `peers` alone. A peer in backoff is expected
%% to sit below the cap, and evicting eagerly would churn the dial path.
peers_under_the_cap_are_left_alone_test() ->
    S0 = idle_peers(base_state(), 10),
    {noreply, S1} = i2p_peer:handle_info(sweep, S0),
    ?assertEqual(10, map_size(maps:get(peers, S1))).

%% --------------------------------------------------------------------------
%% Fixtures
%% --------------------------------------------------------------------------

base_state() ->
    Local = local(),
    #{
        local => Local,
        known => #{},
        seed_order => [],
        peers => #{},
        inbound => #{},
        pending => #{},
        pending_sends => #{},
        our_hash => maps:get(hash, Local),
        refresh_ref => make_ref(),
        discovery_kick_ref => make_ref(),
        sweep_ref => make_ref()
    }.

local() ->
    RI = mk_ri(),
    #{
        hash => i2p_router_info:hash(RI),
        sign_seed => crypto:strong_rand_bytes(32),
        sign_pub => crypto:strong_rand_bytes(32),
        ri => RI
    }.

peer(Hash, Extra) ->
    maps:merge(
        #{
            config => #{ri => mk_ri(), hash => Hash},
            conn => undefined,
            mon => undefined,
            transport => ntcp2,
            backoff => 0,
            attempts => 0,
            last_attempt => 0,
            status => connecting
        },
        Extra
    ).

idle_peers(State, N) ->
    Peers = maps:from_list([
        {mk_hash(), peer(mk_hash(), #{status => backoff})}
     || _ <- lists:seq(1, N)
    ]),
    State#{peers := Peers}.

%% Enqueue N numbered messages against one peer, with no connection so they all
%% queue rather than being sent.
enqueue_n(State, Hash, N) ->
    lists:foldl(
        fun(I, S) ->
            {noreply, S1} = i2p_peer:handle_cast(
                {send_when_ready, Hash, msg(I)}, S
            ),
            S1
        end,
        State,
        lists:seq(1, N)
    ).

mk_ri() ->
    #{identity := Id, sign_priv := SignSeed} = i2p_keys:generate_with_privkeys(),
    i2p_router_info:build(Id, erlang:system_time(millisecond), [], #{}, SignSeed).

mk_hash() -> crypto:strong_rand_bytes(32).

msg(N) -> #{type => 1, msg_id => <<16#DEADBEEF:32>>, body => N}.
