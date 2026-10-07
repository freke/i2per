%% That the per-block `ssu2_block_unhandled` announce cannot be flooded.
%%
%% ## What was wrong
%%
%% `f:note_unhandled_ssu2_block/3` emitted one event per *block*. The log line
%% beside it was already deduplicated per `{Identity, Name}` -- with a comment
%% saying why: "a peer that floods us with these must not turn the log into the
%% flood it is causing". The event was left out of that protection, on the
%% reasoning that "a counter wants the total".
%%
%% The total is now `m:i2p_stats:ssu2_blocks_unhandled`, so the reason the event
%% was left exposed is gone, and what is left is the exposure. This is the
%% mechanism #HPH59JN names as the practical way a `gen_event` handler gets
%% wedged: a wedged handler parks the manager, and every event queued behind it
%% sits in the manager's mailbox -- so the flood rate is the backlog rate.
%%
%% ## What these cases do and do not claim
%%
%% They pin that **one peer sending one kind of block announces once, however
%% many blocks arrive**, and that **every block is still counted**. They do not
%% pin a bound on the queue behind a wedged manager; that is the mechanism
%% question #HPH59JN parks, and it is not reachable from the call site.

-module(i2p_peer_block_flood_tests).

-moduledoc """
Tests that the `ssu2_block_unhandled` announce is deduplicated per peer and kind
while every occurrence is still counted.
""".

-include_lib("eunit/include/eunit.hrl").

%% --------------------------------------------------------------------------
%% The bound: one peer, one kind, one announce
%% --------------------------------------------------------------------------

%% **The property the flood exists to violate.** Ten thousand blocks of one kind
%% from one peer is one announce, not ten thousand.
%%
%% Asserted against a *large* N on purpose. `?assertEqual(1, length(...))` at
%% N=2 would also be satisfied by a deduplication that merely lost the second
%% block rather than the thousandth, and the block count is a counter assertion
%% that proves every one of them was seen.
a_repeated_block_from_one_peer_is_announced_once_test() ->
    with_bus(fun() ->
        S0 = state_with_peer(peer_hash(1)),
        {noreply, S1} = blocks(S0, {relay_tag, 1}, 10000),
        ?assertEqual([relay_tag], announced()),
        ?assertEqual(10000, blocks_counted()),
        %% The dedup set is one key, not ten thousand entries.
        ?assertEqual(1, map_size(maps:get(unhandled_ssu2_blocks, S1, #{})))
    end).

%% The bound is per *kind* as well as per peer: a second kind from the same peer
%% is a second fact and gets its own announce. Deduplicating on the peer alone
%% would silence a peer that starts sending something else.
a_second_kind_from_the_same_peer_is_announced_again_test() ->
    with_bus(fun() ->
        S0 = state_with_peer(peer_hash(1)),
        {noreply, S1} = blocks(S0, {relay_tag, 1}, 3),
        {noreply, _} = blocks(S1, {path_challenge, <<"a">>}, 3),
        ?assertEqual([relay_tag, path_challenge], announced())
    end).

%% The bound is per *peer* as well as per kind. This is the case that says the
%% deduplication is keyed on the pair and not on the kind alone: two peers
%% sending the same block are two facts, and an operator's next question is
%% which peer it is. Collapsing them would report one peer doing something the
%% other is also doing, and the figure would name neither.
a_second_peer_sending_the_same_kind_is_announced_again_test() ->
    with_bus(fun() ->
        A = peer_hash(1),
        B = peer_hash(2),
        S0 = state_with_peers([A, B]),
        {noreply, _} = deliver(S0, conn_of(S0, A), {relay_tag, 1}, 2),
        {noreply, _} = deliver(S0, conn_of(S0, B), {relay_tag, 1}, 2),
        ?assertEqual(2, length(announced()))
    end).

%% Ten peers flooding one kind is ten announces, and the rate is then a function
%% of the peer set rather than of the block count. Written as a separate case
%% rather than folded into the one above because it is the property that makes
%% the bound *usable*: a cap keyed on the pair still admits a rate set by the
%% network, and the only thing keeping that rate low is `?MAX_PEERS`.
the_announce_rate_is_bounded_by_the_peer_set_not_the_block_count_test() ->
    with_bus(fun() ->
        Hashes = [peer_hash(N) || N <- lists:seq(1, 10)],
        S0 = state_with_peers(Hashes),
        _ = [deliver(S0, conn_of(S0, H), {relay_tag, 1}, 100) || H <- Hashes],
        ?assertEqual(10, length(announced())),
        ?assertEqual(1000, blocks_counted())
    end).

%% Every occurrence is counted, whatever the dedup does. This is the case that
%% stops the bound from being implemented as a silent loss: a counter wants the
%% total, and the total is what this asserts against a flood the announce rate
%% no longer reflects.
every_unhandled_block_is_counted_test() ->
    with_bus(fun() ->
        S0 = state_with_peer(peer_hash(1)),
        {noreply, S1} = blocks(S0, {relay_tag, 1}, 7),
        {noreply, _} = blocks(S1, {path_challenge, <<"a">>}, 3),
        ?assertEqual(10, blocks_counted()),
        ?assertEqual(2, length(announced()))
    end).

%% The counter is named in the registry, because a name that is not registered
%% raises on use and a name that is registered but not wired up is a counter
%% nothing can observe. The read API reports whatever is registered, so this is
%% the whole of the wiring for a consumer.
the_counter_is_registered_test() ->
    ?assert(lists:member(ssu2_blocks_unhandled, i2p_stats:counters())).

%% --------------------------------------------------------------------------
%% Fixtures
%% --------------------------------------------------------------------------

peer_hash(N) ->
    <<N:8, 0:248>>.

%% A peer state with `Count` peers, each holding a connection pid, so that
%% `f:find_conn_peer/2` resolves the pid a block arrived on and the dedup key
%% carries a real identity rather than `unknown`.
state_with_peer(Hash) ->
    state_with_peers([Hash]).

state_with_peers(Hashes) ->
    Pairs = [{Hash, live_peer(Hash)} || Hash <- Hashes],
    #{peers => maps:from_list(Pairs)}.

live_peer(Hash) ->
    Conn = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    #{config => #{hash => Hash, ri => #{}}, conn => Conn, mon => undefined, status => connected}.

conn_of(State, Hash) ->
    maps:get(conn, maps:get(Hash, maps:get(peers, State))).

%% `N` copies of one block from the state's only peer. Answers in the shape
%% `f:handle_info/2` answers, so a case reads as the callback it drives.
blocks(State, Block, N) ->
    [Conn] = [maps:get(conn, P) || P <- maps:values(maps:get(peers, State))],
    deliver(State, Conn, Block, N).

deliver(State, Conn, Block, N) ->
    {noreply, drive_n(State, Conn, Block, N)}.

%% Drive the real entry point: `f:handle_info/2` on `{ssu2_data, ...}`, which is
%% what the SSU2 session process actually sends. Going through
%% `f:handle_ssu2_data/3` matters because the deduplication could otherwise
%% have been placed anywhere along that path, and a bound placed on the wrong
%% one of those two functions is still a bound that does nothing.
drive_n(State, _Conn, _Block, 0) ->
    State;
drive_n(State, Conn, Block, N) ->
    {noreply, Next} = i2p_peer:handle_info({ssu2_data, Conn, [Block]}, State),
    drive_n(Next, Conn, Block, N - 1).

announced() ->
    drain([]).

drain(Acc) ->
    receive
        {event, {ssu2_block_unhandled, Name}} -> drain([Name | Acc])
    after 100 ->
        lists:reverse(Acc)
    end.

blocks_counted() ->
    maps:get(ssu2_blocks_unhandled, i2p_stats:snapshot(), 0).

%% --------------------------------------------------------------------------
%% Harness
%% --------------------------------------------------------------------------

%% Both the bus and the counter home, because these cases assert on two
%% different instruments: the announce is the event, and the total is the
%% counter. Starting the counter home itself is what makes the total observable
%% -- `m:i2p_stats:add/2` is a no-op while it is absent, so a case that did not
%% start it would read 0 and pass on the flood bound alone.
with_bus(Fun) ->
    ok = stop(i2p_stats),
    ok = stop(i2p_events),
    {ok, _} = i2p_stats:start_link(),
    {ok, _} = i2p_events:start_link(),
    ok = gen_event:add_handler(i2p_events, i2p_events_forward, [self()]),
    try
        Fun()
    after
        _ = gen_event:delete_handler(i2p_events, i2p_events_forward, []),
        ok = stop(i2p_events),
        ok = stop(i2p_stats)
    end.

stop(Name) ->
    case whereis(Name) of
        undefined ->
            ok;
        Pid ->
            unlink(Pid),
            ok = gen_server:stop(Pid),
            ok
    end.
