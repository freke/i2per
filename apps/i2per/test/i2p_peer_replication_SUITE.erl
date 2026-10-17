%% Which DatabaseStore entries a floodfill is allowed to push on.
%%
%% `f:i2p_peer:handle_db_store/4` used to call `f:maybe_replicate/5`
%% unconditionally, on a path that had already decided whether the entry was
%% stored. So a type we do not implement (ELS2, MetaLeaseSet) and an entry the
%% NetDb refused were both handed to the 3 closest eligible floodfills with the
%% original type byte intact — a router asking the network to serve something it
%% never held. And because the per-type handlers *also* replicated, through
%% `f:replicate_if_new/6`, every entry we did store went out twice.
%%
%% `f:maybe_replicate/5`'s own comment already claimed it fired only on `added`
%% or `updated`. These cases are what make that true.
%%
%% There is a second half to "allowed to push on", and it is not about the entry
%% at all: the store's reply token. Both references forward only a store that
%% asked to be forwarded — i2pd's `if (replyToken && context.IsFloodfill () &&
%% updated)` (`libi2pd/NetDb.cpp:925`), Java's `floodfillEnabled() &&
%% getReplyToken() > 0` (`HandleFloodfillDatabaseStoreMessageJob.java:486`) — and
%% `f:i2p_floodfill:flood_requested/1` is that condition. So a case that is about
%% *which entries* may be pushed on has to send a token, or the gate would
%% suppress the store first and the case would pass without ever testing its
%% claim. `store_without_reply_token_does_not_replicate` is the case about the
%% gate itself, and it is the only one that sends none.
%%
%% Replication is observed by tracing `f:i2p_floodfill:replication_outbox/5`,
%% which is the single point every forwarded entry passes through, and by reading
%% the two replication counters the same decision moves. The NetDb,
%% the event bus, the counters and the peer manager are started standalone:
%% starting the whole application would leave `i2p_tunnel_srv` running and fail
%% the suites that follow, which start it themselves.

-module(i2p_peer_replication_SUITE).

-export([all/0, suite/0, init_per_testcase/2, end_per_testcase/2]).

-export([
    stored_router_info_replicates_exactly_once/1,
    store_without_reply_token_does_not_replicate/1,
    unimplemented_store_type_does_not_replicate/1,
    refused_router_info_does_not_replicate/1,
    undecodable_store_does_not_replicate/1,
    unstored_outcomes_are_reported/1
]).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

%% 27 hours is `?MAX_EXPIRATION_MS` in m:i2p_netdb, and the NetDb's acceptance
%% window rejects anything older. A day past that cannot be stored.
-define(TOO_OLD_MS, 28 * 60 * 60 * 1000).

%% How long to watch for forwards before concluding there were none. The peer
%% manager is a local process, so a few hundred milliseconds is generous; the
%% negative cases are the ones that make a regression expensive to miss.
-define(SETTLE_MS, 500).

%% I2NP DatabaseStore message type (see i2p_i2np:db_store/5).
-define(I2NP_DB_STORE, 1).

%% The reply token on the stores that are meant to be forwarded. The value only
%% has to be nonzero — one value is enough because `f:i2p_floodfill:flood_requested/1`
%% does not branch on it — and the reply gateway is a random hash no peer here
%% answers as, so the DeliveryStatus goes nowhere and nothing else moves.
-define(REPLY_TOKEN, 16#5EEDCAFE).

%% Enough floodfills for the 3 replication targets to exist alongside self and
%% the originator, which `f:i2p_floodfill:replication_outbox/5` excludes.
-define(POOL, 6).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        stored_router_info_replicates_exactly_once,
        store_without_reply_token_does_not_replicate,
        unimplemented_store_type_does_not_replicate,
        refused_router_info_does_not_replicate,
        undecodable_store_does_not_replicate,
        unstored_outcomes_are_reported
    ].

init_per_testcase(_Case, Config) ->
    ok = i2p_ct_helpers:stop_app(),
    {ok, Netdb} = i2p_netdb_srv:start_link(),
    {ok, _Events} = i2p_events:start_link(),
    ok = gen_event:add_handler(i2p_events, i2p_events_forward, [self()]),
    %% Standalone, like the rest of the tree here. `f:i2p_counters:add/2` is
    %% documented to no-op when this process is not running, so a suite that
    %% starts part of the tree is allowed to leave it out -- but then the two
    %% replication counters are asserted against nothing and a gate that never
    %% counted would pass. This case is about what the decision *reports*, so the
    %% reporter is running.
    {ok, _Counters} = i2p_counters:start_link(),
    Dir = i2p_ct_helpers:temp_data_dir(Config),
    {ok, Id} = i2p_identity:ensure_identity(Dir),
    Local = i2p_identity:build_local(Id, <<"127.0.0.1">>, 9150, maps:get(sign_seed, Id)),
    {ok, Peer} = i2p_peer:start_link(Local, []),
    application:set_env(i2per, floodfill, true),
    Now = erlang:system_time(millisecond),
    lists:foreach(
        fun(_N) ->
            added = i2p_netdb_srv:store(fresh(Now), Now)
        end,
        lists:seq(1, ?POOL)
    ),
    ok = trace_replication(Peer),
    [{peer, Peer}, {netdb, Netdb}, {now, Now} | Config].

end_per_testcase(_Case, _Config) ->
    ok = untrace_replication(),
    application:unset_env(i2per, floodfill),
    _ = catch gen_event:delete_handler(i2p_events, i2p_events_forward, []),
    _ = catch i2p_peer:stop(),
    _ = catch gen_event:stop(i2p_events),
    teardown_netdb(whereis(i2p_netdb_srv)),
    %% Not under the application supervisor here, so `stop_app/0` does not reach
    %% it, and leaving it up would keep `persistent_term` holding a state whose
    %% owner is gone.
    _ = catch gen_server:stop(i2p_counters),
    ok = i2p_ct_helpers:stop_app(),
    ok.

%% --------------------------------------------------------------------------
%% Cases
%% --------------------------------------------------------------------------

%% The entry we actually stored is the one entry we push on, and we push it
%% once. Before, it went out twice: `f:handle_ri_store/4` replicated through
%% `f:replicate_if_new/6` and `f:handle_db_store/4` replicated again.
%%
%% The token is what asks for the forward, and the two counters are the same
%% decision reported: one entry forwarded, none withheld.
stored_router_info_replicates_exactly_once(Config) ->
    Peer = ?config(peer, Config),
    Now = ?config(now, Config),
    Key = crypto:strong_rand_bytes(32),
    send(Peer, i2p_ct_helpers:db_store_block(0, Key, ?REPLY_TOKEN, fresh(Now))),
    ?assertEqual([0], forwards(?SETTLE_MS)),
    ?assertEqual(1, counter(netdb_replications_sent)),
    ?assertEqual(0, counter(netdb_replications_suppressed_no_token)).

%% The gate, and the case that holds it. A token-free store is a direct
%% announcement — a peer telling us its own RouterInfo, or i2pd's "tell floodfill
%% about us" — and the references store it and stop. We used to forward it, which
%% asks the network to hold an entry nobody requested and, because the forwarded
%% copy also carries no token, hands the same entry on again from the floodfill
%% that receives it. The entry is stored; nothing goes out; the suppression is
%% reported, because a router that stopped forwarding silently would look
%% identical to one that never had anything to forward.
store_without_reply_token_does_not_replicate(Config) ->
    Peer = ?config(peer, Config),
    Now = ?config(now, Config),
    send(Peer, i2p_ct_helpers:db_store_block(0, crypto:strong_rand_bytes(32), fresh(Now))),
    ?assertEqual([], forwards(?SETTLE_MS)),
    ?assertEqual(0, counter(netdb_replications_sent)),
    ?assertEqual(1, counter(netdb_replications_suppressed_no_token)).

%% The defect the ticket is named for. ELS2 (type 5) decodes, and we do not
%% implement it — so we hold nothing, and we may not ask three other routers to
%% hold it for us. The type byte went out intact. The token is set so that what
%% stops this is the entry, not the gate.
unimplemented_store_type_does_not_replicate(Config) ->
    Peer = ?config(peer, Config),
    lists:foreach(
        fun(Type) ->
            send(
                Peer,
                i2p_ct_helpers:db_store_block(
                    Type, crypto:strong_rand_bytes(32), ?REPLY_TOKEN, <<"x">>
                )
            ),
            ?assertEqual([], forwards(?SETTLE_MS))
        end,
        [5, 7]
    ).

%% A RouterInfo the NetDb's clock window refuses is not in our store either, so
%% it is not ours to forward. `m:i2p_netdb` refuses these as `too_old`.
refused_router_info_does_not_replicate(Config) ->
    Peer = ?config(peer, Config),
    Now = ?config(now, Config),
    send(
        Peer,
        i2p_ct_helpers:db_store_block(
            0, crypto:strong_rand_bytes(32), ?REPLY_TOKEN, fresh(Now - ?TOO_OLD_MS)
        )
    ),
    ?assertEqual([], forwards(?SETTLE_MS)).

%% A DatabaseStore we cannot even parse is not replicated either, and the peer
%% that sent it is torn down: it is not speaking the protocol.
undecodable_store_does_not_replicate(Config) ->
    Peer = ?config(peer, Config),
    %% An already-dead connection, because the correct response to a store we
    %% cannot parse is to drop the peer that sent it. Passing the test process
    %% would have the manager tear down the test instead.
    send(Peer, i2p_ct_helpers:dead_pid(), {i2np, ?I2NP_DB_STORE, 7, 0, <<1, 2, 3>>}),
    ?assertEqual([], forwards(?SETTLE_MS)),
    ?assert(is_process_alive(Peer)).

%% Replication and observability are the same decision seen from two sides: if
%% we counted nothing, the two fixes could drift apart. Every unstored outcome
%% is on the bus, with the reason, and the stored one is not reported at all.
unstored_outcomes_are_reported(Config) ->
    Peer = ?config(peer, Config),
    Now = ?config(now, Config),
    %% A type we do not implement, named as such rather than as a refusal.
    send(Peer, i2p_ct_helpers:db_store_block(5, crypto:strong_rand_bytes(32), <<"x">>)),
    ?assertEqual({unsupported_type, 5}, await_not_stored(5000)),
    %% A RouterInfo the clock window refuses, with the NetDb's own reason. The
    %% two are different answers and must not collapse into one.
    send(
        Peer,
        i2p_ct_helpers:db_store_block(0, crypto:strong_rand_bytes(32), fresh(Now - ?TOO_OLD_MS))
    ),
    ?assertEqual({refused_with_reason, too_old}, await_not_stored(5000)),
    %% Storing an entry is the ordinary case and must not be reported as news:
    %% a counter that reported it would drown in it.
    send(Peer, i2p_ct_helpers:db_store_block(0, crypto:strong_rand_bytes(32), fresh(Now))),
    ?assertEqual({error, timeout}, await_not_stored(300)).

%% --------------------------------------------------------------------------
%% Replication observation
%% --------------------------------------------------------------------------

%% Every forwarded entry passes through replication_outbox/5, so tracing its
%% calls counts the forwards and, via the type argument, says what they were.
trace_replication(Peer) ->
    1 = erlang:trace_pattern(
        {i2p_floodfill, replication_outbox, 5},
        [{'_', [], [{return_trace}]}],
        [local]
    ),
    1 = erlang:trace(Peer, true, [call]),
    ok.

untrace_replication() ->
    _ = erlang:trace_pattern({i2p_floodfill, replication_outbox, 5}, false, [local]),
    _ = erlang:trace(all, false, [call]),
    ok.

send(Peer, Block) ->
    send(Peer, self(), Block).

send(Peer, ConnPid, Block) ->
    Peer ! {ssu2_data, ConnPid, [Block]},
    ok.

%% The store types forwarded over the next `Timeout` ms, in order. A fixed
%% window rather than a poll, because half these cases assert an absence: they
%% have to wait long enough to be wrong, and a poll that gives up early would
%% pass a broken build.
forwards(Timeout) ->
    forwards(Timeout, []).

forwards(Budget, Acc) ->
    receive
        {trace, _Pid, call, {i2p_floodfill, replication_outbox, [Type | _]}} ->
            forwards(Budget, [Type | Acc])
    after Budget ->
        lists:reverse(Acc)
    end.

%% Wait for the next unstored report and return its reason.
await_not_stored(Timeout) ->
    receive
        {event, {db_store_not_stored, Reason}} -> Reason
    after Timeout ->
        {error, timeout}
    end.

%% One counter, read through the public snapshot rather than the registry, so a
%% counter that is registered but not reported fails here instead of reading 0.
counter(Name) ->
    maps:get(Name, i2p_counters:snapshot()).

%% --------------------------------------------------------------------------
%% Fixtures
%% --------------------------------------------------------------------------

%% A RouterInfo published `Now`, so the NetDb accepts it as a new key. The
%% address is fixed because what makes the entry distinct is its keypair, and
%% no test here dials it.
fresh(Now) ->
    i2p_ct_helpers:floodfill_router_info(Now, <<"192.0.2.10">>).

teardown_netdb(undefined) ->
    ok;
teardown_netdb(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    ok.
