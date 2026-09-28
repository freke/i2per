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
%% Replication is observed by tracing `f:i2p_floodfill:replication_outbox/5`,
%% which is the single point every forwarded entry passes through. The NetDb,
%% the event bus and the peer manager are started standalone: starting the whole
%% application would leave `i2p_tunnel_srv` running and fail the suites that
%% follow, which start it themselves.

-module(i2p_peer_replication_SUITE).

-export([all/0, suite/0, init_per_testcase/2, end_per_testcase/2]).

-export([
    stored_router_info_replicates_exactly_once/1,
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

%% Enough floodfills for the 3 replication targets to exist alongside self and
%% the originator, which `f:i2p_floodfill:replication_outbox/5` excludes.
-define(POOL, 6).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        stored_router_info_replicates_exactly_once,
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
    ok = i2p_ct_helpers:stop_app(),
    ok.

%% --------------------------------------------------------------------------
%% Cases
%% --------------------------------------------------------------------------

%% The entry we actually stored is the one entry we push on, and we push it
%% once. Before, it went out twice: `f:handle_ri_store/4` replicated through
%% `f:replicate_if_new/6` and `f:handle_db_store/4` replicated again.
stored_router_info_replicates_exactly_once(Config) ->
    Peer = ?config(peer, Config),
    Now = ?config(now, Config),
    Key = crypto:strong_rand_bytes(32),
    send(Peer, i2p_ct_helpers:db_store_block(0, Key, fresh(Now))),
    ?assertEqual([0], forwards(?SETTLE_MS)).

%% The defect the ticket is named for. ELS2 (type 5) decodes, and we do not
%% implement it — so we hold nothing, and we may not ask three other routers to
%% hold it for us. The type byte went out intact.
unimplemented_store_type_does_not_replicate(Config) ->
    Peer = ?config(peer, Config),
    lists:foreach(
        fun(Type) ->
            send(Peer, i2p_ct_helpers:db_store_block(Type, crypto:strong_rand_bytes(32), <<"x">>)),
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
        i2p_ct_helpers:db_store_block(0, crypto:strong_rand_bytes(32), fresh(Now - ?TOO_OLD_MS))
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
