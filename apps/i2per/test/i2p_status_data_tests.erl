-module(i2p_status_data_tests).

-moduledoc """
Tests for the `m:i2p_status_data` peer-status aggregation: only `connected`
states count toward connected, everything else lands in `other`, and the
connecting subset is counted again on its own.
""".

-include_lib("eunit/include/eunit.hrl").

%% Every key is asserted on every case rather than matched as a subset. A
%% regression that *dropped* `connecting` would satisfy a subset match on the
%% original two, and the whole point of the key is that it is always there.

empty_peers_test() ->
    ?assertEqual(
        #{connected => 0, connecting => 0, other => 0},
        i2p_status_data:aggregate_peers(#{})
    ).

only_connected_test() ->
    Status = #{
        <<"a">> => #{status => connected},
        <<"b">> => #{status => connected}
    },
    ?assertEqual(
        #{connected => 2, connecting => 0, other => 0},
        i2p_status_data:aggregate_peers(Status)
    ).

mixed_states_test() ->
    Status = #{
        <<"a">> => #{status => connected},
        <<"b">> => #{status => idle},
        <<"c">> => #{status => failed},
        <<"d">> => #{status => excluded}
    },
    ?assertEqual(
        #{connected => 1, connecting => 0, other => 3},
        i2p_status_data:aggregate_peers(Status)
    ).

no_connected_test() ->
    Status = #{<<"a">> => #{status => idle}, <<"b">> => #{}},
    ?assertEqual(
        #{connected => 0, connecting => 0, other => 2},
        i2p_status_data:aggregate_peers(Status)
    ).

%% A dial in flight is counted as `connecting` *and* as `other`, and the two
%% clauses are asserted rather than described: the alternative reading of this
%% shape is three disjoint buckets, and the count that tells them apart is
%% `other = 3` here versus `other = 2` under that reading. Which is right is
%% decided by the additive-only contract -- `other` meant "not connected" in
%% version 1, and a consumer reading it must not get a smaller number because a
%% newer key appeared.
connecting_is_counted_in_other_too_test() ->
    Status = #{
        <<"a">> => #{status => connecting},
        <<"b">> => #{status => connecting},
        <<"c">> => #{status => backoff}
    },
    ?assertEqual(
        #{connected => 0, connecting => 2, other => 3},
        i2p_status_data:aggregate_peers(Status)
    ).

%% The distinction the ticket exists for: a dial in flight and a peer being
%% retried are different facts, and before this key they were one number. The
%% backoff count is therefore `other - connecting`, which is why the case
%% asserts both terms and the difference rather than either alone.
connecting_is_distinguishable_from_backoff_test() ->
    Status = #{
        <<"a">> => #{status => connecting},
        <<"b">> => #{status => backoff},
        <<"c">> => #{status => backoff}
    },
    #{connecting := Connecting, other := Other} = i2p_status_data:aggregate_peers(Status),
    ?assertEqual(1, Connecting),
    ?assertEqual(2, Other - Connecting).

%% A peer with no status key at all is still counted, and still not counted as
%% connecting: `i2p_peer:status/0` has always promised a `status` for every peer
%% it returns, so this shape is defensive -- but it is the shape that reaches the
%% aggregation if that promise is ever broken, and a fold that crashed there
%% would take the read API down rather than report a smaller number.
peer_without_a_status_is_still_counted_test() ->
    ?assertEqual(
        #{connected => 0, connecting => 0, other => 1},
        i2p_status_data:aggregate_peers(#{<<"a">> => #{attempts => 0}})
    ).

%% `lease_set_detail/0` never returns a partial entry: every map it yields
%% carries all of `key`, `expires`, `leases` and `published`. A LeaseSet that
%% expired between `ls_keys/0` and `find_ls/1` is dropped rather than emitted
%% as `#{key => K}`.
lease_set_detail_returns_complete_entries_test() ->
    {Owner, SavedDataDir} = ensure_netdb(),
    try
        SeedKey = new_seed_key(),
        {Identity, Seed} = identity_seed(SeedKey),
        NowSec = now_sec(),
        LS = i2p_leaset:build(Identity, NowSec, 7, fixture_leases(1), Seed),
        added = i2p_netdb_srv:store_ls(LS, NowSec),
        LSKey = i2p_leaset:hash(LS),
        Entries = i2p_status_data:lease_set_detail(),
        ?assert(lists:any(fun(E) -> maps:get(key, E, undefined) =:= LSKey end, Entries)),
        lists:foreach(
            fun(E) ->
                ?assert(maps:is_key(key, E)),
                ?assert(maps:is_key(expires, E)),
                ?assert(maps:is_key(leases, E)),
                ?assert(maps:is_key(published, E))
            end,
            Entries
        )
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end,
        case SavedDataDir of
            {ok, Value} -> application:set_env(i2per, data_dir, Value);
            undefined -> application:unset_env(i2per, data_dir)
        end
    end.

%%% --------------------------------------------------------------------------
%%% Fixtures
%%% --------------------------------------------------------------------------

ensure_netdb() ->
    case whereis(i2p_netdb_srv) of
        undefined ->
            SavedDataDir = application:get_env(i2per, data_dir),
            application:unset_env(i2per, data_dir),
            {ok, _Pid} = i2p_netdb_srv:start_link(),
            {started, SavedDataDir};
        _Pid ->
            {existing, undefined}
    end.

now_sec() ->
    erlang:system_time(second).

new_seed_key() ->
    {{SPub, Seed}, {CPub, _}} = {i2p_crypto:ed25519_keygen(), i2p_crypto:x25519_keygen()},
    {{SPub, Seed}, {CPub, crypto:strong_rand_bytes(32)}}.

identity_seed({{SPub, Seed}, {CPub, _}}) ->
    {i2p_keys:from_keys(CPub, SPub), Seed}.

fixture_leases(N) ->
    [
        #{
            gateway => crypto:strong_rand_bytes(32),
            tunnel_id => I + 1,
            end_date => (erlang:system_time(second) * 1000 + 60 * 1000) band 16#FFFFFFFF
        }
     || I <- lists:seq(0, N - 1)
    ].
