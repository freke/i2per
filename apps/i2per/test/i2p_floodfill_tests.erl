%% Unit tests for floodfill election and store replication.
%%
%% Tests i2p_floodfill as a pure library: election via app env and the
%% floodfill cap wiring through i2p_identity:build_local/4. The outbox cases
%% that couple to the running NetDb gen_server live in the Common Test suite;
%% the remaining assertion here is the pure non-floodfill short-circuit.

-module(i2p_floodfill_tests).

-include_lib("eunit/include/eunit.hrl").

%%%%%%%%% Floodfill election %%%%%%%%%

%% Default (no app env set) → false.
is_floodfill_default_false_test() ->
    application:unset_env(i2per, floodfill),
    ?assertEqual(false, i2p_floodfill:is_floodfill()).

%% Explicit {ok, true} → true.
is_floodfill_explicit_true_test() ->
    application:set_env(i2per, floodfill, true),
    ?assertEqual(true, i2p_floodfill:is_floodfill()),
    application:unset_env(i2per, floodfill).

%% {ok, false} → false.
is_floodfill_explicit_false_test() ->
    application:set_env(i2per, floodfill, false),
    ?assertEqual(false, i2p_floodfill:is_floodfill()),
    application:unset_env(i2per, floodfill).

%%%%%%%%% Replication outbox %%%%%%%%%

%% When not a floodfill, outbox is always empty (the netdb lookup is never
%% even attempted — a pure short-circuit).
outbox_empty_when_not_floodfill_test() ->
    application:unset_env(i2per, floodfill),
    Key = crypto:strong_rand_bytes(32),
    Data = crypto:strong_rand_bytes(64),
    ?assertEqual([], i2p_floodfill:replication_outbox(0, Key, Data, Key, Key)).

%%%%%%%%% The reply token is the flood request %%%%%%%%%

%% Zero asks for nothing: a token-free store is a direct announcement, which the
%% references store and stop on. Every other value asks. No timing, no process:
%% this is the whole gate, and the integration that consults it is observed in
%% `i2p_peer_replication_SUITE`.
flood_requested_is_the_token_being_nonzero_test() ->
    ?assertNot(i2p_floodfill:flood_requested(0)),
    ?assert(i2p_floodfill:flood_requested(1)),
    ?assert(i2p_floodfill:flood_requested(16#DEADBEEF)),
    ?assert(i2p_floodfill:flood_requested(16#7FFFFFFF)).

%% `16#FFFFFFFF` is the value i2pd does not *reply* to, and it is a common place
%% to assume the opposite of what it means. i2pd skips only the DeliveryStatus
%% (`NetDb.cpp:822`) and floods anyway, so a gate that treated it as a refusal
%% would diverge from the implementation it exists to match.
flood_requested_accepts_the_ignore_reply_token_test() ->
    ?assert(i2p_floodfill:flood_requested(16#FFFFFFFF)).

%%%%%%%%% Floodfill caps wiring through i2p_identity %%%%%%%%%

%% When floodfill=true, build_local includes a spec-valid `caps` with the `f`
%% marker appended to the bandwidth class + reachability prefix (public host,
%% no private opt-out here => `RLf`).
identity_includes_floodfill_caps_test() ->
    application:set_env(i2per, floodfill, true),
    Id = new_identity_file(),
    Local = i2p_identity:build_local(Id, <<"192.0.2.1">>, 4668, maps:get(sign_seed, Id)),
    RI = maps:get(ri, Local),
    Caps = maps:get(<<"caps">>, i2p_router_info:options(RI)),
    ?assertEqual(<<"RLf">>, Caps),
    ?assert(i2p_router_info:validate_caps(Caps)),
    application:unset_env(i2per, floodfill).

%% When floodfill=false (default), caps does not contain 'f'.
identity_no_floodfill_caps_by_default_test() ->
    application:unset_env(i2per, floodfill),
    Id = new_identity_file(),
    Local = i2p_identity:build_local(Id, <<"192.0.2.1">>, 4668, maps:get(sign_seed, Id)),
    RI = maps:get(ri, Local),
    Caps = maps:get(<<"caps">>, i2p_router_info:options(RI), <<>>),
    ?assertNot(lists:member($f, binary_to_list(Caps))),
    ?assert(i2p_router_info:validate_caps(Caps)).

%%%%%%%%% Helpers %%%%%%%%%

new_identity_file() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, SignSeed} = i2p_crypto:ed25519_keygen(),
    IV = crypto:strong_rand_bytes(16),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        sign_pub => SignPub,
        sign_seed => SignSeed,
        iv => IV,
        identity => i2p_keys:from_keys(StaticPub, SignPub)
    }.
