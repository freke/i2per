-module(i2p_sam_api_tests).

-include_lib("eunit/include/eunit.hrl").

version_test() ->
    ?assertEqual(1, i2p_sam_api:version()).

create_destination_test() ->
    D = i2p_sam_api:create_destination(),
    ?assert(maps:is_key(identity, D)),
    ?assert(maps:is_key(crypto_priv, D)),
    ?assert(maps:is_key(sign_priv, D)),
    ?assert(maps:is_key(dest_b64, D)),
    ?assertEqual({ok, maps:get(identity, D)}, i2p_keys:from_b64(maps:get(dest_b64, D))).

create_destination_opts_test() ->
    D = i2p_sam_api:create_destination(#{}),
    ?assert(is_binary(maps:get(dest_b64, D))).

naming_lookup_b32_passthrough_test() ->
    D = i2p_sam_api:create_destination(),
    B64 = maps:get(dest_b64, D),
    ?assertEqual({ok, B64}, i2p_sam_api:naming_lookup(B64)).

create_session_test() ->
    {ok, Pid, DestB64} = i2p_sam_api:create_session(),
    ?assert(is_pid(Pid)),
    ?assert(is_binary(DestB64)),
    ?assertEqual(DestB64, i2p_sam_api:session_dest_b64(Pid)).

stream_connect_no_router_test() ->
    {ok, Pid, _DestB64} = i2p_sam_api:create_session(),
    %% Without a running router there is no route; the call must fail
    %% cleanly rather than crash.
    Result = i2p_sam_api:stream_connect(Pid, <<"not-a-destination">>, self()),
    ?assertMatch({error, _}, Result).
