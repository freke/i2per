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

%% A destination map has no session pid to hand back, so stream_connect/3
%% spawns one. A failed connect must not leave that session running: before
%% FZKBZ1H, repeated calls accumulated sessions, published LeaseSets and
%% registrations.
destination_map_connect_failure_leaves_no_session_test() ->
    Before = client_session_pids(),
    Dest = i2p_sam_api:create_destination(),
    Result = i2p_sam_api:stream_connect(Dest, <<"not-a-destination">>, self()),
    ?assertMatch({error, _}, Result),
    wait_for_no_new_sessions(Before, 100).

client_session_pids() ->
    lists:sort([P || P <- processes(), is_client_session(P)]).

is_client_session(Pid) ->
    case catch proc_lib:initial_call(Pid) of
        {i2p_client_session, init, _} -> true;
        _ -> false
    end.

wait_for_no_new_sessions(_Before, 0) ->
    ?assert(false);
wait_for_no_new_sessions(Before, Attempts) ->
    case client_session_pids() -- Before of
        [] ->
            ok;
        _ ->
            timer:sleep(10),
            wait_for_no_new_sessions(Before, Attempts - 1)
    end.
