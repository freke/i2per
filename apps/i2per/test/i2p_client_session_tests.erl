-module(i2p_client_session_tests).

-moduledoc """
Session lifetime across the API boundary.

`f:i2p_sam_api:create_session/1` is reached over `erpc:call/5`, and the worker
erpc spawns for a call with a timeout exits *abnormally* as it delivers the
reply. A session linked to that worker is therefore killed at creation, and the
caller cannot see it: it gets `{ok, Pid}`, and the next call on that pid is a
noproc. The companion apps treat the noproc as "the core path did not work" and
fall back to SAM, so the bug is silent.

These cases hold the two halves of the contract that make it visible: the
session is alive after the call that created it, and it is gone after
`f:i2p_sam_api:close_session/1`.
""".

-include_lib("eunit/include/eunit.hrl").

create_session_survives_the_calling_process_test() ->
    {ok, Pid, DestB64} = erpc:call(node(), i2p_sam_api, create_session, [#{}], 5000),
    try
        ?assert(is_binary(DestB64)),
        ?assert(is_process_alive(Pid))
    after
        i2p_sam_api:close_session(Pid)
    end.

close_session_ends_the_session_test() ->
    {ok, Pid, _DestB64} = i2p_sam_api:create_session(),
    ?assert(is_process_alive(Pid)),
    ok = i2p_sam_api:close_session(Pid),
    wait_until_dead(Pid, 100).

no_listener_registered_for_headless_session_test() ->
    case whereis(i2p_sam_sup) of
        undefined ->
            {ok, SupPid} = i2p_sam_sup:start_link(),
            unlink(SupPid);
        _ ->
            ok
    end,
    {ok, Pid, DestB64} = i2p_sam_api:create_session(),
    try
        {ok, Identity} = i2p_keys:from_b64(DestB64),
        DestHash = i2p_keys:hash(Identity),
        ?assertEqual(not_found, i2p_sam_sup:listener_lookup(DestHash))
    after
        i2p_sam_api:close_session(Pid)
    end.

%% close_session/1 returns when the reply is sent, not when the process has
%% gone, so the death is a short wait rather than an assertion on the next line.
wait_until_dead(_Pid, 0) ->
    ?assert(false);
wait_until_dead(Pid, Attempts) ->
    case is_process_alive(Pid) of
        true ->
            timer:sleep(10),
            wait_until_dead(Pid, Attempts - 1);
        false ->
            ok
    end.
