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
    with_sam_sup(fun() ->
        {ok, Pid, DestB64} = i2p_sam_api:create_session(),
        try
            {ok, Identity} = i2p_keys:from_b64(DestB64),
            DestHash = i2p_keys:hash(Identity),
            ?assertEqual(not_found, i2p_sam_sup:listener_lookup(DestHash))
        after
            i2p_sam_api:close_session(Pid)
        end
    end).

stream_connect_replies_ok_and_registers_conn_test() ->
    with_sam_sup(fun() ->
        with_fake_client(fun() ->
            {ok, Pid, DestB64} = i2p_sam_api:create_session(#{}),
            try
                Res = i2p_sam_api:stream_connect(Pid, DestB64, self()),
                ?assertMatch({ok, _}, Res),
                {ok, ConnPid} = Res,
                ?assert(is_process_alive(ConnPid)),
                St = sys:get_state(Pid),
                Conns = maps:get(conns, St, #{}),
                ?assert(maps:is_key(ConnPid, Conns))
            after
                catch i2p_sam_api:close_session(Pid)
            end
        end)
    end).

%% A session spawned only to serve one stream_connect/3 must not outlive the
%% stream. Before this, the destination-map branch returned the connection and
%% leaked the session behind it (FZKBZ1H).
ephemeral_session_stops_when_its_only_conn_dies_test() ->
    with_sam_sup(fun() ->
        with_fake_client(fun() ->
            {ok, Pid, DestB64} = i2p_sam_api:create_session(#{ephemeral => true}),
            ?assert(is_process_alive(Pid)),
            {ok, ConnPid} = i2p_sam_api:stream_connect(Pid, DestB64, self()),
            exit(ConnPid, kill),
            wait_until_dead(Pid, 100)
        end)
    end).

%% The owner still owns a session it created itself: losing a connection must
%% not stop it. This is the behaviour the ephemeral cleanup must not change.
caller_owned_session_survives_its_conn_dying_test() ->
    with_sam_sup(fun() ->
        with_fake_client(fun() ->
            {ok, Pid, DestB64} = i2p_sam_api:create_session(),
            try
                {ok, ConnPid} = i2p_sam_api:stream_connect(Pid, DestB64, self()),
                exit(ConnPid, kill),
                timer:sleep(50),
                ?assert(is_process_alive(Pid))
            after
                i2p_sam_api:close_session(Pid)
            end
        end)
    end).

%% A companion app that dies without calling close_session must not leave the
%% session, its connections, or the resources behind them alive.
owner_death_stops_session_and_conns_test() ->
    with_sam_sup(fun() ->
        with_fake_client(fun() ->
            Owner = spawn(fun() ->
                receive
                    stop -> ok
                end
            end),
            {ok, Pid, DestB64} = i2p_sam_api:create_session(#{owner => Owner}),
            {ok, ConnPid} = i2p_sam_api:stream_connect(Pid, DestB64, self()),
            ?assert(is_process_alive(Pid)),
            ?assert(is_process_alive(ConnPid)),
            exit(Owner, kill),
            wait_until_dead(Pid, 100),
            wait_until_dead(ConnPid, 100)
        end)
    end).

%% The full eunit run shares one node, so the supervisor may already be up: take
%% it if it is not, and stop only a supervisor this case started. Leaving one
%% behind is what made every later core test fail on `already_started`.
with_sam_sup(Fun) ->
    case ensure_sam_sup() of
        started ->
            try
                Fun()
            after
                stop_sam_sup()
            end;
        already_running ->
            Fun()
    end.

ensure_sam_sup() ->
    case whereis(i2p_sam_sup) of
        undefined ->
            {ok, SupPid} = i2p_sam_sup:start_link(),
            unlink(SupPid),
            started;
        _ ->
            already_running
    end.

stop_sam_sup() ->
    _ = catch gen_server:stop(i2p_sam_sup),
    ok.

%% Replace i2p_client with a stub so a connect reaches the stream-conn layer
%% without a running router. i2p_stream_conn then has a route to send on.
with_fake_client(Fun) ->
    %% `code:which/1` answers `cover_compiled` under `eunit --cover`, so take
    %% the object code instead of reading a file path.
    {i2p_client, OrigBin, OrigPath} = code:get_object_code(i2p_client),
    Forms = [
        {attribute, 1, module, i2p_client},
        {attribute, 2, export, [{route_to_dest, 1}, {send_wire, 2}]},
        {function, 3, route_to_dest, 1, [
            {clause, 3, [{var, 3, '_'}], [], [{tuple, 3, [{atom, 3, ok}, {atom, 3, fake}]}]}
        ]},
        {function, 4, send_wire, 2, [
            {clause, 4, [{var, 4, '_'}, {var, 4, '_'}], [], [{atom, 4, ok}]}
        ]}
    ],
    {ok, _, Bin} = compile:forms(Forms, []),
    code:purge(i2p_client),
    code:load_binary(i2p_client, "fake", Bin),
    try
        Fun()
    after
        code:purge(i2p_client),
        code:load_binary(i2p_client, OrigPath, OrigBin)
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
