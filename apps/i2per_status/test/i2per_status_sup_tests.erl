-module(i2per_status_sup_tests).

-moduledoc """
Tests that the status service's processes are actually supervised.

The listener used to be started by `ok = start_listener()` inside the
supervisor's `f:init/1`, before it returned any child spec. It was linked to the
supervisor, so application stop took it down, but it was never a child — so a
listener that died stayed dead, and the supervisor, whose whole job is to report
the state of its children, reported healthy while serving nothing.

That failure mode is why these cases kill a process and look for a replacement
rather than only inspecting `which_children/1`: a supervisor that merely lists
the right children is exactly what the broken version could have been made to
do.

Each case starts the service itself and stops it afterwards, matching the
end-to-end cases in `m:i2per_status_tests`.
""".

-include_lib("eunit/include/eunit.hrl").

%% Both processes are children, not bystanders linked to the supervisor.
both_processes_are_children_test() ->
    with_status(fun(_Port) ->
        ?assertEqual(
            [i2per_status_listener, i2per_status_state],
            lists:sort([Id || {Id, _, _, _} <- supervisor:which_children(i2per_status_sup)])
        )
    end).

%% The listener's real test. Kill it outright — not a graceful close, which a
%% healthy supervisor also handles — and require a different pid serving the same
%% port within a deadline. Under the old arrangement the port simply stayed
%% closed while the supervisor reported success throughout.
listener_is_restarted_after_dying_test() ->
    with_status(fun(Port) ->
        Before = must_live(i2per_status_listener),
        exit(Before, kill),
        ok = await_replacement(i2per_status_listener, Before),
        ?assertNotEqual(Before, must_live(i2per_status_listener)),
        %% A restarted process is not a restarted *service*. 503, not 200: no
        %% router is reachable from this node, so "the service is up, the router
        %% is not" is the honest answer. What used to happen is that the port
        %% stayed closed and httpc returned `{error, econnrefused}` — which
        %% `f:http_status/2` raises on, so this assertion is the regression.
        ?assertEqual(503, status(Port, "/status.json")),
        ?assertEqual(503, status(Port, "/"))
    end).

%% The snapshot server is what the listener asks for data, so while it is gone the
%% endpoints must answer 503 rather than crash into a 500. This is the state the
%% ticket called reachable: a live listener and a dead snapshot server, which used
%% to be an unhandled `exit` in each handler.
endpoints_answer_503_while_snapshot_server_is_down_test() ->
    with_status(fun(Port) ->
        State = must_live(i2per_status_state),
        exit(State, kill),
        ok = i2p_ct_helpers:await(
            fun() -> status(Port, "/status.json") =:= 503 end, 10000
        ),
        ?assertEqual(503, status(Port, "/"))
    end).

%% And the server comes back on its own, being `permanent`.
snapshot_server_is_restarted_after_dying_test() ->
    with_status(fun(_Port) ->
        Before = must_live(i2per_status_state),
        exit(Before, kill),
        ok = await_replacement(i2per_status_state, Before),
        ?assertNotEqual(Before, must_live(i2per_status_state))
    end).

%% %%%%% %%% Internal helpers %%%%% %%%

with_status(Test) ->
    {ok, _} = application:ensure_all_started(inets),
    Port = i2p_ct_helpers:free_port(),
    application:set_env(i2per_status, port, Port),
    application:unset_env(i2per_status, router_node),
    {ok, _} = application:ensure_all_started(i2per_status),
    try
        Test(Port)
    after
        _ = application:stop(i2per_status)
    end.

must_live(Name) ->
    case whereis(Name) of
        undefined -> erlang:error({not_running, Name});
        Pid -> Pid
    end.

%% Wait for `Name` to be running as a pid other than the one that died.
await_replacement(Name, Before) ->
    i2p_ct_helpers:await(
        fun() ->
            case whereis(Name) of
                undefined -> false;
                Pid when Pid =:= Before -> false;
                _Pid -> true
            end
        end,
        10000
    ).

status(Port, Path) ->
    http_status(Port, Path).

%% Any response counts: the point is that cowboy answers, so an error tuple is a
%% failure too.
http_status(Port, Path) ->
    Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ Path,
    case httpc:request(get, {Url, []}, [{timeout, 5000}], []) of
        {ok, {{_, Status, _}, _Headers, _Body}} -> Status;
        {error, Reason} -> erlang:error({http, Reason})
    end.
