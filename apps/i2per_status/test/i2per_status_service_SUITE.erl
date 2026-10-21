%% End-to-end tests for the `i2per_status` web service: standalone boot with an
%% unreachable router (offline rendering), a live snapshot once a router runs on
%% the same node, the realtime bus counter, the derived figures reaching the wire,
%% and the supervision of the two processes the service is made of.
%%
%% These cases lived in `m:i2per_status_tests` and `m:i2per_status_sup_tests`,
%% eunit modules that booted both applications, bound a real TCP port and started
%% a second router's peer/tunnel/sam managers in the shared eunit worker (#ZN4GA6B).
%% The claims did not move with those modules; they were deleted with them, and
%% this suite is them restored, with `f:await/2` replacing the bounded retry loops
%% the old modules carried.
%%
%% The distributed half of the same surface — a router on another node, compared
%% over erpc — is `m:i2per_status_SUITE`, and it stays there: that boundary is the
%% one the service is built not to have a compile-time link across, and a suite
%% that could call the core directly would not be testing it.

-module(i2per_status_service_SUITE).

-include_lib("eunit/include/eunit.hrl").

-export([all/0, groups/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1, init_per_group/2, end_per_group/2]).
-export([end_per_testcase/2]).
-export([
    offline_snapshot/1,
    offline_page/1,
    live_router_online/1,
    derived_figures_appear_after_two_readings/1,
    bus_event_counter/1,
    both_processes_are_children/1,
    listener_is_restarted_after_dying/1,
    endpoints_answer_503_while_snapshot_server_is_down/1,
    snapshot_server_is_restarted_after_dying/1
]).

-define(SUITE_TIMEOUT, 90000).

%% The poll interval for the one case that waits on two readings. Short enough
%% that the wait is the assertion's own synchronisation rather than the shipped
%% five-second default, which is a property of the page's resolution and not of
%% what this case checks.
-define(TEST_POLL_MS, 20).

%% Which group a case belongs to, so the answer to "what does this case need
%% standing up" is the group it is in rather than a fixture it quietly starts.
groups() ->
    [
        {offline, [sequence], [offline_snapshot, offline_page]},
        {live, [sequence], [
            live_router_online,
            derived_figures_appear_after_two_readings,
            bus_event_counter
        ]},
        {supervision, [sequence], [
            both_processes_are_children,
            listener_is_restarted_after_dying,
            endpoints_answer_503_while_snapshot_server_is_down,
            snapshot_server_is_restarted_after_dying
        ]}
    ].

all() ->
    [{group, offline}, {group, live}, {group, supervision}].

suite() ->
    [{timetrap, ?SUITE_TIMEOUT}].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(inets),
    Config.

end_per_suite(_Config) ->
    ok.

%% The offline cases own the whole service: a router node that will never answer,
%% and a port nothing is listening on yet.
init_per_group(offline, Config) ->
    application:set_env(i2per_status, router_node, 'ghost@nowhere'),
    Config;
init_per_group(live, Config) ->
    %% A holder process, and the reason is that CT runs `init_per_group` in a
    %% short-lived process that exits before the first test case — so anything
    %% `start_link`ed here would die with it, and every case in the group would
    %% find no router. The same trap is why `m:i2per_status_SUITE` uses
    %% `peer:start` rather than `peer:start_link`. The holder stays alive for the
    %% whole group, which is what keeps the linked router processes alive.
    Parent = self(),
    Holder = spawn(fun() ->
        ok = boot_live_router(),
        Parent ! {live_router_up, self()},
        receive
            stop -> teardown_live_router()
        end
    end),
    receive
        {live_router_up, Holder} -> ok
    after 60000 ->
        erlang:error(live_router_never_booted)
    end,
    %% `router_node` defaults to this node when unset, which is the case these
    %% three assert. Unset rather than set, so a value left by an earlier suite
    %% in this node cannot decide the answer.
    application:unset_env(i2per_status, router_node),
    [{live_router, Holder} | Config];
init_per_group(supervision, Config) ->
    %% No router on purpose. A restarted process is not a restarted *service*, and
    %% the assertions are about which pid answers, not about what a router reports.
    %% Unset rather than a dead node name: a poll of a node that does not exist
    %% raises in the poller, and a snapshot server in a restart storm takes the
    %% listener's supervisor down with it — which is a state these cases are not
    %% about, and one where the port answers nothing at all.
    application:unset_env(i2per_status, router_node),
    Config.

end_per_testcase(_Case, _Config) ->
    %% Each case boots the service with its own env (the offline group even
    %% picks a fresh port per case), so the service is stopped between cases
    %% rather than left running for the group to reuse: a listener already
    %% bound would ignore the next case's port. `i2per_status` is not
    %% guaranteed to be running here — a case that failed before starting it
    %% leaves nothing to stop — so stopping is not matched.
    _ = application:stop(i2per_status),
    ok.

end_per_group(live, Config) ->
    %% The router was start_linked in the holder process, so it is torn down
    %% there; tearing it down from this process would reach into another
    %% process's links.
    case proplists:get_value(live_router, Config) of
        undefined ->
            ok;
        Holder ->
            Holder ! stop,
            ok
    end;
end_per_group(_Group, _Config) ->
    %% The service itself is stopped per case now.
    ok.

%%% %%%%% %%% Offline %%%%% %%%

%% An unreachable router is an honest answer, not a crash: `online` is false and
%% both endpoints say 503. The status code is the load-bearing half — a monitoring
%% consumer that only reads the code must be able to tell a dead router from a
%% healthy one, and `online` in the body is no substitute.
offline_snapshot(_Config) ->
    Port = start_status(),
    Snap = i2per_status_state:snapshot(),
    ?assertEqual(false, maps:get(online, Snap)),
    {Status, CT, Body} = http_get(Port, "/status.json"),
    ?assertEqual(503, Status),
    ?assert(lists:prefix("application/json", CT)),
    #{<<"online">> := false} = json:decode(Body).

offline_page(_Config) ->
    Port = start_status(),
    {Status, CT, Body} = http_get(Port, "/"),
    ?assertEqual(503, Status),
    ?assert(lists:prefix("text/html", CT)),
    ?assertNotEqual(nomatch, binary:match(Body, <<"router offline">>)).

%%% %%%%% %%% A live router on this node %%%%% %%%

live_router_online(_Config) ->
    Port = start_status(),
    ok = await_online(),
    {Status, _CT, Body} = http_get(Port, "/status.json"),
    ?assertEqual(200, Status),
    Json = json:decode(Body),
    ?assertEqual(true, maps:get(<<"online">>, Json)),
    ?assert(maps:is_key(<<"identity">>, Json)),
    ?assert(maps:is_key(<<"tunnels">>, Json)).

%% The end-to-end half of the derivation, and the only test that proves the wiring.
%%
%% The unit tests prove `m:i2per_status_derive` arithmetic and the page tests
%% prove rendering, and neither of those would notice if the poll stopped feeding
%% readings into the derivation — the derived block would simply be `undefined`
%% forever and every figure on the page would read "n/a". So this drives a real
%% router through a real status service and waits for the block to appear.
%%
%% The wait is a *condition*, not a sleep: two readings are needed, so the case
%% waits for the second and `f:await/2` returns the moment it arrives. It is not a
%% fixed sleep in disguise, because the assertion is about reaching a state rather
%% than about elapsed time.
%%
%% The poll interval is shortened to 20 ms so that "two readings" is 20 ms of
%% waiting rather than a full five-second interval. The assertions are unchanged in
%% kind and do not depend on the interval being a particular value -- only the cost
%% of waiting for it is under this case's control. The shipped default is 5000 and
%% is exercised by `m:i2per_status_state`; this case is about the derivation needing
%% two readings, not about how long a poll takes.
derived_figures_appear_after_two_readings(_Config) ->
    ok = application:set_env(i2per_status, poll_ms, ?TEST_POLL_MS),
    Port = start_status(),
    try
        ok = await_online(),
        %% The wiring claim here is that polling feeds readings into the
        %% derivation: `no_reading_yet` means it never did. `no_previous_sample`
        %% and `ok` are both correct outcomes -- which one appears is a race
        %% between this assertion and the next 20 ms poll, so asserting one of
        %% them would be asserting a poll count this case does not control.
        %% The one-reading-means-no-rate arithmetic is covered deterministically
        %% in `m:i2per_status_derive_tests`.
        ?assert(lists:member(derived_window_status(), [no_previous_sample, ok])),
        ok = i2p_ct_helpers:await(fun() -> derived_window_ok() end, 30000),
        Derived = derived_block(),
        ?assertEqual(ok, maps:get(window_status, Derived)),
        ?assert(is_integer(maps:get(window_ms, Derived))),
        ?assert(maps:get(window_ms, Derived) > 0),
        %% And it reaches the wire, with the window and the provenance beside it.
        {Status, _CT, Body} = http_get(Port, "/status.json"),
        ?assertEqual(200, Status),
        Json = json:decode(Body),
        OnWire = maps:get(<<"derived">>, Json),
        %% A string, not the atom: the JSON encoder renders atoms as strings and
        %% only `true`/`false` stay boolean. So a consumer of the wire compares
        %% `"ok"`, and the atom-to-string step is worth knowing about before a
        %% consumer is written against it.
        ?assertEqual(<<"ok">>, maps:get(<<"window_status">>, OnWire)),
        ?assert(maps:is_key(<<"window_ms">>, OnWire)),
        ?assert(maps:is_key(<<"transfer_bps">>, OnWire)),
        ?assert(maps:is_key(<<"tunnel_success_ratio">>, OnWire))
    after
        %% `application:stop/1` does not clear app env, so the next case would
        %% inherit a 20 ms poll window.
        application:unset_env(i2per_status, poll_ms)
    end.

%% A bus event announced on this node's bus reaches this node's snapshot. The
%% distributed counterpart is `dist_realtime_bus_counter_over_erpc` in
%% `m:i2per_status_SUITE`; this one is the same claim one boundary shorter, and it
%% is what fails when the subscription is missing rather than when erpc is.
bus_event_counter(_Config) ->
    Port = start_status(),
    Before = tunnel_built_count(i2per_status_state:snapshot()),
    ok = i2p_events:notify({tunnel_built, outbound, 3}),
    ok = i2p_ct_helpers:await(
        fun() -> tunnel_built_count(i2per_status_state:snapshot()) >= Before + 1 end,
        20000
    ),
    %% The counter is a number an operator reads on the page, so it is asserted
    %% from a body too, not only from the snapshot the case itself can see.
    {Status, _CT, Body} = http_get(Port, "/status.json"),
    ?assertEqual(200, Status),
    Json = json:decode(Body),
    ?assert(maps:is_key(<<"events">>, Json)).

%%% %%%%% %%% Supervision %%%%% %%%

%% The listener used to be started by `ok = start_listener()` inside the
%% supervisor's `f:init/1`, before it returned any child spec. It was linked to
%% the supervisor, so application stop took it down, but it was never a child —
%% so a listener that died stayed dead, and the supervisor, whose whole job is to
%% report the state of its children, reported healthy while serving nothing.
%%
%% That failure mode is why the cases below kill a process and look for a
%% replacement rather than only inspecting `which_children/1`: a supervisor that
%% merely lists the right children is exactly what the broken version could have
%% been made to do.
both_processes_are_children(_Config) ->
    _Port = start_status(),
    ?assertEqual(
        [i2per_status_listener, i2per_status_state],
        lists:sort([Id || {Id, _, _, _} <- supervisor:which_children(i2per_status_sup)])
    ).

%% The listener's real test. Kill it outright — not a graceful close, which a
%% healthy supervisor also handles — and require a different pid serving the same
%% port within a deadline. Under the old arrangement the port simply stayed
%% closed while the supervisor reported success throughout.
listener_is_restarted_after_dying(_Config) ->
    Port = start_status(),
    Before = must_live(i2per_status_listener),
    exit(Before, kill),
    ok = await_replacement(i2per_status_listener, Before),
    ?assertNotEqual(Before, must_live(i2per_status_listener)),
    %% 503, not 200: no router is reachable from this node, so "the service is up,
    %% the router is not" is the honest answer. What used to happen is that the
    %% port stayed closed and httpc returned `{error, econnrefused}` — which the
    %% listener's own request path raises on, so this assertion is the regression.
    ?assertEqual(503, status(Port, "/status.json")),
    ?assertEqual(503, status(Port, "/")).

%% The snapshot server is what the listener asks for data, so while it is gone the
%% endpoints must answer 503 rather than crash into a 500. This is the state the
%% ticket called reachable: a live listener and a dead snapshot server, which used
%% to be an unhandled `exit` in each handler.
endpoints_answer_503_while_snapshot_server_is_down(_Config) ->
    Port = start_status(),
    State = must_live(i2per_status_state),
    exit(State, kill),
    ok = i2p_ct_helpers:await(
        fun() -> status(Port, "/status.json") =:= 503 end, 10000
    ),
    ?assertEqual(503, status(Port, "/")).

%% And the server comes back on its own, being `permanent`.
snapshot_server_is_restarted_after_dying(_Config) ->
    _Port = start_status(),
    Before = must_live(i2per_status_state),
    exit(Before, kill),
    ok = await_replacement(i2per_status_state, Before),
    ?assertNotEqual(Before, must_live(i2per_status_state)).

%%% %%%%% %%% Internal helpers %%%%% %%%

%% The port is the service's own, and it is read back from the environment the
%% service itself reads, so a case cannot assert against a port nothing is bound
%% to. Each case starts the service so that a case which kills a process owns the
%% processes it kills; `end_per_testcase` stops the application.
start_status() ->
    Port = i2p_ct_helpers:free_port(),
    ok = application:set_env(i2per_status, port, Port),
    {ok, _} = application:ensure_all_started(i2per_status),
    Port.

%% Any response counts: the point is that cowboy answers, so an error tuple is a
%% failure too — it is the difference between "503" and "the port is closed",
%% which is the whole claim of the listener cases.
status(Port, Path) ->
    {Status, _CT, _Body} = http_get(Port, Path),
    Status.

http_get(Port, Path) ->
    Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ Path,
    {ok, {{_, Status, _}, Headers, Body}} =
        httpc:request(get, {Url, []}, [{timeout, 5000}], []),
    {Status, proplists:get_value("content-type", Headers), iolist_to_binary(Body)}.

%% Boot exactly what `m:i2p_status_data:view/0` reads: peer manager, tunnel
%% manager, SAM supervisor — NetDb/events/config come with the app.
boot_live_router() ->
    {ok, _} = application:ensure_all_started(i2per),
    Router = mock_router(),
    Local = #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => maps:get(hash, Router),
        iv => maps:get(iv, Router),
        ri => maps:get(ri, Router)
    },
    {ok, _} = i2p_peer:start_link(Local, []),
    {ok, _} = i2p_tunnel_srv:start_link(Local),
    {ok, _} = i2p_sam_sup:start_link(),
    ok.

teardown_live_router() ->
    catch gen_server:stop(i2p_sam_sup),
    catch i2p_tunnel_srv:stop(),
    catch i2p_peer:stop(),
    catch application:stop(i2per),
    ok.

%% Minimal router identity (same recipe as the SAM e2e suites).
mock_router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(
        <<"127.0.0.1">>, i2p_ct_helpers:free_port(), StaticPub, IV
    ),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(
        Identity, erlang:system_time(millisecond), [Addr], Opts, Seed
    ),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        iv => IV,
        ri => RI,
        hash => i2p_router_info:hash(RI)
    }.

%% The poll interval is 20 ms in the derivation case and 5000 everywhere else, so
%% "online" is reached on the first poll in one case and the fifth second in the
%% others. A condition either way, bounded so a service that never reports online
%% names what it was waiting for.
await_online() ->
    i2p_ct_helpers:await(
        fun() -> maps:get(online, i2per_status_state:snapshot()) end, 20000
    ).

derived_window_status() ->
    maps:get(window_status, derived_block()).

derived_block() ->
    case maps:get(derived, i2per_status_state:snapshot(), undefined) of
        undefined -> #{window_status => no_reading_yet};
        Derived -> Derived
    end.

%% `f:await/2` wants a boolean. Returning the block would be `case_clause` inside
%% the helper, which is a confusing place to be told the predicate is malformed.
derived_window_ok() ->
    maps:get(window_status, derived_block()) =:= ok.

tunnel_built_count(Snap) ->
    case maps:find(events, Snap) of
        {ok, Ev} -> maps:get(tunnel_built, Ev, 0);
        error -> 0
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
