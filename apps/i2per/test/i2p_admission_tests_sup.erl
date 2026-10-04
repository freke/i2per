%% A supervisor that gives up on the first restart, so a wait for a restarting
%% child can be shown to end.
%%
%% `i2p_admission_tests` waits on a killed child coming back. Every production
%% supervisor in the tree allows several restarts, so killing one child in a test
%% always brings it back and the wait always terminates -- which is why the wait's
%% own bound is not exercised by the tree as it stands. This one is started with
%% `intensity => 0`, so the first death is one too many: the supervisor terminates,
%% the child's registered name is never claimed again, and a wait that polls it
%% forever has something real to hang on.
%%
%% The child is a bare registered process rather than a `gen_server` because a
%% named holder that never answers is the whole requirement; nothing is asked of
%% it except that it hold a name, and stopping it is how the case sets up.

-module(i2p_admission_tests_sup).

-moduledoc """
Test helper: a supervisor whose restart intensity is zero, so the first restart
is the last one and a wait for the child to come back has to give up.

Started with the registered name its `permanent` child should hold, because that
name is the thing under test -- not the supervisor. Lives in `test/` only, and its
name deliberately does not end in `_tests`, so `scripts/eunit-modules.sh` does not
run it as a suite of its own.
""".

-behaviour(supervisor).

-export([start_link/1, hold/1]).

-export([init/1]).

-doc """
Start a supervisor that will not restart its child.

`ChildName` is the name the child registers as, and is the name a caller waits on.
The returned supervisor is linked to the caller, and its exit reason when it gives
up is `reached_max_restart_intensity` rather than `normal` -- so unlink it before
killing the child, or the link takes the caller with it.
""".
-spec start_link(atom()) -> {ok, pid()}.
start_link(ChildName) ->
    supervisor:start_link(?MODULE, [ChildName]).

-doc false.
-spec init([atom()]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([ChildName]) ->
    SupFlags = #{strategy => one_for_one, intensity => 0, period => 10},
    {ok, {SupFlags, [holder_child(ChildName)]}}.

%% **`permanent`, and that is the defect under demonstration.** A `temporary`
%% child would not be restarted either, but it would leave the supervisor standing,
%% which is a different state: the name would be unclaimed for a reason that says
%% nothing about a supervisor giving up. `permanent` is what makes the supervisor's
%% own restart budget the thing that runs out.
holder_child(Name) ->
    #{
        id => named_holder,
        start => {?MODULE, hold, [Name]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [?MODULE]
    }.

-doc false.
-spec hold(atom()) -> {ok, pid()}.
hold(Name) ->
    %% Spawned from inside the supervisor, so the link is the one a supervisor
    %% child is expected to have. Registered before `start_link/2` returns, so a
    %% caller that has the pid has the name too.
    Pid = spawn_link(fun() ->
        true = register(Name, self()),
        hold()
    end),
    {ok, Pid}.

hold() ->
    receive
        _Ignored -> hold()
    end.
