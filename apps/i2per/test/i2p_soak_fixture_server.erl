%% A `gen_server` fixture that holds a referenced binary and, on `dirty`,
%% builds and drops a larger one. The soak's barrier (`f:collect/1`) sends a
%% system message, and only a `proc_lib`/`gen`-managed process answers those, so
%% the fixture must be one: a bare spawn or a plain `proc_lib:spawn` would time
%% out the barrier and make every test here measure the timeout rather than the
%% reading. Verified against the router's own children -- all such processes --
%% where `f:collect/1` takes **2 us**.
-module(i2p_soak_fixture_server).

-behaviour(gen_server).

-export([start/0, dirty/1, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

start() ->
    %% `gen_server:start`, deliberately NOT `start_link`: if the fixture were
    %% linked and then killed by a test's teardown, the `killed` exit would
    %% propagate to the caller too, because that is what `link/2` guarantees
    %% between two processes with that signal in flight.
    gen_server:start(?MODULE, #{}, []).

dirty(Pid) ->
    gen_server:cast(Pid, dirty),
    ok.

stop(Pid) ->
    gen_server:stop(Pid).

init(State) ->
    {ok, State#{held => binary:copy(<<0>>, 4096)}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(dirty, State) ->
    %% Build and drop a larger binary: the garbage a forced collection must
    %% reclaim, and nothing here reaches a collection referenced from the state.
    _ = binary:copy(<<0>>, 40000),
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.
