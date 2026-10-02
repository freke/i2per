%% A `gen_event` handler that stops answering, for #4F1M83V.
%%
%% The point of this handler is the `receive` with no timeout: it is entered and
%% it does not come back. `gen_event` runs handlers in the manager's own process,
%% so while this is inside `handle_event/2` the manager is inside it too, and
%% every process currently blocked in `m:i2p_events:notify/1` is blocked with it.
%%
%% It blocks on a message rather than for ever so the test can let it go. A
%% handler that never returned would wedge the manager for the rest of the CT
%% node, and every later `notify/1` in any suite would hang behind it -- so the
%% case has to be able to clean up after itself, and "release" is that door.
-module(i2p_test_wedged_handler).

-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2, terminate/2, code_change/3]).

%% `TestPid` is told the handler's own pid twice: once from `init/1`, so the case
%% can bind the pid it will later release, and once from `handle_event/2`, so it
%% can assert the handler really wedged. Both are needed because
%% `f:gen_event:add_handler/3` answers bare `ok`, and the case cannot see a
%% variable bound inside its own `try` from the `after` clause that releases it.
init([TestPid]) ->
    TestPid ! {wedged_handler, added, self()},
    {ok, TestPid}.

handle_event(_Event, TestPid) ->
    TestPid ! {wedged_handler, entered, self()},
    receive
        release -> {ok, TestPid}
    end.

handle_call(_Query, State) ->
    {ok, {error, unsupported}, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
