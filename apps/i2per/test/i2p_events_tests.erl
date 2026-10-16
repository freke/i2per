-module(i2p_events_tests).

-moduledoc """
One tripwire about the `m:i2p_events` bus: this module is not the event manager.

That is all that is left here. The rest of the bus contract — manager lifecycle
under the real router application, end-to-end delivery into a subscriber, the
backlog gauge, the registry's reconciliation of dead subscribers — needs a
running application, a deliberately wedged `gen_event` manager, or a
message-passing barrier, so it belongs in Common Test rather than in a unit test
that may only call one production function with data and assert on what comes
back.
""".

-include_lib("eunit/include/eunit.hrl").

%% This module is not the event manager, and nothing here may make it look like one.
%%
%% **A gate on a recorded decision, not on behaviour (#N722YKK).** `m:i2p_events`
%% used to declare `-behaviour(gen_event)` and export the six manager callbacks,
%% and the case that stood here called all six directly -- so it passed whether or
%% not anything called them, and six functions that cannot run read as covered.
%% Both are gone; what replaces them is this assertion that they stay gone, because
%% what was wrong with them is invisible in the code: no `f:gen_event:start_link/2`
%% form registers a name *and* names a callback module, so the manager runs
%% `f:gen_event`'s own callbacks (measured in the module note).
%%
%% Reading it as a tripwire rather than as a property: putting the attribute back
%% would be a deliberate act, and this says one has happened, which is the failure
%% the deleted case was -- inverted so that it fails instead of passing.
the_manager_is_not_this_module_test() ->
    ?assertNot(lists:keymember(behaviour, 1, i2p_events:module_info(attributes))),
    Exports = i2p_events:module_info(exports),
    Callbacks = [init, handle_event, handle_call, handle_info, terminate, code_change],
    ?assertEqual([], [C || C <- Callbacks, lists:keymember(C, 1, Exports)]).
