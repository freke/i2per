%% The invariants that hold only because the eunit tier shares one process.
%%
%% **This module is the third payment for the same class.** `i2per_status_state`
%% grew a self-rearming poll chain, `i2p_peer` leaked application environment, and
%% `i2p_addressbook_subs` armed two hour-long timers -- each fixed in the one
%% module that owned the symptom, and the class stayed. So the rule is stated once
%% here and checked against the tree, rather than rediscovered per module.
%%
%% What is checked is deliberately narrow, because a check that is broader than the
%% evidence is a check that gets disabled: **no eunit test module may arm a timer.**
%% Common Test is exempt by construction -- a testcase gets its own process and
%% mailbox -- and the glob below matches only `*_tests.erl`, so `*_SUITE.erl` is
%% not scanned at all rather than scanned and excused.
%%
%% ## Why static, when the failure is dynamic
%%
%% The natural instrument would be a runtime census, and there is none:
%% `erlang:process_info(Pid, timers)` raises `badarg` at OTP 28, so a process's
%% armed timers cannot be enumerated and no amount of waiting reveals them. Tracing
%% `erlang:send_after/3` *does* work -- `erlang:trace_pattern/3` on the BIF plus
%% `erlang:trace(all, true, [call, {tracer, Pid}])` reports every call with its
%% caller and target -- but it has to be installed before the tier starts, and
%% `rebar3 eunit` offers no hook for that. Measured, both, rather than assumed.
%%
%% So this reads the source. That has a real limit and it is stated rather than
%% hidden: a call hidden behind a macro would not be seen, because the scan
%% tokenizes and does not expand. A macro that wraps `erlang:send_after/3` is
%% already a second description of a timer, which is the thing this file exists to
%% discourage.
%%
%% The glob is `apps/*/test/*_tests.erl`, the same shape `scripts/eunit-modules.sh`
%% derives the tier from, so a module added tomorrow is in tomorrow's run for the
%% same reason it is in tomorrow's tier.

-module(i2p_shared_worker_tests).

-include_lib("eunit/include/eunit.hrl").

%% The only rule stated here. A test arming a timer into the shared worker is a
%% timer that outlives its test; everything else about self-scheduling callbacks is
%% handled by `m:i2p_ct_helpers:in_throwaway/1`.
-define(TIMER_FUNS, [send_after, start_timer, send_interval]).

%%% %%%%% The rule %%%%% %%%

%% The full explanation is emitted and the failure term stays short, following
%% `f:i2p_ct_helpers:await_timeout/1`: eunit reports a raised reason with `~p` at
%% default depth, which truncates a message binary to `<<"An eunit test module
%% arms a timer. The whole eunit tier runs in one "...>>` -- so a message carried
%% in the reason reaches the reader as a rule with its middle cut out. Printed, it
%% arrives whole; raised, the offender list stays machine-readable.
no_eunit_test_arms_a_timer_test() ->
    case lists:sort(lists:flatmap(fun timer_calls_in/1, eunit_test_files())) of
        [] ->
            ok;
        Offenders ->
            ct:pal("~ts", [explain(Offenders)]),
            erlang:error({eunit_test_arms_a_timer, Offenders})
    end.

explain(Offenders) ->
    iolist_to_binary([
        "An eunit test module arms a timer. The whole eunit tier runs in one "
        "process, so that timer outlives the test that made it and fires into "
        "whichever module runs next.\n\n",
        "  ",
        lists:join(
            "\n  ",
            [
                io_lib:format("~ts:~b -- ~ts", [File, Line, Func])
             || {File, Line, Func} <- Offenders
            ]
        ),
        "\n\nRun the callback through i2p_ct_helpers:in_throwaway/1, so the timer "
        "dies with the process that armed it. A self-send that the case asserts on "
        "with recv/1 is not this rule: only an armed timer outlives the test.\n"
    ]).

%%% %%%%% Locating the tree %%%%% %%%

%% Every eunit-discoverable test module, by the `_tests.erl` convention that
%% `scripts/eunit-modules.sh` partitions on. `filelib:is_regular/1` because a glob
%% can return something unreadable, and a `file:read_file/1` failure inside the scan
%% would look like a broken test rather than a broken glob.
-spec eunit_test_files() -> [file:filename_all()].
eunit_test_files() ->
    Glob = filename:join(i2p_ct_helpers:project_root(), "apps/*/test/*_tests.erl"),
    [F || F <- filelib:wildcard(Glob), filelib:is_regular(F)].

%%% %%%%% Reading a module %%%%% %%%

%% Timer calls in one file, as `{Module, Line}`.
%%
%% **Tokenized, not grepped.** A grep for `send_after` matches this file's own
%% comment naming the rule, and would match any prose about it -- a check that
%% reports itself is a check nobody runs. `erl_scan` drops comments for free: they
%% arrive as `{comment, _, _}` tokens and are filtered here. `erl_scan` also does
%% not expand macros, which is the limit named in the module doc.
%% Timer calls in one file, as `{File, Line, Func}`.
%%
%% **Tokenized, not grepped.** A grep for `send_after` matches this file's own
%% comment naming the rule, and would match any prose about it -- a check that
%% reports itself is a check nobody runs. `erl_scan` drops comments for free: they
%% arrive as `{comment, _, _}` tokens and are filtered here. `erl_scan` also does
%% not expand macros, which is the limit named in the module doc.
-spec timer_calls_in(file:filename_all()) -> [{file:filename_all(), integer(), atom()}].
timer_calls_in(File) ->
    {ok, Bin} = file:read_file(File),
    %% A list, not the binary `read_file` hands back: `erl_scan:string/3` takes
    %% `char_list()` and raises `function_clause` on a binary, which it does by
    %% delegating `/1` to `/3` -- so the failure lands three frames from here.
    {ok, Tokens, _EndLine} = erl_scan:string(unicode:characters_to_list(Bin)),
    [
        {File, Line, Func}
     || {{atom, Line, Func}, {'(', _}} <- with_successor(Tokens),
        lists:member(Func, ?TIMER_FUNS)
    ].

%% Each token paired with the one after it, so a call can be told from a bare
%% mention of the same name -- `erlang:send_after/3` in a comment is not a call,
%% and `?TIMER_FUNS` in a spec is not either.
%%
%% **The successor is matched as `{'(', _}` rather than compared to `'('`.**
%% `erl_scan` returns an open paren as a *token*, `{'(', Line}`, while the Erlang
%% literal `'('` is the integer 40 -- so `Next =:= '('` is false for every call in
%% the tree, and this check passes on a module that arms a timer on every line. It
%% did, until a deliberately injected offender was run through it.
%%
%% No line accumulator: `erl_scan` numbers every token with its own line, so
%% threading one through the recursion would be a second source of line numbers
%% that could only ever disagree with the token's own.
with_successor([]) -> [];
with_successor([Token]) -> [{Token, none}];
with_successor([Token | Rest]) -> [{Token, hd(Rest)} | with_successor(Rest)].
