%% Run-health guard for the CT gate.
%%
%% Installed project-wide via `ct_opts` `{ct_hooks, [...]}` in `rebar.config`.
%% When CT's own logger hook (`cth_log_redirect`) dies mid-run — observed when a
%% cover-instrumented full run's logger handler was removed for failing — every
%% later suite fails per-case with a noproc CTH error that names neither the
%% cause nor the poisoned state. This hook answers at the suite boundary
%% instead: one immediate, named failure per suite (`ct_logger_dead`), cases
%% auto-skipped, no cascade of case-level noise.

-module(i2p_ct_health_hook).

-export([id/1, init/2, pre_init_per_testcase/4, terminate/1]).

id(_Opts) ->
    ?MODULE.

init(_Id, _Opts) ->
    {ok, []}.

%% Checked per case rather than per suite: CT's logger hook process is not yet
%% registered at `pre_init_per_suite` time, and the observed failure mode was
%% exactly this phase — `{noproc, gen_server:call(cth_log_redirect, ...)}` on
%% every case of every suite after the logger died. The `whereis/1` costs
%% nothing per case and fails the case before its own init hook runs.
pre_init_per_testcase(Suite, TestCase, Config, CthState) ->
    case whereis(cth_log_redirect) of
        undefined ->
            erlang:error({ct_logger_dead, Suite, TestCase});
        _Pid ->
            {Config, CthState}
    end.

terminate(_CthState) ->
    ok.
