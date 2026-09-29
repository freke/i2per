-module(i2p_log).

-moduledoc """
The router's logging floor, and the only place in the tree that can change it.

Decided in [ADR 0002](https://github.com/freke/i2per/blob/main/docs/adr/0002-the-logging-floor-the-bus-is-the-instrument.md).
The short version: the event bus is the instrument for anything that happens while
someone could be watching, and this log is the record that exists when nobody is.
A fact that is on the bus is not also written here.

So this module owns exactly three things, and is thin on purpose:

- **the levels the router accepts** — the eight OTP levels, as a list, which is the
  only copy of that vocabulary in the tree. `m:i2p_config`'s ini whitelist and
  `m:i2p_config_srv`'s validator both read it rather than restating it, so adding a
  level is one edit and a level the router will not accept cannot reach the log
  layer by being spelled in two places that disagree;
- **the level the router considers itself to be at**;
- **the one call that applies a level**.

Everything else about logging — where output goes, how it is formatted, how much is
kept — is configuration, and configuration is deployment's business (ADR 0001). A
deployment that wants a file handler configures one; this module neither ships nor
forbids it.

## Why a module for a level setter

Because without one the checklist has no addressable home. Declared in an ADR it
would be prose, and declared in a test module it would be invisible to the code
that has to satisfy it. Declared here, both the code and the test read one list. A
wrapper that only forwarded to `logger` would not be worth its indirection; this one
is narrowly more than that.

## Where the level may be set

`log_level`, as an `i2per` application environment key, from three places: the
`logger` section of `sys.config` via the `i2per` section, an `i2per.conf` line, and
`f:i2p_config_srv:set/2` at runtime. All three land in the same key, and
`f:apply_configured/0` is what turns that into a level at boot.

Setting `logger`'s primary level directly in `sys.config` is **not** a supported
path. `f:apply_configured/0` applies the level unconditionally at boot, so such a
setting would be silently overwritten. `log_level` is the one way in, and it is
hot: the level is the thing you want to change at 3am without a restart.
""".

-export([levels/0, default_level/0, is_level/1, level/0, set_level/1, apply_configured/0]).

-export_type([level/0]).

%% The app-env key. Named once here and read by `m:i2p_config`'s whitelist and
%% `m:i2p_config_srv`'s validator, so the key name is not spelled three times.
-define(APP_ENV_KEY, log_level).

-doc """
One of OTP's eight log levels.

Ordered here most severe first, which is the order `f:levels/0` reports and the
order an operator reads them in: the first is the one that is always logged.
""".
-type level() ::
    emergency | alert | critical | error | warning | notice | info | debug.

%%% %%%%% The vocabulary %%%%% %%%

-doc """
Every level the router accepts, most severe first.

The single copy. `m:i2p_config:coerce_scalar/2` and
`m:i2p_config_srv:validate_value/2` both consult this rather than listing levels of
their own, so a level can never be accepted by the configuration file and refused
by the service that is supposed to apply it.
""".
%% `underspecs` is off here for the reason it is off on the read API: the spec is
%% the promise ("a list of levels") and the success typing is today's literal list of
%% them. Narrowing the spec to the literal union would make it a hand-maintained copy
%% that has to be edited whenever a level is added -- which is the duplication this
%% module exists to remove, and it would be introduced by the module that removes it.
%% `every_level_the_module_owns_is_one_logger_accepts_test` is what pins the list to
%% the eight the tree agrees on, and the two configuration front doors read this
%% function rather than any list of their own.
-dialyzer({no_underspecs, [levels/0]}).
-spec levels() -> [level()].
levels() ->
    [emergency, alert, critical, error, warning, notice, info, debug].

-doc """
The level in force when nothing has been configured.

`notice`, per the 0.2.0 map. It is also OTP's own default, so a stock install that
never touches `log_level` lands here either way — stated explicitly rather than
inherited, because a default that is only correct by accident is not a default.
""".
%% Spelled out as `notice` rather than `t:level/0`. Dialyzer is right that the
%% function cannot return anything else, and the map pins the default, so widening the
%% spec to the whole union would be a claim this function does not make.
-spec default_level() -> notice.
default_level() -> notice.

-doc "Whether a term is one of `t:level/0`.".
-spec is_level(term()) -> boolean().
is_level(Level) ->
    lists:member(Level, levels()).

%%% %%%%% The level in force %%%%% %%%

-doc """
The level the router is at.

Output: the configured `log_level`, or `f:default_level/0` when the key is unset.
Reports intent rather than querying `logger` — this module is the thing that sets
the level, so asking it what the level is would be circular.
""".
-spec level() -> level().
level() ->
    case application:get_env(i2per, ?APP_ENV_KEY) of
        {ok, Configured} -> Configured;
        undefined -> default_level()
    end.

-doc """
Set the level, and remember it.

Input: a `t:level/0`. Output: `ok`, or `{error, {invalid_level, Term}}` for
anything else — refused rather than coerced, because a typo in a level name that
silently became `notice` would turn a debugging session off at exactly the moment
someone turned it on.

The level is written to the `log_level` app-env key as well as applied, so a later
`f:apply_configured/0` at boot reaches the same answer without anything else having
to remember it.
""".
-spec set_level(term()) -> ok | {error, {invalid_level, term()}}.
set_level(Level) ->
    case is_level(Level) of
        true ->
            ok = apply(Level),
            application:set_env(i2per, ?APP_ENV_KEY, Level),
            ok;
        false ->
            {error, {invalid_level, Level}}
    end.

-doc """
Apply the configured level at boot.

Input: none. Output: `ok`, or `{error, {invalid_level, Term}}` if the key holds
something that is not a level.

Called by `m:i2per_app` after `m:i2p_config:load_default/0` has run — so a level
set in `i2per.conf` is in the environment by then — and before the supervisor
starts, so nothing in the tree logs at the wrong level while it is coming up.

Unconditional on purpose. The alternative is to leave `logger`'s own configuration
alone when the key is unset, which leaves two ways to set a level and no way to tell
which one won. One key, applied once, is the whole point of the module.
""".
-spec apply_configured() -> ok | {error, {invalid_level, term()}}.
apply_configured() ->
    case application:get_env(i2per, ?APP_ENV_KEY) of
        undefined -> apply(default_level());
        {ok, Configured} -> set_level(Configured)
    end.

%% %%%%% Internal %%%%%

%% The one call that touches `logger`.
%%
%% `logger:update_primary_config/1` rather than a hypothetical
%% `logger:set_primary_config_level/1`, which does not exist — checked against this
%% OTP rather than assumed, because an undef at boot is exactly the kind of fault
%% the logging floor is supposed to prevent.
%%
%% A refusal leaves the level untouched: `logger` validates the whole config before
%% applying any of it, so an invalid level cannot half-take effect.
-spec apply(level()) -> ok.
apply(Level) ->
    case logger:update_primary_config(#{level => Level}) of
        ok -> ok;
        {error, Reason} -> erlang:error({log_level_not_applied, Level, Reason})
    end.
