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

## The checklist, and the one way to record a fact

`f:checklist/0` declares the facts the router is required to record and which
instrument carries each one. `f:emit/3` is the only way to record a `log`-carried
fact, and it refuses a fact the checklist does not declare.

That refusal is the reason this module is more than a level setter. A log line
written anywhere in the tree can be at any level, and a fact nobody listed is a
fact nobody will go looking for at 3am. Routing every line through one function
that reads the declaration makes the checklist load-bearing rather than
aspirational.

The bus-carried rows of the checklist are declared but not emittable, and that is
what the `instrument` field is for: **a fact on the bus is not also written to the
log.** `f:emit/3` refuses one, so the overlap ADR 0002 warns about is something
the code prevents rather than something a reviewer has to notice.

## What may be logged about the configuration

`f:loggable_config_keys/0` is an allowlist, and the boot's configuration line is
built from it rather than from the environment as it stands. An allowlist rather
than a denylist because the environment carries material that must never be
printed: the distribution cookie lives in `kernel`, but the explicit-mode
`i2p_peer` key holds the identity's static private key and signing seed, and a
denylist is only ever as good as the list of secrets somebody remembered to name.
""".

-export([
    levels/0,
    default_level/0,
    is_level/1,
    level/0,
    set_level/1,
    apply_configured/0,
    checklist/0,
    fact_names/0,
    emit/3,
    loggable_config_keys/0
]).

-export_type([level/0, fact/0, instrument/0]).

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

It goes through `f:set_level/1` rather than calling `f:apply/1` directly, even when
the key is unset, so that the level actually applied is also *recorded*. That is not
tidiness: the boot's configuration line is assembled from the environment and reports
the level in force, so a level applied but not recorded would be a level the router
was running at and no line could name. That is exactly the shape of bug this whole
module exists to prevent, and it was in the module itself.
""".
-spec apply_configured() -> ok | {error, {invalid_level, term()}}.
apply_configured() ->
    set_level(configured_level()).

-spec configured_level() -> level().
configured_level() ->
    case application:get_env(i2per, ?APP_ENV_KEY) of
        {ok, Configured} -> Configured;
        undefined -> default_level()
    end.

%%% %%%%% The checklist %%%%% %%%

%% `underspecs` is off for the checklist and the allowlist, deliberately, and for
%% the same reason it is off on the read API: both specs are **contracts**.
%%
%% `f:checklist/0` promises "every required fact, each with a level and an
%% instrument" and `f:loggable_config_keys/0` promises "the keys a boot line may
%% name". Dialyzer's success typing is today's literal map and today's literal
%% list, so a strict spec would have to be edited in lockstep with both -- turning
%% each contract into a second copy of the data, which is the one thing this project
%% has a standing rule against. Narrowing the spec to the literal unions would mean
%% the duplication was introduced by the very module whose purpose is to remove it.
%%
%% It also keeps `f:emit/3`'s `bus` clause live. With the literal map inlined, dialyzer
%% would see that no row is `bus` today and report the clause as unreachable; the
%% `bus` rows arrive with the checklist-enforcement ticket, and a compile error here
%% saying so would be the wrong place to learn it.
-dialyzer({no_underspecs, [checklist/0, loggable_config_keys/0]}).

-doc """
A fact the router is required to record.

One atom per fact, named for the symptom it answers rather than for the module
that happens to record it today. A symptom is stable across a refactor; a call
site is not.
""".
-type fact() ::
    %% The three boot gaps. Each happens before a subscriber could exist, or
    %% outside anything that reports, so the log is the only instrument that can
    %% carry them.
    config_in_force
    | started_as
    | online
    %% The four log-only facts the tree already records. Each has no possible
    %% subscriber: none of them is about a pending lookup, so no event exists to
    %% describe it.
    | netdb_store_type_unsupported
    | unhandled_ssu2_block_peer
    | netdb_refused_routerinfo
    | reseed_failed.

-doc """
Which instrument carries a fact.

`log` means this tree writes it to the log, at the level the checklist declares.
`bus` means the event bus carries it and the log must not, because ADR 0002's
rule is that a fact is recorded once, on one instrument.

The `bus` rows are added by the ticket that enforces the checklist end to end.
They are absent here rather than stubbed, so this map is always the set of rows
that are actually enforced.
""".
-type instrument() :: log | bus.

-doc """
The facts the router is required to record, and how.

Output: a map from `t:fact/0` to `{t:level/0, t:instrument/0}`. This is the single
copy: `f:emit/3` reads the level out of it, and the test whose whole job is to
fail when a declared fact is never emitted reads the fact set out of it too.

Adding a row here without emitting it is not something the compiler can see,
which is why the enforcement test exists rather than a type.
""".
-spec checklist() -> #{fact() => {level(), instrument()}}.
checklist() ->
    #{
        %% The boot gaps. `notice` and not `info`: an operator who has never seen
        %% the router come up should not have to turn the level up to find out
        %% that it did.
        config_in_force => {notice, log},
        started_as => {notice, log},
        online => {notice, log},
        %% Log-only faults. All four `warning`, because each is a peer or a
        %% source behaving in a way the operator may want to act on.
        netdb_store_type_unsupported => {warning, log},
        unhandled_ssu2_block_peer => {warning, log},
        netdb_refused_routerinfo => {warning, log},
        reseed_failed => {warning, log}
    }.

-doc """
Every declared fact, sorted.

Output: the keys of `f:checklist/0`. Convenience for the tests, and for anyone
reading the module who wants the list rather than the map.
""".
-spec fact_names() -> [fact()].
fact_names() ->
    lists:sort(maps:keys(checklist())).

-doc """
Record a fact, at the level the checklist declares.

Input: a `t:fact/0` whose instrument is `log`, an `io:format/2`-style format and
its arguments. Output: `ok`.

Raises `{undeclared_fact, Fact}` for a fact `f:checklist/0` does not declare, and
`{fact_on_the_bus, Fact}` for one the checklist marks `bus`. Neither is a
recoverable condition: both mean the tree is recording a fact the ADR's table does
not sanction, and continuing would put the wrong number of copies of it on the
wrong instrument.

The level is looked up rather than passed, so no caller can record a declared fact
at a level nobody chose for it.
""".
-spec emit(fact(), io:format(), list()) -> ok.
emit(Fact, Format, Args) ->
    Checklist = checklist(),
    case maps:find(Fact, Checklist) of
        {ok, {_Level, log}} -> emit_at(Fact, Checklist, Format, Args);
        {ok, {_Level, bus}} -> erlang:error({fact_on_the_bus, Fact});
        error -> erlang:error({undeclared_fact, Fact})
    end.

-doc """
The configuration keys a boot line may name.

Output: the allowlist, as `f:i2p_config:in_force/0` filters it and
`m:i2per_app`'s boot line reports it.

An allowlist, for the reason given in the module doc: a key that is not on this
list is simply not printed, so adding a secret to the environment cannot leak it
into a log, and adding a key an operator wants to see is a deliberate edit here
rather than an omission nobody noticed.
""".
-spec loggable_config_keys() -> [atom()].
loggable_config_keys() ->
    [
        allow_private_host,
        data_dir,
        floodfill,
        host,
        listen_host,
        live_network,
        log_level,
        max_ntcp2_connections,
        max_sam_sessions,
        max_ssu2_sessions,
        net_id,
        ntcp2_keepalive_interval_ms,
        ntcp2_published,
        port,
        sam_port,
        ssu2_enabled,
        transit_bandwidth_kbps,
        transit_max_tunnels,
        tunnel_build_rate
    ].

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

%% `f:emit/3` with the level already resolved. Separate so the caller has one
%% branch to take per outcome, and so the level can only arrive from the
%% checklist and nowhere else.
-spec emit_at(fact(), #{fact() => {level(), instrument()}}, io:format(), list()) -> ok.
emit_at(Fact, Checklist, Format, Args) ->
    {Level, log} = maps:get(Fact, Checklist),
    logger:log(Level, Format, Args).
