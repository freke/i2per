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

## Where the level may be set, and who wins

Two places, and they answer different windows. `config/sys.config` sets
`kernel`/`logger_level`, which is in force from the moment the node starts until
`m:i2per_app:start/2` runs -- so it governs the kernel, stdlib and the config
loader, which all report before this module exists. `f:apply_configured/0` then
applies the `log_level` key, and from that point `log_level` is the level.

The two must therefore agree, and they are pinned together by
`the_shipped_sys_config_level_matches_the_module_default_test`: a release whose
file says one thing and whose code says another starts at one verbosity and
becomes another without anything saying so. `config/sys.config` ships
`i2p_log:default_level/0`'s value for exactly that reason.

The handler in that file carries **no** level of its own. It inherits
`logger_level`, so there is one verbosity control rather than two, and no way to
leave them disagreeing.

`log_level` is the one way to change it while running, and it is hot: the level is
the thing you want to change at 3am without a restart. The file is for what a node
starts at, not for what it becomes.

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

## Two entry points, and why a frame is not a fact

`f:emit/3` and `f:debug/2` both reach `logger`, and they are not
interchangeable.

`f:emit/3` records a **checklist fact**: something an operator would actually
report, at a level `f:checklist/0` declares, refusing anything it does not. It
is gated because a fact nobody listed is a fact nobody will go looking for at 3am.

`f:debug/2` records a **diagnostic frame**: the shape of a thing that just
happened, for whoever is reading with the level turned up. It is not gated,
because the checklist is a table of symptoms and no operator has ever come to a
log asking to see one SSU2 datagram. The SSU2 transport is the caller that needs
this -- 65 sites, one per event on the wire -- and a checklist row per frame
would be a list nobody could read.

The gate is on the *instrument*, not on the module. A checklist fact is held to
the discipline; a frame is off by default because `debug` is off by default,
which is the same reason the bus is not a checklist row per event.
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
    debug/2,
    loggable_config_keys/0
]).

-export_type([level/0, fact/0, instrument/0, entry/0, label/0]).

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
%% It also keeps `f:emit/3`'s `bus` clause honest. With the literal map inlined,
%% dialyzer would see the declared `bus` rows as an open set it can reason about and
%% the `log` rows as the only reachable ones, which is a thinner guarantee than it
%% looks.
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
    %% The five log-only faults the tree records. Each has no possible subscriber:
    %% none of them is about a pending lookup, so no event exists to describe it.
    | netdb_store_type_unsupported
    | unhandled_ssu2_block_peer
    | netdb_refused_routerinfo
    | reseed_failed
    | reseed_routerinfo_skipped
    %% ADR 0002's seven bus-carried rows. Named for the event that carries them,
    %% because the fact *is* the event: an operator's symptom and the announcement
    %% that answers it are the same thing here, so a second name for it would be a
    %% second thing to keep in step.
    | peer_connect_failed
    | peer_send_stalled
    | lookup_failed
    | reachability
    | transit_denied
    | leaseset_publish_failed
    | db_store_not_stored.

-doc """
Which instrument carries a fact.

`log` means this tree writes it to the log, at the level the row declares.
`bus` means the event bus carries it and the log must not, because ADR 0002's rule
is that a fact is recorded once, on one instrument.

The two are not interchangeable and the distinction is the point of the whole
checklist: a `log` row is a fact with no possible subscriber, and a `bus` row is a
fact a counter will read. Putting either on the wrong instrument is a defect the
build now reports.
""".
-type instrument() :: log | bus.

-doc """
One row of the checklist: which instrument carries the fact, and at what level.

`level` is present exactly when `instrument` is `log`, and that is not a shorthand.
A `bus` row has no level because there is no log record to have one, and giving it
one anyway would be a decorative field: it would invite a future caller to log a
bus-carried fact at a level nobody chose, which is the mistake
`f:emit/3` exists to refuse. An optional key states the truth; a required one
would have to be filled in with a lie.
""".
-type entry() :: #{level => level(), instrument => instrument()}.

-doc """
The facts the router is required to record, and on which instrument.

Output: a map from `t:fact/0` to a `t:entry/0`. This is the single copy. `f:emit/3`
reads the level out of it, and `i2p_log_checklist_tests` reads the fact set, the
instrument and the level out of it -- so a declared fact that nothing in the tree
records, on either instrument, fails the build.

Adding a row here without recording it is not something the compiler can see. A
type is not data, so nothing at the type level can say whether `started_as` is ever
written; only a check that reads the tree can, and that is what this row is for.

**What is deliberately not here.** `m:i2p_events:event/0` admits nineteen event
shapes and only seven are checklist rows, because the checklist is not the event
vocabulary. It is ADR 0002's table of *symptoms an operator would report*, and a
`peer_disconnected` is not one -- nothing an operator would come to the log to ask
about. Declaring the rest would make the checklist a second copy of the event type,
and the event type is already covered from both sides by
`i2p_events_vocabulary_tests`. Two lists of the same nineteen things is the
duplication this project refuses; so is a third list of seven of them.
""".
-spec checklist() -> #{fact() => entry()}.
checklist() ->
    #{
        %% The boot gaps. `notice` and not `info`: an operator who has never seen
        %% the router come up should not have to turn the level up to find out
        %% that it did.
        config_in_force => #{level => notice, instrument => log},
        started_as => #{level => notice, instrument => log},
        online => #{level => notice, instrument => log},
        %% Log-only faults. All five `warning`, because each is a peer or a
        %% source behaving in a way the operator may want to act on.
        netdb_store_type_unsupported => #{level => warning, instrument => log},
        unhandled_ssu2_block_peer => #{level => warning, instrument => log},
        netdb_refused_routerinfo => #{level => warning, instrument => log},
        reseed_failed => #{level => warning, instrument => log},
        %% **Its own fact rather than a second reseed_failed line.** A bundle
        %% that fails wholesale is an operator's "the reseed did not work"; a
        %% bundle this router accepted and then took two entries out of is
        %% "the reseed half-worked", and the second is the one with no other
        %% symptom at all -- the NetDb is a router short and every other line
        %% says the reseed succeeded. `#Q6NKB9P`.
        reseed_routerinfo_skipped => #{level => warning, instrument => log},
        %% ADR 0002's seven bus-carried rows, one per entry, in the order the ADR's
        %% table lists them. No `level` on any of them: see `t:entry/0`.
        peer_connect_failed => #{instrument => bus},
        peer_send_stalled => #{instrument => bus},
        lookup_failed => #{instrument => bus},
        reachability => #{instrument => bus},
        transit_denied => #{instrument => bus},
        leaseset_publish_failed => #{instrument => bus},
        db_store_not_stored => #{instrument => bus}
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
        {ok, #{level := _, instrument := log}} -> emit_at(Fact, Checklist, Format, Args);
        {ok, #{instrument := bus}} -> erlang:error({fact_on_the_bus, Fact});
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
        max_stream_connections,
        net_id,
        ntcp2_keepalive_interval_ms,
        ntcp2_published,
        port,
        sam_port,
        ssu2,
        transit_bandwidth_kbps,
        transit_max_tunnels,
        tunnel_build_rate
    ].

%%% %%%%% Diagnostic frames %%%%% %%%%

%% `f:label/0` is a free-form tag rather than `t:fact/0`, and the looseness is
%% deliberate. A fact is drawn from a closed set the checklist declares, so a
%% typo is a compile-time-adjacent mistake worth typing tightly. A frame is a
%% shape at the call site -- `{recv, RecvDir, Num, new, Blocks}`, `{relay, rejected, code, Code}`
%% -- and pinning that to a union would mean a type edit at every one of the 65
%% sites for no gain: an unexpected shape here is a diagnostic line nobody reads
%% until they are already reading debug output.
-type label() :: atom() | tuple().

-doc """
Record a diagnostic frame at `debug`.

Input: a `t:label/0` naming what happened and a `Context` term carrying whatever
else the site knows -- the role, the peer, the nonce. Output: `ok`.

**Not gated by the checklist, on purpose.** See the module doc: a frame is not a
symptom, and the SSU2 transport emits one per thing on the wire. What keeps that
from being a flood is the level, not the gate: `debug` is off at the `notice`
default, and the `log_level` key is what turns it on.

**The label goes in the message *and* in the metadata.** Both, from the one
argument, rather than a choice between them. The message is what the shipped
`config/sys.config` template renders -- and that template names no `metadata`
placeholder, so a label carried only as metadata would print as a line ending in
the colon. The metadata is what makes the frame filterable by a handler that
wants `{recv, _, _, new, _}` without parsing text. The two are the same value
formatted twice inside one call, not two hand-maintained copies: the duplication
this project refuses is a second declaration that can disagree, and these cannot.
""".
-spec debug(label(), term()) -> ok.
debug(Label, Context) ->
    logger:debug("~0p ~0p", [Label, Context], #{label => Label, context => Context}).

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
-spec emit_at(fact(), #{fact() => entry()}, io:format(), list()) -> ok.
emit_at(Fact, Checklist, Format, Args) ->
    #{level := Level, instrument := log} = maps:get(Fact, Checklist),
    logger:log(Level, Format, Args).
