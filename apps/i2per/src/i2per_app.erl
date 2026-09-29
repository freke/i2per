-module(i2per_app).

-moduledoc """
The i2per OTP application callback.

Starts the top-level supervisor `m:i2per_sup`. Before the tree comes up,
`f:i2p_config:load_default/0` applies an optional `i2per.conf` (fail-closed:
a malformed or unknown entry aborts boot), and `f:i2p_log:apply_configured/0`
sets the log level. The supervisor owns the NetDb, transport listeners and
connection supervisors, peer and tunnel managers, lookup and address-book
services, the event bus, and the SAM services.

The order of those two matters and is the reason it is written out here rather
than left for a reader to infer: the level is applied *after* the ini loader, so a
`log_level` line in `i2per.conf` is in the environment by then, and *before* the
supervisor, so nothing in the tree logs at the wrong level while it comes up.
""".

-behaviour(application).

-export([start/2, stop/1]).

-spec start(application:start_type(), term()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    case i2p_config:load_default() of
        ok ->
            apply_log_level(),
            i2per_sup:start_link();
        {error, Reason} ->
            erlang:error({config, Reason})
    end.

%% A level that will not apply is a boot failure rather than a warning. The
%% alternative is a router running at a verbosity nobody asked for, discovered
%% later by the person who asked for a different one — and the log is the last
%% place to discover it, because the log is what is misbehaving.
-spec apply_log_level() -> ok.
apply_log_level() ->
    case i2p_log:apply_configured() of
        ok -> ok;
        {error, Reason} -> erlang:error({log_level, Reason})
    end.

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
