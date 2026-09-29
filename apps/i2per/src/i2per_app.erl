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

-export([start/2, stop/1, report_online/0]).

-spec start(application:start_type(), term()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    case i2p_config:load_default() of
        ok ->
            apply_log_level(),
            report_config_in_force(),
            start_tree();
        {error, Reason} ->
            erlang:error({config, Reason})
    end.

%% The tree starts in two steps around a report, and the order is the point. The
%% configuration line goes out before the supervisor, so a router that dies during
%% startup still leaves behind the answer to "what was it even running with". The
%% online line goes out after, because it claims the bus and the read API are up
%% and neither is true until the children are.
-spec start_tree() -> {ok, pid()} | {error, term()}.
start_tree() ->
    case i2per_sup:start_link() of
        {ok, Pid} ->
            report_online(),
            {ok, Pid};
        Failed ->
            Failed
    end.

%% A level that will not apply is a boot failure rather than a warning. The
%% alternative is a router running at a verbosity nobody asked for, discovered
%% later by the person who asked for a different one — and the log is the last
%% place to discover it, because the log is what is misbehaving.
%% ADR 0002's "the config isn't what I set". Reads the environment rather than the
%% file, which is the only version of this answer that cannot be wrong -- see
%% `m:i2p_config:in_force/0` -- and includes the level in force, because a log
%% that says nothing about its own verbosity makes the operator guess which of
%% these lines they are looking at.
-spec report_config_in_force() -> ok.
report_config_in_force() ->
    i2p_log:emit(config_in_force, "i2per config in force: ~s", [render_config_in_force()]).

%% ADR 0002's "it started and I don't know with what" lives in `m:i2per_sup`,
%% which is where that answer is computed.

%% ADR 0002's "the status page shows nothing". This is the router's own side of
%% that question, and it is asked before anybody could have attached to either the
%% bus or the read API -- which is what makes an empty status page later
%% distinguishable from a router that never came up.
%%
%% Exported so both of its branches can be driven. The `bus=up` / `read_api=
%% answering` branch is what every boot produces, and a case covering only that one
%% would leave `bus=down` and `read_api=silent` unexercised -- the two branches that
%% exist precisely for the situation an operator needs them in, and the two that
%% would otherwise be reached for the first time during an incident.
-spec report_online() -> ok.
report_online() ->
    i2p_log:emit(online, "i2per online: bus=~0p read_api=~s", [
        bus_state(), read_api_state()
    ]).

-spec render_config_in_force() -> string().
render_config_in_force() ->
    case i2p_config:in_force() of
        [] ->
            %% Not an empty line and not a shrug. An operator reading
            %% "config in force:" with nothing after it cannot tell a router
            %% running on defaults from a reporter that fell over.
            "(nothing set; no i2per.conf was loaded and every key is unset)";
        Pairs ->
            lists:join(" ", [io_lib:format("~p=~p", [Key, Value]) || {Key, Value} <- Pairs])
    end.

%% `up` and `down` spelled out rather than `string()`: dialyzer is right that nothing
%% else can come back, and a wider spec here would be a claim this function does not
%% make. The online line interpolates it, so nothing downstream needs more.
%% An atom, rendered with `~0p` by the caller, rather than the string `"up"`.
%% Erlang has no string literals in specs, so a string return here would have to be
%% typed `string()` -- wider than what the function can produce, which dialyzer
%% reports. An atom types exactly and renders identically in the line.
-spec bus_state() -> up | down.
bus_state() ->
    case whereis(i2p_events) of
        undefined -> down;
        _Pid -> up
    end.

%% Whether `m:i2p_status_data:view/0` answers.
%%
%% The `catch` here is the tree's only one and it is here for a reason worth
%% stating: the question being asked is "does this call work", so an exception is
%% an *answer*, not a fault. Letting it propagate would replace a truthful line
%% naming the failure with a boot that dies for being unable to report that it is
%% broken -- and the operator would get the same stack trace with nothing pointing
%% at the fact that the bus was fine and only the read API was not.
-spec read_api_state() -> string().
read_api_state() ->
    case catch i2p_status_data:view() of
        View when is_map(View) ->
            Peers = maps:get(peers, View),
            NetDb = maps:get(netdb, View),
            %% Every value is a scalar, deliberately. The read API's `peers` and
            %% `netdb` are maps, and `~p` wraps a map across several lines at this
            %% width -- which would make this "one line" the one thing it most needs
            %% not to be, and would split the fact a reader is scanning for away
            %% from its own prefix.
            lists:flatten(
                io_lib:format(
                    "answering(version=~p identity=~s uptime_ms=~p "
                    "peers_connected=~p peers_other=~p netdb_ri=~p netdb_ls=~p)",
                    [
                        maps:get(version, View),
                        maps:get(identity, View),
                        maps:get(uptime_ms, View),
                        maps:get(connected, Peers),
                        maps:get(other, Peers),
                        maps:get(ri, NetDb),
                        maps:get(ls, NetDb)
                    ]
                )
            );
        {'EXIT', {Reason, _Call}} ->
            lists:flatten(io_lib:format("silent(~0p)", [Reason]));
        {'EXIT', Reason} ->
            lists:flatten(io_lib:format("silent(~0p)", [Reason]));
        Unexpected ->
            lists:flatten(io_lib:format("silent(unexpected ~0p)", [Unexpected]))
    end.

-spec apply_log_level() -> ok.
apply_log_level() ->
    case i2p_log:apply_configured() of
        ok -> ok;
        {error, Reason} -> erlang:error({log_level, Reason})
    end.

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
