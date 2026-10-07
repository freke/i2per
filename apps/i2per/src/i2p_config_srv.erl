-module(i2p_config_srv).

-moduledoc """
Validated configuration front door for the running router.

The ini loader (`m:i2p_config`) owns boot-time files; this service owns
runtime access. Readers call `f:get/1`, operators (or the `i2per_status`
service, from any connected node via `{i2p_config_srv, Node}`) call `f:set/2`.

## Set semantics

Runtime keys (`transit_max_tunnels`, `tunnel_pool`, `floodfill`, `net_id`,
`transit_bandwidth_kbps`, `tunnel_build_rate`) are accepted without restarting
the router. `f:set/2` validates the value, updates the application environment,
and announces `{config_changed, Key, Value}`. The first four keys are read by
their consumers at use time. The two rate-limit keys are read when the tunnel
server starts, so restart that service before relying on their new values.

Restart-required keys are all other known keys, including `host`, `port`,
`sam_port`, `data_dir`, `reseed`, `addressbook`, `server_tunnels`,
`ntcp2_published`, `live_network`, `listen_host`, the listener and SAM limits,
and `ntcp2_keepalive_interval_ms`. `f:set/2` validates and announces them but
does not update the running router's application environment; it returns
`{ok, pending_restart}`. Persist an accepted value in the deployment's active
configuration source before restarting.

Unknown keys and malformed values return `{error, Reason}`. This service never
writes configuration files.
""".

-behaviour(gen_server).

-export([start_link/0, get/1, get_all/0, set/2]).

-export_type([known_key/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% Runtime keys: consumers re-read the app env at use time, except the two
%% bucket keys below, which the tunnel server reads when it starts.
-define(RUNTIME_KEYS, [
    transit_max_tunnels,
    tunnel_pool,
    floodfill,
    net_id,
    transit_bandwidth_kbps,
    tunnel_build_rate,
    %% Applied immediately rather than merely stored. `m:i2p_log:set_level/1` is the
    %% only thing in the tree that can change the level, so this key routes through
    %% it: going through `application:set_env/3` alone would record the new level
    %% without applying it, and the router would appear to have accepted a verbosity
    %% change it had not made.
    log_level
]).

%% Every key this service will acknowledge, hot or not.
-define(KNOWN_KEYS,
    ?RUNTIME_KEYS ++
        [
            host,
            port,
            sam_port,
            data_dir,
            reseed,
            addressbook,
            server_tunnels,
            ntcp2_published,
            live_network,
            listen_host,
            max_ntcp2_connections,
            max_sam_sessions,
            max_ssu2_sessions,
            max_stream_connections,
            ntcp2_keepalive_interval_ms
        ]
).

-doc """
Read one configuration value.

Input: an app-env key atom. Output: `{ok, Value}` when set, `error` otherwise.
""".
-spec get(known_key()) -> {ok, term()} | error.
get(Key) ->
    case application:get_env(i2per, Key) of
        {ok, _} = Ok -> Ok;
        undefined -> error
    end.

-doc """
Read every currently-set known key.

Output: a map `Key => Value` covering exactly the known keys currently present
in the application environment. Unset keys are absent.
""".
-spec get_all() -> #{known_key() => term()}.
get_all() ->
    maps:from_list(
        [
            {Key, Value}
         || Key <- ?KNOWN_KEYS,
            {ok, Value} <- [application:get_env(i2per, Key)]
        ]
    ).

-doc """
Validate and apply a configuration change at runtime.

Input: a known key (`t:known_key/0`) and its value. Output:

- `ok` — runtime key accepted into the application environment and announced;
  use-time keys take effect on their next read, while the two rate-limit keys
  take effect from the next tunnel-server start;
- `{ok, pending_restart}` — valid value for a boot-time key; announced, not
  applied;
- `{error, Reason}` — unknown key or malformed value; nothing changed.
""".
-spec set(known_key(), term()) -> ok | {ok, pending_restart} | {error, term()}.
set(Key, Value) ->
    gen_server:call(?MODULE, {set, Key, Value}).

-doc "Known configuration keys.".
-type known_key() ::
    transit_max_tunnels
    | tunnel_pool
    | floodfill
    | net_id
    | transit_bandwidth_kbps
    | tunnel_build_rate
    | ntcp2_published
    | live_network
    | listen_host
    | max_ntcp2_connections
    | max_sam_sessions
    | max_ssu2_sessions
    | max_stream_connections
    | ntcp2_keepalive_interval_ms
    | log_level
    | host
    | port
    | sam_port
    | data_dir
    | reseed
    | addressbook
    | server_tunnels.

%% %%%%% %%% gen_server %%%%% %%%

-doc """
Start the service.

Registered locally as `i2p_config_srv`; called only by `m:i2per_sup`.
Output: the usual `gen_server` start result.
""".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    {ok, #{}}.

handle_call({set, Key, Value}, _From, State) ->
    case apply_set(Key, Value) of
        {ok, Reply} ->
            i2p_events:notify({config_changed, Key, Value}),
            {reply, Reply, State};
        {error, _} = Err ->
            {reply, Err, State}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% apply_set/2 — validate first; only runtime keys reach the app env.
apply_set(Key, Value) ->
    case validate(Key, Value) of
        ok ->
            case lists:member(Key, ?RUNTIME_KEYS) of
                true ->
                    store_runtime(Key, Value),
                    {ok, ok};
                false ->
                    {ok, {ok, pending_restart}}
            end;
        {error, _} = Err ->
            Err
    end.

%% store_runtime/2 — persist a runtime key, applying the ones that need it.
%%
%% Only `log_level` needs more than storing. Everything else in the set is read from
%% the app env by its consumer at use time, so writing the env *is* the whole of
%% "apply". The log level is the exception because the thing that reads it is
%% `logger`, and `logger` is not an application environment.
-spec store_runtime(atom(), term()) -> ok.
store_runtime(log_level, Value) ->
    case i2p_log:set_level(Value) of
        ok -> ok;
        %% Already refused by `f:validate_value/2`, so this is unreachable rather
        %% than handled. Left as an error rather than a silent success because a
        %% runtime key that reports `ok` and did nothing is the exact failure the
        %% comment on the key above describes.
        {error, Reason} -> erlang:error({log_level_not_applied, Reason})
    end;
store_runtime(Key, Value) ->
    application:set_env(i2per, Key, Value),
    ok.

%% %%%%% %%% Validation %%%%% %%%

validate(Key, Value) when is_atom(Key) ->
    case lists:member(Key, ?KNOWN_KEYS) of
        false ->
            {error, {unknown_key, Key}};
        true ->
            validate_value(Key, Value)
    end;
validate(Key, _Value) ->
    {error, {unknown_key, Key}}.

validate_value(Key, Value) ->
    case {Key, Value} of
        {transit_max_tunnels, V} when is_integer(V), V > 0 -> ok;
        {transit_bandwidth_kbps, V} when is_integer(V), V > 0 -> ok;
        {tunnel_build_rate, V} when is_integer(V), V > 0 -> ok;
        {max_ntcp2_connections, V} when is_integer(V), V > 0 -> ok;
        {max_sam_sessions, V} when is_integer(V), V > 0 -> ok;
        {max_ssu2_sessions, V} when is_integer(V), V > 0 -> ok;
        {max_stream_connections, V} when is_integer(V), V > 0 -> ok;
        {ntcp2_keepalive_interval_ms, V} when is_integer(V), V > 0 -> ok;
        {floodfill, V} when is_boolean(V) -> ok;
        {ntcp2_published, V} when is_boolean(V) -> ok;
        {live_network, V} when is_boolean(V) -> ok;
        {listen_host, V} when is_binary(V), byte_size(V) > 0 -> ok;
        {net_id, V} when is_integer(V), V >= 0 -> ok;
        %% The vocabulary is `m:i2p_log`'s, not a list written out here. Two lists of
        %% levels in two modules is a level the ini accepts and this service refuses,
        %% or the reverse, and neither is discoverable without running both.
        {log_level, V} ->
            case i2p_log:is_level(V) of
                true -> ok;
                false -> {error, {bad_value, Key, V}}
            end;
        {tunnel_pool, V} when is_map(V) ->
            case maps:find(outbound, V) of
                {ok, O} when is_integer(O), O > 0 ->
                    case maps:find(inbound, V) of
                        {ok, I} when is_integer(I), I > 0 ->
                            ExpOk = optional_pos(maps:find(exploratory, V), V),
                            HopsOk = optional_hops(maps:find(exploratory_hops, V), V),
                            case ExpOk andalso HopsOk of
                                true -> ok;
                                false -> {error, {bad_value, Key, Value}}
                            end;
                        {ok, _} ->
                            {error, {bad_value, Key, Value}};
                        error ->
                            {error, {bad_value, Key, Value}}
                    end;
                {ok, _} ->
                    {error, {bad_value, Key, Value}};
                error ->
                    {error, {bad_value, Key, Value}}
            end;
        {host, V} when is_binary(V) -> ok;
        {port, V} when is_integer(V), V >= 1, V =< 65535 -> ok;
        {sam_port, V} when is_integer(V), V >= 1, V =< 65535 -> ok;
        {data_dir, V} when is_list(V); is_binary(V) -> ok;
        {reseed, #{enabled := B}} when is_boolean(B) -> ok;
        {addressbook, #{subscriptions := L}} when is_list(L) -> ok;
        {server_tunnels, [_ | _]} ->
            ok;
        _ ->
            {error, {bad_value, Key, Value}}
    end.

%% optional_pos/2 — exploratory pool size: absent is fine, present must be a
%% strictly positive integer.
optional_pos({ok, E}, _V) when is_integer(E), E > 0 -> true;
optional_pos(error, _V) -> true;
optional_pos(_, _V) -> false.

%% optional_hops/2 — exploratory_hops: absent is fine, present must be 1..3.
optional_hops({ok, H}, _V) when is_integer(H), H >= 1, H =< 3 -> true;
optional_hops(error, _V) -> true;
optional_hops(_, _V) -> false.
