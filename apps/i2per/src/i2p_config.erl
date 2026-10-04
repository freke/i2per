-module(i2p_config).

-moduledoc """
Ini-style router configuration loader.

Loads operator configuration from a plain-text `i2per.conf` file (next to the
working directory by default). Values are validated against a strict
whitelist and applied to the `i2per` application environment before the
supervisor starts.

## File format

```ini
# comment
data_dir = /var/lib/i2per
port = 9150
sam_port = 7656
ssu2_port = 13873
listen_host = 127.0.0.1
live_network = false
max_ntcp2_connections = 64
max_sam_sessions = 32
max_ssu2_sessions = 32
max_stream_connections = 128
ntcp2_keepalive_interval_ms = 60000
log_level = notice           # one of the eight OTP levels, hot
caps.bandwidth = L
transit_bandwidth_kbps = 256   # per-hop relay cap, whole kbit/s bucket fill
tunnel_build_rate = 2          # accepted build decisions per second

[tunnel_pool]
outbound = 3
inbound = 3
exploratory = 2          # optional: enables the lookup pool at this size
exploratory_hops = 2     # optional: lookup tunnel hops, 1..3 (default 2)

[reseed]
enabled = false        # live_network/reseed must be explicitly enabled
```

Rules:

- Keys and section names are case-insensitive and lowercased.
- `#` or `;` starts a comment (at line start, or after whitespace).
- Blank lines are ignored.
- A line outside a section header that carries no `=` is malformed.
- **Unknown keys, unknown sections and duplicate keys or sections are
  rejected** — the router refuses to boot on a bad config file (fail-closed).
- Section-less entries in `tunnels.conf` are rejected as unknown top-level keys.

A second file, `tunnels.conf`, declares server tunnels as `[name]` sections
(see `f:parse_tunnels/1`); its declarations land in the
`server_tunnels_file` app env where `m:i2per_sup` merges them with any
programmatic `server_tunnels`.

## Semantics

- The file never overwrites an explicitly-set application environment entry:
  programmatic `application:set_env(i2per, ...)` calls (tests, sys.config)
  always win. The file fills gaps only.
- Test/bootstrap envs (`i2p_peer`, `seeds`) are intentionally not expressible
  here — they are test overrides, not operations knobs.
- Addressbook subscription maps are app-env-only: configure them through
  `application:set_env/3` or `sys.config`; this file loader rejects the
  `[addressbook]` section.
- `reseed.trust_extra` is likewise app-env-only (a DER certificate map with
  no sane text form).

## Usage

```erlang
ok = i2p_config:load_default(),   %% called from i2per_app:start/2
{ok, Envs} = i2p_config:validate(Raw),
```
""".

-export([
    load_default/0,
    load/1,
    parse/1,
    validate/1,
    parse_tunnels/1,
    listen_ip/0,
    in_force/0
]).

-export_type([config/0]).

-doc """
Parsed configuration as returned by `f:parse/1`: the reserved key `top`
holds the section-less entries; every `[section]` header introduces its own
key/value map. Keys are lowercase binaries, values raw trimmed strings.
""".
-type config() ::
    #{top => #{binary() => string()}}
    | #{binary() => #{binary() => string()}}.

-doc """
Resolve the address used by the local TCP control listeners.

Input: the `i2per` application environment, where `listen_host` defaults to
`127.0.0.1`. Output: an IPv4 or IPv6 tuple accepted by `gen_tcp:listen/2`.
A configured hostname is resolved through the system resolver; an invalid or
unresolvable value raises a configuration error instead of silently widening
the bind address.
""".
-spec listen_ip() -> inet:ip_address().
listen_ip() ->
    Host =
        case application:get_env(i2per, listen_host) of
            {ok, Value} -> Value;
            undefined -> <<"127.0.0.1">>
        end,
    parse_listen_host(Host).

parse_listen_host(Host) when is_binary(Host) ->
    parse_listen_host(binary_to_list(Host));
parse_listen_host(Host) when is_list(Host) ->
    case inet:parse_address(Host) of
        {ok, IP} ->
            IP;
        {error, _} ->
            case inet:getaddrs(Host, inet) of
                {ok, [ResolvedIP | _]} ->
                    ResolvedIP;
                _ ->
                    exit({config_error, {invalid_listen_host, Host}})
            end
    end;
parse_listen_host(Host) ->
    exit({config_error, {invalid_listen_host, Host}}).

-doc """
Every rejection reason the loader can produce, wrapped as `{error, Reason}`.
""".
-type load_error() ::
    {error,
        {file:name_all(), term()}
        | {line, pos_integer(),
            malformed | {duplicate_key, binary()} | {duplicate_section, binary()}}
        | {unknown_key, binary()}
        | {unknown_section, binary()}
        | {missing_key, atom()}
        | {app_env_only, atom()}
        | {bad_value, atom(), string()}
        | {tunnel_error, binary(), term()}}.

%% %%%%% %%% Loading %%%%% %%%

-doc """
Load configuration from the default location and apply it.

The path comes from the `config_file` application env when set, otherwise
`"i2per.conf"` in the current working directory. A missing file is not an
error — the router runs with defaults and pre-set envs. Output: `ok`, or
`{error, Reason}` from parsing/validation.
""".
-spec load_default() -> ok | load_error().
load_default() ->
    Path =
        case application:get_env(i2per, config_file) of
            {ok, P} -> P;
            undefined -> "i2per.conf"
        end,
    case step_conf(Path) of
        ok -> step_tunnels();
        {error, _} = Err -> Err
    end.

%% i2per.conf: apply validated env pairs (gap-fill semantics).
step_conf(Path) ->
    case file:read_file(Path) of
        {ok, Text} ->
            case pipeline(Text) of
                {ok, Envs} -> apply_env(Envs);
                {error, _} = Err -> Err
            end;
        {error, enoent} ->
            ok;
        {error, Reason} ->
            {error, {Path, Reason}}
    end.

%% tunnels.conf: parsed server-tunnel declarations land in the
%% `server_tunnels_file` app env for `m:i2per_sup` to merge.
step_tunnels() ->
    Path =
        case application:get_env(i2per, tunnels_conf_file) of
            {ok, P} -> P;
            undefined -> "tunnels.conf"
        end,
    case file:read_file(Path) of
        {ok, Text} ->
            case parse_tunnels(Text) of
                {ok, []} ->
                    ok;
                {ok, Decls} ->
                    application:set_env(i2per, server_tunnels_file, Decls),
                    ok;
                {error, _} = Err ->
                    Err
            end;
        {error, enoent} ->
            ok;
        {error, Reason} ->
            {error, {Path, Reason}}
    end.

-doc """
Load, validate and apply the configuration file at `Path`.

Input: an ini file path. Output: `ok` once every recognized entry was applied
to the application environment (without overwriting already-set entries), or
`{error, Reason}` naming the first offending construct — malformed line,
duplicate key, unknown key/section, or bad value.
""".
-spec load(file:filename_all()) -> ok | load_error().
load(Path) ->
    case file:read_file(Path) of
        {ok, Text} ->
            case pipeline(Text) of
                {ok, Envs} -> apply_env(Envs);
                {error, _} = Err -> Err
            end;
        {error, Reason} ->
            {error, {Path, Reason}}
    end.

%% Parse + validate in one step for the loading flow.
pipeline(Text) ->
    case parse(Text) of
        {ok, Raw} -> validate(Raw);
        {error, _} = Err -> Err
    end.

%% Apply validated pairs; explicitly-set entries win over the file.
apply_env([{Key, Value} | Rest]) ->
    case application:get_env(i2per, Key) of
        undefined -> application:set_env(i2per, Key, Value);
        {ok, _} -> ok
    end,
    apply_env(Rest);
apply_env([]) ->
    ok.

-doc """
The configuration in force, as the application environment actually holds it.

Output: `[{Key, Value}]` for every key `m:i2p_log:loggable_config_keys/0` allows
to be printed and that is set, sorted by key so two boots of the same
configuration read identically. A key that is allowed but unset is absent rather
than reported as `undefined`, because "not configured" and "configured to
undefined" are the same thing here and only one of them is worth a line of output.

The environment is the answer, never the file. `f:apply_env/1` merges the file
*under* whatever is already set — `sys.config` wins over `i2per.conf` — so the two
can disagree while the router runs with the environment's value. A reporter that
read the file would be reporting a configuration that is not in force, which is
the one failure this function exists to make impossible.

Values are reported as they are stored, with no rendering or normalisation. A
boot line that printed a prettified version of a value could disagree with the
value the router is using, and the whole value of the line is that it does not.
""".
-spec in_force() -> [{atom(), term()}].
in_force() ->
    lists:keysort(
        1,
        [
            {Key, Value}
         || Key <- i2p_log:loggable_config_keys(),
            {ok, Value} <- [application:get_env(i2per, Key)]
        ]
    ).

%% %%%%% %%% Parser %%%%% %%%

-doc """
Parse ini text into raw sections.

Input: file contents as bytes. Output: `{ok, t:config/0}`, or
`{error, {line, N, malformed}}` for a line without `=` outside a section
header, or `{error, {line, N, {duplicate_key, K}}}` when a key repeats within
its section. Semantic validation happens in `f:validate/1`.
""".
-spec parse(binary()) -> {ok, config()} | {error, term()}.
parse(Text) ->
    parse_lines(string:split(unicode:characters_to_list(Text), "\n", all), 1, top, #{
        top => #{}
    }).

parse_lines([], _N, _Section, Acc) ->
    {ok, Acc};
parse_lines([Line0 | Rest], N, Section, Acc) ->
    Line = strip_comment(string:trim(Line0)),
    case Line of
        [] ->
            parse_lines(Rest, N + 1, Section, Acc);
        [$[ | BracketRest] ->
            section_head(BracketRest, N, Rest, Acc);
        _ ->
            case string:split(Line, "=") of
                [Key0, Value] ->
                    Key = lower(string:trim(Key0)),
                    entry(Section, Key, string:trim(Value), N, Rest, Acc);
                _ ->
                    {error, {line, N, malformed}}
            end
    end.

%% `[name]` header: switch the current section (must be well-formed).
section_head(BracketRest, N, Rest, Acc) ->
    case lists:reverse(BracketRest) of
        [$] | NameRev] ->
            case string:trim(lists:reverse(NameRev)) of
                [] ->
                    {error, {line, N, malformed}};
                Name0 ->
                    case maps:is_key(lower(Name0), Acc) of
                        true ->
                            {error, {line, N, {duplicate_section, lower(Name0)}}};
                        false ->
                            Name = lower(Name0),
                            parse_lines(Rest, N + 1, Name, Acc#{Name => #{}})
                    end
            end;
        _ ->
            {error, {line, N, malformed}}
    end.

entry(Section, Key, Value, N, Rest, Acc) ->
    Cfg = maps:get(Section, Acc),
    case maps:is_key(Key, Cfg) of
        true ->
            {error, {line, N, {duplicate_key, Key}}};
        false ->
            parse_lines(Rest, N + 1, Section, Acc#{Section => Cfg#{Key => Value}})
    end.

%% Drop a comment tail: `#`/`;` at column 0 (already handled as empty line)
%% or preceded by whitespace inside the line.
strip_comment(Line) ->
    strip_comment(Line, []).

strip_comment([], Acc) ->
    lists:reverse(Acc);
strip_comment([C | Rest], Acc) when C =:= $# orelse C =:= $; ->
    case Acc of
        [$\s | _] -> lists:reverse(Acc);
        [] -> [];
        _ -> strip_comment(Rest, [C | Acc])
    end;
strip_comment([C | Rest], Acc) ->
    strip_comment(Rest, [C | Acc]).

lower(S) ->
    string:lowercase(unicode:characters_to_binary(S)).

%% %%%%% %%% Validation %%%%% %%%

-doc """
Validate parsed sections against the whitelist and coerce values.

Input: the output of `f:parse/1`. Output: an ordered list of
`{AppEnvKey :: atom(), Value}` pairs ready for `application:set_env/3` — or
`{error, Reason}` for unknown keys/sections, missing mandatory entries, or
values of the wrong shape.
""".
-spec validate(config()) -> {ok, [{atom(), term()}]} | {error, term()}.
validate(Raw) ->
    case validate_top(maps:to_list(maps:get(top, Raw, #{})), []) of
        {ok, Pairs} ->
            validate_sections(maps:to_list(maps:remove(top, Raw)), Pairs);
        {error, _} = Err ->
            Err
    end.

validate_top([], Acc) ->
    {ok, lists:reverse(Acc)};
validate_top([{Key, Value} | Rest], Acc) ->
    case coerce_scalar(Key, Value) of
        {ok, Pair} -> validate_top(Rest, [Pair | Acc]);
        {error, _} = Err -> Err
    end.

coerce_scalar(<<"data_dir">>, V) ->
    {ok, {data_dir, V}};
coerce_scalar(<<"host">>, V) ->
    {ok, {host, unicode:characters_to_binary(V)}};
coerce_scalar(K, V) when
    K =:= <<"port">>;
    K =:= <<"sam_port">>;
    K =:= <<"ssu2_port">>;
    K =:= <<"net_id">>;
    K =:= <<"transit_max_tunnels">>
->
    coerce_int(env_key(K), V);
coerce_scalar(K, V) when
    K =:= <<"transit_bandwidth_kbps">>;
    K =:= <<"tunnel_build_rate">>;
    K =:= <<"max_ntcp2_connections">>;
    K =:= <<"max_sam_sessions">>;
    K =:= <<"max_ssu2_sessions">>;
    K =:= <<"max_stream_connections">>;
    K =:= <<"ntcp2_keepalive_interval_ms">>
->
    coerce_pos_int(env_key(K), V);
coerce_scalar(<<"floodfill">>, V) ->
    coerce_bool(floodfill, V);
coerce_scalar(<<"ntcp2_published">>, V) ->
    coerce_bool(ntcp2_published, V);
coerce_scalar(<<"live_network">>, V) ->
    coerce_bool(live_network, V);
%% The level vocabulary is `m:i2p_log`'s. The whitelist is fail-closed, so this
%% clause has to exist for the key to be usable from a file at all -- and it consults
%% the owner rather than listing levels, so a level cannot be accepted here and
%% refused by the service that applies it.
coerce_scalar(<<"log_level">>, V) ->
    case i2p_log:is_level(coerce_level_name(V)) of
        true -> {ok, {log_level, coerce_level_name(V)}};
        false -> {error, {bad_value, <<"log_level">>, V}}
    end;
coerce_scalar(<<"listen_host">>, V) ->
    {ok, {listen_host, unicode:characters_to_binary(V)}};
coerce_scalar(<<"caps.bandwidth">>, V) ->
    coerce_bandwidth(V);
coerce_scalar(K, _V) ->
    {error, {unknown_key, K}}.

env_key(<<"port">>) -> port;
env_key(<<"sam_port">>) -> sam_port;
env_key(<<"ssu2_port">>) -> ssu2_port;
env_key(<<"net_id">>) -> net_id;
env_key(<<"transit_max_tunnels">>) -> transit_max_tunnels;
env_key(<<"transit_bandwidth_kbps">>) -> transit_bandwidth_kbps;
env_key(<<"tunnel_build_rate">>) -> tunnel_build_rate;
env_key(<<"max_ntcp2_connections">>) -> max_ntcp2_connections;
env_key(<<"max_sam_sessions">>) -> max_sam_sessions;
env_key(<<"max_ssu2_sessions">>) -> max_ssu2_sessions;
env_key(<<"max_stream_connections">>) -> max_stream_connections;
env_key(<<"ntcp2_keepalive_interval_ms">>) -> ntcp2_keepalive_interval_ms.

%% An ini value arrives as a binary and a level is an atom, so the name is matched
%% as a binary first and only then looked up. Deliberately not `binary_to_atom/3`:
%% a configuration file is operator input, and a file naming something that is not a
%% level must not add it to the atom table on the way to being rejected.
%%
%% Case-insensitive, like every other value this loader normalises (`f:coerce_bool/2`
%% and `f:coerce_bandwidth/1` both lowercase first). It has to be: this loader is
%% fail-closed and refuses to boot on a bad value, so refusing `NOTICE` would mean an
%% operator who wrote a level in the case they saw on a web page could not start the
%% router at all, over a capital letter.
coerce_level_name(V) ->
    Name = lower(unicode:characters_to_binary(V)),
    case [L || L <- i2p_log:levels(), atom_to_binary(L, utf8) =:= Name] of
        [Level] -> Level;
        [] -> V
    end.

coerce_int(Key, V) ->
    case string:to_integer(V) of
        {Int, []} when Int >= 0 -> {ok, {Key, Int}};
        {Int, _} when Int >= 0 -> {error, {bad_value, Key, V}};
        _ -> {error, {bad_value, Key, V}}
    end.

%% Rate-limit keys must name a strictly positive whole number of
%% units/second: zero or negative would silently mean "unlimited".
coerce_pos_int(Key, V) ->
    case string:to_integer(V) of
        {Int, []} when Int > 0 -> {ok, {Key, Int}};
        _ -> {error, {bad_value, Key, V}}
    end.

coerce_bool(Key, V) ->
    case lower(V) of
        <<"true">> -> {ok, {Key, true}};
        <<"false">> -> {ok, {Key, false}};
        _ -> {error, {bad_value, Key, V}}
    end.

%% Router bandwidth class for the `caps` option: one of K/L/M/N/O/P/X,
%% case-insensitive, normalised to uppercase (e.g. `"l"` -> $L).
coerce_bandwidth(V) ->
    case lower(V) of
        <<"k">> -> {ok, {caps_bandwidth, $K}};
        <<"l">> -> {ok, {caps_bandwidth, $L}};
        <<"m">> -> {ok, {caps_bandwidth, $M}};
        <<"n">> -> {ok, {caps_bandwidth, $N}};
        <<"o">> -> {ok, {caps_bandwidth, $O}};
        <<"p">> -> {ok, {caps_bandwidth, $P}};
        <<"x">> -> {ok, {caps_bandwidth, $X}};
        _ -> {error, {bad_value, caps_bandwidth, V}}
    end.

validate_sections([], Acc) ->
    {ok, lists:reverse(Acc)};
validate_sections([{Name, Entries} | Rest], Acc) ->
    case section_pairs(Name, Entries) of
        {ok, Pairs} -> validate_sections(Rest, Pairs ++ Acc);
        {error, _} = Err -> Err
    end.

section_pairs(<<"tunnel_pool">>, Entries) ->
    tunnel_pool_pairs(Entries);
section_pairs(<<"reseed">>, Entries) ->
    reseed_pairs(Entries);
section_pairs(<<"addressbook">>, _Entries) ->
    {error, {app_env_only, addressbook}};
section_pairs(Name, _Entries) ->
    {error, {unknown_section, Name}}.

%% Both directions must be declared together: the pool tick pattern-matches
%% them as required keys of one map. `exploratory` and `exploratory_hops`
%% are optional extras with code-side defaults (2 / 2).
tunnel_pool_pairs(Entries) ->
    case {maps:find(<<"outbound">>, Entries), maps:find(<<"inbound">>, Entries)} of
        {{ok, Out}, {ok, In}} ->
            case {coerce_pos(outbound, Out), coerce_pos(inbound, In)} of
                {{ok, {outbound, O}}, {ok, {inbound, I}}} ->
                    fold_pool_extras(Entries, #{outbound => O, inbound => I});
                {{error, _} = E, _} ->
                    E;
                {_, {error, _} = E} ->
                    E
            end;
        _ ->
            {error, {missing_key, tunnel_pool}}
    end.

%% fold_pool_extras/2 — optional `exploratory` (pool size) and
%% `exploratory_hops` (1..3) on top of the required outbound/inbound pair;
%% anything else in the section is a hard error like everywhere else.
-spec fold_pool_extras(#{binary() := binary()}, map()) ->
    {ok, [{tunnel_pool, map()}]} | {error, term()}.
fold_pool_extras(Entries, Pool) ->
    case maps:fold(fun pool_extra/3, {ok, Pool}, Entries) of
        {ok, Pool1} -> {ok, [{tunnel_pool, Pool1}]};
        {error, _} = Err -> Err
    end.

pool_extra(<<"outbound">>, _V, Acc) ->
    Acc;
pool_extra(<<"inbound">>, _V, Acc) ->
    Acc;
pool_extra(<<"exploratory">>, V, {ok, Pool}) ->
    case coerce_pos(exploratory, V) of
        {ok, {exploratory, Exp}} -> {ok, Pool#{exploratory => Exp}};
        {error, _} = Err -> Err
    end;
pool_extra(<<"exploratory_hops">>, V, {ok, Pool}) ->
    case coerce_int(exploratory_hops, V) of
        {ok, {exploratory_hops, H}} when H >= 1, H =< 3 ->
            {ok, Pool#{exploratory_hops => H}};
        {ok, _} ->
            {error, {bad_value, exploratory_hops, V}};
        {error, _} = Err ->
            Err
    end;
pool_extra(Key, _V, _Acc) ->
    {error, {unknown_key, {tunnel_pool, Key}}}.

coerce_pos(Key, V) ->
    case coerce_int(Key, V) of
        {ok, {_, 0}} -> {error, {bad_value, Key, V}};
        {ok, _} = Ok -> Ok;
        {error, _} = Err -> Err
    end.

reseed_pairs(Entries) ->
    case reseed_collect(maps:to_list(Entries), []) of
        {ok, Pairs} -> {ok, [fold_reseed(Pairs, #{})]};
        {error, _} = Err -> Err
    end.

reseed_collect([], Acc) ->
    {ok, lists:reverse(Acc)};
reseed_collect([{Key, Value} | Rest], Acc) ->
    case reseed_pair(Key, Value) of
        {ok, Pair} -> reseed_collect(Rest, [Pair | Acc]);
        {error, _} = Err -> Err
    end.

%% Fold the collected pairs into the single map the app env expects.
fold_reseed([{K, V} | Rest], Map) ->
    fold_reseed(Rest, Map#{K => V});
fold_reseed([], Map) ->
    {reseed, Map}.

reseed_pair(<<"enabled">>, V) ->
    coerce_bool(enabled, V);
reseed_pair(<<"min_routers">>, V) ->
    coerce_int(min_routers, V);
reseed_pair(<<"hosts">>, V) ->
    {ok, {hosts, csv(V)}};
reseed_pair(<<"trust_extra">>, _) ->
    {error, {app_env_only, trust_extra}};
reseed_pair(Key, _) ->
    {error, {unknown_key, Key}}.

csv(V) ->
    [Item || Item0 <- string:split(V, ",", all), Item <- trimmed_nonempty(Item0)].

trimmed_nonempty(Item0) ->
    case S = string:trim(Item0) of
        [] -> [];
        S -> [S]
    end.

%% %%%%% %%% tunnels.conf %%%%% %%%

-doc """
Parse `tunnels.conf` into server-tunnel declarations.

Input: file contents as bytes. Every `[name]` section declares one service
for `m:i2p_server_tunnel`:

```ini
[eepsite]
type = server
host = 127.0.0.1   %% optional, default 127.0.0.1
port = 8081        %% required, 1..65535
```

`type` must be `server` — client tunnels are SAM sessions, not config-file
entities here. Output: `{ok, [t:i2p_server_tunnel:declaration/0]}` in file
order, or `{error, Reason}` (same shapes as `f:parse/1`, plus
`{tunnel_error, Name, Reason}`).
""".
-spec parse_tunnels(binary()) ->
    {ok, [i2p_server_tunnel:declaration()]} | {error, term()}.
parse_tunnels(Text) ->
    case parse(Text) of
        {ok, Raw} ->
            case maps:take(top, Raw) of
                {Top, Sections} ->
                    case maps:to_list(Top) of
                        [] -> tunnels(maps:to_list(Sections), []);
                        [{Key, _Value} | _Rest] -> {error, {unknown_key, Key}}
                    end
            end;
        {error, _} = Err ->
            Err
    end.

%% Preserve file order for deterministic child-spec ordering.
tunnels([], Acc) ->
    {ok, lists:reverse(Acc)};
tunnels([{Name, Entries} | Rest], Acc) when is_binary(Name) ->
    case tunnel_decl(Name, Entries) of
        {ok, Decl} -> tunnels(Rest, [Decl | Acc]);
        {error, Reason} -> {error, {tunnel_error, Name, Reason}}
    end.

tunnel_decl(Name, Entries) ->
    case maps:to_list(Entries) of
        [] ->
            {error, empty_section};
        _ ->
            case validate_tunnel_keys(maps:to_list(Entries), []) of
                {ok, KV} -> build_decl(Name, KV);
                {error, _} = Err -> Err
            end
    end.

validate_tunnel_keys([], Acc) ->
    {ok, lists:reverse(Acc)};
validate_tunnel_keys([{<<"type">>, V} | Rest], Acc) ->
    case lower(V) of
        <<"server">> -> validate_tunnel_keys(Rest, [{type, server} | Acc]);
        _ -> {error, unsupported_type}
    end;
validate_tunnel_keys([{<<"host">>, V} | Rest], Acc) ->
    validate_tunnel_keys(Rest, [{host, unicode:characters_to_binary(V)} | Acc]);
validate_tunnel_keys([{<<"port">>, V} | Rest], Acc) ->
    case coerce_int(port, V) of
        {ok, {port, P}} when P >= 1, P =< 65535 ->
            validate_tunnel_keys(Rest, [{port, P} | Acc]);
        _ ->
            {error, {bad_value, port, V}}
    end;
validate_tunnel_keys([{Key, _} | _Rest], _Acc) ->
    {error, {unknown_key, Key}}.

build_decl(Name, KV) ->
    Type = proplists:get_value(type, KV),
    Port = proplists:get_value(port, KV),
    if
        Type =:= server, is_integer(Port) ->
            Host =
                case proplists:get_value(host, KV) of
                    undefined -> <<"127.0.0.1">>;
                    H -> H
                end,
            {ok, #{name => Name, host => Host, port => Port}};
        Type =/= server ->
            {error, missing_type};
        true ->
            {error, missing_port}
    end.
