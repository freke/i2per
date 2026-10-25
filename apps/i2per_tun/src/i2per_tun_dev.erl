-module(i2per_tun_dev).

-moduledoc """
Owner of one TUN device: opens it, drains it, re-arms it.

The device name is the `dev_name` app env of `i2per_tun` (default
`<<"i2per0">>`). Opening needs CAP_NET_ADMIN, so on an unprivileged host this
process fails to start and the supervisor surfaces the failed start — the same
shape as a listener that cannot bind, and the reason the app is never started
automatically.

Each readiness message drains the device until `eagain`, then re-arms. The
packet handler counts packets/bytes, maintains per-flow packet counts, and,
for a new TCP flow whose destination IP is in the static map, opens and holds
a SAM STREAM session (via `m:i2per_tun_flow:run_session/3`) keyed by the flow.
Session spawning is synchronous within the drain and can be disabled with the
`spawn_sessions` option (used by tests).
""".

-behaviour(gen_server).

-export([start_link/0, start_link/1, stats/0, stats/1, flows/0, flows/1, sessions/0, sessions/1]).
-export([inject/1, inject/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(READY_TAG, i2per_tun_ready).
-define(DEFAULT_DEV_NAME, <<"i2per0">>).

-record(state, {
    dev :: term(),
    tun_mod :: module(),
    name :: binary(),
    packets = 0 :: non_neg_integer(),
    bytes = 0 :: non_neg_integer(),
    flows = #{} :: #{term() => non_neg_integer()},
    sessions = #{} :: #{term() => pid()},
    sam_host = <<"127.0.0.1">> :: binary(),
    sam_port = 7656 :: inet:port_number(),
    destinations = #{} :: #{binary() => binary()},
    spawn_sessions = true :: boolean()
}).

-doc "Start the device owner. A failed TUN open is a failed start.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc "Start the device owner with overrides (sam_host, sam_port, destinations, spawn_sessions, dev_name).".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) when is_map(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Opts], []).

%% gen_server callbacks

-doc "Read the device's packet/byte counters. `undefined` if the owner is not running.".
-spec stats() -> #{packets => non_neg_integer(), bytes => non_neg_integer()} | undefined.
stats() ->
    case whereis(?MODULE) of
        undefined ->
            undefined;
        _Pid ->
            try gen_server:call(?MODULE, stats, 1000) of
                M when is_map(M) -> M
            catch
                _:_ -> undefined
            end
    end.

-doc "Read the per-flow packet counts. `undefined` if the owner is not running.".
-spec flows() -> #{term() => non_neg_integer()} | undefined.
flows() ->
    case whereis(?MODULE) of
        undefined ->
            undefined;
        _Pid ->
            try gen_server:call(?MODULE, flows, 1000) of
                M when is_map(M) -> M
            catch
                _:_ -> undefined
            end
    end.

-doc "Read the map of flow key -> held SAM session pid. `undefined` if the owner is not running.".
-spec sessions() -> #{term() => pid()} | undefined.
sessions() ->
    case whereis(?MODULE) of
        undefined ->
            undefined;
        _Pid ->
            try gen_server:call(?MODULE, sessions, 1000) of
                M when is_map(M) -> M
            catch
                _:_ -> undefined
            end
    end.

-spec sessions(pid() | atom()) -> #{term() => pid()} | undefined.
sessions(Pid) ->
    try gen_server:call(Pid, sessions, 1000) of
        M when is_map(M) -> M
    catch
        _:_ -> undefined
    end.

-spec flows(pid() | atom()) -> #{term() => non_neg_integer()} | undefined.
flows(Pid) ->
    try gen_server:call(Pid, flows, 1000) of
        M when is_map(M) -> M
    catch
        _:_ -> undefined
    end.

-spec stats(pid() | atom()) ->
    #{packets => non_neg_integer(), bytes => non_neg_integer(), sessions => non_neg_integer()}
    | undefined.
stats(Pid) ->
    try gen_server:call(Pid, stats, 1000) of
        M when is_map(M) -> M
    catch
        _:_ -> undefined
    end.

-doc "Feed one packet through the device's flow/session logic (test seam).".
-spec inject(binary()) -> ok | {error, term()}.
inject(Packet) when is_binary(Packet) ->
    case whereis(?MODULE) of
        undefined -> {error, not_running};
        _Pid -> gen_server:call(?MODULE, {inject, Packet}, 5000)
    end.

-doc "Feed one packet to a named device process (test seam).".
-spec inject(pid() | atom(), binary()) -> ok | {error, term()}.
inject(Pid, Packet) when is_binary(Packet) ->
    gen_server:call(Pid, {inject, Packet}, 5000).

init([]) ->
    init([#{}]);
init([Opts]) when is_map(Opts) ->
    %% Without trapping exits, the parent's `shutdown` signal kills this
    %% gen_server before terminate/2 runs — and terminate/2 is the only path
    %% that stops the armed enif_select. Skipping it keeps the fd selected and
    %% the interface claimed (the select pins the resource), so a restart
    %% fails in TUNSETIFF with ebusy until the VM exits.
    process_flag(trap_exit, true),
    TunMod = maps:get(tun_mod, Opts, i2per_tun_tun),
    Name = maps:get(dev_name, Opts, dev_name()),
    SamHost = maps:get(sam_host, Opts, i2per_tun_config:sam_host()),
    SamPort = maps:get(sam_port, Opts, i2per_tun_config:sam_port()),
    Destinations = maps:get(destinations, Opts, i2per_tun_config:destinations()),
    Spawn = maps:get(spawn_sessions, Opts, true),
    case TunMod:open(Name) of
        {ok, Dev} ->
            ok = TunMod:arm(Dev, self()),
            {ok, #state{
                dev = Dev,
                tun_mod = TunMod,
                name = Name,
                sam_host = SamHost,
                sam_port = SamPort,
                destinations = Destinations,
                spawn_sessions = Spawn
            }};
        {error, Reason} ->
            {stop, {tun_open_failed, Name, Reason}}
    end.

handle_call(stats, _From, #state{packets = P, bytes = B, sessions = S} = State) ->
    {reply, #{packets => P, bytes => B, sessions => map_size(S)}, State};
handle_call(flows, _From, #state{flows = F} = State) ->
    {reply, F, State};
handle_call(sessions, _From, #state{sessions = S} = State) ->
    {reply, S, State};
handle_call({inject, Pkt}, _From, State) ->
    {reply, ok, handle_packet(Pkt, State)};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

%% One readiness notification per arm; drain until eagain, then re-arm.
handle_info({?READY_TAG, Dev}, #state{dev = Dev} = State) ->
    {noreply, drain(State)};
handle_info({'DOWN', _Mon, process, Pid, _Reason}, State) ->
    Sessions = maps:filter(fun(_K, V) -> V =/= Pid end, State#state.sessions),
    {noreply, State#state{sessions = Sessions}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{dev = Dev, tun_mod = TunMod, sessions = Sessions}) ->
    lists:foreach(fun(Pid) -> catch i2per_tun_flow:stop_session(Pid) end, maps:values(Sessions)),
    _ = TunMod:stop(Dev),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal

maybe_spawn_session(Key, Parsed, State, Sessions) ->
    case State#state.spawn_sessions of
        false ->
            Sessions;
        true ->
            DstIp = ip_to_binary(maps:get(dst, Parsed)),
            case maps:find(DstIp, State#state.destinations) of
                {ok, DestHost} ->
                    SH = State#state.sam_host,
                    SP = State#state.sam_port,
                    case i2per_tun_flow:run_session(DestHost, SH, SP) of
                        {ok, _SessionId, HoldPid} ->
                            monitor(process, HoldPid),
                            maps:put(Key, HoldPid, Sessions);
                        {error, _} ->
                            Sessions
                    end;
                error ->
                    Sessions
            end
    end.

maybe_spawn_raw_session(Key, Parsed, State, Sessions) ->
    case State#state.spawn_sessions of
        false ->
            Sessions;
        true ->
            DstIp = ip_to_binary(maps:get(dst, Parsed)),
            case maps:find(DstIp, State#state.destinations) of
                {ok, DestHost} ->
                    SH = State#state.sam_host,
                    SP = State#state.sam_port,
                    UdpPayload = udp_payload(Parsed),
                    case i2per_tun_flow:run_raw_session(DestHost, SH, SP) of
                        {ok, _SessionId, HoldPid} ->
                            monitor(process, HoldPid),
                            _ = i2per_tun_flow:send_raw(HoldPid, UdpPayload),
                            maps:put(Key, HoldPid, Sessions)
                    end;
                error ->
                    Sessions
            end
    end.

udp_payload(Parsed) ->
    case i2per_tun_ip:udp_parse(maps:get(payload, Parsed, <<>>)) of
        {ok, #{payload := P}} -> P;
        _ -> <<>>
    end.

ip_to_binary({A, B, C, D}) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D])).

%% Internal

dev_name() ->
    case application:get_env(i2per_tun, dev_name) of
        {ok, Name} when is_binary(Name), byte_size(Name) > 0 -> Name;
        _ -> ?DEFAULT_DEV_NAME
    end.

drain(#state{dev = Dev, tun_mod = TunMod, name = Name} = State) ->
    case TunMod:read(Dev) of
        {ok, Pkt} ->
            logger:debug(
                #{at => ?MODULE, dev => Name, bytes => byte_size(Pkt)},
                #{domain => [i2per, tun]}
            ),
            drain(handle_packet(Pkt, State));
        {error, eagain} ->
            ok = TunMod:arm(Dev, self()),
            State;
        {error, Reason} ->
            logger:warning(
                #{at => ?MODULE, dev => Name, reason => Reason},
                #{domain => [i2per, tun]}
            ),
            %% A hard read error is not survivable state: stop and let the
            %% supervisor decide.
            exit({tun_read_failed, Name, Reason})
    end.

%% Per-packet flow/session handling, shared by drain and the inject test seam.
handle_packet(Pkt, State) ->
    case i2per_tun_ip:parse(Pkt) of
        {ok, Parsed} ->
            Key = i2per_tun_ip:flow_key(Parsed),
            Proto = maps:get(protocol, Parsed, 0),
            NewFlows = maps:update_with(Key, fun(N) -> N + 1 end, 1, State#state.flows),
            NewSessions =
                case maps:is_key(Key, State#state.sessions) of
                    true ->
                        case Proto of
                            17 ->
                                Pid = maps:get(Key, State#state.sessions),
                                _ = i2per_tun_flow:send_raw(Pid, udp_payload(Parsed)),
                                State#state.sessions;
                            _ ->
                                State#state.sessions
                        end;
                    false ->
                        case Proto of
                            17 -> maybe_spawn_raw_session(Key, Parsed, State, State#state.sessions);
                            _ -> maybe_spawn_session(Key, Parsed, State, State#state.sessions)
                        end
                end,
            State#state{
                packets = State#state.packets + 1,
                bytes = State#state.bytes + byte_size(Pkt),
                flows = NewFlows,
                sessions = NewSessions
            };
        {error, _} ->
            State#state{
                packets = State#state.packets + 1,
                bytes = State#state.bytes + byte_size(Pkt)
            }
    end.
