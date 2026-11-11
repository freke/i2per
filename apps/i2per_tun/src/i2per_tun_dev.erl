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
for a new TCP or UDP flow whose destination IP is in the static map, starts
session creation in a worker and applies the result asynchronously
(`{session_ready, Key, HoldPid}`), so the drain keeps reading. Session
creation is bounded to a small number of concurrent in-flight creates.
Session spawning can be disabled with the `spawn_sessions` option (used by
tests).
""".

-behaviour(gen_server).

-export([start_link/0, start_link/1, stats/0, stats/1, flows/0, flows/1, sessions/0, sessions/1]).
-export([inject/1, inject/2]).
-export([inflight/0, inflight/1]).
-export([udp_payload/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(READY_TAG, i2per_tun_ready).
-define(DEFAULT_DEV_NAME, <<"i2per0">>).
-define(DEFAULT_MAX_INFLIGHT, 4).

-record(state, {
    dev :: term(),
    tun_mod :: module(),
    name :: binary(),
    packets = 0 :: non_neg_integer(),
    bytes = 0 :: non_neg_integer(),
    flows = #{} :: #{term() => non_neg_integer()},
    sessions = #{} :: #{term() => pid()},
    inflight = #{} :: #{term() => {pid(), reference()}},
    max_inflight = ?DEFAULT_MAX_INFLIGHT :: pos_integer(),
    sam_host = <<"127.0.0.1">> :: binary(),
    sam_port = 7656 :: inet:port_number(),
    destinations = #{} :: #{binary() => binary()},
    spawn_sessions = true :: boolean()
}).

-doc "Start the device owner. A failed TUN open is a failed start.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
Start the device owner with overrides.

Recognised keys: `sam_host`, `sam_port`, `destinations`, `spawn_sessions`,
`dev_name`, and `max_inflight_session_creates` (also readable from the
`i2per_tun` application environment; defaults to `?DEFAULT_MAX_INFLIGHT`).
""".
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

-doc "Read the number of in-flight session creates. `undefined` if the owner is not running.".
-spec inflight() -> non_neg_integer() | undefined.
inflight() ->
    case whereis(?MODULE) of
        undefined ->
            undefined;
        _Pid ->
            try gen_server:call(?MODULE, inflight, 1000) of
                N when is_integer(N) -> N
            catch
                _:_ -> undefined
            end
    end.

-doc "Read the number of in-flight session creates for a named device process.".
-spec inflight(pid() | atom()) -> non_neg_integer() | undefined.
inflight(Pid) ->
    try gen_server:call(Pid, inflight, 1000) of
        N when is_integer(N) -> N
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
    MaxInflight = max_inflight_from_opts(Opts),
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
                spawn_sessions = Spawn,
                max_inflight = MaxInflight
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
handle_call(inflight, _From, #state{inflight = I} = State) ->
    {reply, map_size(I), State};
handle_call({inject, Pkt}, _From, State) ->
    {reply, ok, handle_packet(Pkt, State)};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

%% One readiness notification per arm; drain until eagain, then re-arm.
handle_info({?READY_TAG, Dev}, #state{dev = Dev} = State) ->
    {noreply, drain(State)};
handle_info({tun_write, Bytes}, State) when is_binary(Bytes) ->
    _ = (State#state.tun_mod):write(State#state.dev, Bytes),
    {noreply, State};
handle_info({session_ready, Key, HoldPid}, State) when is_pid(HoldPid) ->
    MonRef =
        case maps:find(Key, State#state.inflight) of
            {ok, {_WorkerPid, MR}} -> MR;
            error -> undefined
        end,
    case MonRef of
        undefined -> ok;
        _ -> demonitor(MonRef, [flush])
    end,
    monitor(process, HoldPid),
    Sessions = (State#state.sessions)#{Key => HoldPid},
    Inflight = maps:remove(Key, State#state.inflight),
    {noreply, State#state{sessions = Sessions, inflight = Inflight}};
handle_info({'DOWN', MonRef, process, Pid, _Reason}, State) ->
    case inflight_key_for_mon(State#state.inflight, MonRef) of
        {ok, Key} ->
            {noreply, State#state{inflight = maps:remove(Key, State#state.inflight)}};
        error ->
            DeadKeys = [K || {K, V} <- maps:to_list(State#state.sessions), V =:= Pid],
            case DeadKeys of
                [] ->
                    {noreply, State};
                _ ->
                    Sessions = maps:filter(fun(_K, V) -> V =/= Pid end, State#state.sessions),
                    Flows = lists:foldl(
                        fun(K, Acc) -> maps:remove(K, Acc) end, State#state.flows, DeadKeys
                    ),
                    {noreply, State#state{sessions = Sessions, flows = Flows}}
            end
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{dev = Dev, tun_mod = TunMod, sessions = Sessions, inflight = Inflight}) ->
    %% Cancel any in-flight session-creation workers so a worker cannot
    %% create a holder after the device has exited. Holders already reported
    %% are stopped via sessions below; holders reported during shutdown are
    %% drained from the mailbox.
    lists:foreach(
        fun({WorkerPid, MonRef}) ->
            exit(WorkerPid, kill),
            receive
                {'DOWN', MonRef, process, WorkerPid, _} -> ok
            after 1000 -> ok
            end
        end,
        maps:values(Inflight)
    ),
    %% Drain any session_ready messages already in the mailbox and stop the
    %% holders they name, so a holder created during shutdown is stopped
    %% rather than omitted from sessions.
    drain_session_ready(),
    lists:foreach(fun(Pid) -> catch i2per_tun_flow:stop_session(Pid) end, maps:values(Sessions)),
    _ = TunMod:stop(Dev),
    ok.

drain_session_ready() ->
    receive
        {session_ready, _Key, HoldPid} when is_pid(HoldPid) ->
            catch i2per_tun_flow:stop_session(HoldPid),
            drain_session_ready()
    after 0 ->
        ok
    end.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal

maybe_spawn_session(Key, Parsed, State) ->
    case State#state.spawn_sessions of
        false ->
            {State#state.sessions, State};
        true ->
            case maps:is_key(Key, State#state.sessions) of
                true ->
                    {State#state.sessions, State};
                false ->
                    case maps:is_key(Key, State#state.inflight) of
                        true ->
                            {State#state.sessions, State};
                        false ->
                            DstIp = ip_to_binary(maps:get(dst, Parsed)),
                            case maps:find(DstIp, State#state.destinations) of
                                {ok, DestHost} ->
                                    case
                                        map_size(State#state.inflight) < State#state.max_inflight
                                    of
                                        true ->
                                            start_session_create(
                                                Key,
                                                DestHost,
                                                State#state.sam_host,
                                                State#state.sam_port,
                                                State
                                            );
                                        false ->
                                            {State#state.sessions, State}
                                    end;
                                error ->
                                    {State#state.sessions, State}
                            end
                    end
            end
    end.

maybe_spawn_raw_session(Key, Parsed, State) ->
    case State#state.spawn_sessions of
        false ->
            {State#state.sessions, State};
        true ->
            case maps:is_key(Key, State#state.sessions) of
                true ->
                    {State#state.sessions, State};
                false ->
                    case maps:is_key(Key, State#state.inflight) of
                        true ->
                            {State#state.sessions, State};
                        false ->
                            case udp_payload(Parsed) of
                                {error, _} ->
                                    {State#state.sessions, State};
                                {ok, UdpPayload} ->
                                    DstIp = ip_to_binary(maps:get(dst, Parsed)),
                                    case maps:find(DstIp, State#state.destinations) of
                                        {ok, DestHost} ->
                                            case
                                                map_size(State#state.inflight) <
                                                    State#state.max_inflight
                                            of
                                                true ->
                                                    start_raw_session_create(
                                                        Key,
                                                        DestHost,
                                                        UdpPayload,
                                                        State#state.sam_host,
                                                        State#state.sam_port,
                                                        State
                                                    );
                                                false ->
                                                    {State#state.sessions, State}
                                            end;
                                        error ->
                                            {State#state.sessions, State}
                                    end
                            end
                    end
            end
    end.

start_session_create(Key, DestHost, SamHost, SamPort, State) ->
    Parent = self(),
    DevPid = self(),
    {Pid, MonRef} = spawn_monitor(fun() ->
        case i2per_tun_flow:run_session(DestHost, SamHost, SamPort, 5000, DevPid) of
            {ok, _SessionId, HoldPid} ->
                Parent ! {session_ready, Key, HoldPid};
            _ ->
                ok
        end
    end),
    Inflight = (State#state.inflight)#{Key => {Pid, MonRef}},
    {State#state.sessions, State#state{inflight = Inflight}}.

start_raw_session_create(Key, DestHost, UdpPayload, SamHost, SamPort, State) ->
    Parent = self(),
    DevPid = self(),
    {Pid, MonRef} = spawn_monitor(fun() ->
        case i2per_tun_flow:run_raw_session(DestHost, SamHost, SamPort, 5000, DevPid) of
            {ok, _SessionId, HoldPid} ->
                _ = catch i2per_tun_flow:send_raw(HoldPid, UdpPayload),
                Parent ! {session_ready, Key, HoldPid}
        end
    end),
    Inflight = (State#state.inflight)#{Key => {Pid, MonRef}},
    {State#state.sessions, State#state{inflight = Inflight}}.

-spec udp_payload(map()) -> {ok, binary()} | {error, not_udp}.
udp_payload(Parsed) ->
    case i2per_tun_ip:udp_parse(maps:get(payload, Parsed, <<>>)) of
        {ok, #{payload := P}} -> {ok, P};
        {error, Reason} -> {error, Reason}
    end.

ip_to_binary({A, B, C, D}) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D])).

%% Internal

dev_name() ->
    case application:get_env(i2per_tun, dev_name) of
        {ok, Name} when is_binary(Name), byte_size(Name) > 0 -> Name;
        _ -> ?DEFAULT_DEV_NAME
    end.

max_inflight_from_opts(Opts) ->
    case maps:find(max_inflight_session_creates, Opts) of
        {ok, V} when is_integer(V), V > 0 ->
            V;
        _ ->
            case application:get_env(i2per_tun, max_inflight_session_creates) of
                {ok, V} when is_integer(V), V > 0 -> V;
                _ -> ?DEFAULT_MAX_INFLIGHT
            end
    end.

inflight_key_for_mon(Inflight, MonRef) ->
    case [K || {K, {_Pid, MR}} <- maps:to_list(Inflight), MR =:= MonRef] of
        [Key | _] -> {ok, Key};
        [] -> error
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
            {NewSessions, State1} =
                case maps:is_key(Key, State#state.sessions) of
                    true ->
                        case Proto of
                            17 ->
                                case udp_payload(Parsed) of
                                    {ok, UdpPayload} ->
                                        Pid = maps:get(Key, State#state.sessions),
                                        _ = i2per_tun_flow:send_raw(Pid, UdpPayload),
                                        {State#state.sessions, State};
                                    {error, _} ->
                                        {State#state.sessions, State}
                                end;
                            6 ->
                                case i2per_tun_ip:tcp_parse(maps:get(payload, Parsed, <<>>)) of
                                    {ok, #{payload := TcpPayload}} when byte_size(TcpPayload) > 0 ->
                                        Pid = maps:get(Key, State#state.sessions),
                                        _ = i2per_tun_flow:send(Pid, TcpPayload),
                                        {State#state.sessions, State};
                                    _ ->
                                        {State#state.sessions, State}
                                end;
                            _ ->
                                {State#state.sessions, State}
                        end;
                    false ->
                        case Proto of
                            17 -> maybe_spawn_raw_session(Key, Parsed, State);
                            6 -> maybe_spawn_session(Key, Parsed, State);
                            _ -> {State#state.sessions, State}
                        end
                end,
            State1#state{
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
