-module(i2per_tun_listener).

-moduledoc """
TCP listener for `i2per_tun`: accepts host TCP connections and forwards each
one through a SAM STREAM session to the configured destination.

Companion to `m:i2per_tun_dev`: the device owner handles the TUN fd, while
this module is the host-facing side of the flow translator. One process owns
the listening socket and spawns a worker per accepted connection; the worker
runs `m:i2per_tun_flow:run/4`.

The destination a connection is forwarded to is resolved from app env:

- `destination` (binary) wins if set;
- otherwise the first value of the `destinations` map;
- otherwise the connection is refused.

This keeps the listener hermetic-testable against a mock SAM server without a
real TUN device.
""".

-behaviour(gen_server).

-export([start_link/0, start_link/1, port/0, port/1, address/0, stop/1, handle_client/3]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(REF, i2per_tun_listener).

-record(state, {
    lsock :: gen_tcp:socket(),
    ip :: inet:ip_address(),
    port :: inet:port_number(),
    sam_host :: binary(),
    sam_port :: inet:port_number()
}).

-doc "Start the listener with defaults from app env.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link(#{}).

-doc "Start the listener with overrides.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

-doc "Bound port of the default listener.".
-spec port() -> inet:port_number().
port() ->
    port(?MODULE).

-doc "Bound port of the named listener process.".
-spec port(pid() | atom()) -> inet:port_number().
port(Pid) ->
    gen_server:call(Pid, port, 5000).

-doc "Bound address of the default listener.".
-spec address() -> inet:ip_address().
address() ->
    gen_server:call(?MODULE, address, 5000).

-doc "Stop the listener.".
-spec stop(pid() | atom()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% gen_server callbacks

init(Opts) ->
    Port = maps:get(port, Opts, i2per_tun_config:listen_port()),
    ListenIP = listen_ip(maps:get(listen_host, Opts, {127, 0, 0, 1})),
    SamHost = maps:get(sam_host, Opts, i2per_tun_config:sam_host()),
    SamPort = maps:get(sam_port, Opts, i2per_tun_config:sam_port()),
    {ok, LSock} = gen_tcp:listen(Port, [
        {ip, ListenIP},
        binary,
        {packet, raw},
        {active, false},
        {reuseaddr, true},
        {nodelay, true}
    ]),
    {ok, {BoundIP, BoundPort}} = inet:sockname(LSock),
    erlang:send_after(0, self(), accept),
    {ok, #state{
        lsock = LSock, ip = BoundIP, port = BoundPort, sam_host = SamHost, sam_port = SamPort
    }}.

handle_call(port, _From, #state{port = P} = State) ->
    {reply, P, State};
handle_call(address, _From, #state{ip = IP} = State) ->
    {reply, IP, State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(accept, #state{lsock = LSock, sam_host = SH, sam_port = SP} = State) ->
    case gen_tcp:accept(LSock, 100) of
        {ok, ClientSock} ->
            Worker = spawn(fun() ->
                receive
                    start -> handle_client(ClientSock, SH, SP)
                end
            end),
            ok = gen_tcp:controlling_process(ClientSock, Worker),
            Worker ! start,
            erlang:send_after(0, self(), accept),
            {noreply, State};
        {error, timeout} ->
            erlang:send_after(0, self(), accept),
            {noreply, State};
        {error, closed} ->
            {stop, normal, State};
        {error, _} ->
            erlang:send_after(100, self(), accept),
            {noreply, State}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{lsock = LSock}) ->
    gen_tcp:close(LSock),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal

listen_ip({127, _, _, _} = IP) ->
    IP;
listen_ip({0, 0, 0, 0} = IP) ->
    IP;
listen_ip(IP) when is_tuple(IP), tuple_size(IP) =:= 8 -> IP;
listen_ip(Host) when is_binary(Host) ->
    case inet:parse_address(binary_to_list(Host)) of
        {ok, IP} -> IP;
        {error, _} -> erlang:error({listener, {invalid_listen_host, Host}})
    end;
listen_ip(Other) ->
    erlang:error({listener, {invalid_listen_host, Other}}).

handle_client(ClientSock, SamHost, SamPort) ->
    Dest =
        case application:get_env(i2per_tun, destination) of
            {ok, D} when is_binary(D), byte_size(D) > 0 -> {ok, D};
            _ ->
                case i2per_tun_config:destinations() of
                    M when map_size(M) > 0 ->
                        {_, D} = lists:nth(1, maps:to_list(M)),
                        {ok, D};
                    _ ->
                        error
                end
        end,
    case Dest of
        {ok, DestHost} ->
            _ = i2per_tun_flow:run(ClientSock, DestHost, SamHost, SamPort),
            ok;
        error ->
            gen_tcp:close(ClientSock)
    end,
    gen_tcp:close(ClientSock).
