-module(i2per_proxy_listener).

-moduledoc """
TCP listener for `i2per_proxy`: binds a port per protocol (HTTP or SOCKS)
and dispatches each accepted connection to the matching handler.
""".

-behaviour(gen_server).

-export([start_link/0, start_link/1, port/0, port/1, address/0, address/1, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {
    lsock :: gen_tcp:socket(),
    ip :: inet:ip_address(),
    port :: inet:port_number(),
    protocol :: http | socks
}).

start_link() ->
    start_link(#{protocol => http}).

start_link(Opts) ->
    Protocol = maps:get(protocol, Opts, http),
    RegName = reg_name(Protocol),
    gen_server:start_link({local, RegName}, ?MODULE, Opts, []).

reg_name(http) -> i2per_proxy_http_listener;
reg_name(socks) -> i2per_proxy_socks_listener.

port() ->
    port(i2per_proxy_http_listener).

port(Name) when is_atom(Name); is_pid(Name) ->
    gen_server:call(Name, port, 5000).

address() ->
    address(i2per_proxy_http_listener).

address(Name) when is_atom(Name); is_pid(Name) ->
    gen_server:call(Name, address, 5000).

stop(Name) ->
    gen_server:stop(Name).

init(Opts) ->
    Protocol = maps:get(protocol, Opts, http),
    {Port, ListenIP0} =
        case Protocol of
            http ->
                {
                    maps:get(port, Opts, i2per_proxy_config:http_port()),
                    i2per_proxy_config:listen_host()
                };
            socks ->
                {
                    maps:get(port, Opts, i2per_proxy_config:socks_port()),
                    i2per_proxy_config:listen_host()
                }
        end,
    ListenIP = listen_ip(ListenIP0),
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
    {ok, #state{lsock = LSock, ip = BoundIP, port = BoundPort, protocol = Protocol}}.

handle_call(port, _From, #state{port = P} = State) ->
    {reply, P, State};
handle_call(address, _From, #state{ip = IP} = State) ->
    {reply, IP, State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(accept, #state{lsock = LSock, protocol = Proto} = State) ->
    case gen_tcp:accept(LSock, 100) of
        {ok, ClientSock} ->
            Worker = spawn(fun() ->
                receive
                    start -> dispatch(Proto, ClientSock)
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
            {stop, normal, State}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{lsock = LSock}) ->
    gen_tcp:close(LSock),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

dispatch(http, ClientSock) ->
    i2per_proxy_http:handle(ClientSock);
dispatch(socks, ClientSock) ->
    i2per_proxy_socks:handle(ClientSock).

listen_ip(IP) when is_tuple(IP) -> IP;
listen_ip(Host) when is_binary(Host) ->
    case inet:parse_address(binary_to_list(Host)) of
        {ok, IP} -> IP;
        {error, _} -> erlang:error({listener, {invalid_listen_host, Host}})
    end.
