-module(i2per_status_listener).

-moduledoc """
The HTTP listener, as a supervised child of `m:i2per_status_sup`.

This used to be started by `ok = start_listener()` inside the supervisor's
`f:init/1`, before it returned any child spec. That linked the listener to the
supervisor but never registered it as a child, so a listener that died was not
brought back and the supervisor still reported healthy — the one situation where
a supervisor's report and the system's actual state disagree. Starting it from
`f:init/1` also meant the listen socket was opened during `init/1`, so a failure
to bind aborted the application from inside a callback that is supposed to be
pure description.

As a child it is `permanent`: it dies, the supervisor restarts it, and the
listener is back. The routes are compiled once per start and the listen address
is validated here, so an invalid `listen_host` is a child start failure the
supervisor reports with its reason rather than an exception out of `f:init/1`.

Nothing here talks to the snapshot server. A handler that finds it unavailable
answers 503 (`m:i2per_status_json`, `m:i2per_status_page`), which is the honest
answer: this service is up, and the thing it reports on is not.
""".

-behaviour(gen_server).

-export([start_link/0, port/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(REF, i2per_status_http).

-doc "Start the listener. Called only by `m:i2per_status_sup`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
The port the listener actually bound.

Not the configured value: the port is resolved here, so this is the only
honest answer to "where is it listening", and a test needs it without reaching
into application env.
""".
-spec port() -> inet:port_number().
port() ->
    gen_server:call(?MODULE, port).

%% %%%%% %%% gen_server %%%%% %%%

init([]) ->
    %% A crash out of here is a start failure, which the supervisor reports with
    %% its reason. That is the point of moving this out of `f:init/1`.
    Port = application:get_env(i2per_status, port, 7662),
    ListenIP = listen_ip(),
    Dispatch = routes(),
    ok = open(Port, ListenIP, Dispatch),
    {ok, #{port => Port, ip => ListenIP}}.

handle_call(port, _From, #{port := Port} = State) ->
    {reply, Port, State};
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

%% Stop the listener explicitly. Ranch would clean it up when this process dies,
%% but saying so here keeps the socket's lifetime bound to this process's rather
%% than to ranch's bookkeeping.
terminate(_Reason, _State) ->
    _ = cowboy:stop_listener(?REF),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% %%%%% %%% Listener %%%%% %%%

routes() ->
    cowboy_router:compile([
        {'_', [
            {"/", i2per_status_page, []},
            {"/status.json", i2per_status_json, []}
        ]}
    ]).

%% Bind the socket. A lingering instance under the same name is replaced, which
%% is what a previous application instance that was not shut down cleanly leaves
%% behind; anything else fails the start.
open(Port, ListenIP, Dispatch) ->
    Opts = [{port, Port}, {ip, ListenIP}],
    ProtoOpts = #{env => #{dispatch => Dispatch}},
    case cowboy:start_clear(?REF, Opts, ProtoOpts) of
        {ok, _Pid} ->
            ok;
        {error, {already_started, _}} ->
            ok = cowboy:stop_listener(?REF),
            case cowboy:start_clear(?REF, Opts, ProtoOpts) of
                {ok, _Pid} -> ok;
                {error, Reason} -> erlang:error({status_listener, Reason})
            end;
        {error, Reason} ->
            erlang:error({status_listener, Reason})
    end.

%% The address to bind, validated here rather than trusted from app env. Loopback
%% is the default: this service is an operator's view of one router and has no
%% business being reachable off-host unless an operator says so.
listen_ip() ->
    case application:get_env(i2per_status, listen_host, {127, 0, 0, 1}) of
        {127, _, _, _} = IP ->
            IP;
        {0, 0, 0, 0} = IP ->
            IP;
        IP when is_tuple(IP), tuple_size(IP) =:= 8 ->
            IP;
        Host when is_binary(Host) ->
            case inet:parse_address(binary_to_list(Host)) of
                {ok, IP} -> IP;
                {error, _} -> erlang:error({status_listener, {invalid_listen_host, Host}})
            end;
        Other ->
            erlang:error({status_listener, {invalid_listen_host, Other}})
    end.
