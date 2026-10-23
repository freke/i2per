-module(i2per_tun_dev).

-moduledoc """
Owner of one TUN device: opens it, drains it, re-arms it.

The device name is the `dev_name` app env of `i2per_tun` (default
`<<"i2per0">>`). Opening needs CAP_NET_ADMIN, so on an unprivileged host this
process fails to start and the supervisor surfaces the failed start — the same
shape as a listener that cannot bind, and the reason the app is never started
automatically.

Each readiness message drains the device until `eagain`, then re-arms. This
spike's packet handler is a debug log line plus the `packets`/`bytes`
counters in the state; the production shape (a flow table fed by these
packets) is decided by the shape spikes, not by this module.
""".

-behaviour(gen_server).

-export([start_link/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(READY_TAG, i2per_tun_ready).
-define(DEFAULT_DEV_NAME, <<"i2per0">>).

-record(state, {
    dev :: i2per_tun_tun:dev(),
    name :: binary(),
    packets = 0 :: non_neg_integer(),
    bytes = 0 :: non_neg_integer()
}).

-doc "Start the device owner. A failed TUN open is a failed start.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% gen_server callbacks

init([]) ->
    %% Without trapping exits, the parent's `shutdown` signal kills this
    %% gen_server before terminate/2 runs — and terminate/2 is the only path
    %% that stops the armed enif_select. Skipping it keeps the fd selected and
    %% the interface claimed (the select pins the resource), so a restart
    %% fails in TUNSETIFF with ebusy until the VM exits.
    process_flag(trap_exit, true),
    Name = dev_name(),
    case i2per_tun_tun:open(Name) of
        {ok, Dev} ->
            ok = i2per_tun_tun:arm(Dev, self()),
            {ok, #state{dev = Dev, name = Name}};
        {error, Reason} ->
            {stop, {tun_open_failed, Name, Reason}}
    end.

handle_call(_Request, _From, State) ->
    {reply, {error, unsupported}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

%% One readiness notification per arm; drain until eagain, then re-arm.
handle_info({?READY_TAG, Dev}, #state{dev = Dev} = State) ->
    {noreply, drain(State)};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{dev = Dev}) ->
    _ = i2per_tun_tun:stop(Dev),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal

dev_name() ->
    case application:get_env(i2per_tun, dev_name) of
        {ok, Name} when is_binary(Name), byte_size(Name) > 0 -> Name;
        _ -> ?DEFAULT_DEV_NAME
    end.

drain(#state{dev = Dev, name = Name, packets = Packets, bytes = Bytes0} = State) ->
    case i2per_tun_tun:read(Dev) of
        {ok, Pkt} ->
            logger:debug(
                #{at => ?MODULE, dev => Name, bytes => byte_size(Pkt)},
                #{domain => [i2per, tun]}
            ),
            drain(State#state{
                packets = Packets + 1,
                bytes = Bytes0 + byte_size(Pkt)
            });
        {error, eagain} ->
            ok = i2per_tun_tun:arm(Dev, self()),
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
