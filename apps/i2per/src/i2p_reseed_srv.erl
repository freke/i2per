-module(i2p_reseed_srv).

-moduledoc """
One-shot reseed worker: fetches a signed SU3 reseed file and feeds the
resulting RouterInfos into the NetDb via `f:i2p_peer:learn_ri/1`.

Started by `m:i2per_sup` only when app env `i2per` -> `reseed` is enabled:

```erlang
application:set_env(i2per, reseed, #{
    enabled => true,          %% default: absent (off)
    min_routers => 50,        %% skip when the NetDb already holds this many
    hosts => [..],            %% optional host list override
    trust_extra => #{...}     %% optional extra signer certificates
})
```

The worker checks the threshold when it runs, not when its child spec is
built — the supervisor constructs all specs before any child starts, so the
NetDb is guaranteed to be up by then. It exits normally after one pass;
`temporary` restart semantics mean it never runs twice per boot, whether it
succeeds or fails. A failed bootstrap is logged and waits for the next router
start; recovery lives above, in the operator's boot cycle.
""".

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(DEFAULT_MIN_ROUTERS, 50).

-doc "Start one bootstrap pass. `Opts` — see the module doc.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

-spec init(map()) -> {ok, map(), 0}.
init(Opts) ->
    %% Timeout 0 = run on the next scheduler slot, so start_link returns
    %% before any network I/O happens.
    {ok, #{opts => Opts}, 0}.

-spec handle_call(term(), term(), map()) -> {reply, ok, map()}.
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec handle_cast(term(), map()) -> {noreply, map()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), map()) -> {stop, normal | shutdown, map()}.
handle_info(timeout, State) ->
    maybe_reseed(State);
handle_info(_Info, State) ->
    {stop, normal, State}.

%%%%%%% %%% Internal %%%%%%%

maybe_reseed(State) ->
    #{opts := Opts} = State,
    MinRouters = maps:get(min_routers, Opts, ?DEFAULT_MIN_ROUTERS),
    case i2p_netdb_srv:count() < MinRouters of
        true -> reseed(State);
        false -> {stop, normal, State}
    end.

reseed(State) ->
    #{opts := Opts} = State,
    Hosts = maps:get(hosts, Opts, i2p_reseed:default_hosts()),
    TrustStore = maps:merge(i2p_reseed:load_trust_store(), maps:get(trust_extra, Opts, #{})),
    case i2p_reseed:run(Hosts, TrustStore) of
        {ok, Ris} ->
            lists:foreach(fun i2p_peer:learn_ri/1, Ris),
            ok = i2p_peer:discover(),
            {stop, normal, State};
        {error, Reason} ->
            %% Log-only. A reseed is out-of-band bootstrapping: there is no pending
            %% lookup and no store to be refused, so no event describes it.
            logger:warning("reseed failed: ~p", [Reason]),
            {stop, normal, State}
    end.
