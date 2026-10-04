-module(i2p_addressbook_subs).

-moduledoc """
Subscription fetcher: periodically downloads hosts.txt files from
configured eepsite destinations over our own streaming stack and merges the
entries into `m:i2p_addressbook`.

Enabled via app env `i2per` -> `addressbook`:

```erlang
application:set_env(i2per, addressbook, #{
    subscriptions => [
        #{host => <<"stats.i2p">>, dest_b64 => DestB64}
    ],
    interval_min => 60       %% optional, default 60 minutes
})
```

Each fetch opens a streaming connection to the subscription's lease: packets
are wrapped as end-to-end garlic (`m:i2p_client`) and pushed through an
outbound tunnel; replies arrive inside our inbound tunnels. To receive them
without a SAM session this process owns a persistent internal client
destination that participates in the inbound unwrap scan alongside SAM
sessions (`f:client_destinations/0`, consulted by `m:i2p_tunnel_srv`).
""".

-behaviour(gen_server).

-export([
    start_link/1,
    fetch_now/0,
    ingest_response/1,
    client_destinations/0,
    client_public_key/0,
    stop/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(FETCH_TIMEOUT_MS, 15_000).

-doc """
Server state: configured options, the internal signing seed, the refresh
timer, the in-flight fetch context and the running entry total.
""".
-opaque state() :: #{
    opts := map(),
    sign_seed := binary(),
    timer := reference() | undefined,
    fetch := undefined | map(),
    total => non_neg_integer()
}.
-export_type([state/0]).

-doc "Start the subscription fetcher with the parsed app-env options.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Opts], []).

-doc """
Fetch every configured subscription once.

Output: the final result `{ok, Total}` (entries merged across all
subscriptions) is sent asynchronously to the caller as
`{fetch_result, Result}`; the call itself always returns `ok` immediately
after arming the pipeline.
""".
-spec fetch_now() -> ok.
fetch_now() ->
    gen_server:call(?MODULE, fetch_now).

-doc """
Internal destinations participating in inbound delivery.

Output: one `{DestHash, Pid, CryptoPriv}` entry for this service when running
(its persistent internal client destination), else `[]`. `m:i2p_tunnel_srv`
offers every end-to-end garlic it cannot otherwise open to these entries
exactly like SAM sessions.
""".
-spec client_destinations() ->
    [{i2p_crypto:hash(), pid(), binary()}].
client_destinations() ->
    case whereis(?MODULE) of
        undefined ->
            [];
        Pid ->
            Identity = persistent_term:get({?MODULE, identity}),
            CryptoPriv = persistent_term:get({?MODULE, crypto_priv}),
            [{i2p_keys:hash(Identity), Pid, CryptoPriv}]
    end.

-doc "The internal client destination's 32-byte ECIES public key.".
-spec client_public_key() -> i2p_crypto:key().
client_public_key() ->
    persistent_term:get({?MODULE, client_pub}).

-doc """
Merge an HTTP response (headers + hosts.txt body) into the address book.

Public so tests and tooling can exercise the ingestion half of a
subscription without a live network.
""".
-spec ingest_response(binary()) -> non_neg_integer().
ingest_response(Body) ->
    ingest_hosts(Body).

-doc "Stop the fetcher.".
-spec stop() -> ok.
stop() ->
    gen_server:stop(?MODULE).

-spec init([map(), ...]) -> {ok, state(), 0}.
init([Opts]) ->
    #{identity := Identity, crypto_priv := CryptoPriv, sign_priv := SignSeed} =
        i2p_keys:generate_with_privkeys(),
    persistent_term:put({?MODULE, identity}, Identity),
    persistent_term:put({?MODULE, client_pub}, i2p_keys:public_key(Identity)),
    persistent_term:put({?MODULE, crypto_priv}, CryptoPriv),
    IntervalMin = maps:get(interval_min, Opts, 60),
    Timer = erlang:send_after(IntervalMin * 60_000, self(), refresh),
    %% Timeout 0: run the first fetch on the next scheduler slot.
    {ok, #{opts => Opts, sign_seed => SignSeed, timer => Timer, fetch => undefined}, 0}.

-spec handle_call(term(), gen_server:from(), map()) -> {reply, ok, map()}.
handle_call(fetch_now, _From, State) ->
    self() ! {start_pipeline, []},
    {reply, ok, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec handle_cast(term(), map()) -> {noreply, map()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), map()) -> {noreply, map()}.
handle_info(timeout, State) ->
    self() ! {start_pipeline, []},
    {noreply, State};
handle_info(refresh, State = #{}) ->
    self() ! {start_pipeline, []},
    IntervalMin = maps:get(interval_min, maps:get(opts, State), 60),
    NewTimer = erlang:send_after(IntervalMin * 60_000, self(), refresh),
    {noreply, State#{timer := NewTimer}};
handle_info({start_pipeline, Done}, State) ->
    Subs = maps:get(subscriptions, maps:get(opts, State), []),
    case next_target(Subs, Done) of
        done ->
            {noreply, State};
        {Sub, Rest} ->
            self() ! {fetch_sub, Sub, Rest},
            {noreply, State}
    end;
handle_info({fetch_sub, Sub, Rest}, State = #{sign_seed := SignSeed}) ->
    #{host := Host, dest_b64 := DestB64} = Sub,
    case route_to(DestB64) of
        {ok, Route} ->
            %% The cap is a refusal like any other failed dial, not a crash: a
            %% router at `max_stream_connections` cannot fetch this subscription
            %% now, and the pipeline must move on to the next one rather than
            %% take the fetcher down and with it every future refresh. The
            %% timeout is armed only once there is a connection to time out, so
            %% a refusal leaves no stray `fetch_timeout` behind.
            case start_http_conn(Route, Host, SignSeed) of
                {ok, Conn} ->
                    TimeoutRef = erlang:send_after(?FETCH_TIMEOUT_MS, self(), fetch_timeout),
                    {noreply, State#{
                        fetch => #{
                            host => Host,
                            rest => Rest,
                            buf => <<>>,
                            count => 0,
                            timeout_ref => TimeoutRef,
                            conn => Conn
                        }
                    }};
                {error, _Refused} ->
                    self() ! {start_pipeline, Rest},
                    {noreply, State}
            end;
        error ->
            self() ! {start_pipeline, Rest},
            {noreply, State}
    end;
%% Inbound wire from try_stream_delivery: exactly one streaming connection
%% is active per fetch, so every wire goes straight into it.
handle_info({stream_data, WireBin}, State = #{fetch := #{conn := Conn}}) when
    is_binary(WireBin)
->
    ok = i2p_stream_conn:handle_packet(Conn, WireBin),
    {noreply, State};
%% Data delivered by the connection itself after reassembly.
handle_info({stream_data, _Conn, Payload}, State = #{fetch := #{buf := Buf} = Fetch}) when
    is_binary(Payload)
->
    Buf1 = <<Buf/binary, Payload/binary>>,
    case complete_response(Buf1) of
        true -> finish_fetch(State#{fetch := Fetch#{buf := Buf1}});
        false -> {noreply, State#{fetch := Fetch#{buf := Buf1}}}
    end;
handle_info({stream_closed, _Conn}, State) ->
    finish_fetch(State);
handle_info({stream_reset, _Conn}, State) ->
    abandon_fetch(State);
handle_info(fetch_timeout, State) ->
    abandon_fetch(State);
handle_info({'DOWN', _MRef, process, _ConnPid, _Reason}, State = #{fetch := Fetch}) when
    Fetch =/= undefined
->
    %% The streaming connection died: abandon this subscription and move on.
    self() ! {start_pipeline, maps:get(rest, Fetch)},
    {noreply, State#{fetch => undefined}};
handle_info(_Info, State) ->
    {noreply, State}.

%%%%%%% %%% Internal %%%%%%%

next_target(Subs, Done) when length(Subs) =:= length(Done) -> done;
next_target(Subs, Done) ->
    DoneHosts = [Host || #{host := Host} <- Done],
    [Sub = #{host := _Host} | Rest] =
        lists:dropwhile(fun(#{host := H}) -> lists:member(H, DoneHosts) end, Subs),
    {Sub, Rest ++ Done}.

%% route_to/1 - LeaseSet + outbound tunnel for a subscription destination
%% (see `f:i2p_client:route_to_dest/1`).
route_to(DestB64) ->
    {ok, #{identity := Identity}} = i2p_keys:parse_dest_blob(
        i2p_keys:decode_b64(DestB64)
    ),
    i2p_client:route_to_dest(i2p_keys:to_binary(Identity)).

%% start_http_conn/3 - open the streaming connection and queue an HTTP GET
%% (buffered by the connection until the handshake completes).
%%
%% Output: `{ok, Conn}`, or the admission's own `{error, Refused}`. A refusal at
%% `max_stream_connections` is a failed dial, and a subscription fetch that
%% cannot dial now is a fetch that has to be retried later -- not a fetcher to
%% take down, since it also owns the refresh timer for every other subscription.
start_http_conn(Route, Host, SignSeed) ->
    ConnOpts = #{
        role => connect,
        owner => self(),
        send_fn => fun(Wire) -> i2p_client:send_wire(Route, Wire) end,
        local_seed => SignSeed,
        local_dest_bin =>
            i2p_keys:to_binary(persistent_term:get({?MODULE, identity})),
        local_dest_hash =>
            i2p_keys:hash(persistent_term:get({?MODULE, identity})),
        remote_dest_bin => maps:get(dest_bin, Route),
        remote_dest_hash => maps:get(dest_hash, Route)
    },
    case i2p_sam_sup:start_stream_conn(ConnOpts) of
        {ok, Conn} ->
            erlang:monitor(process, Conn),
            %% Buffered while connecting; flushed automatically once established.
            Request = [
                <<"GET / HTTP/1.0\r\n">>,
                <<"Host: ">>,
                Host,
                <<"\r\n">>,
                <<"Accept: text/plain\r\n\r\n">>
            ],
            ok = i2p_stream_conn:send(Conn, iolist_to_binary(Request)),
            {ok, Conn};
        {error, _Refused} = Refused ->
            Refused
    end.

%% complete_response/1 - true once HTTP headers plus Content-Length worth of
%% body have arrived (or no length was declared and the peer half-closed).
complete_response(Buf) ->
    case binary:match(Buf, <<"\r\n\r\n">>) of
        nomatch ->
            false;
        {Pos, 4} ->
            Head = binary:part(Buf, 0, Pos),
            BodyStart = Pos + 4,
            case content_length(Head) of
                unknown -> false;
                Len -> byte_size(Buf) - BodyStart >= Len
            end
    end.

content_length(Head) ->
    Lines = binary:split(Head, <<"\r\n">>, [global]),
    Fold =
        fun(Line, Acc) ->
            case Acc of
                unknown ->
                    case binary:split(Line, <<": ">>) of
                        [<<"Content-Length">>, V] ->
                            try binary_to_integer(V) of
                                Int when Int >= 0 -> Int
                            catch
                                _:_ -> unknown
                            end;
                        _ ->
                            Acc
                    end;
                Set ->
                    Set
            end
        end,
    lists:foldl(Fold, unknown, Lines).

finish_fetch(State = #{fetch := #{buf := Buf, rest := Rest, count := Count0}}) ->
    Count1 = Count0 + ingest_hosts(Buf),
    self() ! {start_pipeline, Rest},
    {noreply, State#{fetch => undefined, total => Count1}};
finish_fetch(State) ->
    {noreply, State}.

abandon_fetch(State = #{fetch := #{rest := Rest}}) ->
    self() ! {start_pipeline, Rest},
    {noreply, State#{fetch => undefined}};
abandon_fetch(State) ->
    {noreply, State}.

%% ingest_hosts/1 - strip HTTP headers, feed hosts.txt lines to the book.
ingest_hosts(Body) ->
    Content =
        case binary:match(Body, <<"\r\n\r\n">>) of
            {Pos, 4} -> binary:part(Body, Pos + 4, byte_size(Body) - Pos - 4);
            nomatch -> Body
        end,
    Lines = binary:split(Content, <<"\n">>, [global]),
    lists:foldl(
        fun(RawLine, N) ->
            case entry_of(trim_cr(RawLine)) of
                {Name, DestB64} ->
                    ok = i2p_addressbook:add(Name, DestB64),
                    N + 1;
                skip ->
                    N
            end
        end,
        0,
        Lines
    ).

entry_of(Line) ->
    case Line of
        <<$#, _/binary>> ->
            skip;
        _ ->
            case binary:split(Line, <<"=">>) of
                [Name, Dest] when Name =/= <<>>, Dest =/= <<>> ->
                    {Name, Dest};
                _ ->
                    skip
            end
    end.

trim_cr(Bin) ->
    Size = byte_size(Bin),
    case Bin of
        <<Body:(Size - 1)/binary, $\r>> when Size >= 1 -> Body;
        _ -> Bin
    end.
