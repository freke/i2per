-module(i2p_server_tunnel).

-moduledoc """
Server tunnels publish a local TCP service as an I2P destination.

One process handles each declared service. Declarations can come from the
`i2per` application environment or from `tunnels.conf`:

```
#{name => <<"eepsite">>, host => "127.0.0.1", port => 8080}
```

On start the tunnel loads or generates its destination keys
(`<data_dir>/<name>.keys`, base64 private destination blob) so the service
keeps one stable identity across restarts, publishes a signed LeaseSet2 whose
lease is the freshest inbound tunnel (`m:i2p_tunnel_srv:publish_lease_set/2`),
and joins the router's inbound unwrap scan via `f:client_destinations/0`.

Inbound garlic that opens under the service key carries streaming packets:
a SYN for this destination starts an accept-role streaming connection
(`m:i2p_stream_conn`) plus a local TCP connection to the declared host/port,
and bytes are piped in both directions — one relay per peer stream, owned by
this process. A dead local service kills only its own stream relays; the
tunnel and its published lease survive.

## Usage

```erlang
application:set_env(i2per, server_tunnels,
                    [#{name => <<"eepsite">>, host => "127.0.0.1", port => 8080}]),
%% started by m:i2per_sup; remotes reach the service through any SAM client
```
""".
-behaviour(gen_server).

-export([
    start_link/1,
    child_spec/1,
    client_destinations/0,
    stop/1
]).
-export_type([declaration/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-doc "One service declaration from app env `i2per` -> `server_tunnels`.".
-type declaration() :: #{
    name := binary(),
    host := string() | binary(),
    port := inet:port_number()
}.

-doc "Internal server-tunnel state.".
-type state() :: #{
    name := binary(),
    host := string(),
    port := inet:port_number(),
    dest := i2p_keys:identity(),
    crypto_priv := binary(),
    sign_seed := binary(),
    dest_hash := i2p_crypto:hash(),
    keys_path => file:filename_all(),
    %% Relays dialled but not yet handshaken (keyed by process), then live
    %% relays keyed by the streaming demux ID the connection announces.
    pending := #{pid() => relay()},
    conns := #{0..16#FFFFFFFF => relay()}
}.

-doc "One accepted peer stream: the streaming connection and its local socket.".
-type relay() :: #{
    conn := pid(),
    mon := reference(),
    sock := gen_tcp:socket()
}.

-doc """
Start a server-tunnel process for one service declaration (supervisor use).
""".
-spec start_link(declaration()) -> {ok, pid()} | {error, term()}.
start_link(Decl = #{name := Name}) ->
    gen_server:start_link({local, tunnel_name(Name)}, ?MODULE, [Decl], []).

-doc """
Supervisor child spec for one service declaration; the child id doubles as
the registered process name so several services can coexist.
""".
-spec child_spec(declaration()) -> supervisor:child_spec().
child_spec(Decl = #{name := Name}) ->
    #{
        id => tunnel_name(Name),
        start => {i2p_server_tunnel, start_link, [Decl]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [i2p_server_tunnel]
    }.

-doc """
Destinations participating in inbound delivery, one entry per running
service: `{DestHash, Pid, CryptoPriv}` — the same shape SAM sessions expose.
Consulted by the tunnel dispatcher's unwrap scan (`m:i2p_tunnel_srv`).
""".
-spec client_destinations() -> [{i2p_crypto:hash(), pid(), binary()}].
client_destinations() ->
    lists:filtermap(
        fun(#{name := Name}) ->
            case persistent_term:get({?MODULE, Name}, undefined) of
                undefined -> false;
                Entry -> {true, Entry}
            end
        end,
        declarations()
    ).

-doc "Stop the tunnel serving `Name`.".
-spec stop(binary()) -> ok.
stop(Name) ->
    case whereis(tunnel_name(Name)) of
        undefined ->
            ok;
        Pid ->
            gen_server:stop(Pid)
    end.

-spec init([declaration()]) -> {ok, state()}.
init([Decl = #{name := Name, port := Port}]) ->
    Host = host_str(maps:get(host, Decl)),
    KeysPath = keys_path(Name),
    #{identity := Dest, crypto_priv := CryptoPriv, sign_priv := SignSeed} =
        load_or_generate_keys(KeysPath),
    DestHash = i2p_keys:hash(Dest),
    persistent_term:put({?MODULE, Name}, {DestHash, self(), CryptoPriv}),
    ok = i2p_tunnel_srv:publish_lease_set(Dest, SignSeed),
    %% Drain the manager's queue so the publication above is fully processed
    %% before our init returns (keeps supervisor teardown races out of tests).
    _ = i2p_tunnel_srv:status(),
    {ok, #{
        name => Name,
        host => Host,
        port => Port,
        dest => Dest,
        crypto_priv => CryptoPriv,
        sign_seed => SignSeed,
        dest_hash => DestHash,
        keys_path => KeysPath,
        pending => #{},
        conns => #{}
    }}.

-spec handle_call(term(), gen_server:from(), state()) -> {reply, ok, state()}.
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

%% Inbound wire from try_stream_delivery: garlic that opened under our key
%% carries exactly one streaming packet.
-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info({stream_data, WireBin}, State) when is_binary(WireBin) ->
    case i2p_streaming:decode(WireBin) of
        {ok, Pkt} ->
            {noreply, dispatch_packet(Pkt, WireBin, State)};
        {error, _Reason} ->
            {noreply, State}
    end;
%% The connection announces its stream ID - the demux key for inbound
%% packets (a post-handshake packet's send ID equals OUR announced ID).
handle_info({stream_started, Conn, MyId}, State) ->
    case maps:take(Conn, maps:get(pending, State)) of
        {Relay, Pending} ->
            Conns = maps:put(MyId, Relay, maps:get(conns, State)),
            {noreply, State#{pending := Pending, conns := Conns}};
        error ->
            {noreply, State}
    end;
%% Reassembled payload bytes from one of our stream relays → local service.
handle_info({stream_data, Conn, Bytes}, State) when is_pid(Conn) ->
    case find_relay_by_conn(Conn, State) of
        {ok, #{sock := Sock}} ->
            ok = gen_tcp:send(Sock, Bytes);
        not_found ->
            ok
    end,
    {noreply, State};
%% Peer closed or reset the stream: tear down both sides.
handle_info({stream_closed, Conn}, State) ->
    {noreply, drop_relay_by_conn(Conn, State)};
handle_info({stream_reset, Conn}, State) ->
    {noreply, drop_relay_by_conn(Conn, State)};
handle_info({'DOWN', _Mon, process, Conn, _Reason}, State) ->
    {noreply, drop_relay_by_conn(Conn, State)};
%% Local service answered or hung up.
handle_info({tcp, Sock, Data}, State) ->
    ok = inet:setopts(Sock, [{active, once}]),
    case find_relay_by_sock(Sock, State) of
        {ok, #{conn := Conn}} ->
            ok = i2p_stream_conn:send(Conn, Data);
        not_found ->
            ok
    end,
    {noreply, State};
handle_info({tcp_closed, Sock}, State) ->
    {noreply, drop_relay_by_sock(Sock, State)};
handle_info({tcp_error, Sock, _Reason}, State) ->
    {noreply, drop_relay_by_sock(Sock, State)};
handle_info(_Info, State) ->
    {noreply, State}.

%%%%%%% %%% Internal %%%%%%%

%% dispatch_packet/3 — SYN opens a new relay; everything else belongs to an
%% existing one keyed by the peer's send ID. Unknown streams are dropped.
-spec dispatch_packet(i2p_streaming:packet(), binary(), state()) -> state().
dispatch_packet(Pkt, WireBin, State) ->
    case i2p_streaming:send_id(Pkt) of
        0 -> accept_syn(Pkt, State);
        SendId -> forward_to_relay(SendId, WireBin, State)
    end.

%% accept_syn/2 — verify the SYN names THIS destination, route back to the
%% sender's freshest lease, dial the local service, and start the accept-role
%% streaming connection that answers the handshake.
-spec accept_syn(i2p_streaming:packet(), state()) -> state().
accept_syn(Pkt, State = #{dest_hash := DestHash}) ->
    SynBit = i2p_streaming:flag_synchronize(),
    HashOk =
        i2p_streaming:replay_hash(Pkt) =:= {ok, DestHash},
    case
        i2p_streaming:has_flag(Pkt, SynBit) andalso HashOk andalso
            (i2p_streaming:from(Pkt) =/= undefined)
    of
        false ->
            State;
        true ->
            FromBin = i2p_streaming:from(Pkt),
            case i2p_client:route_to_dest(FromBin) of
                {ok, Route} ->
                    open_relay(Route, Pkt, State);
                error ->
                    State
            end
    end.

%% open_relay/4 — dial the local service and start the streaming connection.
%% Either side failing aborts the acceptance: the sender retries.
-spec open_relay(i2p_client:route(), i2p_streaming:packet(), state()) -> state().
open_relay(
    Route,
    Pkt,
    State = #{
        host := Host,
        port := Port,
        dest := Dest,
        sign_seed := SignSeed,
        dest_hash := DestHash
    }
) ->
    case
        gen_tcp:connect(
            Host,
            Port,
            [binary, {active, once}, {exit_on_close, true}]
        )
    of
        {ok, Sock} ->
            ConnOpts = #{
                role => accept,
                syn => Pkt,
                owner => self(),
                send_fn => fun(Wire) -> i2p_client:send_wire(Route, Wire) end,
                local_seed => SignSeed,
                local_dest_bin => i2p_keys:to_binary(Dest),
                local_dest_hash => DestHash
            },
            case i2p_sam_sup:start_stream_conn(ConnOpts) of
                {ok, Conn} ->
                    Mon = erlang:monitor(process, Conn),
                    Relay = #{conn => Conn, mon => Mon, sock => Sock},
                    Pending = maps:put(Conn, Relay, maps:get(pending, State)),
                    State#{pending := Pending};
                {error, _Reason} ->
                    %% A refusal at `max_stream_connections` lands here too, and
                    %% the socket is closed either way: the SYN is unanswered, so
                    %% the sender retries. The local service keeps its listener
                    %% either way — what it loses is one in-flight stream, not the
                    %% ability to accept the next one.
                    ok = gen_tcp:close(Sock),
                    State
            end;
        {error, _Reason} ->
            %% No local service behind the tunnel right now: ignore the SYN.
            State
    end.

%% forward_to_relay/3 — hand a non-SYN packet to its relay's connection.
-spec forward_to_relay(0..16#FFFFFFFF, binary(), state()) -> state().
forward_to_relay(SendId, WireBin, State) ->
    case maps:find(SendId, maps:get(conns, State)) of
        {ok, #{conn := Conn}} ->
            ok = i2p_stream_conn:handle_packet(Conn, WireBin);
        error ->
            %% Late packet for a torn-down relay — drop.
            ok
    end,
    State.

%% drop_relay_by_conn/2 / drop_relay_by_sock/2 — remove one relay and close
%% whichever side remains.
-spec drop_relay_by_conn(pid(), state()) -> state().
drop_relay_by_conn(Conn, State) ->
    case find_relay_by_conn(Conn, State) of
        {ok, Relay} -> finish_drop(Relay, State);
        not_found -> State
    end.

-spec drop_relay_by_sock(gen_tcp:socket(), state()) -> state().
drop_relay_by_sock(Sock, State) ->
    case find_relay_by_sock(Sock, State) of
        {ok, Relay} -> finish_drop(Relay, State);
        not_found -> State
    end.

-spec finish_drop(relay(), state()) -> state().
finish_drop(#{conn := Conn, mon := Mon, sock := Sock}, State) ->
    erlang:demonitor(Mon, [flush]),
    catch gen_tcp:close(Sock),
    catch i2p_stream_conn:close(Conn),
    State#{
        conns :=
            maps:filter(
                fun(_SendId, #{conn := C}) -> C =/= Conn end,
                maps:get(conns, State)
            ),
        pending := maps:remove(Conn, maps:get(pending, State))
    }.

-spec find_relay_by_conn(pid(), state()) -> {ok, relay()} | not_found.
find_relay_by_conn(Conn, State) ->
    find_relay(fun(#{conn := C}) -> C =:= Conn end, State).

-spec find_relay_by_sock(gen_tcp:socket(), state()) -> {ok, relay()} | not_found.
find_relay_by_sock(Sock, State) ->
    find_relay(fun(#{sock := S}) -> S =:= Sock end, State).

-spec find_relay(fun((relay()) -> boolean()), state()) -> {ok, relay()} | not_found.
find_relay(Pred, State) ->
    All =
        maps:to_list(maps:get(conns, State)) ++ maps:to_list(maps:get(pending, State)),
    Matches = [Relay || {_Key, Relay} <- All, Pred(Relay)],
    case Matches of
        [Relay | _] -> {ok, Relay};
        [] -> not_found
    end.

%% declarations/0 - configured services, in app env order.
-spec declarations() -> [declaration()].
declarations() ->
    case application:get_env(i2per, server_tunnels) of
        {ok, Decls} when is_list(Decls) ->
            Decls;
        _ ->
            []
    end.

%% tunnel_name/1 - registered process name and supervisor child id.
-spec tunnel_name(binary()) -> atom().
tunnel_name(Name) ->
    binary_to_atom(<<"i2p_server_tunnel_", (sanitize(Name))/binary>>, utf8).

%% sanitize/1 - lowercase alphanumerics and dashes only, for file paths.
-spec sanitize(binary()) -> binary().
sanitize(Name) ->
    <<<<(sanitize_byte(C))>> || <<C>> <= Name>>.

-spec sanitize_byte(byte()) -> byte().
sanitize_byte(C) when C >= $A, C =< $Z -> C + 32;
sanitize_byte(C) when C >= $a, C =< $z -> C;
sanitize_byte(C) when C >= $0, C =< $9 -> C;
sanitize_byte(_) -> $-.

%% host_str/1 - normalise the declared host to a string for gen_tcp.
-spec host_str(string() | binary()) -> string().
host_str(Host) when is_binary(Host) ->
    binary_to_list(Host);
host_str(Host) when is_list(Host) ->
    Host.

%% keys_path/1 - <data_dir>/<name>.keys, or none without persistence.
-spec keys_path(binary()) -> file:filename_all() | undefined.
keys_path(Name) ->
    case application:get_env(i2per, data_dir) of
        {ok, Dir} ->
            filename:join(Dir, <<(sanitize(Name))/binary, ".keys">>);
        undefined ->
            undefined
    end.

%% load_or_generate_keys/1 - stable destination identity: parse the stored
%% base64 private-destination blob or mint one and write it back.
-spec load_or_generate_keys(file:filename_all() | undefined) ->
    #{identity := i2p_keys:identity(), crypto_priv := binary(), sign_priv := binary()}.
load_or_generate_keys(undefined) ->
    i2p_keys:generate_with_privkeys();
load_or_generate_keys(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            {ok, Keys} = i2p_keys:parse_dest_blob(i2p_keys:decode_b64(trim(Bin))),
            Keys;
        {error, _enoent} ->
            Keys = i2p_keys:generate_with_privkeys(),
            Blob = i2p_keys:dest_blob(Keys),
            ok = filelib:ensure_dir(Path),
            ok = file:write_file(Path, [i2p_keys:encode_b64(Blob), $\n]),
            Keys
    end.

trim(Bin) ->
    string:trim(Bin, both, " \r\n\t").
