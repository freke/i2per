-module(i2p_client_session).

-moduledoc """
Headless client session for companion applications (E1CHFWF).

A socket-free counterpart to `m:i2p_sam_session`: it owns a destination
(identity + keys) and publishes its LeaseSet, but never touches a TCP
socket. Inbound/outbound byte flow happens through `m:i2p_stream_conn`
processes that report `{stream_data, Conn, Bytes}` to their owner, so a
companion app can read and write streams directly.

This is the client side only: no `STREAM ACCEPT`/`FORWARD`, no datagram
sessions. Companion apps that need to accept inbound streams will get
those in a later slice.

## Ownership

A session belongs to whoever holds the pid, and it ends when that caller
stops it — never when the call that created it returns. `f:start/1` is
therefore unlinked: companion apps reach it over `erpc`, and the worker
erpc spawns for a call with a timeout exits *abnormally* as it delivers
the reply, so a link would kill the session before the caller could use
it. See `f:i2p_sam_api:create_session/1` for the callers' side.

The one exception is a session started with `ephemeral => true`, which
`f:i2p_sam_api:stream_connect/3` uses when it is given a destination map
rather than a session pid: it stops itself when its last connection ends,
so the caller has nothing to close.
""".

-behaviour(gen_server).

-export([start/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-export_type([session/0]).

-type session() :: pid().

-doc """
Start a headless client session, unlinked from the caller.

Input: `Args` — a map with `identity`, `crypto_priv`, `sign_priv`, and
optional `tunnel_lengths` and `ephemeral`.
Output: `{ok, Pid}` or `{error, Reason}`. The caller owns the session and
must stop it with `f:i2p_sam_api:close_session/1`; nothing else will, unless
`ephemeral` is true and its last connection has ended.
""".
-spec start(map()) -> {ok, pid()} | {error, term()}.
start(#{identity := _} = Args) ->
    gen_server:start(?MODULE, Args, []).

init(#{identity := Identity, crypto_priv := CPriv, sign_priv := SPriv} = Args) ->
    DestHash = i2p_keys:hash(Identity),
    DestBin = i2p_keys:to_binary(Identity),
    DestB64 = i2p_keys:to_b64(Identity),
    Lengths = maps:get(tunnel_lengths, Args, #{}),
    Ephemeral = maps:get(ephemeral, Args, false),
    %% Publish a LeaseSet so remote peers can reach us, mirroring SAM's
    %% SESSION CREATE. Best-effort: a router that is not fully booted
    %% (hermetic unit tests) simply leaves the publish pending.
    catch i2p_tunnel_srv:publish_lease_set(Identity, SPriv, in_len(Lengths)),
    catch register_lengths(Lengths, self()),
    {ok, #{
        identity => Identity,
        crypto_priv => CPriv,
        sign_priv => SPriv,
        dest_b64 => DestB64,
        dest_hash => DestHash,
        dest_bin => DestBin,
        tunnel_lengths => Lengths,
        ephemeral => Ephemeral,
        conns => #{},
        monitors => #{}
    }}.

handle_call({stream_connect, Target, Owner}, _From, State) ->
    {Result, State2} = do_stream_connect(Target, Owner, State),
    {reply, Result, State2};
handle_call(dest_b64, _From, #{dest_b64 := B64} = State) ->
    {reply, B64, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Req, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% The session is the stream owner so it can register each stream ID for
%% inbound dispatch; events are forwarded to the caller-supplied owner below.
handle_info({stream_started, Conn, MyId}, State) ->
    catch i2p_sam_sup:stream_conn_register(maps:get(dest_hash, State), MyId, Conn),
    {noreply, State};
handle_info({stream_data, Conn, Bytes}, State) when is_pid(Conn) ->
    forward_to_owner(Conn, {stream_data, Conn, Bytes}, State),
    {noreply, State};
handle_info({stream_established, Conn, PeerHash}, State) when is_pid(Conn) ->
    forward_to_owner(Conn, {stream_established, Conn, PeerHash}, State),
    {noreply, State};
handle_info({stream_closed, Conn}, State) when is_pid(Conn) ->
    forward_to_owner(Conn, {stream_closed, Conn}, State),
    State2 = forget_conn(Conn, State),
    case ephemeral_stop(State2) of
        stop -> {stop, normal, State2};
        continue -> {noreply, State2}
    end;
handle_info({stream_reset, Conn}, State) when is_pid(Conn) ->
    forward_to_owner(Conn, {stream_reset, Conn}, State),
    State2 = forget_conn(Conn, State),
    case ephemeral_stop(State2) of
        stop -> {stop, normal, State2};
        continue -> {noreply, State2}
    end;
handle_info({'DOWN', Mon, process, ConnPid, _Reason}, State) when is_pid(ConnPid) ->
    Monitors = maps:get(monitors, State, #{}),
    case maps:get(ConnPid, Monitors, undefined) of
        Mon ->
            State2 = forget_conn(ConnPid, State#{
                monitors => maps:remove(ConnPid, Monitors)
            }),
            Conns2 = maps:get(conns, State2, #{}),
            case maps:get(ephemeral, State, false) of
                true when map_size(Conns2) =:= 0 ->
                    {stop, normal, State2};
                _ ->
                    {noreply, State2}
            end;
        _ ->
            {noreply, State}
    end;
handle_info({stream_data, Wire}, State) when is_binary(Wire) ->
    case i2p_streaming:decode(Wire) of
        {ok, Pkt} ->
            DestHash = maps:get(dest_hash, State),
            SendId = i2p_streaming:send_id(Pkt),
            case catch i2p_sam_sup:stream_conn_lookup(DestHash, SendId) of
                {ok, ConnPid} ->
                    i2p_stream_conn:handle_packet(ConnPid, Wire);
                _ ->
                    ok
            end;
        _ ->
            ok
    end,
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    lists:foreach(
        fun(Conn) -> catch i2p_stream_conn:close(Conn) end,
        maps:keys(maps:get(conns, State, #{}))
    ),
    ok.

forward_to_owner(Conn, Msg, State) ->
    case maps:find(Conn, maps:get(conns, State, #{})) of
        {ok, Owner} ->
            Owner ! Msg,
            ok;
        error ->
            ok
    end.

forget_conn(Conn, State) ->
    State#{conns => maps:remove(Conn, maps:get(conns, State, #{}))}.

ephemeral_stop(#{ephemeral := true, conns := Conns} = _State) when map_size(Conns) =:= 0 ->
    stop;
ephemeral_stop(_) ->
    continue.

%% ---- helpers ----

in_len(Lengths) ->
    maps:get(in_len, Lengths, 3).

register_lengths(Lengths, _Self) when map_size(Lengths) =:= 0 ->
    ok;
register_lengths(Lengths, Self) ->
    InLen = maps:get(in_len, Lengths, 3),
    OutLen = maps:get(out_len, Lengths, 3),
    catch i2p_tunnel_srv:set_lengths(Self, InLen, OutLen),
    ok.

do_stream_connect(Target, Owner, State) ->
    case resolve_target(Target) of
        {error, Reason} ->
            {{error, Reason}, State};
        {ok, _TargetB64, TargetBin, TargetHash} ->
            case i2p_client:route_to_dest(TargetBin) of
                error ->
                    {{error, no_route}, State};
                {ok, Route} ->
                    ConnOpts = #{
                        role => connect,
                        owner => self(),
                        send_fn => fun(Wire) -> i2p_client:send_wire(Route, Wire) end,
                        local_seed => maps:get(sign_priv, State),
                        local_dest_bin => maps:get(dest_bin, State),
                        local_dest_hash => maps:get(dest_hash, State),
                        remote_dest_bin => TargetBin,
                        remote_dest_hash => TargetHash
                    },
                    Result =
                        case whereis(i2p_sam_sup) of
                            undefined -> i2p_stream_conn:start_link(ConnOpts);
                            _ -> i2p_sam_sup:start_stream_conn(ConnOpts)
                        end,
                    case Result of
                        {ok, ConnPid} ->
                            Conns = maps:get(conns, State, #{}),
                            Mon = erlang:monitor(process, ConnPid),
                            Monitors = maps:get(monitors, State, #{}),
                            {{ok, ConnPid}, State#{
                                conns => Conns#{ConnPid => Owner},
                                monitors => Monitors#{ConnPid => Mon}
                            }};
                        {error, Reason} ->
                            {{error, Reason}, State}
                    end
            end
    end.

resolve_target(Target) when is_binary(Target) ->
    case i2p_keys:from_b64(Target) of
        {ok, Identity} ->
            {ok, Target, i2p_keys:to_binary(Identity), i2p_keys:hash(Identity)};
        {error, _} ->
            %% hostname / .b32: try address book, then naming
            case i2p_addressbook:resolve(Target) of
                {ok, DestB64} ->
                    case i2p_keys:from_b64(DestB64) of
                        {ok, Id} ->
                            {ok, DestB64, i2p_keys:to_binary(Id), i2p_keys:hash(Id)};
                        {error, _} ->
                            {error, bad_destination}
                    end;
                {error, _} ->
                    {error, not_found}
            end
    end;
resolve_target(Target) when is_list(Target) ->
    resolve_target(list_to_binary(Target));
resolve_target(Target) when is_map(Target) ->
    {error, bad_target}.
