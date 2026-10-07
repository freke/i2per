-module(i2p_sam_session).

-moduledoc """
SAM v3 session process: one per TCP connection, owns the socket and drives
the SAM line protocol until `STREAM CONNECT` or `STREAM ACCEPT`, after
which the socket switches to raw data mode. DATAGRAM and RAW sessions stay
in line mode for their whole life: `DATAGRAM SEND` / `RAW SEND` commands
read a fixed-size payload off the socket, and inbound traffic surfaces as
`DATAGRAM RECEIVED` / `RAW RECEIVED` announcements followed by the payload
bytes.

`STREAM FORWARD` binds a local host:port service to the session's
destination and keeps the control socket in line mode: every inbound peer
stream is answered by an accept-role `m:i2p_stream_conn` whose payload is
piped to a fresh local TCP connection, one relay per peer stream.

The session is a `temporary` child of `m:i2p_sam_sup`. When the socket
closes — or a protocol violation is detected — the process exits and the
supervisor cleans up. No other process can be affected.

Two concerns are extracted into helper modules over the same state map:
`m:i2p_sam_parse` holds the pure line-protocol text parsers (commands,
options, `.b32.i2p` addresses), and `m:i2p_sam_forward` owns the STREAM
FORWARD relay table — while live relays exist every `handle_info` message is
offered there first, falling through here when unhandled.

## Usage

Sessions are spawned by `m:i2p_sam_listener` and are not started directly.
""".

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-export_type([session_id/0, tunnel_lengths/0, style/0, send_kind/0, state/0]).

%% DATAGRAM/RAW SEND payload cap. SAM allows raw payloads up to 32768 bytes
%% and repliable ones up to 31744 including from+signature; anything larger
%% cannot fit the tunnel budget anyway and is treated as a protocol
%% violation rather than buffered.
-define(MAX_DATAGRAM, 32768).

%% Tunnel-length bounds for SESSION CREATE options: values are clamped into
%% 1..3 hops, matching the router's practical tunnel budget (?NUM_HOPS in
%% m:i2p_tunnel_srv).
-define(MAX_HOPS, 3).

-doc "A SAM session identifier (the ID= value from SESSION CREATE).".
-type session_id() :: binary().

-doc "Session state phases.".
-type phase() :: hello | established | raw.

-doc "Session client form — the STYLE= of SESSION CREATE.".
-type style() :: stream | datagram | raw.

-doc "Datagram kind carried by a DATAGRAM/RAW SEND command.".
-type send_kind() :: repliable | raw.

-doc """
Tunnel-length options parsed from SESSION CREATE (`inbound.length` /
`outbound.length`, clamped to 1..3 hops). Only explicitly given keys appear.
""".
-type tunnel_lengths() :: #{in_len => 1..?MAX_HOPS, out_len => 1..?MAX_HOPS}.

-doc "Pending fixed-size payload read of a DATAGRAM/RAW SEND command.".
-type read_state() :: #{
    kind := send_kind(),
    dest_b64 := binary(),
    need := non_neg_integer(),
    acc := binary()
}.

-doc "Local service bound by STREAM FORWARD.".
-type forward_target() :: #{host := string(), port := inet:port_number()}.

-doc """
One FORWARD relay: the streaming connection's monitor plus the local socket
dialled once the handshake completed (`sock` is `undefined` while dialling).
""".
-type fwd_relay() :: #{
    mon := reference(),
    sock => gen_tcp:socket() | undefined
}.

-doc "Internal session state.".
-type state() :: #{
    sock := gen_tcp:socket(),
    phase := phase(),
    local := i2p_peer:local_keys(),
    session_id => session_id(),
    style => style(),
    dest => i2p_keys:identity(),
    dest_b64 => binary(),
    dest_hash => i2p_crypto:hash(),
    tunnel_opts => tunnel_lengths(),
    crypto_priv => binary(),
    sign_priv => binary(),
    read => read_state() | undefined,
    paired_pid => pid() | undefined,
    route => i2p_client:route(),
    buf => binary(),
    conn => pid() | undefined,
    conn_mon => reference() | undefined,
    conn_myid => 0..16#FFFFFFFF | undefined,
    connecting => boolean(),
    pending_connect_b64 => binary() | undefined,
    forward => forward_target() | undefined,
    fwd_relays => #{pid() => fwd_relay()}
}.

-doc "Start a SAM session process.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(#{sock := Sock, local := Local}) ->
    gen_server:start_link(?MODULE, #{sock => Sock, local => Local}, []).

%%%%%%% %%% gen_server callbacks %%%%%%%

init(#{sock := Sock, local := Local}) ->
    %% Set active-once to receive data; we buffer in handle_info
    %% but don't start reading until the socket_ready message
    {ok, #{
        sock => Sock,
        phase => hello,
        local => Local,
        buf => <<>>,
        read => undefined
    }}.

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

%% terminate/2 — announce session end on the bus; pre-SESSION CREATE
%% sockets (hello phase) have no session_id and announce nothing.
terminate(_Reason, #{session_id := Id}) ->
    i2p_events:notify({sam_session_closed, Id}),
    ok;
terminate(_Reason, _State) ->
    ok.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({socket_ready, Sock}, #{sock := Sock} = State) ->
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply, State};
%%%%%% %%%% FORWARD relays %%%%%%
%%
%% A FORWARD session stays in line mode forever. While live relays exist,
%% every message is offered to m:i2p_sam_forward first; anything it does not
%% own falls through to the ordinary single-stream handling below.
handle_info(Msg, #{fwd_relays := Relays} = State) when map_size(Relays) > 0 ->
    case i2p_sam_forward:info(Msg, State) of
        unhandled -> handle_control_info(Msg, State);
        Reply -> Reply
    end;
handle_info(Msg, State) ->
    handle_control_info(Msg, State).

%% handle_control_info/2 — everything that is not a FORWARD relay event:
%% socket driving, line/raw phases, the session's single stream, datagram
%% delivery, and monitor deaths.
-spec handle_control_info(term(), state()) ->
    {noreply, state()} | {stop, normal | shutdown, state()}.
handle_control_info(
    {tcp, Sock, Data}, #{sock := Sock, phase := raw, paired_pid := Peer} = State
) when
    is_pid(Peer)
->
    Peer ! {data, Data},
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply, State};
handle_control_info({tcp, Sock, Data}, #{sock := Sock, phase := raw, conn := Conn} = State) when
    is_pid(Conn)
->
    %% Network path: hand the bytes to the streaming connection; it chunks
    %% them into packets and its send_fn injects each into our outbound
    %% tunnel. While the handshake is still in flight the conn buffers.
    i2p_stream_conn:send(Conn, Data),
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply, State};
handle_control_info({tcp, Sock, _Data}, #{sock := Sock, phase := raw} = State) ->
    %% Raw mode but no peer — discard
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply, State};
handle_control_info({tcp, Sock, Data}, #{sock := Sock} = State0) ->
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply, consume(State0, Data)};
handle_control_info({data, Data}, #{sock := Sock} = State) ->
    ok = gen_tcp:send(Sock, Data),
    {noreply, State};
handle_control_info({tcp_closed, _Sock}, State) ->
    {stop, normal, State};
handle_control_info({tcp_error, _Sock, _Reason}, State) ->
    {stop, normal, State};
handle_control_info({stream_pair, PeerPid}, #{sock := Sock} = State) ->
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply, State#{phase => raw, paired_pid => PeerPid}};
handle_control_info({stream_started, Conn, MyId}, #{conn := Conn} = State) ->
    %% The conn announces its stream ID — the demux key for inbound packets.
    i2p_sam_sup:stream_conn_register(maps:get(dest_hash, State), MyId, Conn),
    {noreply, State#{conn_myid => MyId}};
handle_control_info(
    {stream_established, Conn, _PeerHash}, #{conn := Conn, connecting := true} = State
) ->
    %% CONNECT-side handshake completed: release the client socket.
    send_line(State, <<"STREAM STATUS RESULT=OK">>),
    {noreply, State#{
        connecting => false,
        pending_connect_b64 => undefined
    }};
handle_control_info({stream_established, Conn, _PeerHash}, #{conn := Conn} = State) ->
    %% Inbound (ACCEPT-side) connection: the socket has been raw
    %% since STREAM ACCEPT; nothing further to signal.
    {noreply, State};
handle_control_info({stream_data, Conn, Bytes}, #{sock := Sock, conn := Conn} = State) when
    is_pid(Conn)
->
    %% Ordered payload bytes from our streaming connection.
    ok = gen_tcp:send(Sock, Bytes),
    {noreply, State};
handle_control_info({stream_data, Wire}, #{style := datagram} = State) when is_binary(Wire) ->
    %% Garlic opened under this DATAGRAM session's key: one repliable
    %% datagram.
    {noreply, deliver_datagram(Wire, State)};
handle_control_info({stream_data, Wire}, #{style := raw} = State) when is_binary(Wire) ->
    %% Garlic opened under this RAW session's key: one anonymous datagram.
    {noreply, deliver_raw(Wire, State)};
handle_control_info({stream_data, WireBin}, #{} = State) when is_binary(WireBin) ->
    %% End-to-end garlic that opened under this session's key carries one
    %% streaming packet; route it to its connection by demux key.
    {noreply, dispatch_stream_packet(WireBin, State)};
handle_control_info({stream_closed, _Conn}, State) ->
    {stop, normal, State};
handle_control_info({stream_reset, _Conn}, State) ->
    {stop, normal, State};
handle_control_info(
    {'DOWN', Mon, process, _Pid, _Reason},
    #{
        conn_mon := Mon,
        connecting := true
    } = State
) ->
    B64 = maps:get(pending_connect_b64, State, <<>>),
    send_line(State, [
        <<"STREAM STATUS RESULT=CANT_REACH DESTINATION=">>,
        B64
    ]),
    {noreply, cleared_conn(State#{connecting => false})};
handle_control_info({'DOWN', Mon, process, _Pid, Reason}, #{conn_mon := Mon} = _State) ->
    exit({stream_conn_died, Reason});
handle_control_info({'DOWN', _Mon, process, _Pid, _Reason}, State) ->
    {noreply, State}.

%%%%%%% %%% Line protocol %%%%%%%

-spec handle_line(binary(), state()) -> state().
handle_line(Line, #{phase := hello} = State) ->
    handle_hello(Line, State);
handle_line(Line, #{phase := established} = State) ->
    handle_command(Line, State).

-spec handle_hello(binary(), state()) -> state().
handle_hello(Line, State) ->
    case i2p_sam_parse:parse_hello(Line) of
        ok ->
            send_line(State, <<"HELLO REPLY RESULT=OK VERSION=3.1">>),
            State#{phase => established};
        {error, _Reason} ->
            send_line(State, <<"HELLO REPLY RESULT=I2P_ERROR MESSAGE=\"bad hello\"">>),
            exit({protocol_error, bad_hello})
    end.

-spec handle_command(binary(), state()) -> state().
handle_command(Line, State) ->
    case i2p_sam_parse:parse_command(Line) of
        {dest_generate, SigType} ->
            handle_dest_generate(SigType, State);
        {session_create, Style, Id, DestBlob64, LengthOpts} ->
            handle_session_create(Style, Id, DestBlob64, LengthOpts, State);
        {stream_connect, Id, DestB64} ->
            handle_stream_connect(Id, DestB64, State);
        {stream_accept, Id} ->
            handle_stream_accept(Id, State);
        {stream_forward, Id, Host, PortBin} ->
            handle_stream_forward(Id, Host, PortBin, State);
        {datagram_send, Kind, DestB64, SizeBin} ->
            handle_datagram_send(Kind, DestB64, SizeBin, State);
        {naming_lookup, Name} ->
            handle_naming_lookup(Name, State);
        {error, _Reason} ->
            send_line(State, <<"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"unknown command\"">>),
            State
    end.

-spec handle_dest_generate(non_neg_integer(), state()) -> state().
handle_dest_generate(SigType, State) when SigType =:= 7 ->
    #{identity := Id, crypto_priv := CPriv, sign_priv := SPriv} =
        i2p_keys:generate_with_privkeys(),
    Blob = i2p_keys:dest_blob(#{identity => Id, crypto_priv => CPriv, sign_priv => SPriv}),
    B64 = i2p_keys:encode_b64(Blob),
    send_line(State, B64),
    State;
handle_dest_generate(_SigType, State) ->
    send_line(State, <<"HELLO REPLY RESULT=I2P_ERROR MESSAGE=\"unsupported signature type\"">>),
    exit({protocol_error, unsupported_sig_type}).

-spec handle_session_create(
    stream | datagram | raw,
    session_id(),
    binary() | undefined,
    tunnel_lengths() | {error, bad_length},
    state()
) -> state().
handle_session_create(_Style, _Id, _DestBlob64, {error, bad_length}, State) ->
    send_line(State, <<"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"bad length option\"">>),
    exit({protocol_error, bad_tunnel_length});
handle_session_create(Style, Id, DestBlob64, Lengths, State) ->
    case resolve_destination(DestBlob64, State) of
        {ok, DestMap} ->
            #{identity := Dest, crypto_priv := CPriv, sign_priv := SPriv} = DestMap,
            DestHash = i2p_keys:hash(Dest),
            DestB64 = i2p_keys:to_b64(Dest),
            i2p_sam_sup:session_register(Id, self(), DestHash, Style, CPriv),
            %% Every session form needs a LeaseSet2 so remote peers can find
            %% the destination's inbound tunnels; the router retries until
            %% one exists. A demanded inbound length steers which tunnel the
            %% lease names.
            i2p_tunnel_srv:publish_lease_set(Dest, SPriv, in_len(Lengths)),
            register_lengths(Lengths),
            send_line(State, <<"SESSION STATUS RESULT=OK DESTINATION=", DestB64/binary>>),
            i2p_events:notify({sam_session_created, Id, Style}),
            State#{
                session_id => Id,
                style => Style,
                dest => Dest,
                dest_b64 => DestB64,
                dest_hash => DestHash,
                tunnel_opts => Lengths,
                crypto_priv => CPriv,
                sign_priv => SPriv
            };
        {error, _} ->
            send_line(State, <<"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"bad destination\"">>),
            exit({protocol_error, bad_destination})
    end.

%% register_lengths/1 — hand non-default length demands to the tunnel
%% manager so its pool tick builds matching tunnels while this session
%% lives. Absent options mean "no opinion" and register nothing.
-spec register_lengths(tunnel_lengths()) -> ok.
register_lengths(Lengths) when map_size(Lengths) =:= 0 ->
    ok;
register_lengths(Lengths) ->
    InLen = maps:get(in_len, Lengths, ?MAX_HOPS),
    OutLen = maps:get(out_len, Lengths, ?MAX_HOPS),
    ok = i2p_tunnel_srv:set_lengths(self(), InLen, OutLen).

%% in_len/1 — a session's demanded inbound hop count for lease publication.
-spec in_len(tunnel_lengths()) -> 1..?MAX_HOPS.
in_len(Lengths) ->
    maps:get(in_len, Lengths, ?MAX_HOPS).

-spec handle_stream_connect(session_id(), binary(), state()) -> state().
handle_stream_connect(Id, TargetB64, #{session_id := Id} = State) ->
    case decode_dest_b64(TargetB64) of
        {error, _} ->
            %% Not base64: a hostname from the address book?
            case i2p_addressbook:resolve(TargetB64) of
                {ok, DestB64} -> handle_stream_connect(Id, DestB64, State);
                {error, not_found} -> cant_reach(TargetB64, State)
            end;
        {ok, TargetHash} ->
            case i2p_sam_sup:listener_lookup(TargetHash) of
                {ok, AcceptPid} ->
                    i2p_sam_sup:listener_unregister(TargetHash),
                    send_line(State, <<"STREAM STATUS RESULT=OK">>),
                    AcceptPid ! {stream_pair, self()},
                    State#{phase => raw, paired_pid => AcceptPid};
                not_found ->
                    connect_network(TargetB64, TargetHash, State)
            end
    end;
handle_stream_connect(_Id, _DestB64, State) ->
    send_line(State, <<"STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"session id mismatch\"">>),
    State.

%% connect_network/3 — no local listener for the target: route the stream
%% through tunnels. Resolve the destination's LeaseSet2 from the NetDb,
%% pick its freshest lease plus one of our outbound tunnels, and start a
%% streaming connection whose SYN/SYN-ACK handshake must complete before
%% the client sees STREAM STATUS RESULT=OK.
-spec connect_network(binary(), i2p_crypto:hash(), state()) -> state().
connect_network(TargetB64, TargetHash, State) ->
    case resolve_route(TargetB64, TargetHash) of
        {ok, Route} ->
            ConnOpts = #{
                role => connect,
                owner => self(),
                send_fn => fun(WireBin) -> stream_send(Route, WireBin) end,
                local_seed => maps:get(sign_priv, State),
                local_dest_bin => i2p_keys:to_binary(maps:get(dest, State)),
                local_dest_hash => maps:get(dest_hash, State),
                remote_dest_bin => maps:get(dest_bin, Route),
                remote_dest_hash => maps:get(dest_hash, Route)
            },
            case i2p_sam_sup:start_stream_conn(ConnOpts) of
                {ok, ConnPid} ->
                    Mon = erlang:monitor(process, ConnPid),
                    State#{
                        phase => raw,
                        route => Route,
                        conn => ConnPid,
                        conn_mon => Mon,
                        conn_myid => undefined,
                        connecting => true,
                        pending_connect_b64 => TargetB64
                    };
                {error, _Reason} ->
                    %% **Including a refusal at `max_stream_connections`, and the
                    %% client is told `CANT_REACH`** rather than nothing. A client
                    %% that opened one session is not thereby entitled to an
                    %% unbounded number of streams through it, and a silent drop
                    %% here would leave it waiting on a `STREAM STATUS` line that
                    %% never comes -- the same shape as a route that cannot be
                    %% resolved, which is what `CANT_REACH` already means to it.
                    cant_reach(TargetB64, State)
            end;
        error ->
            cant_reach(TargetB64, State)
    end.

cant_reach(B64, State) ->
    send_line(State, [
        <<"STREAM STATUS RESULT=CANT_REACH DESTINATION=">>,
        B64
    ]),
    State#{connecting => false, pending_connect_b64 => undefined}.

cleared_conn(State) ->
    State#{conn => undefined, conn_mon => undefined, conn_myid => undefined}.

%% dispatch_stream_packet/2 — a garlic payload opened under this
%% destination carried one streaming packet. Hand it to its connection by
%% demux key; SYNs for unregistered streams are accepted by the session owner.
-spec dispatch_stream_packet(binary(), state()) -> state().
dispatch_stream_packet(WireBin, State) ->
    case i2p_streaming:decode(WireBin) of
        {ok, Pkt} ->
            DestHash = maps:get(dest_hash, State),
            SendId = i2p_streaming:send_id(Pkt),
            case i2p_sam_sup:stream_conn_lookup(DestHash, SendId) of
                {ok, ConnPid} ->
                    i2p_stream_conn:handle_packet(ConnPid, WireBin),
                    State;
                not_found when SendId =:= 0 ->
                    maybe_accept_syn(Pkt, State);
                not_found ->
                    %% Unknown stream and not a SYN: late packet for a
                    %% closed connection — drop.
                    State
            end;
        {error, _Reason} ->
            %% Garlic that opens under our key is ours, but only streaming
            %% packets are valid session data; anything undecodable is noise.
            State
    end.

%% maybe_accept_syn/2 — an inbound SYN for a destination with a pending
%% STREAM ACCEPT: pre-filter it (replay hash binds it to this destination),
%% resolve a return route to the peer's freshest lease, and start an
%% accept-role streaming connection that answers the handshake. Anything
%% unverifiable or unroutable is silently dropped.
-spec maybe_accept_syn(i2p_streaming:packet(), state()) -> state().
maybe_accept_syn(Pkt, State) ->
    case accept_precheck(Pkt, State) of
        ok -> route_and_accept(Pkt, State);
        drop -> State
    end.

%% route_and_accept/2 — pin a return route to the SYN sender's freshest
%% lease before spawning anything; unroutable SYNs are dropped silently.
-spec route_and_accept(i2p_streaming:packet(), state()) -> state().
route_and_accept(Pkt, State) ->
    FromBin = i2p_streaming:from(Pkt),
    case peer_route_from_destination(FromBin) of
        {ok, Route} -> start_accept_conn(Route, Pkt, State);
        error -> State
    end.

%% start_accept_conn/3 — spawn an accept-role streaming connection that
%% answers the handshake; spawn failure drops the SYN silently.
%%
%% **A refusal at `max_stream_connections` is a spawn failure here**, and dropping
%% the SYN is the right answer to it: the sender is a remote peer, no client is
%% waiting on a SAM reply for an unsolicited inbound SYN, and the sender retries.
%% Which is also the whole reason the accept path and the connect path below can
%% treat the same `{error, stream_limit}` differently.
-spec start_accept_conn(i2p_client:route(), i2p_streaming:packet(), state()) -> state().
start_accept_conn(Route, Pkt, State) ->
    ConnOpts = #{
        role => accept,
        syn => Pkt,
        owner => self(),
        send_fn => fun(Wire) -> stream_send(Route, Wire) end,
        local_seed => maps:get(sign_priv, State),
        local_dest_bin =>
            i2p_keys:to_binary(maps:get(dest, State)),
        local_dest_hash => maps:get(dest_hash, State)
    },
    case i2p_sam_sup:start_stream_conn(ConnOpts) of
        {ok, ConnPid} ->
            Mon = erlang:monitor(process, ConnPid),
            accept_spawned(ConnPid, Mon, State);
        {error, _Reason} ->
            State
    end.

%% accept_spawned/3 — wire up a just-spawned accept-role connection: a
%% FORWARD session tracks it as a relay awaiting its local dial, while a
%% STREAM ACCEPT session hands the raw socket over to this one stream.
-spec accept_spawned(pid(), reference(), state()) -> state().
accept_spawned(ConnPid, Mon, #{forward := Forward} = State) when Forward =/= undefined ->
    i2p_sam_forward:add_relay(ConnPid, Mon, State);
accept_spawned(ConnPid, Mon, State) ->
    %% The socket now owns this one stream (STREAM ACCEPT).
    i2p_sam_sup:listener_unregister(maps:get(dest_hash, State)),
    State#{
        conn => ConnPid,
        conn_mon => Mon,
        conn_myid => undefined,
        connecting => false,
        pending_connect_b64 => undefined
    }.

%% accept_precheck/2 — cheap SYN gating before any process is spawned.
%% Accepts a destination with either a pending STREAM ACCEPT listener or a
%% STREAM FORWARD binding.
-spec accept_precheck(i2p_streaming:packet(), state()) -> ok | drop.
accept_precheck(Pkt, State) ->
    SynBit = i2p_streaming:flag_synchronize(),
    HasSyn = i2p_streaming:has_flag(Pkt, SynBit),
    HashOk =
        i2p_streaming:replay_hash(Pkt) =:=
            {ok, maps:get(dest_hash, State)},
    Bound =
        case i2p_sam_sup:listener_lookup(maps:get(dest_hash, State)) of
            {ok, _ListenerPid} ->
                true;
            not_found ->
                case i2p_sam_sup:forward_lookup(maps:get(dest_hash, State)) of
                    {ok, _Target} -> true;
                    not_found -> false
                end
        end,
    case HasSyn andalso HashOk of
        false ->
            drop;
        true ->
            case Bound of
                true -> ok;
                false -> drop
            end
    end.

%% peer_route_from_destination/1 — parse the FROM destination and pin a
%% return route to its freshest lease.
-spec peer_route_from_destination(binary() | undefined) ->
    {ok, i2p_client:route()} | error.
peer_route_from_destination(undefined) ->
    error;
peer_route_from_destination(FromBin) ->
    i2p_client:route_to_dest(FromBin).

%% resolve_route/2 — LeaseSet + outbound tunnel lookup for the network path.
-spec resolve_route(binary(), i2p_crypto:hash()) ->
    {ok, i2p_client:route()} | error.
resolve_route(TargetB64, _TargetHash) ->
    case target_identity(TargetB64) of
        {ok, #{bin := DestBin}} -> i2p_client:route_to_dest(DestBin);
        error -> error
    end.

%% target_identity/1 — parse the ECIES public key out of a base64
%% destination blob (identity prefix, private keys absent) and return the
%% 391-byte destination binary the FROM option needs.
-spec target_identity(binary()) ->
    {ok, #{pub := i2p_crypto:x25519_public_key(), bin := binary()}} | error.
target_identity(B64) ->
    try i2p_keys:decode_b64(B64) of
        <<IdentityBin:391/binary, _/binary>> ->
            case i2p_keys:parse(IdentityBin) of
                {ok, Id} ->
                    {ok, #{pub => i2p_keys:public_key(Id), bin => IdentityBin}};
                {error, _} ->
                    error
            end;
        _ ->
            error
    catch
        error:_ -> error
    end.

-spec handle_stream_accept(session_id(), state()) -> state().
handle_stream_accept(Id, #{session_id := Id, dest_hash := DestHash} = State) ->
    i2p_sam_sup:listener_register(DestHash, self()),
    send_line(State, i2p_keys:to_b64(maps:get(dest, State))),
    %% Wait for stream_pair message from the CONNECT side
    State#{phase => raw};
handle_stream_accept(_Id, State) ->
    send_line(State, <<"STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"session id mismatch\"">>),
    State.

%% handle_stream_forward/4 — bind a local service to this destination
%% (SAM v3 STREAM FORWARD): every inbound peer stream is relayed to a fresh
%% TCP connection at Host:Port. Unlike ACCEPT the control socket stays in
%% line mode and any number of concurrent streams may be relayed; the
%% binding lives until the session dies.
-spec handle_stream_forward(session_id(), binary() | undefined, binary(), state()) ->
    state().
handle_stream_forward(Id, HostBin, PortBin, #{session_id := Id, dest_hash := DestHash} = State) ->
    case i2p_sam_parse:parse_port(PortBin) of
        {ok, Port} ->
            Host = i2p_sam_parse:host_string(HostBin),
            i2p_sam_sup:forward_register(DestHash, Host, Port),
            send_line(State, <<"STREAM STATUS RESULT=OK">>),
            State#{forward => #{host => Host, port => Port}};
        error ->
            send_line(State, <<"STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"bad port\"">>),
            exit({protocol_error, bad_forward_port})
    end;
handle_stream_forward(_Id, _HostBin, _PortBin, State) ->
    send_line(State, <<"STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"session id mismatch\"">>),
    State.

%% handle_datagram_send/4 — the command half of DATAGRAM/RAW SEND: validate
%% parameters and arm a fixed-size payload read. The bytes following the
%% newline are consumed by `f:payload_step/2` until `need` is satisfied, then
%% `f:finish_send/4` routes the datagram. A malformed SIZE is a protocol
%% violation (the byte stream can no longer be framed), so the process dies.
-spec handle_datagram_send(send_kind(), binary(), binary(), state()) -> state().
handle_datagram_send(Kind, DestB64, SizeBin, State) ->
    case maps:get(style, State, undefined) of
        Style when Style =:= datagram orelse Style =:= raw ->
            Size = binary_to_integer(SizeBin),
            case Size >= 1 andalso Size =< ?MAX_DATAGRAM of
                true ->
                    State#{read => #{kind => Kind, dest_b64 => DestB64, need => Size, acc => <<>>}};
                false ->
                    exit({protocol_error, bad_datagram_size})
            end;
        _Other ->
            exit({protocol_error, datagram_send_without_datagram_session})
    end.

-spec handle_naming_lookup(binary(), state()) -> state().
handle_naming_lookup(Name, State) ->
    case resolve_name(Name) of
        {ok, DestB64} ->
            send_line(State, [
                <<"NAMING REPLY RESULT=OK NAME=">>,
                Name,
                <<" VALUE=">>,
                DestB64
            ]),
            State;
        {error, _} ->
            send_line(State, [
                <<"NAMING REPLY RESULT=CANT_FIND NAME=">>, Name
            ]),
            State
    end.

%%%%%%% %%% Internal %%%%%%%

%% consume/2 — feed socket bytes through the session's read state machine:
%% an armed payload read (`read`) consumes fixed-size SEND payload bytes,
%% otherwise data is split into lines. Leftover bytes after a completed
%% read flow back through this dispatcher.
-spec consume(state(), binary()) -> state().
consume(State, <<>>) ->
    State;
consume(#{phase := raw} = State, _Data) ->
    %% In raw mode, leftover data is noise — ignore
    State;
consume(#{read := Read} = State, Data) when Read =/= undefined ->
    payload_step(State, Data);
consume(#{buf := Buf} = State, Data) ->
    All = <<Buf/binary, Data/binary>>,
    case binary:split(All, <<"\n">>) of
        [_] ->
            State#{buf => All};
        [<<>>, Rest] ->
            consume(State#{buf => <<>>}, Rest);
        [Line, Rest] ->
            consume(handle_line(Line, State#{buf => <<>>}), Rest)
    end.

%% payload_step/2 — accumulate exactly `need` payload bytes for an armed
%% DATAGRAM/RAW SEND, then hand the completed datagram to `f:finish_send/4`
%% and resume line framing with whatever followed the payload.
-spec payload_step(state(), binary()) -> state().
payload_step(#{read := Read} = State, Data) ->
    Need = maps:get(need, Read),
    Take = min(Need, byte_size(Data)),
    <<Chunk:Take/binary, Rest/binary>> = Data,
    Acc = <<(maps:get(acc, Read))/binary, Chunk/binary>>,
    case Need - Take of
        0 ->
            State1 =
                finish_send(
                    maps:get(kind, Read),
                    maps:get(dest_b64, Read),
                    Acc,
                    State#{read => undefined}
                ),
            consume(State1, Rest);
        More ->
            State#{read => Read#{need => More, acc => Acc}}
    end.

%% finish_send/4 — route one client-supplied datagram: resolve the target,
%% wrap (repliable adds our destination + Ed25519 signature; raw is bare),
%% and inject via the shared tunnel transport. Fire-and-forget: there is no
%% STATUS reply, and an unroutable target drops silently.
-spec finish_send(send_kind(), binary(), binary(), state()) -> state().
finish_send(Kind, DestB64, Payload, State) ->
    case resolve_send_target(DestB64) of
        {ok, Route} ->
            i2p_client:send_wire(Route, datagram_wire(Kind, Payload, State)),
            State;
        error ->
            State
    end.

%% datagram_wire/3 — build the garlic Data-clove payload for one send.
-spec datagram_wire(send_kind(), binary(), state()) -> binary().
datagram_wire(repliable, Payload, State) ->
    {ok, Wire} =
        i2p_datagram:encode(
            i2p_keys:to_binary(maps:get(dest, State)),
            maps:get(sign_priv, State),
            Payload
        ),
    Wire;
datagram_wire(raw, Payload, _State) ->
    Payload.

%% resolve_send_target/1 — a base64 destination (or address-book name)
%% resolved to a lease route like STREAM CONNECT.
-spec resolve_send_target(binary()) -> {ok, i2p_client:route()} | error.
resolve_send_target(TargetB64) ->
    case target_identity(TargetB64) of
        {ok, #{bin := DestBin}} -> i2p_client:route_to_dest(DestBin);
        error -> resolve_book_target(TargetB64)
    end.

%% resolve_book_target/1 — the base64 parse failed: retry through the
%% address book (hosts.txt names from subscriptions).
-spec resolve_book_target(binary()) -> {ok, i2p_client:route()} | error.
resolve_book_target(TargetB64) ->
    case i2p_addressbook:resolve(TargetB64) of
        {ok, DestB64} -> resolve_direct_target(DestB64);
        {error, _} -> error
    end.

%% resolve_direct_target/1 — route to a plain base64 destination blob.
-spec resolve_direct_target(binary()) -> {ok, i2p_client:route()} | error.
resolve_direct_target(DestB64) ->
    case target_identity(DestB64) of
        {ok, #{bin := Bin}} -> i2p_client:route_to_dest(Bin);
        error -> error
    end.

%% deliver_datagram/2 — announce an authenticated inbound repliable
%% datagram on the control socket (sender destination + size line, then the
%% bare payload). Unauthenticated or malformed frames are dropped per the
%% datagram spec.
-spec deliver_datagram(binary(), state()) -> state().
deliver_datagram(Wire, State) ->
    case i2p_datagram:decode(Wire) of
        {ok, #{from := FromBin, payload := Payload}} ->
            send_line(State, [
                <<"DATAGRAM RECEIVED DESTINATION=">>,
                i2p_keys:encode_b64(FromBin),
                <<" SIZE=">>,
                integer_to_binary(byte_size(Payload))
            ]),
            ok = gen_tcp:send(maps:get(sock, State), Payload),
            State;
        error ->
            State
    end.

%% deliver_raw/2 — announce an inbound anonymous datagram on the control
%% socket: size line then the bare payload.
-spec deliver_raw(binary(), state()) -> state().
deliver_raw(Payload, State) ->
    send_line(State, [
        <<"RAW RECEIVED SIZE=">>,
        integer_to_binary(byte_size(Payload))
    ]),
    ok = gen_tcp:send(maps:get(sock, State), Payload),
    State.

%% stream_send/2 — the streaming connection's transport (see
%% `f:i2p_client:send_wire/2`).
-spec stream_send(i2p_client:route(), binary()) -> ok.
stream_send(Route, Data) ->
    i2p_client:send_wire(Route, Data).

-spec send_line(state(), iodata()) -> ok.
send_line(#{sock := Sock}, Line) ->
    gen_tcp:send(Sock, [Line, <<"\n">>]).

-spec resolve_destination(binary() | undefined, state()) ->
    {ok, #{identity := i2p_keys:identity(), crypto_priv := binary(), sign_priv := binary()}}
    | {error, term()}.
resolve_destination(undefined, _State) ->
    %% No DESTINATION provided — generate a transient identity
    {ok, i2p_keys:generate_with_privkeys()};
resolve_destination(DestB64, _State) ->
    i2p_keys:parse_dest_blob(i2p_keys:decode_b64(DestB64)).

-spec decode_dest_b64(binary()) -> {ok, i2p_crypto:hash()} | {error, term()}.
decode_dest_b64(B64) ->
    try i2p_keys:decode_b64(B64) of
        <<Identity:391/binary, _/binary>> ->
            {ok, crypto:hash(sha256, Identity)}
    catch
        error:_ -> {error, bad_dest_blob}
    end.

-spec resolve_name(binary()) -> {ok, binary()} | {error, not_found}.
resolve_name(Name) ->
    case i2p_sam_parse:parse_b32_address(Name) of
        {ok, DestHash} ->
            case i2p_netdb_srv:find_ls(DestHash) of
                {ok, LS} ->
                    Identity = i2p_leaset:identity(LS),
                    {ok, i2p_keys:to_b64(Identity)};
                not_found ->
                    {error, not_found}
            end;
        error ->
            resolve_host_name(Name)
    end.

%% resolve_host_name/1 - anything that is not a b32 address: a hosts.txt name
%% resolves through the address book, plain base64 passes through.
-spec resolve_host_name(binary()) -> {ok, binary()} | {error, not_found}.
resolve_host_name(Name) ->
    case decode_dest_b64(Name) of
        {ok, _DestHash} ->
            {ok, Name};
        {error, _} ->
            i2p_addressbook:resolve(Name)
    end.
