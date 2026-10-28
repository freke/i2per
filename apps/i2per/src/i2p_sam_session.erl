-module(i2p_sam_session).

-moduledoc """
SAM v3 connection process: one per accepted TCP socket, owning that socket
and driving the SAM line protocol on it.

## Two roles, one module

SAM v3 gives *each* I2P stream a client-to-SAM socket of its own, and the
role a process plays is decided by the first command it answers.

A **session socket** runs `SESSION CREATE` and keeps the line protocol for
its whole life: `NAMING LOOKUP`, `DATAGRAM SEND` / `RAW SEND`, and for
STREAM sessions `STREAM FORWARD` and `STREAM ACCEPT`. DATAGRAM and RAW
sessions stay in line mode; their inbound traffic surfaces as
`DATAGRAM RECEIVED` / `RAW RECEIVED` announcements followed by the payload
bytes. `STREAM ACCEPT` is the one command that takes the socket raw, because
it hands the whole control socket to a single inbound stream.

A **stream socket** is a fresh connection that carries `STREAM CONNECT` and
then becomes raw for that one stream. It owns no destination: it looks the
session up in `m:i2p_sam_sup`'s registry, asks that process to open the
stream, and receives the live connection back once the SYN has been answered
locally. From then on the stream's data events (`{stream_data, Conn, Bytes}`,
`{stream_established, Conn, PeerHash}`, `{stream_closed, Conn}`) arrive here
and are written straight to this socket, and client bytes go to the
connection. The session stays in line mode and is untouched by the stream's
fate, which is what lets one session carry several streams.

Because SAM requires it, a `STREAM CONNECT` on a socket that already ran
`SESSION CREATE` is refused exactly as i2pd refuses it — `SESSION STATUS
RESULT=I2P_ERROR MESSAGE="Socket already in use"` — and the socket is closed.

`STREAM FORWARD` binds a local host:port service to the session's
destination and keeps the control socket in line mode: every inbound peer
stream is answered by an accept-role `m:i2p_stream_conn` whose payload is
piped to a fresh local TCP connection, one relay per peer stream.

The process is a `temporary` child of `m:i2p_sam_sup`. When the socket
closes — or a protocol violation is detected — the process exits and the
supervisor cleans up. No other process can be affected.

Two concerns are extracted into helper modules over the same state map:
`m:i2p_sam_parse` holds the pure line-protocol text parsers (commands,
options, `.b32.i2p` addresses), and `m:i2p_sam_forward` owns the STREAM
FORWARD relay table — while live relays exist every `handle_info` message is
offered there first, falling through here when unhandled.

## Usage

Connections are spawned by `m:i2p_sam_listener` and are not started directly.
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
%% 1..7 hops, matching the router's maximum tunnel budget (?MAX_HOPS in
%% m:i2p_tunnel_srv).
-define(MAX_HOPS, 7).

%% The hop count an absent length option means. Not the maximum: a session that
%% asks only for `inbound.length=2` is stating no opinion about its outbound
%% side, and "no opinion" is the router's ordinary default build, which is 3
%% (m:i2p_tunnel_build). Feeding ?MAX_HOPS in for a side the caller never named
%% made every half-specified session demand a 7-hop pool for the other side.
-define(DEFAULT_HOPS, 3).

-doc "A SAM session identifier (the ID= value from SESSION CREATE).".
-type session_id() :: binary().

-doc "Session state phases.".
-type phase() :: hello | established | raw.

-doc "Session client form — the STYLE= of SESSION CREATE.".
-type style() :: stream | datagram | datagram2 | raw.

-doc "Datagram kind carried by a DATAGRAM/RAW SEND command.".
-type send_kind() :: repliable | raw | datagram2.

-doc """
Tunnel-length options parsed from SESSION CREATE (`inbound.length` /
`outbound.length`, clamped to 1..7 hops). Only explicitly given keys appear.
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
    sock => gen_tcp:socket(),
    send_fn => fun((iodata()) -> ok | {error, term()}),
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
    buf => binary(),
    conn => pid() | undefined,
    conn_mon => reference() | undefined,
    conn_myid => 0..16#FFFFFFFF | undefined,
    connecting => boolean(),
    pending_connect_b64 => binary() | undefined,
    pending_connect_ref => reference() | undefined,
    pending_session_mon => reference() | undefined,
    pending_stream_started => {pid(), 0..16#FFFFFFFF} | undefined,
    delegated => #{reference() => pid()},
    forward => forward_target() | undefined,
    fwd_relays => #{pid() => fwd_relay()},
    replay_window => term()
}.

-doc "Start a SAM session process.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(#{sock := Sock, local := Local} = Args) ->
    gen_server:start_link(?MODULE, Args#{sock => Sock, local => Local}, []);
start_link(#{local := Local} = Args) ->
    gen_server:start_link(?MODULE, Args#{local => Local}, []).

%%%%%%% %%% gen_server callbacks %%%%%%%

init(#{local := Local} = Args) ->
    Sock = maps:get(sock, Args, undefined),
    SendFn =
        case maps:get(send_fn, Args, undefined) of
            undefined when Sock =/= undefined ->
                fun(Data) -> gen_tcp:send(Sock, Data) end;
            undefined ->
                fun(_Data) -> ok end;
            Fn when is_function(Fn, 1) ->
                Fn
        end,
    %% Set active-once to receive data; we buffer in handle_info
    %% but don't start reading until the socket_ready message
    State0 = #{
        phase => hello,
        local => Local,
        buf => <<>>,
        read => undefined,
        replay_window => i2p_datagram_replay:new(1024),
        send_fn => SendFn
    },
    State1 =
        case Sock of
            undefined -> State0;
            _ -> State0#{sock => Sock}
        end,
    {ok, State1}.

handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

%% terminate/2 — announce session end on the bus, drop the registry row, and
%% take down what this process owns: a session owns the lifetime of every
%% stream it opened, and a socket owns the connection it was handed. Pre-
%% SESSION CREATE sockets (hello phase, and stream sockets) have no session_id
%% and announce nothing.
terminate(_Reason, #{session_id := Id} = State) ->
    i2p_events:notify({sam_session_closed, Id}),
    i2p_sam_sup:session_unregister(Id),
    close_conn(State),
    close_delegated(State),
    ok;
terminate(_Reason, State) ->
    close_conn(State),
    ok.

%% A connection the process still holds: the accept-role stream on a session
%% socket, or the connected stream on a stream socket.
close_conn(#{conn := Conn}) when is_pid(Conn) ->
    i2p_stream_conn:close(Conn);
close_conn(_State) ->
    ok.

close_delegated(#{delegated := Delegated}) ->
    lists:foreach(fun(Conn) -> i2p_stream_conn:close(Conn) end, maps:values(Delegated));
close_delegated(_State) ->
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
%% Socket-less (translator) path: inbound bytes pushed by the owner of the
%% socket, which is the thin-translator form of the listener (E1CHFWF).
handle_control_info({inbound, Data}, #{phase := raw, paired_pid := Peer} = State) when
    is_pid(Peer)
->
    Peer ! {data, Data},
    {noreply, State};
handle_control_info({inbound, Data}, #{phase := raw, conn := Conn} = State) when
    is_pid(Conn)
->
    i2p_stream_conn:send(Conn, Data),
    {noreply, State};
handle_control_info({inbound, Data}, State0) ->
    {noreply, consume(State0, Data)};
handle_control_info({data, Data}, #{send_fn := SendFn} = State) ->
    case SendFn(Data) of
        ok -> {noreply, State};
        {error, _} = Err -> {stop, normal, State#{last_error => Err}}
    end;
handle_control_info({tcp_closed, _Sock}, State) ->
    {stop, normal, State};
handle_control_info({tcp_error, _Sock, _Reason}, State) ->
    {stop, normal, State};
handle_control_info({stream_pair, PeerPid}, #{sock := Sock} = State) ->
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply, State#{phase => raw, paired_pid => PeerPid}};
%% A stream socket asked this session to open a stream for it — the two-socket
%% shape SAM v3 requires. The socket owns the result; this process only keeps
%% its lifetime.
handle_control_info({stream_connect, Ref, TargetB64, From}, State) when is_pid(From) ->
    {noreply, delegate_stream(Ref, TargetB64, From, State)};
%% The session answered a delegated connect. One message carries both the
%% verdict and the stream, so the status line is written before any relayed
%% byte can be: the client is entitled to read STREAM STATUS first.
handle_control_info(
    {sam_stream_connect_result, Ref, Result}, #{pending_connect_ref := Ref} = State
) ->
    erlang:demonitor(maps:get(pending_session_mon, State), [flush]),
    apply_connect_result(Result, State);
%% A connection announces its demux key as its very first act, which can beat
%% the session's hand-off message: hold it until the stream is ours.
handle_control_info(
    {stream_started, _Conn, _MyId} = Started, #{pending_connect_ref := Ref} = State
) when
    Ref =/= undefined
->
    {noreply, State#{pending_stream_started => Started}};
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
handle_control_info({stream_data, Conn, Bytes}, #{send_fn := SendFn, conn := Conn} = State) when
    is_pid(Conn)
->
    %% Ordered payload bytes from our streaming connection.
    case SendFn(Bytes) of
        ok -> {noreply, State};
        {error, _} -> {stop, normal, State}
    end;
handle_control_info({stream_data, Wire}, #{style := datagram} = State) when is_binary(Wire) ->
    %% Garlic opened under this DATAGRAM session's key: one repliable
    %% datagram.
    {noreply, deliver_datagram(Wire, State)};
handle_control_info({stream_data, Wire}, #{style := datagram2} = State) when is_binary(Wire) ->
    %% Garlic opened under this DATAGRAM2 session's key: one Datagram2.
    {noreply, deliver_datagram2(Wire, State)};
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
    Cleared = cleared_conn(State#{connecting => false}),
    %% A stream socket exists only to carry this one stream, so its failure is
    %% the end of the socket. A session socket outlives the failed connect so
    %% the client can try another target on it.
    case maps:is_key(session_id, State) of
        true -> {noreply, Cleared};
        false -> {stop, normal, Cleared}
    end;
handle_control_info(
    {'DOWN', Mon, process, _Pid, _Reason}, #{pending_session_mon := Mon} = State
) ->
    %% The session died before it could answer: the id no longer names a
    %% session, so this connect can never become a stream.
    send_line(State, <<"STREAM STATUS RESULT=INVALID_ID">>),
    {stop, normal, clear_pending_connect(State#{connecting => false})};
handle_control_info(
    {'DOWN', Mon, process, _Pid, _Reason}, #{delegated := Delegated} = State
) when is_map_key(Mon, Delegated) ->
    %% The stream socket went away: its stream goes with it.
    i2p_stream_conn:close(maps:get(Mon, Delegated)),
    {noreply, State#{delegated => maps:remove(Mon, Delegated)}};
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

%% register_lengths/1 — hand this session's length demands to the tunnel
%% manager so its pool tick builds matching tunnels while this session
%% lives. Absent options mean "no opinion" and take the router default, not
%% the maximum: a one-sided request must not drag the other side up to 7
%% hops.
-spec register_lengths(tunnel_lengths()) -> ok.
register_lengths(Lengths) when map_size(Lengths) =:= 0 ->
    ok;
register_lengths(Lengths) ->
    InLen = maps:get(in_len, Lengths, ?DEFAULT_HOPS),
    OutLen = maps:get(out_len, Lengths, ?DEFAULT_HOPS),
    ok = i2p_tunnel_srv:set_lengths(self(), InLen, OutLen).

%% in_len/1 — a session's demanded inbound hop count for lease publication.
%% An absent option is the router default, so a session with no length
%% options steers its lease to the ordinary 3-hop inbound tunnel.
-spec in_len(tunnel_lengths()) -> 1..?MAX_HOPS.
in_len(Lengths) ->
    maps:get(in_len, Lengths, ?DEFAULT_HOPS).

-spec handle_stream_connect(session_id(), binary(), state()) -> state().
handle_stream_connect(_Id, _TargetB64, #{pending_connect_ref := Ref} = State) when
    Ref =/= undefined
->
    %% One connect per socket: SAM gives each stream its own socket, so a
    %% second command while the first is in flight has nowhere to go.
    send_line(State, <<"STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"connect already in progress\"">>),
    State;
handle_stream_connect(_Id, _TargetB64, #{session_id := _} = State) ->
    %% SAM v3 gives every stream its own client-to-SAM socket, and i2pd
    %% enforces it: a CONNECT on the socket that ran SESSION CREATE is
    %% answered with this error and the socket is closed
    %% (SAMSocket::ProcessStreamConnect -> SendReplyWithMessage, whose reply
    %% is a closing one), which ends the session with it. Answering with a
    %% stream status here would let a one-socket client pass against i2per
    %% and fail against every other bridge.
    send_line(State, <<"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"Socket already in use\"">>),
    exit({protocol_error, socket_already_in_use});
handle_stream_connect(Id, TargetB64, State) ->
    %% A stream socket: this connection owns no destination, so it resolves
    %% the session by ID and asks that process to open the stream. The lookup
    %% comes first, as in i2pd — an id nobody owns is INVALID_ID whatever the
    %% destination says.
    case i2p_sam_sup:session_lookup(Id) of
        {ok, {SessionPid, _DestHash, stream}} ->
            case is_process_alive(SessionPid) of
                true ->
                    request_stream(SessionPid, TargetB64, State);
                false ->
                    %% Died without reaching terminate/2 (kill, or the
                    %% supervisor tearing it down). Drop the row so the id
                    %% cannot be reused, and treat it as unknown.
                    i2p_sam_sup:session_unregister(Id),
                    invalid_id(State)
            end;
        _ ->
            invalid_id(State)
    end.

%% request_stream/3 — hand the connect to the session that owns the
%% destination. The reply carries the live connection, whose owner becomes
%% this process, so the handshake's STREAM STATUS and the payload bytes land
%% on this socket.
-spec request_stream(pid(), binary(), state()) -> state().
request_stream(SessionPid, TargetB64, State) ->
    Ref = make_ref(),
    Mon = erlang:monitor(process, SessionPid),
    SessionPid ! {stream_connect, Ref, TargetB64, self()},
    State#{
        pending_connect_ref => Ref,
        pending_session_mon => Mon,
        pending_connect_b64 => TargetB64,
        connecting => true
    }.

%% invalid_id/1 — the id names no live STREAM session. i2pd closes the socket
%% after this reply; it can never carry anything else, so there is nothing to
%% keep open.
-spec invalid_id(state()) -> no_return().
invalid_id(State) ->
    send_line(State, <<"STREAM STATUS RESULT=INVALID_ID">>),
    exit({protocol_error, invalid_session_id}).

%%%%%%% %%% Delegated streams %%%%%%%

%% delegate_stream/4 — the session half of a stream socket's CONNECT. Decide
%% how the connect reaches its target and answer the socket in one message, so
%% the socket writes its STREAM STATUS line and starts relaying in a fixed
%% order. The stream itself is never this process's: the socket owns it, which
%% leaves this session free to carry several streams and to stay in line mode.
-spec delegate_stream(reference(), binary(), pid(), state()) -> state().
delegate_stream(Ref, TargetB64, From, State) ->
    case resolve_target(TargetB64) of
        {ok, DestB64, TargetHash} ->
            case i2p_sam_sup:listener_lookup(TargetHash) of
                {ok, AcceptPid} ->
                    i2p_sam_sup:listener_unregister(TargetHash),
                    AcceptPid ! {stream_pair, From},
                    From ! {sam_stream_connect_result, Ref, {paired, AcceptPid}},
                    State;
                not_found ->
                    delegate_network(Ref, DestB64, TargetHash, From, State)
            end;
        error ->
            From ! {sam_stream_connect_result, Ref, cant_reach},
            State
    end.

%% resolve_target/1 — a base64 destination, or a hostname the address book
%% knows. Returns the base64 form to route to as well as its hash.
-spec resolve_target(binary()) -> {ok, binary(), i2p_crypto:hash()} | error.
resolve_target(TargetB64) ->
    case decode_dest_b64(TargetB64) of
        {ok, TargetHash} ->
            {ok, TargetB64, TargetHash};
        {error, _} ->
            case i2p_addressbook:resolve(TargetB64) of
                {ok, DestB64} ->
                    case decode_dest_b64(DestB64) of
                        {ok, TargetHash} -> {ok, DestB64, TargetHash};
                        {error, _} -> error
                    end;
                {error, not_found} ->
                    error
            end
    end.

%% delegate_network/5 — no local listener for the target: route the stream
%% through tunnels. Resolve the destination's LeaseSet2 from the NetDb, pick
%% its freshest lease plus one of our outbound tunnels, and start a streaming
%% connection owned by the socket. The SYN/SYN-ACK handshake must complete
%% before the client sees STREAM STATUS RESULT=OK, and the connection notifies
%% its owner when it does.
-spec delegate_network(reference(), binary(), i2p_crypto:hash(), pid(), state()) -> state().
delegate_network(Ref, TargetB64, TargetHash, From, State) ->
    case resolve_route(TargetB64, TargetHash) of
        {ok, Route} ->
            ConnOpts = #{
                role => connect,
                owner => From,
                send_fn => fun(WireBin) -> stream_send(Route, WireBin) end,
                local_seed => maps:get(sign_priv, State),
                local_dest_bin => i2p_keys:to_binary(maps:get(dest, State)),
                local_dest_hash => maps:get(dest_hash, State),
                remote_dest_bin => maps:get(dest_bin, Route),
                remote_dest_hash => maps:get(dest_hash, Route)
            },
            case i2p_sam_sup:start_stream_conn(ConnOpts) of
                {ok, ConnPid} ->
                    Mon = erlang:monitor(process, From),
                    From !
                        {sam_stream_connect_result, Ref,
                            {conn, ConnPid, maps:get(dest_hash, State)}},
                    track_delegated(Mon, ConnPid, State);
                {error, _Reason} ->
                    %% **Including a refusal at `max_stream_connections`, and the
                    %% client is told `CANT_REACH`** rather than nothing. A client
                    %% that opened one session is not thereby entitled to an
                    %% unbounded number of streams through it, and a silent drop
                    %% here would leave it waiting on a `STREAM STATUS` line that
                    %% never comes -- the same shape as a route that cannot be
                    %% resolved, which is what `CANT_REACH` already means to it.
                    From ! {sam_stream_connect_result, Ref, cant_reach},
                    State
            end;
        error ->
            From ! {sam_stream_connect_result, Ref, cant_reach},
            State
    end.

%% track_delegated/3 — remember a stream this session opened for a socket, so
%% that the session's death takes it down (a session owns its streams) and the
%% socket's death releases it.
-spec track_delegated(reference(), pid(), state()) -> state().
track_delegated(Mon, ConnPid, State) ->
    Delegated = maps:get(delegated, State, #{}),
    State#{delegated => Delegated#{Mon => ConnPid}}.

cleared_conn(State) ->
    State#{conn => undefined, conn_mon => undefined, conn_myid => undefined}.

%% apply_connect_result/2 — the stream socket's half of a delegated connect.
%% Every failure replies and then ends the socket, as i2pd does: once CONNECT
%% has been sent, that socket can never carry another command or stream.
-spec apply_connect_result(term(), state()) ->
    {noreply, state()} | {stop, normal, state()}.
apply_connect_result({conn, ConnPid, DestHash}, State) ->
    %% The session handed the live connection over. This socket owns it from
    %% here, so the handshake's STREAM STATUS and the payload arrive here and
    %% the demux row is registered against this socket's destination.
    Mon = erlang:monitor(process, ConnPid),
    %% Clear the pending *request* markers first: the replay below must reach the
    %% registration clause, not be stashed again. The target blob stays, because
    %% a connection that dies before its SYN-ACK is answered names it in the
    %% CANT_REACH reply; `stream_established` is what finally retires it.
    State1 = (State#{
        phase => raw,
        conn => ConnPid,
        conn_mon => Mon,
        conn_myid => undefined,
        dest_hash => DestHash,
        connecting => true
    })#{
        pending_connect_ref => undefined,
        pending_session_mon => undefined
    },
    %% Replay the announcement the connection made before this message landed,
    %% so the demux key is registered before the peer's answer can need it.
    State2 =
        case maps:get(pending_stream_started, State1, undefined) of
            {stream_started, ConnPid, _MyId} = Started ->
                {noreply, Registered} = handle_control_info(Started, State1),
                Registered#{pending_stream_started => undefined};
            _ ->
                State1
        end,
    {noreply, State2};
apply_connect_result({paired, PeerPid}, #{sock := Sock} = State) ->
    %% Same-router shortcut: the target had a pending STREAM ACCEPT, so the
    %% two sockets relay raw bytes to each other.
    send_line(State, <<"STREAM STATUS RESULT=OK">>),
    ok = inet:setopts(Sock, [{active, once}]),
    {noreply,
        clear_pending_connect(State#{
            phase => raw, paired_pid => PeerPid, connecting => false
        })};
apply_connect_result(cant_reach, State) ->
    send_line(State, [
        <<"STREAM STATUS RESULT=CANT_REACH DESTINATION=">>,
        maps:get(pending_connect_b64, State, <<>>)
    ]),
    {stop, normal, clear_pending_connect(State#{connecting => false})};
apply_connect_result(invalid_id, State) ->
    send_line(State, <<"STREAM STATUS RESULT=INVALID_ID">>),
    {stop, normal, clear_pending_connect(State#{connecting => false})}.

clear_pending_connect(State) ->
    State#{
        pending_connect_ref => undefined,
        pending_session_mon => undefined,
        pending_connect_b64 => undefined
    }.

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
        Style when Style =:= datagram orelse Style =:= datagram2 orelse Style =:= raw ->
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
            Wire =
                case {Kind, maps:get(style, State, undefined)} of
                    {raw, _} ->
                        Payload;
                    {datagram2, _} ->
                        datagram2_wire(Payload, State, Route);
                    {repliable, datagram2} ->
                        datagram2_wire(Payload, State, Route);
                    {repliable, _} ->
                        datagram_wire(repliable, Payload, State)
                end,
            i2p_client:send_wire(Route, Wire),
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
    Wire.

%% datagram2_wire/3 — build a Datagram2 garlic Data-clove payload for one send.
-spec datagram2_wire(binary(), state(), i2p_client:route()) -> binary().
datagram2_wire(Payload, State, Route) ->
    TargetHash = maps:get(dest_hash, Route),
    {ok, Wire} =
        i2p_datagram:encode2(
            i2p_keys:to_binary(maps:get(dest, State)),
            maps:get(sign_priv, State),
            TargetHash,
            Payload
        ),
    Wire.

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

%% deliver_datagram2/2 — announce an authenticated inbound Datagram2 on the
%% control socket, with replay protection. Replayed or malformed frames are
%% dropped silently. An offline-signed datagram carries the sender's
%% signature over the transient key, verified against the sender's From key.
-spec deliver_datagram2(binary(), state()) -> state().
deliver_datagram2(Wire, State) ->
    TargetHash = maps:get(dest_hash, State),
    case i2p_datagram:decode2(Wire, TargetHash) of
        {ok, #{from := FromBin, payload := Payload} = Datagram} ->
            Key = crypto:hash(sha256, Wire),
            W0 = maps:get(replay_window, State, i2p_datagram_replay:new(1024)),
            case i2p_datagram_replay:check(W0, Key) of
                {replay, W1} ->
                    i2p_counters:add(datagram2_replayed, 1),
                    State#{replay_window => W1};
                {accepted, W1} ->
                    i2p_counters:add(datagram2_received, 1),
                    case maps:is_key(offline, Datagram) of
                        true -> i2p_counters:add(datagram2_offline_signed, 1);
                        false -> ok
                    end,
                    send_line(State, [
                        <<"DATAGRAM2 RECEIVED DESTINATION=">>,
                        i2p_keys:encode_b64(FromBin),
                        <<" SIZE=">>,
                        integer_to_binary(byte_size(Payload))
                    ]),
                    ok = gen_tcp:send(maps:get(sock, State), Payload),
                    State#{replay_window => W1}
            end;
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
send_line(#{send_fn := SendFn}, Line) ->
    case SendFn([Line, <<"\n">>]) of
        ok -> ok;
        {error, Reason} -> erlang:error({send_failed, Reason})
    end.

-spec resolve_destination(binary() | undefined, state()) ->
    {ok, #{identity := i2p_keys:identity(), crypto_priv := binary(), sign_priv := binary()}}
    | {error, term()}.
resolve_destination(undefined, _State) ->
    %% No DESTINATION provided — generate a transient identity
    {ok, i2p_keys:generate_with_privkeys()};
resolve_destination(<<"TRANSIENT">>, State) ->
    resolve_destination(undefined, State);
resolve_destination(DestB64, _State) ->
    i2p_keys:parse_dest_blob(i2p_keys:decode_b64(DestB64)).

-spec decode_dest_b64(binary()) -> {ok, i2p_crypto:hash()} | {error, term()}.
decode_dest_b64(B64) ->
    try i2p_keys:decode_b64(B64) of
        <<Identity:391/binary, _/binary>> ->
            {ok, crypto:hash(sha256, Identity)};
        _ ->
            %% Too short to be a destination. A missing `of` clause would raise
            %% `try_clause` outside this catch and kill the session, which turns
            %% one garbage DESTINATION from a client into a crash.
            {error, bad_dest_blob}
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
