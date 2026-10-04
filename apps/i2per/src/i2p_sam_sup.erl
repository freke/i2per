-module(i2p_sam_sup).

-moduledoc """
Dynamic supervisor owning every SAM session and the SAM listener.

Children are `temporary`: a session that dies — even by `kill` — is never
restarted and never hot-loops, and its death cannot take the supervisor
(or the listener, or any sibling session) down. The supervisor is a child
of `m:i2per_sup`.

On init the supervisor creates an ETS table (`i2p_sam_sessions`) that
tracks active sessions and a second table (`i2p_sam_listeners`) that maps
destination hashes to STREAM-ACCEPT session pids. Both tables are owned
by this process; its death tears them down cleanly.

`m:i2p_sam_listener:listen/1` and `m:i2p_sam_session:start_link/2` build
their child specs through `listener_child/1` and `session_child/1`.

In the persistent (operator) boot the supervisor is started with the router's
local keys (`f:start_link/1`) and binds one boot listener on the `sam_port`
app env; explicit/test boots start it empty and bind listeners on demand.

## Two caps, and two admission processes

This supervisor owns **two** bounded resources, and each has its own
`m:i2p_admission` instance as a `permanent` child:

| resource | key | admission process | refusal |
|---|---|---|---|
| SAM sessions | `max_sam_sessions` | `i2p_sam_admission` | `{error, session_limit}` |
| streaming connections | `max_stream_connections` | `i2p_stream_admission` | `{error, stream_limit}` |

**Two instances rather than one, for the reason the first three caps are three.**
A SAM session is a client connection an operator is waiting on by hand — a
handshake budget — while a streaming connection is a socket, a window pair and a
demux row, and the count that drives it is set by *remote* peers: a STREAM
ACCEPT destination invites any number of inbound streams. One admission process
would put every one of those inbound streams in front of the operator's session.
Separate mailboxes never wait on each other.

`f:session_count/0` and `f:stream_conn_count/0` both count this supervisor's
children, tagged `session` and `stream_conn`, which is what the limits bound.
The session count used to count the `i2p_sam_sessions` ETS rows instead, which
is a different number: a session writes its row *after* it is started, so one in
that window counted against nothing, and concurrent accepts could exceed the cap
by the number of sessions mid-registration. Counting children is also what lets
all four caps be counted the same way and pinned by the same case.

Neither admission is a `m:global` lock, and the reason `m:i2p_admission` gives
is the important one: `global:trans/2` is a shared lock rather than a mutex, so
every concurrent accept ran the count-then-start anyway.
""".

-behaviour(supervisor).

-define(DEFAULT_MAX_SESSIONS, 32).

%% Streaming connections are cheaper per unit than a session (no handshake state)
%% and more numerous (one per stream, and a STREAM ACCEPT destination can be sent
%% any number of them), so the default is several times the session cap rather
%% than the same number. It is still a bound: each one holds a window of 8 packets
%% in flight, a demux row, and -- on the server-tunnel path -- a TCP socket.
-define(DEFAULT_MAX_STREAM_CONNS, 128).

%% The admission processes `f:start_session/1` and `f:start_stream_conn/1` go
%% through. Named so the resource each guards is in the supervision tree and
%% answerable to a `whereis/1`.
-define(ADMISSION, i2p_sam_admission).
-define(STREAM_ADMISSION, i2p_stream_admission).

-export([
    start_link/0,
    start_link/1,
    listener_child/1,
    session_child/1,
    start_session/1,
    session_count/0,
    session_limit/0,
    stream_conn_child/1,
    start_stream_conn/1,
    stream_conn_count/0,
    stream_conn_limit/0
]).
-export([init/1]).

%% Session registry API (called by i2p_sam_session).
-export([
    session_register/5,
    session_unregister/1,
    session_lookup/1,
    client_sessions/0,
    listener_register/2,
    listener_lookup/1,
    listener_unregister/1,
    forward_register/3,
    forward_lookup/1,
    forward_unregister/1,
    stream_conn_register/3,
    stream_conn_lookup/2,
    stream_conn_unregister/2
]).

-doc "Start the supervisor, registered locally as `i2p_sam_sup`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc """
Start the supervisor with the router's local keys so a SAM listener is bound
at boot.

Only the persistent (operator) boot — app env `i2per` -> `data_dir` — takes
this path; explicit/test boots call `f:start_link/0` and bind their own
listeners on demand. The listener binds the `i2per` -> `sam_port` app env
(default 7656).
""".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Local) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Local]).

-doc """
A `temporary` worker child spec for one SAM session process.
""".
-spec session_child(map()) -> supervisor:child_spec().
session_child(Args) ->
    #{
        id => {session, erlang:unique_integer([positive, monotonic])},
        start => {i2p_sam_session, start_link, [Args]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_sam_session]
    }.

-doc """
Admit and start one SAM session under the configured active-session limit.

The count and the `m:supervisor:start_child/2` that follows it are one operation
in `m:i2p_admission`, so simultaneous accepts cannot exceed the limit. Output is
the normal `supervisor:start_child/2` result, or `{error, session_limit}`.

This counts SAM sessions only. A session that has gone on to open streaming
connections is bounded separately, by `max_stream_connections` — a client that
opened one session is not thereby entitled to an unbounded number of streams.
""".
-spec start_session(supervisor:child_spec()) ->
    {ok, pid()} | {ok, pid(), term()} | {error, term()}.
start_session(ChildSpec) ->
    i2p_admission:admit(?ADMISSION, ChildSpec).

-doc """
Return the number of live SAM sessions.

The `session` children of this supervisor, which is what `f:session_limit/0`
bounds. Not the `i2p_sam_sessions` ETS rows: those are written by each session
after it starts, so they are a later and smaller number. Zero when this
supervisor is not running.
""".
-spec session_count() -> non_neg_integer().
session_count() ->
    case whereis(?MODULE) of
        undefined ->
            0;
        Sup ->
            length([
                Id
             || {Id, Pid, _Type, _Modules} <- supervisor:which_children(Sup),
                is_pid(Pid),
                is_tuple(Id),
                tuple_size(Id) > 0,
                element(1, Id) =:= session
            ])
    end.

-doc """
Return the maximum number of active SAM sessions.

The default is 32 and can be overridden with the restart-required
`max_sam_sessions` application setting. A zero value is an emergency
fail-closed switch that rejects all new sessions.
""".
-spec session_limit() -> non_neg_integer().
session_limit() ->
    case application:get_env(i2per, max_sam_sessions) of
        {ok, Value} when is_integer(Value), Value >= 0 -> Value;
        _ -> ?DEFAULT_MAX_SESSIONS
    end.

%% `count` and `limit` are read per admission, not captured at boot, so an
%% operator who changes `max_sam_sessions` changes it for the next accept, and a
%% zero -- the emergency fail-closed switch -- works without a restart.
admission_child() ->
    i2p_admission:child_spec(#{
        name => ?ADMISSION,
        supervisor => ?MODULE,
        count => fun session_count/0,
        limit => fun session_limit/0,
        refused => session_limit,
        refused_counter => sam_sessions_refused_limit
    }).

%% The same shape for the second bounded resource this supervisor owns, and the
%% same per-admission read of `count` and `limit` so an operator change to
%% `max_stream_connections` applies to the next stream rather than the next boot.
stream_admission_child() ->
    i2p_admission:child_spec(#{
        name => ?STREAM_ADMISSION,
        supervisor => ?MODULE,
        count => fun stream_conn_count/0,
        limit => fun stream_conn_limit/0,
        refused => stream_limit,
        refused_counter => stream_conns_refused_limit
    }).

-doc """
A `temporary` worker child spec for one streaming connection process
(`m:i2p_stream_conn`).
""".
-spec stream_conn_child(map()) -> supervisor:child_spec().
stream_conn_child(Opts) ->
    #{
        id => {stream_conn, erlang:unique_integer([positive, monotonic])},
        start => {i2p_stream_conn, start_link, [Opts]},
        restart => temporary,
        shutdown => brutal_kill,
        type => worker,
        modules => [i2p_stream_conn]
    }.

-doc """
Admit and start one streaming connection under the configured limit.

Output: `{ok, Pid}` of the new `m:i2p_stream_conn` process; its death is never
restarted. Or `{error, stream_limit}` when `max_stream_connections` is already
reached, charged to the `stream_conns_refused_limit` counter.

**Every caller must handle the refusal**, because the count is driven by remote
peers rather than by anything local. Three sites create these: the SAM STREAM
CONNECT path (a client is waiting on a SAM reply, so it gets
`STREAM STATUS RESULT=CANT_REACH`), the STREAM ACCEPT path and the server-tunnel
relay path (both an unsolicited inbound SYN with no client to answer, so the SYN
is dropped and the sender retries).
""".
-spec start_stream_conn(map()) -> {ok, pid()} | {error, term()}.
start_stream_conn(Opts) ->
    i2p_admission:admit(?STREAM_ADMISSION, stream_conn_child(Opts)).

-doc """
Return the number of live streaming connections.

The `stream_conn` children of this supervisor, which is what
`f:stream_conn_limit/0` bounds. Zero when this supervisor is not running.
""".
-spec stream_conn_count() -> non_neg_integer().
stream_conn_count() ->
    case whereis(?MODULE) of
        undefined ->
            0;
        Sup ->
            length([
                Id
             || {Id, Pid, _Type, _Modules} <- supervisor:which_children(Sup),
                is_pid(Pid),
                is_tuple(Id),
                tuple_size(Id) > 0,
                element(1, Id) =:= stream_conn
            ])
    end.

-doc """
Return the maximum number of live streaming connections.

The default is 128 and can be overridden with the `max_stream_connections`
application setting. A zero value is an emergency fail-closed switch that
rejects all new streaming connections, inbound and outbound alike.

Read on every admission rather than at boot, so an operator can lower the cap on
a router that is already at it without a restart.
""".
-spec stream_conn_limit() -> non_neg_integer().
stream_conn_limit() ->
    case application:get_env(i2per, max_stream_connections) of
        {ok, Value} when is_integer(Value), Value >= 0 -> Value;
        _ -> ?DEFAULT_MAX_STREAM_CONNS
    end.

-doc """
A `temporary` worker child spec for the SAM TCP listener.
""".
-spec listener_child(map()) -> supervisor:child_spec().
listener_child(Args) ->
    #{
        id => {listener, erlang:unique_integer([positive, monotonic])},
        start => {i2p_sam_listener, start_link, [Args]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_sam_listener]
    }.

%%%%%%% %%% Session registry %%%%%%%

-doc """
Register a SAM session by ID together with its destination's ECIES private
key, used by the tunnel manager to open end-to-end garlic addressed to the
session's destination.
""".
-spec session_register(
    i2p_sam_session:session_id(),
    pid(),
    binary(),
    stream | datagram | raw,
    i2p_crypto:x25519_private_key()
) -> true.
session_register(SessionId, Pid, DestHash, Style, CryptoPriv) ->
    ets:insert(?MODULE, {{session, SessionId}, Pid, DestHash, Style, CryptoPriv}).

-doc "Unregister a SAM session by ID.".
-spec session_unregister(i2p_sam_session:session_id()) -> true.
session_unregister(SessionId) ->
    ets:delete(?MODULE, {session, SessionId}).

-doc """
Look up a SAM session by ID.

Output: `{ok, {Pid, DestHash, Style}}` or `not_found`.
""".
-spec session_lookup(i2p_sam_session:session_id()) ->
    {ok, {pid(), binary(), stream | datagram | raw}} | not_found.
session_lookup(SessionId) ->
    case ets:lookup(?MODULE, {session, SessionId}) of
        [{{session, SessionId}, Pid, DestHash, Style, _CryptoPriv}] ->
            {ok, {Pid, DestHash, Style}};
        [] ->
            not_found
    end.

-doc """
Enumerate every registered session — STREAM, DATAGRAM, and RAW — for
end-to-end delivery.

Output: a list of `{DestHash, Pid, CryptoPriv}` triples in registration
order; `m:i2p_tunnel_srv` checks arriving garlic against each key
until one opens. A destination carries exactly one client form, so the
owning session dispatches the opened payload by its style.
""".
-spec client_sessions() -> [{binary(), pid(), i2p_crypto:x25519_private_key()}].
client_sessions() ->
    try
        [
            {DestHash, Pid, CryptoPriv}
         || [Pid, DestHash, _Style, CryptoPriv] <-
                ets:match(?MODULE, {{session, '_'}, '$1', '$2', '$3', '$4'})
        ]
    catch
        error:badarg -> []
    end.

-doc "Register a STREAM-ACCEPT listener for a destination hash.".
-spec listener_register(binary(), pid()) -> true.
listener_register(DestHash, Pid) ->
    ets:insert(?MODULE, {{listener, DestHash}, Pid}).

-doc """
Look up a STREAM-ACCEPT listener for a destination hash.

Output: `{ok, Pid}` or `not_found`.
""".
-spec listener_lookup(binary()) -> {ok, pid()} | not_found.
listener_lookup(DestHash) ->
    case ets:lookup(?MODULE, {listener, DestHash}) of
        [{{listener, DestHash}, Pid}] -> {ok, Pid};
        [] -> not_found
    end.

-doc "Unregister a STREAM-ACCEPT listener by destination hash.".
-spec listener_unregister(binary()) -> true.
listener_unregister(DestHash) ->
    ets:delete(?MODULE, {listener, DestHash}).

-doc """
Register a STREAM FORWARD target for a destination hash: the local
`{Host, Port}` service the router dials for every accepted peer stream.

Unlike a STREAM-ACCEPT listener this binding is persistent — one entry
serves any number of concurrent inbound streams — and it survives until the
session dies (the session owns the table cleanup).
""".
-spec forward_register(binary(), string(), inet:port_number()) -> true.
forward_register(DestHash, Host, Port) ->
    ets:insert(?MODULE, {{forward, DestHash}, {Host, Port}}).

-doc """
Look up the STREAM FORWARD target for a destination hash.

Output: `{ok, {Host, Port}}` or `not_found`.
""".
-spec forward_lookup(binary()) -> {ok, {string(), inet:port_number()}} | not_found.
forward_lookup(DestHash) ->
    case ets:lookup(?MODULE, {forward, DestHash}) of
        [{{forward, DestHash}, Target}] -> {ok, Target};
        [] -> not_found
    end.

-doc "Remove a STREAM FORWARD registration by destination hash.".
-spec forward_unregister(binary()) -> true.
forward_unregister(DestHash) ->
    ets:delete(?MODULE, {forward, DestHash}).

%%%%%%% %%% Stream connection demux registry %%%%%%%

-doc """
Register a live streaming connection under `(DestinationHash, MyStreamId)`.

Inbound packets carry the recipient's own stream ID in the sendStreamId
field, so this pair is the demux key routing garlic-unwrapped packets from
the tunnel manager to their `m:i2p_stream_conn`.
""".
-spec stream_conn_register(binary(), 1..16#FFFFFFFF, pid()) -> true.
stream_conn_register(DestHash, MyStreamId, ConnPid) ->
    ets:insert(?MODULE, {{conn, DestHash, MyStreamId}, ConnPid}).

-doc """
Look up a streaming connection by demux key.

Output: `{ok, Pid}` or `not_found`.
""".
-spec stream_conn_lookup(binary(), 0..16#FFFFFFFF) -> {ok, pid()} | not_found.
stream_conn_lookup(DestHash, MyStreamId) ->
    case ets:lookup(?MODULE, {conn, DestHash, MyStreamId}) of
        [{{conn, DestHash, MyStreamId}, Pid}] -> {ok, Pid};
        [] -> not_found
    end.

-doc "Remove a streaming connection's demux entry.".
-spec stream_conn_unregister(binary(), 1..16#FFFFFFFF) -> true.
stream_conn_unregister(DestHash, MyStreamId) ->
    ets:delete(?MODULE, {conn, DestHash, MyStreamId}).

%%%%%%% %%% Supervisor callback %%%%%%%

init([Local]) ->
    _EtsTid = ets:new(?MODULE, [named_table, public, {read_concurrency, true}]),
    {ok,
        {#{strategy => one_for_one, intensity => 10, period => 10}, [
            admission_child(),
            stream_admission_child(),
            listener_child(boot_listener(Local))
        ]}};
init([]) ->
    _EtsTid = ets:new(?MODULE, [named_table, public, {read_concurrency, true}]),
    {ok,
        {#{strategy => one_for_one, intensity => 10, period => 10}, [
            admission_child(),
            stream_admission_child()
        ]}}.

%%%%%%% %%% Internal %%%%%%%

%% boot_listener/1 — a boot listener bound on `i2per` -> `sam_port` (default
%% 7656). A `temporary` child: its death is permanent and never hot-loops,
%% matching let-it-crash; the next router boot rebinds it.
boot_listener(Local) ->
    Port =
        case application:get_env(i2per, sam_port) of
            {ok, P} -> P;
            undefined -> 7656
        end,
    #{port => Port, local => Local}.
