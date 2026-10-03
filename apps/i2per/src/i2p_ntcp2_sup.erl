-module(i2p_ntcp2_sup).

-moduledoc """
Supervisor owning every NTCP2 connection and listener.

Children are started on demand and are all `temporary`: a connection that dies
— for any reason, including `kill` — is never restarted and never hot-loops, and
its death cannot take the supervisor (or the listener, or any sibling
connection) down. The supervisor is a child of `m:i2per_sup`.

`i2p_ntcp2_conn:connect/3` and `i2p_ntcp2_listener:listen/3` build their child
specs through `conn_child/1` and `listener_child/3`.

## The cap, and what admits a connection

`max_ntcp2_connections` is enforced by `m:i2p_admission`, one instance of which
is a child of this supervisor. It is a separate process because the limit is a
count-then-start and the two halves have to be atomic together: a peer-set
rebuild after a restart completes many handshakes in the same instant, which is
precisely when a count read by one admission is read again by another before
either has started its child.

What it is *not* is a `m:global` lock, which is what enforced it until this
changed — and that is not a smaller thing than a shared process. `global:trans/2`
is a **cooperative, shared** lock, not a mutex: a second process asking for an id
that is already held is added to the holder list and answered `true`, so every
concurrent dial ran the count-then-start. It only looked exclusive because the
critical section was usually short enough that a retrying dialer came back after
the holder had left; this one is a tree walk and a process start. `m:i2p_admission`
has the measurement, and `m:i2p_admission` is local, holds no state, and reads its
count from the supervisor it starts children in — so the count cannot disagree with
what is alive, and a restart cannot leave the cap enforcing a total nobody
checked.
""".

-behaviour(supervisor).

-define(DEFAULT_MAX_CONNECTIONS, 64).

%% The admission process `f:start_connection/1` goes through. Its own name
%% rather than `?MODULE`, so the resource it guards is named in the supervision
%% tree and in a `whereis/1` rather than being an anonymous extra child.
-define(ADMISSION, i2p_ntcp2_admission).

-export([
    start_link/0,
    start_link/3,
    conn_child/1,
    listener_child/3,
    start_connection/1,
    connection_count/0,
    connection_limit/0
]).
-export([init/1]).

-doc "Start the supervisor, registered locally as `i2p_ntcp2_sup`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc """
Start the supervisor with a boot-time listener bound on `Port` (the operator
boot path, `m:i2per_sup`).

Accepted connections announce to `Owner` (the peer manager) and are children
of this supervisor like any on-demand connection. Unlike the on-demand
`f:listen/3` listener, the boot listener is a `permanent` child: if it dies
the supervisor restarts it, and a listener that cannot bind brings the router
down at boot instead of silently running without ingress.
""".
-spec start_link(0..65535, i2p_ntcp2_conn:local_keys(), pid()) ->
    {ok, pid()} | {error, term()}.
start_link(Port, LocalKeys, Owner) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Port, LocalKeys, Owner]).

-doc """
Admit and start one NTCP2 connection under the configured active-connection
limit.

The count and the `m:supervisor:start_child/2` that follows it are one operation
in `m:i2p_admission`, so simultaneous peer dials cannot exceed the limit. Output
is the normal `supervisor:start_child/2` result, or `{error, connection_limit}`.
""".
-spec start_connection(supervisor:child_spec()) ->
    {ok, pid()} | {ok, pid(), term()} | {error, term()}.
start_connection(ChildSpec) ->
    i2p_admission:admit(?ADMISSION, ChildSpec).

-doc "Return the number of active NTCP2 connection workers.".
-spec connection_count() -> non_neg_integer().
connection_count() ->
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
                element(1, Id) =:= conn
            ])
    end.

-doc """
Return the maximum number of active NTCP2 connection workers.

The default is 64 and can be overridden with the restart-required
`max_ntcp2_connections` application setting. A zero value is an emergency
fail-closed switch that rejects all new connections.
""".
-spec connection_limit() -> non_neg_integer().
connection_limit() ->
    case application:get_env(i2per, max_ntcp2_connections) of
        {ok, Value} when is_integer(Value), Value >= 0 -> Value;
        _ -> ?DEFAULT_MAX_CONNECTIONS
    end.

-doc """
A `temporary` worker child spec for one connection process.
`handshake_timeout` defaults to 15 seconds.
""".
-spec conn_child(i2p_ntcp2_conn:config()) -> supervisor:child_spec().
conn_child(Args) ->
    Timeout = maps:get(handshake_timeout, Args, 15000),
    #{
        id => {conn, erlang:unique_integer([positive, monotonic])},
        start => {i2p_ntcp2_conn, start_link, [Args#{handshake_timeout => Timeout}]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_ntcp2_conn]
    }.

-doc """
A `temporary` worker child spec for one listener. One listener per `Port`.
""".
-spec listener_child(0..65535, i2p_ntcp2_conn:local_keys(), pid()) -> supervisor:child_spec().
listener_child(Port, LocalKeys, Owner) ->
    #{
        id => {listener, Port, erlang:unique_integer([positive, monotonic])},
        start => {i2p_ntcp2_listener, start_link, [Port, LocalKeys, Owner]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_ntcp2_listener]
    }.

%% The boot listener: a permanent child so a listener crash is restarted and a
%% bind failure fails the router at boot. Same listener process as above.
boot_listener_child(Port, LocalKeys, Owner) ->
    (listener_child(Port, LocalKeys, Owner))#{restart => permanent}.

%% `count` and `limit` are read per admission, not captured at boot, so an
%% operator who changes `max_ntcp2_connections` changes it for the next
%% connection. That is also what keeps a zero — the emergency fail-closed switch
%% — working without a restart, which is the entire point of having one.
admission_child() ->
    i2p_admission:child_spec(#{
        name => ?ADMISSION,
        supervisor => ?MODULE,
        count => fun connection_count/0,
        limit => fun connection_limit/0,
        refused => connection_limit,
        refused_counter => ntcp2_connections_refused_limit
    }).

init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 5, period => 10}, [admission_child()]}};
init([Port, LocalKeys, Owner]) ->
    {ok,
        {#{strategy => one_for_one, intensity => 5, period => 10}, [
            admission_child(),
            boot_listener_child(Port, LocalKeys, Owner)
        ]}}.
