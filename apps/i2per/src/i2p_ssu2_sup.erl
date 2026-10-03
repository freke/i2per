-module(i2p_ssu2_sup).

-moduledoc """
Supervisor owning every SSU2 session and listener, plus the session registry.

Children are started on demand and are all `temporary`: a session that dies —
for any reason — is never restarted and never hot-loops, and its death cannot
take the supervisor (or the listener, or any sibling) down. The supervisor is
a child of `m:i2per_sup`; tests start it directly.

Two kinds of child live here. Sessions (`f:start_session/1`) are long-lived and
count against `f:session_limit/0`. Charlie responders (`f:start_charlie/1`) are
one per listener, hold a single public key, and run unauthenticated input, so they
sit deliberately outside that limit — see `f:start_charlie/1` for why.

The public ETS table `i2p_ssu2_sessions` maps destination connection ID to
session pid; `f:i2p_ssu2_listener/1` consults it for inbound classification
and sessions are removed by their monitor in `m:i2p_ssu2_listener`. The public
table `i2p_ssu2_relay_tags` maps a handed-out 32-bit relay tag to the session
pid that holds it (plus its expiry); rows are written by the listener's
`f:i2p_ssu2_listener:register_relay_tag/4` cast at the introducer's request
and removed when the session dies.

## The cap, and what admits a session

`max_ssu2_sessions` is enforced by `m:i2p_admission`, one instance of which is
a child of this supervisor. The limit is a count-then-start and the two halves
have to be atomic together, because inbound accepts and outbound handshakes
complete together in exactly the moments the cap exists for.

It is not a `m:global` lock, and the reason `m:i2p_admission` gives is the
important one: `global:trans/2` is a shared lock rather than a mutex, so every
concurrent handshake ran the count-then-start anyway. `m:i2p_admission` is local,
holds no state, and reads its count from this supervisor — so the count cannot
disagree with what is alive.
""".

-behaviour(supervisor).

-define(DEFAULT_MAX_SESSIONS, 32).

%% The admission process `f:start_session/1` goes through. Named so the resource
%% it guards is in the supervision tree and answerable to a `whereis/1`.
-define(ADMISSION, i2p_ssu2_admission).

-export([
    start_link/0,
    start_link/4,
    session_child/1,
    start_session/1,
    charlie_child/1,
    start_charlie/1,
    session_count/0,
    session_limit/0,
    init/1
]).

-doc "Start the supervisor, registered locally as `i2p_ssu2_sup`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    bootstrap_tables(),
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc """
Start the supervisor with a permanent SSU2 boot listener bound on `Host`:`Port`.

Used by the persistent (operator) boot of `m:i2per_sup`; the listener is owned
by `m:i2p_peer`. `LocalKeys` is the `m:i2p_ssu2_conn` local map (must carry
`intro_key`).
""".
-spec start_link(
    inet:ip_address() | binary() | string(),
    0..65535,
    i2p_ssu2_conn:local_keys(),
    pid()
) -> {ok, pid()} | {error, term()}.
start_link(Host, Port, LocalKeys, Owner) ->
    bootstrap_tables(),
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Host, Port, LocalKeys, Owner]).

bootstrap_tables() ->
    case ets:whereis(i2p_ssu2_sessions) of
        undefined ->
            _ = ets:new(
                i2p_ssu2_sessions,
                [named_table, public, set, {read_concurrency, true}]
            ),
            _ = ets:new(
                i2p_ssu2_pending,
                [named_table, public, set, {read_concurrency, true}]
            ),
            _ = ets:new(
                i2p_ssu2_relay_tags,
                [named_table, public, set, {read_concurrency, true}]
            ),
            ok;
        _Existing ->
            ok
    end.

-doc """
A `temporary` worker child spec for one session process
(`t:i2p_ssu2_conn:config/0`).
""".
-spec session_child(i2p_ssu2_conn:config()) -> supervisor:child_spec().
session_child(Args) ->
    #{
        id => {ssu2_conn, erlang:unique_integer([positive, monotonic])},
        start => {i2p_ssu2_conn, start_link, [Args]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_ssu2_conn]
    }.

-doc """
Admit and start one SSU2 session under the configured active-session limit.

The count and the `m:supervisor:start_child/2` that follows it are one operation
in `m:i2p_admission`, so simultaneous inbound/outbound handshakes cannot exceed
the limit. Output is the normal `supervisor:start_child/2` result, or
`{error, session_limit}`.
""".
-spec start_session(supervisor:child_spec()) ->
    {ok, pid()} | {ok, pid(), term()} | {error, term()}.
start_session(ChildSpec) ->
    i2p_admission:admit(?ADMISSION, ChildSpec).

-doc """
A `temporary` worker child spec for one out-of-session Charlie responder
(`m:i2p_ssu2_charlie`).

`temporary` and not `permanent` for the reason every child here is: the responder
runs unauthenticated input, so it is expected to die sometimes, and a permanent
one would be restarted into a hot loop by whatever is killing it. Its owner -- the
listener -- notices the death by monitor and asks for a replacement, which is the
only restart path.
""".
-spec charlie_child(i2p_crypto:key()) -> supervisor:child_spec().
charlie_child(IntroKey) ->
    #{
        id => {ssu2_charlie, erlang:unique_integer([positive, monotonic])},
        start => {i2p_ssu2_charlie, start_link, [IntroKey]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [i2p_ssu2_charlie]
    }.

-doc """
Start one Charlie responder under the same supervisor as the sessions.

Deliberately *not* counted against `f:session_limit/0`: that limit exists to bound
how much of the Noise handshake state one router holds, and a responder holds a
single public key. Counting it would mean a router at its session limit could not
answer a peer test, which is a role rather than a resource.
""".
-spec start_charlie(i2p_crypto:key()) -> {ok, pid()} | {error, term()}.
start_charlie(IntroKey) ->
    supervisor:start_child(?MODULE, charlie_child(IntroKey)).

-doc "Return the number of active SSU2 session workers.".
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
                element(1, Id) =:= ssu2_conn
            ])
    end.

-doc """
Return the maximum number of active SSU2 sessions.

The default is 32 and can be overridden with the restart-required
`max_ssu2_sessions` application setting. A zero value is an emergency
fail-closed switch that rejects all new sessions.
""".
-spec session_limit() -> non_neg_integer().
session_limit() ->
    case application:get_env(i2per, max_ssu2_sessions) of
        {ok, Value} when is_integer(Value), Value >= 0 -> Value;
        _ -> ?DEFAULT_MAX_SESSIONS
    end.

%% `count` and `limit` are read per admission, not captured at boot, so an
%% operator who changes `max_ssu2_sessions` changes it for the next handshake --
%% and a zero, the emergency fail-closed switch, works without a restart.
admission_child() ->
    i2p_admission:child_spec(#{
        name => ?ADMISSION,
        supervisor => ?MODULE,
        count => fun session_count/0,
        limit => fun session_limit/0,
        refused => session_limit,
        refused_counter => ssu2_sessions_refused_limit
    }).

init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 10, period => 10}, [admission_child()]}};
init([Host, Port, LocalKeys, Owner]) ->
    {ok,
        {#{strategy => one_for_one, intensity => 10, period => 10}, [
            admission_child(),
            #{
                id => {ssu2_listener, Port, erlang:unique_integer([positive, monotonic])},
                start =>
                    {i2p_ssu2_listener, start_link, [Host, Port, LocalKeys, Owner, undefined]},
                restart => permanent,
                shutdown => 5000,
                type => worker,
                modules => [i2p_ssu2_listener]
            }
        ]}}.
