-module(i2p_lookup_srv).

-moduledoc """
Remote NetDb lookup orchestrator: answers "fetch this LeaseSet /
RouterInfo from the network" by querying floodfills through our own tunnels
and correlating the tunnel-delivered replies.

Flow for one pending key:

1. The local NetDb is checked first; a hit replies immediately.
2. Otherwise up to three floodfill candidates closest to the key are queried
   in turn. Each query is a DatabaseLookup carrying our inbound-tunnel reply
   address (`f:i2p_i2np:db_lookup_via_tunnel/5`) delivered `{router, FF}`
   through an outbound tunnel (`f:i2p_tunnel_srv:send_via_outbound/3`). The
   lookup paths stay in the tunnel manager rather than playing the role
   themselves: this orchestrator and `m:i2p_peer` are singletons, not
   connections.
3. Replies arrive inside that inbound tunnel and are routed here by
   `m:i2p_tunnel_srv`: a DatabaseStore resolves the waiters, a
   DatabaseSearchReply contributes its closer-peer list to the chase queue.
4. When floodfill candidates run out, queued chase peers (routers the
   responders think are close to the key) are queried directly; after
   `?MAX_ATTEMPTS` sends or the overall deadline the lookup fails.

Callers block in `f:find_ls/1` / `f:find_ri/1` until resolution or failure.
SAM STREAM CONNECT uses this to resolve uncached destinations.
""".

-behaviour(gen_server).

-export([
    start_link/1,
    find_ls/1,
    find_ls/2,
    find_ri/1,
    find_ri/2,
    send_lookup/4,
    stop/0
]).
-export_type([lookup_failed_reason/0, lookup_options/0, pending/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(ATTEMPT_TIMEOUT_MS, 4000).
-define(OVERALL_DEADLINE_MS, 18_000).
-define(MAX_ATTEMPTS, 5).
-define(CANDIDATES_PER_ROUND, 3).

-type kind() :: lease | router.

-doc """
Why a lookup did not produce the record it was asked for.

The point of the vocabulary is the split at the top. `no_answer` means nobody
answered: every peer tried either stayed silent or was unreachable, and the
question of whether this router is on the network is open. `not_stored` means a peer
*did* answer — a record for exactly this key arrived — and this router could not use
it. Those are opposite problems: the first is a connectivity or peering one, the
second is a compatibility or storage one, and an operator reading a log cannot act on
either until they know which they are looking at. Before this the two were the same
`{error, not_found}`.

The inner term of `not_stored` is `m:i2p_peer:store_not_stored_reason/0` unchanged.
That is the vocabulary the store path already settled on for exactly these
conditions; a lookup-specific set of reasons for the same conditions would be a
second description to keep in step.

A closed set apart from the inner term, deliberately. Every clause here is a branch
somewhere in this module, so an open `term()` would let a caller pattern-match on a
reason no path can produce.
""".
-type lookup_failed_reason() ::
    {not_stored, i2p_peer:store_not_stored_reason()}
    %% A responder's record for this key arrived, was handled, and the key still does
    %% not hold what was asked for. Reachable when a LeaseSet resolves a pending
    %% RouterInfo lookup for the same hash: the pending map is keyed by hash alone,
    %% so the two kinds share one entry.
    | not_resolved
    %% Attempts or the overall deadline ran out with no store for this key arriving.
    | no_answer
    %% `f:find_ls/2` was called with no lookup service running.
    | service_unavailable.

-doc """
Per-call options for `f:find_ls/2` and `f:find_ri/2`.

`reason => true` opts into `{error, {lookup_failed, Reason}}`. Without it the reply
is the historical `{error, not_found}`, and that default is not a courtesy: most
callers only branch on whether the lookup worked, and widening the reply for them
would be a breaking change to a contract they never asked to widen.
""".
-type lookup_options() :: #{reason => boolean()}.

-doc """
A pending lookup: which kind of record, who waits, what was tried, which
closer peers to chase, and the retry/deadline bookkeeping.
""".
-type pending() :: #{
    kind := kind(),
    callers := [{gen_server:from(), pid(), reference()}],
    tried := [i2p_crypto:hash()],
    chase := [i2p_crypto:hash()],
    attempts := non_neg_integer(),
    deadline := integer(),

    timer := undefined | reference()
}.

-opaque state() :: #{pending := #{i2p_crypto:hash() => pending()}, our_hash := i2p_crypto:hash()}.
-export_type([state/0]).

-doc """
Start the orchestrator.

Input: `OurHash` — this router's identity hash (the DatabaseLookup sender).
""".
-spec start_link(i2p_crypto:hash()) -> {ok, pid()} | {error, term()}.
start_link(OurHash) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [OurHash], []).

-doc """
Fetch a LeaseSet from the network, blocking until it resolves.

Input: `Key` — the destination hash.
Output: `{ok, LeaseSet}` once a responder's store lands (it is stored into
the NetDb by the tunnel dispatch), or `{error, not_found}` when the lookup does not
succeed. A locally cached LeaseSet replies immediately.

`not_found` covers every failure and says nothing about which. Use `f:find_ls/2` to
be told why.
""".
-spec find_ls(i2p_crypto:hash()) -> {ok, i2p_leaset:lease_set()} | {error, not_found}.
find_ls(Key) ->
    find(Key, lease, #{}).

-doc """
As `f:find_ls/1` but for a RouterInfo.
""".
-spec find_ri(i2p_crypto:hash()) -> {ok, i2p_router_info:router_info()} | {error, not_found}.
find_ri(Key) ->
    find(Key, router, #{}).

-doc """
Fetch a LeaseSet, optionally told why it failed.

Input: `Key` — the destination hash; `Opts` — see `t:lookup_options/0`.
Output: as `f:find_ls/1`, except that with `#{reason => true}` a failure arrives as
`{error, {lookup_failed, Reason}}` where `Reason` is `t:lookup_failed_reason/0`.

The reason is opt-in rather than always present because a caller that only branches
on success must not have to learn a second error shape, and because the reason is
only worth carrying to someone who will act on it. Every failure is announced on the
bus regardless of who asked.
""".
-spec find_ls(i2p_crypto:hash(), lookup_options()) ->
    {ok, i2p_leaset:lease_set()} | {error, not_found | {lookup_failed, lookup_failed_reason()}}.
find_ls(Key, Opts) ->
    find(Key, lease, Opts).

-doc "As `f:find_ls/2` but for a RouterInfo.".
-spec find_ri(i2p_crypto:hash(), lookup_options()) ->
    {ok, i2p_router_info:router_info()}
    | {error, not_found | {lookup_failed, lookup_failed_reason()}}.
find_ri(Key, Opts) ->
    find(Key, router, Opts).

-doc "Stop the orchestrator.".
-spec stop() -> ok.
stop() ->
    gen_server:stop(?MODULE).

%% find/3 — the synchronous front door shared by find_ls/find_ri.
%%
%% The reason is projected away for callers that did not ask for it, which is what
%% keeps the historical `{error, not_found}` intact. The service being absent is
%% announced like any other failure: it is a lookup that did not succeed, and on a
%% router where the orchestrator failed to start it is the *only* thing that says so.
find(Key, Kind, Opts) ->
    case whereis(?MODULE) of
        undefined ->
            failed(service_unavailable, Opts);
        _Pid ->
            project(gen_server:call(?MODULE, {find, Key, Kind}, ?OVERALL_DEADLINE_MS + 2000), Opts)
    end.

%% The reply the orchestrator gives, projected to what the caller asked for.
project({error, {lookup_failed, Reason}}, #{reason := true}) -> {error, {lookup_failed, Reason}};
project({error, {lookup_failed, _Reason}}, _Opts) -> {error, not_found};
project(Other, _Opts) -> Other.

%% A failure raised outside the orchestrator, projected the same way.
failed(Reason, Opts) ->
    i2p_events:notify({lookup_failed, undefined, none, Reason}),
    project({error, {lookup_failed, Reason}}, Opts).

-spec init([i2p_crypto:hash()]) -> {ok, state()}.
init([OurHash]) ->
    {ok, #{pending => #{}, our_hash => OurHash}}.

-spec handle_call(term(), gen_server:from(), state()) ->
    {noreply, state()} | {reply, term(), state()}.
handle_call({find, Key, Kind}, From, State = #{pending := Pending}) ->
    case cached(Kind, Key) of
        {ok, _Result} = Hit ->
            {reply, Hit, State};
        error ->
            _ =
                case maps:is_key(Key, Pending) of
                    false ->
                        %% First waiter arms the machinery.
                        self() ! {next_attempt, Key};
                    true ->
                        ok
                end,
            CallerPid = element(1, From),
            MRef = erlang:monitor(process, CallerPid),
            Entry0 =
                case maps:find(Key, Pending) of
                    {ok, P} ->
                        P;
                    error ->
                        #{
                            kind => Kind,
                            callers => [],
                            tried => [],
                            chase => [],
                            attempts => 0,
                            deadline =>
                                erlang:monotonic_time(millisecond) + ?OVERALL_DEADLINE_MS,
                            timer => undefined
                        }
                end,
            Entry = Entry0#{callers := [{From, CallerPid, MRef} | maps:get(callers, Entry0)]},
            {noreply, State#{pending := maps:put(Key, Entry, Pending)}}
    end;
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info({next_attempt, Key}, State) ->
    {noreply, attempt(Key, State)};
handle_info({db_stored, Key, Kind, Outcome}, State) ->
    {noreply, resolve_stored(Key, Kind, Outcome, State)};
handle_info({search_reply, Key, Peers}, State) ->
    {noreply, chase(Key, Peers, State)};
handle_info({attempt_timeout, Key, Ref}, State) ->
    %% Stale-timeout guard: only advance when the fired timer is still the
    %% pending one (a search reply may already have moved the lookup on).
    {noreply, attempt_timeout(Key, Ref, State)};
handle_info({'DOWN', MRef, process, _Pid, _Reason}, State) ->
    {noreply, drop_caller(MRef, State)};
handle_info(_Info, State) ->
    {noreply, State}.

%%%%%%% %%% Internal %%%%%%%

cached(lease, Key) ->
    case i2p_netdb_srv:find_ls(Key) of
        {ok, LS} -> {ok, LS};
        not_found -> error
    end;
cached(router, Key) ->
    case i2p_netdb_srv:find(Key) of
        {ok, RI} -> {ok, RI};
        not_found -> error
    end.

%% attempt_timeout/3 — advance only when the fired timer is still current.
attempt_timeout(Key, Ref, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        {ok, #{timer := Ref}} -> attempt(Key, State);
        _Other -> State
    end.

%% attempt/2 — send the next DatabaseLookup for Key, or give up.
attempt(Key, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        error ->
            State;
        {ok, P} ->
            DeadlineHit = erlang:monotonic_time(millisecond) >= maps:get(deadline, P),
            Exhausted = maps:get(attempts, P) >= ?MAX_ATTEMPTS,
            case DeadlineHit orelse Exhausted of
                true ->
                    fail(Key, State);
                false ->
                    case next_target(Key, P) of
                        {ok, Hash, P1} ->
                            Timer = arm_timer(Key),
                            P2 = P1#{attempts := maps:get(attempts, P1) + 1, timer := Timer},
                            _ = send_lookup(P2, Key, Hash, maps:get(our_hash, State)),
                            State#{pending := maps:put(Key, P2, Pending)};
                        error ->
                            fail(Key, State)
                    end
            end
    end.

%% next_target/2 — the next untried floodfill candidate, else a chase peer.
next_target(Key, P) ->
    Tried = maps:get(tried, P),
    Fresh = i2p_netdb_srv:closest_floodfills(Key, ?CANDIDATES_PER_ROUND, Tried) -- Tried,
    case Fresh of
        [Hash | Rest] ->
            {ok, Hash, P#{tried := [Hash | Tried], chase := maps:get(chase, P) ++ Rest}};
        [] ->
            case maps:get(chase, P) -- Tried of
                [Hash | Rest] ->
                    {ok, Hash, P#{tried := [Hash | Tried], chase := Rest}};
                [] ->
                    error
            end
    end.

%% send_lookup/4 — one DatabaseLookup toward Target through the tunnels.
%% Lookups prefer the short exploratory pool so client towers stay free
%% for streams; when no tunnel is active the timer simply re-arms via
%% attempt/2 until the deadline fails the lookup.
%%
%% **A send that finds no tunnel is counted, and it is the last of the three
%% injection sites that was not.** The other two charge in the caller
%% (`client_messages_dropped_no_tunnel` in `m:i2p_client`,
%% `lookup_replies_dropped_no_tunnel` in `m:i2p_peer`), so without this one a
%% lookup that never left looked identical to a lookup nobody answered -- which
%% is the distinction `t:lookup_failed_reason/0` exists to draw. `attempt/2`
%% discards this function's answer at the call site, so the count has to happen
%% here or not at all.
%%
%% Exported for the same reason `m:i2p_peer:reply_via_outbound/3` is, and the
%% same reason it is needed rather than merely convenient: the condition needs
%% the two picks to answer `{ok, _}` and the send to answer `error`, and those
%% are three separate calls. A real tunnel manager holding a real tunnel answers
%% `ok` to all three, so reaching this branch means retiring a tunnel inside the
%% window -- a race no test should depend on. Calling it against a stub that
%% answers per request is the only way to put a red case on the line that
%% changed rather than a green one on the give-up path beside it.
-spec send_lookup(pending(), i2p_crypto:hash(), i2p_crypto:hash(), i2p_crypto:hash()) ->
    ok | error.
send_lookup(P, Key, Target, OurHash) ->
    case i2p_tunnel_srv:pick_lookup_inbound() of
        {ok, RecvTid, _InEntry} ->
            Flag = flag_for(maps:get(kind, P)),
            Msg = i2p_i2np:db_lookup_via_tunnel(Key, OurHash, Flag, RecvTid, []),
            StdBin = std_binary(Msg),
            case i2p_tunnel_srv:pick_lookup_outbound() of
                {ok, OutTid, _OutEntry} ->
                    send_lookup_wire(OutTid, {router, Target}, StdBin);
                error ->
                    error
            end;
        error ->
            error
    end.

%% send_lookup_wire/3 — the injection, with its one counted failure mode. The
%% two-step pick-then-send means the tunnel can be retired in between, so
%% `error` here is a real condition and not a theoretical one.
%%
%% **The answer is returned as well as counted.** `f:add/2` answers `ok`, so
%% letting it stand in for the branch's value would quietly widen this
%% function's contract from `ok | error` to `ok` -- and the two callers of that
%% answer would stop being able to tell a delivered query from a lost one. The
%% count is a side effect on the loss, never a replacement for the answer.
%%
%% The delivery is always `{router, Hash}`: a DatabaseLookup names a floodfill
%% or a chase peer, and there is no inbound tunnel of ours for the far end to
%% inject into. No `-spec` here because this module specs no internal helper,
%% and the one that would fit — a standard-header message is at least 64 bits
%% — describes `f:i2p_i2np:encode_std/1` rather than this function.
send_lookup_wire(OutTid, Delivery, StdBin) ->
    case i2p_tunnel_srv:send_via_outbound(OutTid, Delivery, StdBin) of
        ok ->
            ok;
        error ->
            ok = i2p_stats:add(lookup_requests_dropped_no_tunnel, 1),
            error
    end.

%% std_binary/1 — a builder-produced message map to wire form; builders stamp
%% `expiration` in epoch seconds while the standard header wants a relative
%% lifetime in milliseconds.
std_binary(#{type := Type, msg_id := MsgID, body := Body}) ->
    i2p_i2np:encode_std(#{
        type => Type,
        msg_id => MsgID,
        expiration_ms => 60_000,
        body => Body
    }).

flag_for(lease) -> i2p_i2np:lookup_type_leaseset();
flag_for(router) -> i2p_i2np:lookup_type_routerinfo().

arm_timer(Key) ->
    Ref = erlang:make_ref(),
    erlang:send_after(?ATTEMPT_TIMEOUT_MS, self(), {attempt_timeout, Key, Ref}),
    Ref.

%% resolve_stored/4 — a responder sent us a store for a pending key.
%%
%% The first recording point, and where the reason is available rather than inferred:
%% the tunnel dispatch has just put the record in the NetDb and knows whether it was
%% taken, and it says so in the message. That is the whole plumbing this ticket needs
%% — the reason travels the way the store outcome already did — and it is why a
%% lookup that fails here does not report as a timeout.
%%
%% A lookup that succeeds publishes nothing. The event is about failure, and one that
%% also fired on success could not be counted without a subtraction.
resolve_stored(Key, Kind, Outcome, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        error ->
            State;
        {ok, P} ->
            cancel_timer(P),
            case cached(maps:get(kind, P), Key) of
                {ok, _R} = Hit ->
                    reply_all(maps:get(callers, P), Hit),
                    State#{pending := maps:remove(Key, Pending)};
                error ->
                    %% The wake-up arrived, the key is not usable. Two different
                    %% things produce this and they are not the same event: the NetDb
                    %% refused the record, or it took it and the key still does not
                    %% hold what this lookup wanted.
                    Reason = stored_failure(Kind, Outcome),
                    i2p_events:notify({lookup_failed, Key, Kind, Reason}),
                    reply_all(
                        maps:get(callers, P), {error, {lookup_failed, Reason}}
                    ),
                    State#{pending := maps:remove(Key, Pending)}
            end
    end.

%% Why a wake-up left the key unusable.
%%
%% A refused store is reported as refused, and the reason is the store path's own.
%% A store that was taken is reported as unresolved, because if it had been usable
%% `cached/2` would have found it and this function would not be here.
stored_failure(_Kind, {not_stored, Reason}) ->
    {not_stored, Reason};
stored_failure(_Kind, stored) ->
    not_resolved.

%% chase/3 — a search reply contributed closer routers to try.
chase(Key, Peers, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        error ->
            State;
        {ok, P} ->
            cancel_timer(P),
            P1 = P#{chase := Peers ++ maps:get(chase, P)},
            _ = self() ! {next_attempt, Key},
            State#{pending := maps:put(Key, P1, Pending)}
    end.

drop_caller(MRef, State = #{pending := Pending0}) ->
    Pending =
        maps:filtermap(
            fun(_Key, P) ->
                case [C || C = {_F, _Pid, R} <- maps:get(callers, P), R =/= MRef] of
                    [] ->
                        cancel_timer(P),
                        false;
                    Live ->
                        {true, P#{callers := Live}}
                end
            end,
            Pending0
        ),
    State#{pending := Pending}.

%% fail/2 — the lookup has run out of attempts or has passed its deadline.
%%
fail(Key, State = #{pending := Pending}) ->
    case maps:find(Key, Pending) of
        error ->
            State;
        {ok, P} ->
            cancel_timer(P),
            %% The second recording point, and the reason it needs no handover to
            %% carry a reason here: a wake-up that arrived and was unusable ended the
            %% lookup in `f:resolve_stored/4` and announced itself there. Reaching this
            %% function at all means no store for this key ever became usable, so the
            %% only reason available -- and the only honest one -- is that nobody
            %% answered. An earlier version left a refusal on the pending entry for
            %% this function to read back, which could never fire: `resolve_stored/4`
            %% removes the entry on every path that reaches it.
            Reason = no_answer,
            i2p_events:notify({lookup_failed, Key, maps:get(kind, P), Reason}),
            reply_all(maps:get(callers, P), {error, {lookup_failed, Reason}}),
            State#{pending := maps:remove(Key, Pending)}
    end.

reply_all(Callers, Reply) ->
    lists:foreach(
        fun({From, _Pid, MRef}) ->
            erlang:demonitor(MRef, [flush]),
            gen_server:reply(From, Reply)
        end,
        Callers
    ).

cancel_timer(P) ->
    case maps:get(timer, P, undefined) of
        undefined ->
            ok;
        Ref ->
            _ = erlang:cancel_timer(Ref),
            ok
    end.
