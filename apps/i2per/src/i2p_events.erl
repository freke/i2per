-module(i2p_events).

-moduledoc """
Router-wide status event bus (`gen_event` manager).

State changes across the router are announced here so external observers —
notably the separate `i2per_status` web service — can follow them in real
time. Attaching is `f:subscribe/1` and `f:unsubscribe/1`, and **nothing outside
the core calls `gen_event:*`**, which is what makes replacing this manager an
internal refactor rather than a contract break:

```erlang
%% One entry point for a local and a remote subscriber alike. `Collector` may
%% be a pid on any node; on another node, reach the router over distribution and
%% the call lands where the manager is registered.
ok = i2p_events:subscribe(self()).
receive {event, Event} -> ... end.
```

Emitted events (`t:event/0`):

- `{peer_connected, PeerHash}` / `{peer_disconnected, PeerHash}` /
  `{peer_connect_failed, PeerHash, Reason, BackoffSeconds}` — a connect that
  did not become a connection, with the interval the router will now wait
- `{ssu2_dial_parked, PeerHash, Reason}` — a dial sat on SSU2, gave up, and
  went to NTCP2 instead, with the reason it gave up. Distinct from
  `peer_connect_failed`, which needs *both* legs to fail and so never fires
  for a peer that connected over TCP: a park costs real time and connects
  anyway, so the fact that would report it had no instrument
- `{peer_send_stalled, PeerHash, Reason}` — a peer stopped accepting our sends
- `{tunnel_built, Direction, Hops}` / `{tunnel_failed, Direction, Why}` /
  `{tunnel_expired, Direction}`
- `{transit_denied, ReceiveTunnelId, Reason}` — a transit tunnel this router
  refused to carry, and which of the three reasons applied
- `{leaseset_published, DestHash}` / `{leaseset_publish_failed, DestHash, Reason}`
- `{peertest_result, AddressType, Result}` — one SSU2 peer test concluded
- `{reachability, ssu2, Status}` — the router's inbound reachability decision,
  derived from `peertest_result` events (`firewalled` | `reachable` | `unknown`)
- `{lookup_failed, Key, Kind, Reason}` — a lookup did not produce its record; the
  reason separates a responder that answered with something unreadable from one
  that never answered
- `{sam_session_created, SessionId, Style}` / `{sam_session_closed, SessionId}`
- `{config_changed, Key, Value}`

The three failure events — `peer_connect_failed`, `transit_denied`,
`leaseset_publish_failed` — are the answer to "this router is not working and
nothing says why". Each is announced at the point the thing happens, once per
failure rather than once per packet, and each names what failed and why.

Delivery is best-effort: `f:notify/1` always returns `ok` even when the manager
is not running (emitters must never crash over telemetry). The manager is the
first permanent child of the supervisor tree, so while any emitter runs the
manager is up; discarding rare delivery failures keeps telemetry out of the
data path instead of crashing working connections over it.

**The manager's heap carries a bound**, `f:max_heap_words/0`, and crossing it kills
the manager rather than letting the backlog grow without limit. A handler that never
returns parks the manager inside `server_notify/4`, and the events behind it queue
unbounded while `events_notified` climbs regardless — a status page silently frozen
whose counter still moves.

**Read the bound's limit before relying on it: it is evaluated at garbage
collection, so it does not bound a bus that is already wedged.** That case is
measured, not suspected — see the note on `?MAX_HEAP_WORDS` below. The bound is a
defect detector on the manager's own heap, not a bound on the backlog a wedged
handler accumulates; the latter is the gap this does not close.
""".

-behaviour(gen_event).

-export([start_link/0, max_heap_words/0, notify/1, subscribe/1, unsubscribe/1]).

-export([init/1, handle_event/2, handle_call/2, handle_info/2, terminate/2, code_change/3]).

-export_type([event/0, direction/0, lookup_kind/0, subscribe_error/0]).

-doc """
Why a subscription did not happen.

`t:no_bus/0` — there is no bus on this node, so nothing was asked.
`t:wedged/0` — the bus did not answer within `?SUBSCRIBE_BOUND_MS`. **The
subscription may still take effect afterwards**: `gen_event` adds the handler
before it replies, so this answer means "did not complete", not "did not
happen".
`{t:bus_error/0, Reason}` — the bus answered, and the answer was not `ok`.
""".
-type subscribe_error() :: no_bus | wedged | {bus_error, term()}.

-doc "Tunnel direction.".
-type direction() :: inbound | outbound.

-doc """
Which kind of record a `lookup_failed` event was about.

`none` for a failure that is not about a particular record — currently only the
lookup service not being running, where there is no key and nothing was asked for.
""".
-type lookup_kind() :: lease | router | none.

-doc "One router status change, as announced on the bus.".
-type event() ::
    {peer_connected, i2p_crypto:hash()}
    | {peer_disconnected, i2p_crypto:hash()}
    %% A connect attempt that did not become a connection, with the reason the
    %% connection process gave (or `unknown`, for a failure with nothing more to
    %% report) and the backoff now in effect, in seconds. The interval is the
    %% load-bearing field: without it a peer being retried in a tight loop and a
    %% peer the router has given up on look identical.
    | {peer_connect_failed, i2p_crypto:hash(), term(), pos_integer()}
    %% A dial waited on SSU2, gave up, and fell back to NTCP2, carrying why.
    %% **Not a peer that could not be connected** — that is `peer_connect_failed`,
    %% and it needs both legs to fail, so it never fires for the peer this event
    %% describes most often: one that answered on TCP and left a UDP stall behind.
    %% The reason is the load-bearing field, because it is the one bit that says
    %% something came back: `{protocol_error, _}` means a datagram arrived and
    %% could not be used, which is proof UDP works that way, while
    %% `{handshake_timeout, _}` and `timeout` are silence. See
    %% `m:i2p_peer:ssu2_park_reason/0`.
    | {ssu2_dial_parked, i2p_crypto:hash(), i2p_peer:ssu2_park_reason()}
    %% A peer that stopped accepting our sends, and why. The counterpart of
    %% `peer_disconnected`, which says the connection is gone without saying
    %% whether it went on its own terms. A session that merely degrades when it
    %% is busy and one that has stopped taking writes are different faults, and
    %% only this one says which.
    | {peer_send_stalled, i2p_crypto:hash(), i2p_ntcp2_conn:send_stalled_reason()}
    | {tunnel_built, direction(), pos_integer()}
    | {tunnel_failed, direction(), rejected | invalid}
    | {tunnel_expired, direction()}
    %% A build record this router refused to carry, with the receive tunnel ID it
    %% was for and which of the three refusal causes applied.
    | {transit_denied, 0..16#FFFFFFFF, i2p_tunnel_relay:transit_denied_reason()}
    | {leaseset_published, i2p_crypto:hash()}
    %% A client LeaseSet that did not reach the network, with the destination and
    %% the reason. The counterpart of `leaseset_published`, which used to be
    %% announced whether or not anything had actually been published.
    | {leaseset_publish_failed, i2p_crypto:hash(),
        i2p_tunnel_publish:leaset_publish_failed_reason()}
    | {sam_session_created, binary(), term()}
    | {sam_session_closed, binary()}
    | {peertest_result, i2p_peertest:address_type(), i2p_peertest:result()}
    | {reachability, ssu2, firewalled | reachable | unknown}
    | {ssu2_block_unhandled, atom()}
    | {db_store_not_stored, i2p_peer:store_not_stored_reason()}
    %% A lookup that did not produce the record it was asked for. The reason is the
    %% whole point: `no_answer` means nobody answered, while `{not_stored, _}` means
    %% a peer *did* answer and this router could not use what it was given. Those are
    %% opposite problems and used to be the same result.
    | {lookup_failed, i2p_crypto:hash() | undefined, lookup_kind(),
        i2p_lookup_srv:lookup_failed_reason()}
    | {config_changed, atom(), term()}.

%% %%%%% The bound on the manager's heap %%%%% %%%
%%
%% ## What the bound is, and the one thing it does not do
%%
%% **It bounds the manager's heap, and it is a defect detector rather than a
%% load-shedding valve:** correct operation never approaches it, so crossing it
%% means something is wrong rather than that we are busy.
%%
%% **It does not bound the backlog behind a wedged handler, and this is the
%% finding that shaped the whole ticket.** `max_heap_size` is evaluated **at
%% garbage collection**. A handler that never returns parks the manager inside
%% `server_notify/4` holding no data, so the manager allocates nothing, performs
%% no GC, and the bound is never evaluated — while the events behind it queue
%% unbounded. Measured on this build with this bound in force:
%%
%% - 1,200,000 queued events → `total_heap_size` **14,400,089 words** against a
%%   **300,000-word** bound → **still running**
%% - `minor_gcs` delta over that flood: **0**
%% - the same wedged bus, after one `erlang:garbage_collect/1` → **killed**
%%
%% So the bound is fatal to a backlog *once the manager collects*, and cannot fire
%% at all for a manager that never will. The two are different claims and only the
%% first is true of this mechanism. The A/B is what the case
%% `m:i2p_events_tests` pins, and it is why that case forces a GC instead of
%% waiting for a kill that a wedged bus will never deliver on its own.
%%
%% ## Why `spawn_opt` and not the child spec
%%
%% **A `max_heap_size` key in `m:i2per_sup`'s child spec is silently ignored at
%% OTP 28.5 / stdlib 7.3.0.2, and that was measured rather than believed.** A
%% `gen_event` child started with `max_heap_size => 2000` reported
%% `max_heap_size => #{size => 0}` — no limit — and survived a heap of 93,609,153
%% words. `supervisor.erl` in this stdlib contains no occurrence of the string
%% `max_heap_size` at all, `child_spec()` has no such key, and an unrecognised key
%% is not rejected, so a spec carrying one reads exactly like a closed backlog
%% while bounding nothing. Hence the option is passed here, which is the only
%% place it reaches the process: `{spawn_opt, [{max_heap_size, N}]}` on
%% `gen_event:start_link/2` (`gen_event.erl:756`). Two other routes are closed too
%% — `erlang:process_flag(Pid, max_heap_size, _)` on another process is `badarg`,
%% and self-setting from `f:init/1` cannot work either, because `gen_event` starts
%% the manager under `?NO_CALLBACK`, so `f:init/1` is the *event handler* callback
%% and never runs in the manager's process.
%%
%% ## How the number was chosen
%%
%% From measurement, in this order:
%%
%% - Baseline manager heap: **233 words**.
%% - One queued `{notify, Event}`: **~12.33 words (~99 bytes)**, from a 20,000-event
%%   wedge run (246,572 words of heap delta).
%% - Legitimate peak with `f:notify/1` instrumented across the whole gate:
%%   **299 words** over 223 CT cases (249 over 972 eunit), with the mailbox
%%   **empty at every single observation**.
%%
%% That last fact is why the number is not the peak times a small multiple.
%% `notify/1` is a cast, so the notifier never waits and correct operation builds
%% no backlog at all — the peak is baseline plus a message or two in flight.
%% **The peak cannot size a bound; it only proves the bound sits far from ordinary
%% running.** The number is set from that distance: ~1000x the measured peak, so
%% normal running cannot approach it, while a manager that *does* collect with a
%% real backlog behind it dies immediately.
%%
%% **Three different figures, deliberately not interchangeable.** This is
%% **300,000 words**, which is **2,400,000 bytes**, which is **~24,331 events** at
%% the measured per-event cost. It bounds *bytes of heap*; the message count is a
%% derived consequence, not a second limit — and per the paragraph above it is not
%% even a limit, because an uncollected manager crosses no bound at all.
%%
%% ## What crossing it does, which is destructive and deliberate
%%
%% The manager is **killed**, and `m:i2per_sup` gives `i2p_events`
%% `restart => permanent`, so the supervisor restarts it with **zero handlers** and
%% nothing re-attaches: `m:i2p_ssu2_reachability` subscribes once in its
%% `f:init/1`, and `m:i2per_status_state` re-subscribes only on `{nodeup, Node}`,
%% which a restart on a live node never produces. Both detach silently and
%% permanently.
%%
%% That is accepted rather than worked around, on the maintainer's standing rule
%% that volatile data is volatile by design and its loss is not a defect: `m:i2p_stats`
%% is a visualizer over counters that die with their process, and a restart of
%% anything upstream is a smaller version of an event the system already handles
%% deliberately. **A silent detach is the real cost, and it is why the log records
%% matter:** the supervisor's report carries the size at death, so the bound firing
%% is in the log even though the detach itself is not.
-define(MAX_HEAP_WORDS, 300000).

-doc """
Start the manager.

Registered locally as `i2p_events`; called only by `m:i2per_sup` as the first
child of the tree. Output: the usual `gen_event` start result.

The manager is spawned with `max_heap_size` set to `f:max_heap_words/0`, which is
why the bound lives here and not in the supervisor's child spec — a child-spec key
is silently ignored at this OTP. The note on `?MAX_HEAP_WORDS` above carries both
that measurement and the bound's real reach.
""".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_event:start_link(
        {local, ?MODULE}, [{spawn_opt, [{max_heap_size, ?MAX_HEAP_WORDS}]}]
    ).

-doc """
The manager's heap bound in **words**, as passed to `max_heap_size`.

Exported so a case can assert the bound is actually in force on the running bus
rather than inferring it from a source constant, and so the unit of the number is
stated in one place. 300,000 words is ~2.4 MB and, at the measured cost of one
queued event, ~24,000 events — three different figures, of which this is the one
the runtime is actually given.

**What it bounds, precisely:** the manager's own heap, evaluated at garbage
collection. It does not bound the backlog a wedged handler accumulates, because
such a manager never collects. See the note on `?MAX_HEAP_WORDS` for the
measurement.
""".
-spec max_heap_words() -> pos_integer().
max_heap_words() ->
    ?MAX_HEAP_WORDS.

%% dialyzer reads through to the literal 300000 and calls the spec a supertype,
%% which is true and useless here: the value is the point of the function, and
%% narrowing the return type to the constant would put the number in two places.
-dialyzer({nowarn_function, [max_heap_words/0]}).

-doc """
Announce a status change.

Input: an event from `t:event/0`. Output: always `ok` — delivery failures are
discarded deliberately (see the module doc).
""".
-spec notify(event()) -> ok.
notify(Event) ->
    ok = i2p_stats:add(events_notified, 1),
    case whereis(?MODULE) of
        undefined ->
            ok;
        _ ->
            _ = gen_event:notify(?MODULE, Event),
            ok
    end.

%% %%%%% %%% The published entry point %%%%% %%%
%%
%% #WGV1SZ7. `f:gen_event:add_handler/3` and `f:gen_event:delete_handler/3` are
%% the only way to attach to the bus today, and each caller has to know three
%% internal facts: the registered name, the forwarder module, and that the
%% argument is a pid. The two production subscribers **disagreed about the
%% first** — `m:i2per_status_state` used `{i2p_events, Node}` and
%% `m:i2p_ssu2_reachability` used bare `i2p_events` — which is the duplication
%% this pair exists to remove.
%%
%% The local/remote asymmetry disappears with it: a caller on another node
%% reaches these through `erpc:call(RouterNode, i2p_events, subscribe, [Pid])`,
%% so the code runs where the manager is registered and `?MODULE` is the right
%% name in both cases.

-doc """
Subscribe a collector to the bus.

`Collector` is a pid on **any** node; the router's shipped forwarder
(`m:i2p_events_forward`) carries each event to it as `{event, Event}`. Because
`Collector` may be remote and this function may be reached over distribution,
the caller supplies no node and no handler module — which is the whole point of
the entry point.

Input: `Collector`, a pid. Output: `ok`, or `{error, Reason}` — see
`t:subscribe_error/0`. Never exits, and never waits without end, for a bus that
is absent or wedged.
""".
-spec subscribe(pid()) -> ok | {error, subscribe_error()}.
subscribe(Collector) when is_pid(Collector) ->
    bounded(fun() -> attach(Collector) end).

-doc """
Remove a collector's subscription, added by `f:subscribe/1`.

**Idempotent: `ok` whether or not there was a subscription to remove.** A caller
that unsubscribes during shutdown cannot know whether it was ever attached, and
answering differently for the two cases would force every caller to handle a
distinction it has no use for. `f:gen_event:delete_handler/3` itself answers
`{error, module_not_found}` for the nothing-to-remove case, so that is collapsed
here rather than passed on.

Input: `Collector`, the pid passed to `f:subscribe/1`. Output: `ok`, or
`{error, Reason}` — see `t:subscribe_error/0`.
""".
-spec unsubscribe(pid()) -> ok | {error, subscribe_error()}.
unsubscribe(Collector) when is_pid(Collector) ->
    bounded(fun() -> detach(Collector) end).

%% %%%%% %%% Why the wait is bounded %%%%% %%%
%%
%% `gen_event:add_handler/3` and `gen_event:delete_handler/3` are both `rpc/2`,
%% which is `gen:call(M, self(), Cmd, infinity)` (`gen_event.erl:1576`). There is
%% no timeout argument to pass and none to choose, so **every one of those calls
%% waits without end on a bus that is wedged.** Measured on this build against a
%% manager parked inside `handle_event/2`: `add_handler/3`, `delete_handler/3`
%% and `stop/1` were all still running at a 3 s deadline, while the same
%% `add_handler/3` against a healthy manager answered `ok` in **273 µs**. The
%% wait is not slow — it has no end.
%%
%% **`catch` does not rescue it, which is the part that is easy to get wrong.**
%% `catch` fires on an exit, and this call never exits: it is parked in a
%% `receive`. Measured through `m:i2per_status_state:f:subscribe/1`'s own
%% `catch gen_event:add_handler(...) =:= ok`, a wedged bus blocked rather than
%% answering `false`, so the `catch` guarding that boundary was never reached.
%%
%% The reach is the router, not the bus. `m:i2per_sup` lists `events_child()`
%% first and `reachability_child()` fifth, so a bus wedged when
%% `m:i2p_ssu2_reachability:f:init/1` subscribes blocks the supervisor's own
%% `init/1` and the router never finishes starting.
%%
%% ## Why the bound is generous rather than tight
%%
%% Measured against a healthy manager the call answers in hundreds of
%% microseconds, so the number is not sizing a real latency — **it is a hang
%% guard, and the only thing it needs to be is comfortably longer than any answer
%% the bus gives in correct operation.** Tightening it would risk failing a
%% correct subscribe under load, and a false `wedged` is worse than a slow one:
%% it reports a bus that is working as one that is not.
%%
%% ## What a `wedged` answer does not say
%%
%% **It does not say the subscription did not happen.** `gen_event` adds the
%% handler and *then* replies, so a call abandoned here may still be carried out
%% once the bus drains. `f:subscribe/1` is therefore convergent — see
%% `f:detach_all/2` — because being attached twice is a state a caller must be
%% able to recover from rather than one it can detect.
-define(SUBSCRIBE_BOUND_MS, 5000).

%% Ask the bus, giving up after `?SUBSCRIBE_BOUND_MS`.
%%
%% The call is made from a process this function owns and can kill, because the
%% alternative is a `receive` with no deadline — the thing being fixed. The reply
%% carries the value rather than being read off the `'DOWN'`, since a fun whose
%% value is discarded exits `normal` whether the call answered or exited, which
%% would report both identically.
%%
%% **Killing the asker does not cancel the request.** The message is already in
%% the manager's mailbox and the manager will process it when it drains, which is
%% the reason `f:subscribe/1` converges rather than simply giving up.
bounded(Fun) ->
    case whereis(?MODULE) of
        undefined ->
            {error, no_bus};
        _Pid ->
            Parent = self(),
            Ref = make_ref(),
            {Asker, MRef} = spawn_monitor(fun() -> Parent ! {Ref, (catch Fun())} end),
            Reply =
                receive
                    {Ref, Answer} -> classify(Answer)
                after ?SUBSCRIBE_BOUND_MS ->
                    exit(Asker, kill),
                    {error, wedged}
                end,
            %% **The `'DOWN'` is consumed on both paths, and that is load-bearing
            %% rather than tidiness.** The asker is dead either way, but a
            %% `'DOWN'` left in the caller's mailbox is a stray message in
            %% whatever process called this — and the unit tier runs every module
            %% in one shared worker, so the message is inherited by whichever
            %% module reads its mailbox next. #SG93V0P is that class: a leak here
            %% reddens a test in a module that never mentions the bus.
            receive
                {'DOWN', MRef, process, _Asker, _Reason} -> ok
            after ?SUBSCRIBE_BOUND_MS ->
                ok
            end,
            Reply
    end.

%% `ok` stays `ok`; an exit becomes `{bus_error, Reason}`. `catch` turns a
%% `gen_event` failure into the `{'EXIT', Reason}` tuple rather than an exit of
%% the caller, so both shapes are folded to the same thing here.
classify(ok) -> ok;
classify({error, Reason}) -> {error, {bus_error, Reason}};
classify({'EXIT', Reason}) -> {error, {bus_error, Reason}}.

%% Attach, having first made the bus hold exactly one forwarder for this
%% collector.
%%
%% The clear-out is what makes a resubscribe safe. `f:subscribe/1` can be
%% abandoned at `?SUBSCRIBE_BOUND_MS` while the bus still carries the request out,
%% so arriving here may find a handler this collector did not ask for -- and
%% because `gen_event` neither dedups on add nor removes more than one per delete,
%% a plain add on top of it would leave two, and two forwarders deliver every
%% event twice. See `f:detach_all/2`.
attach(Collector) ->
    ok = detach_all(Collector),
    gen_event:add_handler(?MODULE, {i2p_events_forward, Collector}, [Collector]).

%% Remove every forwarder this collector holds, so the next attach leaves exactly
%% one.
%%
%% **Deleting in a loop rather than once, because one delete is not enough.**
%% `gen_event:delete_handler/3` removes exactly one handler per call and
%% `server_add_handler` prepends unconditionally, so N stray handlers need N
%% deletes -- and delete-then-add does *not* converge: measured, a bus holding 2
%% left it holding 2, because one delete removed one and the add made two again.
%% `{error, module_not_found}` is how the bus reports there is nothing left
%% (`gen_event.erl:1848`).
%%
%% **The loop needs no guard of its own.** Each iteration removes a handler from a
%% finite list, so it terminates; and it runs inside `f:bounded/1`, which kills
%% the asker at `?SUBSCRIBE_BOUND_MS` regardless.
detach_all(Collector) ->
    case gen_event:delete_handler(?MODULE, {i2p_events_forward, Collector}, [Collector]) of
        {error, module_not_found} -> ok;
        ok -> detach_all(Collector)
    end.

detach(Collector) ->
    case gen_event:delete_handler(?MODULE, {i2p_events_forward, Collector}, [Collector]) of
        {error, module_not_found} -> ok;
        Other -> Other
    end.

%% %%%%% %%% gen_event callbacks %%%%% %%%
%% The manager ships without built-in handlers; subscribers attach their own.

init([]) ->
    {ok, []}.

handle_event(_Event, State) ->
    {ok, State}.

handle_call(_Query, State) ->
    {ok, {error, unsupported}, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Arg, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
