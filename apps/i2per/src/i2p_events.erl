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

The manager starts before every subscriber, so a bus that is up is a bus something
can already attach to. `m:i2per_sup` now lists `stats_child()` ahead of it, which
changed the *first* claim here without changing the reason: the guarantee that
matters is that the manager precedes `reachability_child()`, whose `init/1`
subscribes.

**A handler that never returns parks the manager inside `server_notify/4`,** and the
events behind it queue without limit while `events_notified` climbs regardless — a
status page silently frozen whose counter still moves.

**That case is reported rather than bounded.** The backlog depth is sampled by
`f:sample_backlog/0` and published as the `bus_backlog` gauge in `m:i2p_stats`, so it
reaches the read API under `i2p_status_data:view/0`'s `gauges` key. The read works on
a wedged manager — measured at 0us per sample against a depth of 2.8 million —
because `process_info/2` does not go through the process it describes, while every
`f:gen_event` call does. A depth alone does not distinguish a backlog from a wedge:
what identifies the fault is a depth that does not fall, which is the consumer's to
read.

**A subscriber on another node has the same problem, and the far side cannot be
bounded at all.** `f:sample_far_backlog/0` reads the queue depth of every remote
subscriber and answers with the deepest. It is a **read rather than a published
figure**, which is the shape the layering requires: the core does not hand data to a
stats process it does not control, so nothing here is pushed anywhere on a timer.
**Neither of the two figures bounds anything.** The near side was measured and the
bound removed (#VH7Z0KJ); the far side has no cap available even in principle —
measured, in the note on that function: `process_info/2` is `badarg` against a remote
pid, the distribution exposes no queue depth on this OTP, and `{async_dist, false}`
does not stop the far mailbox filling because the runtime applies no back-pressure to
a process that is not consuming. The router cannot stop a subscriber on a machine it
does not own from growing; it can only say how far behind that subscriber is.

The manager carries **no** heap bound. One was measured and removed; the note on *Why
there is no heap bound* below carries the measurements for and against it.
""".

%% **No `-behaviour(gen_event)` on purpose, and it was one until #N722YKK removed
%% it.** This module is not a manager and cannot be one on this OTP -- see *The
%% manager is `gen_event`'s own module* below -- so the attribute asserted an
%% arrangement that does not exist. Dialyzer read it as one and was satisfied by
%% six function heads: a behaviour is checked against what is *defined*, never
%% against what is *reached*, which is the whole reason those six read as covered.

-export([
    start_link/0,
    notify/1,
    subscribe/1,
    unsubscribe/1,
    subscribers/0,
    sample_backlog/0,
    sample_far_backlog/0
]).

-export_type([event/0, direction/0, lookup_kind/0, subscribe_error/0]).

-doc """
Why a subscription did not happen. Each cause is a member of the union below,
so it is written as the atom it is rather than as a link to a type.

`no_bus` — there is no bus on this node, so nothing was asked.
`wedged` — the bus did not answer within `?SUBSCRIBE_BOUND_MS`. **The
subscription may still take effect afterwards**: `gen_event` adds the handler
before it replies, so this answer means "did not complete", not "did not
happen".
`{bus_error, Reason}` — the bus answered, and the answer was not `ok`.
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

%% %%%%% Why there is no heap bound on the manager %%%%% %%%
%%
%% ## It was there, and the measurement said it could not do its job
%%
%% The manager used to be spawned with `{max_heap_size, 300000}`, adopted to bound
%% the backlog a wedged handler accumulates. Two measurements removed it, both on
%% this build at OTP 28.5 / ERTS 16.4.0.6.
%%
%% **It could not fire for the case it was adopted for.** `max_heap_size` is
%% evaluated *at garbage collection*. A handler that never returns parks the
%% manager inside `server_notify/4` holding no data, so the manager allocates
%% nothing, never collects, and the bound is never evaluated -- while the events
%% behind it queue without limit. Measured with the bound in force: 1,200,000
%% queued events, `total_heap_size` 14,400,089 words against a 300,000-word bound,
%% still running, `minor_gcs` delta **0**. One `erlang:garbage_collect/1` and the
%% same bus was killed.
%%
%% **And it fired on ordinary load instead.** The number was sized at ~1000x a
%% "legitimate peak" of 299 words measured with the mailbox *empty at every single
%% observation*. A loaded manager does not look like that, because the bound is
%% compared against `total_heap_size`, which measures heap *capacity* -- blocks,
%% message buffer, stack, off-heap binary arena -- and not live data:
%%
%% | manager | `total_heap_size` |
%% |---|---|
%% | idle | 233 |
%% | after 400,000 events, fully drained (empty mailbox, status `waiting`) | **92,844** |
%% | the same manager after one `erlang:garbage_collect/1` | **233** |
%%
%% So a drained manager's live footprint is 233 words while the same manager
%% reports 92,844 -- 31% of the bound -- of uncollected garbage. Two producers
%% then killed a *healthy* manager at a queue depth of **487** messages, with no
%% subscriber attached at all and nothing wedged. Measured capacity is ~1M
%% events/s, so the real headroom was ~1.6x dispatch capacity, not ~1000x.
%%
%% What it bought for all that was a kill that detaches every subscriber silently
%% and permanently: `m:i2per_sup` restarts the bus with zero handlers and nothing
%% re-attaches. Protecting against an unreachable case at the price of a reachable
%% one is a bad trade, so the bound is gone and the backlog is **reported** instead.
%%
%% ## What replaced it: a gauge, not a bound
%%
%% **A handler that wedges the manager is now visible rather than bounded.** The
%% backlog depth is sampled by `f:sample_backlog/0` and published through
%% `m:i2p_stats:set_gauge/2` as `bus_backlog`, reaching the read API under
%% `m:i2p_status_data:view/0`'s `gauges` key.
%%
%% **That is possible because the read does not go through the manager**, which is
%% the property the bound lacked. Measured on a wedged manager, sampling every
%% 200ms: `process_info(Pid, message_queue_len)` answered in **0us** every time,
%% reporting a monotone 936,710 -> 2,803,109. `gen_event:which_handlers/1` -- the
%% management API -- never answered at all, after 1500ms. So a report of the fault
%% does not inherit the fault.
%%
%% **Depth alone does not say "wedged", and this should not pretend otherwise.**
%% 300 messages for 10ms is ordinary traffic; the fault is a depth that does not
%% fall. Reading that is the consumer's job -- `m:i2per_status_derive` already
%% compares consecutive readings -- and it is deliberately not done here, because
%% deciding what counts as stuck is the operator's policy rather than the core's.

-doc """
Start the manager, and the backlog sampler.

Registered locally as `i2p_events`; called only by `m:i2per_sup` as the first
child of the tree. Output: the usual `gen_event` start result.

**No `max_heap_size` on the manager, deliberately.** See *Why there is no heap
bound* above for the two measurements that removed it and what replaced it.

**`{async_dist, true}` on the spawn.** Without it, a subscriber node that
stops draining its distribution socket parks the manager inside the send --
measured 12 of 26 samples suspended under a 200,000-event flood, mailbox
peaking at 169,327 (#ZYNNQKQ). With it, the send never blocks the manager;
the backlog then shows up where it can be watched: `bus_backlog` on the
read API and the far side's own memory, not a parked bus. It is spawned this
way because `gen_event:start_link/2`'s `spawn_opt` is the same route the
removed heap bound took.
""".
-spec start_link() -> {ok, pid()} | {error, term()}.
%% dialyzer: nowarn because proc_lib:start_spawn_option() has no
%% {async_dist, boolean()} entry even though the BIFs accept it and the flag
%% demonstrably lands (verified: process_flag(async_dist, false) in the
%% spawned process reads back true). An OTP types gap, not a bad call.
-dialyzer({nowarn_function, start_link/0}).
%% start_sampler/0 inherits a poisoned success typing from the same type gap:
%% with start_link/0's Ok path invisible to dialyzer, a caller of it looks
%% unreachable. Knock-on of the same causes as above, not dead code — the
%% sampler is what reports the backlog (#VH7Z0KJ).
-dialyzer({nowarn_function, start_sampler/1}).
%% **The sampler's internals, and it is the same knock-on as the two above.**
%% They are reached only from the fun `f:start_sampler/1` spawns, and with
%% `f:start_link/0`'s Ok path invisible to dialyzer the spawn is inside a function
%% whose success typing is `no_return`, so the reference does not count and dialyzer
%% reports "will never be called". Not dead code: `f:start_sampler/1` is called from
%% `f:start_link/0`'s Ok branch, and the sampler is what owns the subscriber registry
%% and reports the backlog (#VH7Z0KJ). The clean fix is the `{async_dist, boolean()}`
%% entry in `proc_lib:start_spawn_option()`'s type, which is OTP's to make.
%%
%% **The registry's reconciler is in this class too, which a comment here once
%% claimed it was not.** `f:reconcile/1`, `f:carry_or_watch/3`, `f:release_all/1`,
%% `f:release/1` and `f:forget_gone/3` are reached only from `f:tick/3`, which is itself
%% only reached from the fun `f:start_sampler/1` spawns -- and dialyzer reports "will
%% never be called" for all of them, measured rather than assumed. It is the same single
%% root cause as every entry above: one poisoned success typing at the spawn, not a
%% separate one each. (Counted rather than left to a reader, because a count that drifts
%% is the same failure this list is fixing: a nowarn that outlives the function it names
%% is a claim about code that is no longer there.)
-dialyzer({nowarn_function, sample_loop/1}).
-dialyzer({nowarn_function, tick/3}).
-dialyzer({nowarn_function, reconcile/1}).
-dialyzer({nowarn_function, carry_or_watch/3}).
-dialyzer({nowarn_function, release_all/1}).
-dialyzer({nowarn_function, release/1}).
-dialyzer({nowarn_function, forget_gone/3}).
-dialyzer({nowarn_function, stop_sampler/0}).
start_link() ->
    %% **Only `{local, Name}` registers the manager locally, and it is the only
    %% form this OTP accepts together with `Opts`.** Measured against
    %% `f:gen_event:start_link/2`: `{Mod, Args}`, `{local, Name, Mod}`,
    %% `{global, Name, Mod}` and `{via, Mod, Name, Args}` each exit `badarg`.
    %% So **there is no form that both registers the manager and names a callback
    %% module**, which means this module's own callbacks would never run -- see
    %% *The manager is `f:gen_event`'s own module* below.
    %%
    %% That is why the subscriber registry is owned by the sampler rather than by
    %% the manager: there is no hook in the manager process this module can run.
    case gen_event:start_link({local, ?MODULE}, [{spawn_opt, [{async_dist, true}]}]) of
        {ok, Pid} ->
            ok = start_sampler(Pid),
            {ok, Pid};
        Other ->
            Other
    end.

%% %%%%% %%% The manager is `f:gen_event`'s own module %%%%% %%%
%%
%% ## This module is not the manager, and cannot be on this OTP
%%
%% `f:gen_event:start_link/2` registers the manager and runs `f:gen_event`'s own
%% callbacks. **There is no form of it that both registers the name and names a
%% callback module**, so a caller's `-behaviour(gen_event)` module is never
%% invoked -- and the name is not optional either, because `f:notify/1`,
%% `f:bounded/1` and `f:depth/0` all resolve the bus through `whereis(?MODULE)`.
%%
%% Measured on this build at OTP 28.5 / ERTS 16.4.0.6. Every form below was passed
%% to `f:gen_event:start_link/2`:
%%
%% | GenMod | outcome |
%% |---|---|
%% | `{local, Name}` | ok, and the manager is `f:gen_event` |
%% | `{global, Name}` | ok, registered globally, and the manager is `f:gen_event` |
%% | `{Mod, Args}` | **badarg** |
%% | `{local, Name, Mod}` | **badarg** |
%% | `{global, Name, Mod}` | **badarg** |
%% | `{via, Mod, Name, Args}` | **badarg** |
%%
%% **All four badargs are the same badarg**, raised from `f:gen:where/1`, which is
%% where `f:gen:start/4` turns a GenMod into the lookup it is going to register --
%% none of the four is a shape it knows. So the two forms that do work are the two
%% that register, and neither of them says which module the manager runs.
%%
%% `{local, Name}` is the form this bus takes, and a manager started that way
%% reports \`current_function = {gen_event, fetch_msg, 6}\`.
%%
%% **And it is not only that `f:gen_event:start_link/2` cannot ask for it.**
%% `f:gen_event`'s own
%% `f:init_it/6` still takes the manager's module and its arguments and **throws
%% both away** -- its head is
%% `f:init_it(Starter, Parent, Name0, _Mod, _Args, Options)` and it goes straight
%% into the manager's loop with an empty state. So the manager-module concept is
%% vestigial upstream rather than merely unexposed, which is why this is a
%% measurement of OTP rather than a workaround missing here (#N722YKK).
%%
%% ## What that costs, and where it put the work
%%
%% **There is no hook in the manager process this module can run, so none of the
%% bus's own state can live in it.** The subscriber registry is owned by the sampler
%% -- see *The subscriber registry* below -- which is a process this module really
%% does start, and it dies with the manager because it monitors it.
%%
%% **A handler is not the missing hook**, and it is worth saying why rather than
%% leaving the objection open: `f:add_handler/3` on this module itself *would* run
%% code inside the manager, and an ETS table created in a handler's `f:init/1` is
%% owned by the manager and so dies with it. But every event reaches a handler on
%% the dispatch path, and bookkeeping would then cost a function call per event on
%% the router's busiest instrument -- to hold a table the sampler already owns.
%%
%% ## What was here instead, and why it is gone
%%
%% This module used to declare `-behaviour(gen_event)` and export `f:init/1`,
%% `f:handle_event/2`, `f:handle_call/2`, `f:handle_info/2`, `f:terminate/2` and
%% `f:code_change/3`. Six functions describing an arrangement that cannot exist, and
%% a test that called all six directly and so certified them as covered.
%%
%% **`f:handle_call/2` was the one that could never have worked even if a form
%% appeared.** `f:gen_event:call/3` and `f:gen_event:call/4` dispatch to a named
%% **handler**, never to the manager module -- the manager looks the handler up in
%% its handler list and calls that one -- so `{error, unsupported}` was a reply to
%% a question no caller could ask. Writing them again is an afternoon's work if OTP
%% grows the form; keeping them until then was a comment that had to stay true
%% (#N722YKK).

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
            %% The manager can die between whereis/1 and the notify itself,
            %% and the raw call surfaces that as an exit -- measured as
            %% {error, badarg} on exactly this race in #ZYNNQKQ. An emitter
            %% must never crash over telemetry.
            try gen_event:notify(?MODULE, Event) of
                _ -> ok
            catch
                _:_ -> ok
            end
    end.

%% %%%%% %%% The backlog gauge %%%%% %%%
%%
%% ## What replaced the heap bound
%%
%% **A handler that wedges the manager is now visible rather than bounded.** The
%% backlog depth is sampled by `f:sample_backlog/0` and published through
%% `m:i2p_stats:set_gauge/2` as `bus_backlog`, reaching the read API under
%% `m:i2p_status_data:view/0`'s `gauges` key.
%%
%% **The read works on a wedged manager, which is the property the bound lacked.**
%% Every `f:gen_event` call is an rpc to the manager, so all of them are unavailable
%% exactly when an operator needs a reading; `process_info/2` is a different kind of
%% call. Measured on a manager parked inside `handle_event/2`, sampled every 200ms:
%% `process_info(Pid, message_queue_len)` answered in **0us** every time, reporting
%% a monotone 936,710 -> 2,803,109, while `gen_event:which_handlers/1` never
%% answered at all after 1500ms. So a report of a wedged bus does not inherit the
%% wedge -- and that is why the sampler is a separate process, because the manager
%% is the thing that stops answering.
%%
%% ## Why the sampler is a spawn and not a child spec
%%
%% **It is a spawn, and it is registered, because it must follow the bus rather than
%% the supervisor.** This note used to claim a link gave it the manager's lifetime
%% "for free"; it does not, and it is worth being precise about why it never could.
%% `f:start_link/0` runs **in the supervisor process**, so `spawn_link` from it links
%% the sampler to the *supervisor* -- which outlives every restart of the bus.
%%
%% **Measured consequence of that, before this was fixed:** the sampler survived a
%% bus restart, and because `f:start_link/0` also ran again on the restart, a
%% **second** sampler started beside it. Two loops writing the same
%% `persistent_term` gauge every 5s, one of them publishing a depth for a manager pid
%% that no longer exists -- which `f:depth/0` answers as `0`. A restarted bus
%% therefore reported "no backlog" from a process watching nothing.
%%
%% **A monitor on the manager is the relationship wanted, and a link is not.** The
%% sampler exits when the manager it watches goes down, so the next
%% `f:start_link/0` finds no sampler and starts exactly one; and it does not add a
%% second link into the supervisor's child set, where a sampler crash would look
%% like a second bus crash. `f:stop_sampler/0` makes the handover synchronous so the
%% old registry table is provably gone before the new one is created -- two samplers
%% cannot own one named table, and a bare `ets:new` against a live one would fail the
%% bus start.
%%
%% **5s is a measured choice, not a round number.** A depth sampled slower than the
%% bus drains measures nothing -- the manager drains a 300,000-message flood in about
%% a second -- and one sampled faster pays a `persistent_term` put per tick, which
%% rehashes every term in the system. 5s is above the drain time and far below any
%% interval an operator would call a freeze.

%% How often the backlog gauge is refreshed. See the note above.
-define(BACKLOG_TICK_MS, 5000).

%% The sampler, registered so a restart can find the one before it is about to make
%% another.
%%
%% **Spelled out rather than built from `?MODULE`**, for the reason
%% `?SUBSCRIBERS` is: `?MODULE_sampler` is one macro called `MODULE_sampler`, not
%% `?MODULE` followed by a suffix.
-define(SAMPLER, i2p_events_sampler).

%% How long `f:stop_sampler/0` waits for the old sampler to be gone. Generous,
%% because it is only ever paid on a bus restart and it is a hang guard: a sampler
%% that outlived the wait would leave a named table behind and fail the next start.
-define(SAMPLER_STOP_MS, 5000).

-doc """
Sample the manager's queue depth, publish it, and emit it.

Input: none. Output: the depth, as a non-negative integer.

**Returns `0` when the manager is not running**, which is what the gauge should show
rather than an error: there is no backlog when there is no bus.
""".
-spec sample_backlog() -> non_neg_integer().
sample_backlog() ->
    Depth = depth(),
    ok = i2p_stats:set_gauge(bus_backlog, Depth),
    %% Emitted so a future consumer attaches rather than polls. Nothing in this tree
    %% attaches yet, and that is deliberate: the event is the seam, not a feature.
    %% `telemetry:execute/3` with no handler attached is close to free.
    _ = telemetry:execute([i2per, i2p_events], #{backlog => Depth}, #{}),
    Depth.

%% %%%%% %%% The far-side gauge %%%%% %%%%%

%% ## What this reports, and what it deliberately does not do
%%
%% **A subscriber on another node that is not keeping up grows without limit, and
%% nothing on this side can stop it.** Measured on this build at OTP 28.5 / ERTS
%% 16.4.0.6 (#RWTMGJ9): every route to a cap is a dead end --
%% `erlang:system_info(dist_buffer_size)` and `erlang:memory(dist_buffer)` are
%% `badarg`, `statistics(dist)` is `badarg`, `port_info(DistPort, queue_size)` reads
%% `{queue_size, 0}` however full it is, and **`erlang:process_info/2` against a
%% remote pid is `badarg` for every item**, `message_queue_len` included -- it raises
%% rather than returning `undefined`.
%%
%% **`{async_dist, false}` does not supply one either, and this was the surprise.**
%% A relay process doing the remote send with `async_dist` off was measured under a
%% 300,000-event flood against a collector that never drains: the far mailbox took
%% **all 300,000**, the relay never parked and its own mailbox never grew a message.
%% The runtime applies no back-pressure to a *process* that is not consuming -- a
%% send completes while the socket accepts, and the far node's distribution keeps
%% reading at line rate into a mailbox that refuses nothing. `async_dist` parks a
%% sender only when the far node stops reading its *socket*, which is a different and
%% much rarer condition.
%%
%% **So the queue is bounded by the collector draining it or dying, and this gauge
%% is how an operator finds out which is happening.** It reports; it does not cap.
%% That is the same answer the near side took when its heap bound was measured and
%% removed (#VH7Z0KJ), applied to the side that measurement was not about.
%%
%% ## Where the number comes from, and why it costs what it costs
%%
%% **One `erpc` round trip per remote subscriber, and there is no cheaper read.**
%% Measured against a 200,000-deep mailbox: min 101 us, median 107 us, max 555 us
%% over 20 samples. That is not a hot path -- it is once per subscriber per
%% `?BACKLOG_TICK_MS`, from a process no packet ever touches -- but it is a real cost
%% and the worst case is `subscribers * ?FAR_SAMPLE_TIMEOUT_MS`, which is why the
%% timeout is a named bound rather than a generous round number.
%%
%% **The read works on a subscriber that is wedged, which is the property the whole
%% gauge rests on.** `process_info/2` on the far node is served by *that node's*
%% scheduler and not by the target process, so a collector stuck in a `receive`
%% answers it as readily as a healthy one. A report of the fault does not inherit
%% the fault -- the same property `f:sample_backlog/0` is built on, and the reason
%% the sampler is a separate process at all.

%% How long one subscriber's depth read may take before it is given up on.
%%
%% **An order of magnitude over the worst reading ever measured** (555 us), and
%% bounded because the alternative -- an un-timed `erpc` into a node the router does
%% not own -- lets one unreachable subscriber decide when the next gauge is taken.
%% With no remote subscribers this costs nothing, which is the ordinary case.
-define(FAR_SAMPLE_TIMEOUT_MS, 1000).

-doc """
Read the queue depth of every remote subscriber, and prune the ones that are gone.

Input: none. Output: the deepest remote queue depth as a non-negative integer, or
`0` when no subscriber is on another node.

**A read, not a published value, and that shape is required rather than chosen.** The
core does not hand figures to a stats process it does not control, so there is no
far-side gauge and no timer feeding one: a collector that wants the number asks for
it here, through the same public entry point it already uses to attach. With nobody
asking, this costs nothing, which is the ordinary case.

**The deepest, not the sum.** A sum over subscribers says "this router is expensive to
observe" and scales with how many operators are watching, which is not the operator
question. The maximum is the one that answers it: *is any subscriber falling behind,
and by how much.*

**A subscriber whose pid is gone is pruned, and that is a fact about the registry
rather than about the depth.** `process_info/2` returns `undefined` for a pid that no
longer exists, and it is how a sweep learns a remote collector died without
unsubscribing. **It is the belt to the sampler's braces, not the braces.** The
subsampler holds a monitor on every registered subscriber and drops the row the moment
the pid goes -- see *Why the sampler watches every subscriber* -- so this sweep is
answering for the window between a subscriber being registered and the subsampler
noticing, and nothing more. What it must *not* become is the only way a dead
collector leaves the registry: a prune that runs when somebody asks for a reading is a
prune that runs exactly when an operator is looking at something else.

**A subscriber that cannot be reached is skipped rather than counted as zero**, so a
node that is down reports as nothing instead of as an idle one -- the single confusion
this figure exists to prevent, and the same reason `f:depth/0` does not report a dead
manager as depth zero. A caller receiving `0` therefore knows one of two things, and
only the caller can tell them apart: nothing is queueing on a far node, or nothing
could be asked.
""".
-spec sample_far_backlog() -> non_neg_integer().
sample_far_backlog() ->
    {Depths, Gone} = lists:foldl(fun far_depth/2, {[], []}, remote_subscribers()),
    ok = forget_all(Gone),
    deepest(Depths).

%% One subscriber's reading. `undefined` from the far node means the pid is gone,
%% which is a fact about the registry rather than about the depth.
%%
%% **`catch` rather than a case on the call, because `erpc` signals an unreachable
%% node by exiting** (`{erpc, noconnection}`) and by *timing out*. A depth read is
%% telemetry about a machine this router does not own, so an exception from it is
%% expected state rather than a fault, and letting it kill the caller would turn one
%% unreachable observer into a broken diagnostic.
far_depth(Collector, {Depths, Gone}) ->
    case
        catch erpc:call(
            node(Collector),
            erlang,
            process_info,
            [Collector, message_queue_len],
            ?FAR_SAMPLE_TIMEOUT_MS
        )
    of
        {message_queue_len, Depth} -> {[Depth | Depths], Gone};
        undefined -> {Depths, [Collector | Gone]};
        _Other -> {Depths, Gone}
    end.

%% Split rather than one function with a `case`, so the empty case reads as its own
%% answer instead of as a branch guarding an accumulator that does not exist.
deepest([]) ->
    0;
deepest(Depths) ->
    lists:max(Depths).

%% %%%%% %%% The subscriber registry %%%%% %%%
%%
%% ## It is the bus's own state, and it lives in the bus
%%
%% **The list of subscribers is something `m:i2p_events` knows because `f:attach/1`
%% added the handler and `f:detach/1` removed it.** Those two functions write this
%% table in the same breath as the `f:gen_event` call, so there is no second copy to
%% keep in step and no other module to ask: a collector cannot be listed without
%% having been attached, and cannot be attached without being listed.
%%
%% **There is a third way off the bus now, and it is not a second copy either.**
%% `m:i2p_events_forward` takes its own handler off when its collector dies (#DN82Z7J),
%% and it cannot drop the row describing it -- see *Why the sampler watches every
%% subscriber* for why that half lands here. So the invariant above is now three paths
%% rather than two, and the sampler's monitor is the third. It is still one row per
%% handler and no other module to ask; what changed is that holding them in step takes
%% a monitor rather than only two write sites.
%%
%% It deliberately does **not** live in `m:i2p_stats`. That module is an observer of
%% the core, not part of it -- the core does not hand data to a stats process it does
%% not control -- so a registry parked there would be the core calling out to its own
%% observer on the subscription path. It would also mean the bus stopped working when
%% no stats process was running, which is the ordinary case.
%%
%% ## Why ETS rather than asking the bus
%%
%% **Because the manager is exactly what is unavailable when the answer is wanted.**
%% Every `f:gen_event` call is an rpc to the manager, and a manager parked inside
%% `f:gen_event:handle_event/2` answers none of them -- measured not answering after
%% 1500 ms in #VH7Z0KJ, and `f:which_handlers/1` is no different. An ETS read is
%% served by the VM rather than by the manager, so a sweep keeps working through a
%% wedge that stops every other read of the bus dead.
%%
%% ## Why the table is `public`
%%
%% **Because the writes come from the collector's own node, not from the owner.**
%% `f:subscribe/1` reaches the bus through `f:bounded/1`, which runs the
%% `f:gen_event` call in a throwaway asker, so the process adding a row is never the
%% manager. `protected` would push that write through an rpc to the owner -- the very
%% dependency this arrangement exists to avoid.
%%
%% ## Why the owner is the manager
%%
%% **So the list cannot outlive the handlers it describes.** A restarted manager comes
%% back with zero handlers, the silent detach #G61Y2QZ records, so a registry that
%% survived it would list subscribers no longer receiving anything. Tying the table to
%% the manager makes the two agree by construction, with no teardown code to get wrong.

%% The registry table. **Named rather than passed around**, because neither long-lived
%% writer (`f:attach/1`, `f:detach/1`) is the process that may own it.
%%
%% **Spelled out rather than built from `?MODULE`**: `?MODULE_subscribers` would be
%% read by the preprocessor as one macro called `MODULE_subscribers`, not as
%% `?MODULE` followed by a suffix.
-define(SUBSCRIBERS, i2p_events_subscribers).

-doc """
Every subscriber attached to this bus, remote and local alike.

Output: a list of collector pids, empty when there is no bus.

**This is what the far-side sweep reads**, exported so a caller that wants to see what
is being measured does not have to reach into the table. **Local subscribers are
included** even though the sweep skips them: the registry records who attached, and
which of them this router can usefully measure is the sweep's decision rather than the
registry's.

**A collector that has died is not on the list, however it died.** Killing the process,
losing the node it was on, or never unsubscribing at all -- all three are answered by a
monitor the subsampler holds, so the row goes when the pid does rather than when
somebody remembers to unsubscribe. A restarted status service used to leave one behind
per restart (#DN82Z7J), and a list that grows for the life of the router is a list
nobody can act on.
""".
-spec subscribers() -> [pid()].
subscribers() ->
    case ets:info(?SUBSCRIBERS, name) of
        undefined -> [];
        _ -> [P || {P} <- ets:tab2list(?SUBSCRIBERS)]
    end.

remote_subscribers() ->
    [P || P <- subscribers(), node(P) =/= node()].

%% A row per attached handler, written where the handler is added and removed.
%% `ets:insert/2` on a `set` is idempotent, which is what a convergent
%% `f:subscribe/1` needs, and every write is guarded because the sampler can be
%% replaced between the `f:gen_event` call and the row.
%%
%% **`ok` rather than the ETS return value**, because both `ets:insert/2` and
%% `ets:delete/2` answer `true` and the callers match on `ok`. Letting the raw
%% `true` through reads as a failed match in `f:attach/1`, which is the kind of
%% error that points at the wrong function entirely.
%%
%% **This is a plain `{Collector}` row and not a `{Collector, MRef}` one**, because
%% nothing outside this module reads the subsampler's monitors and a second column
%% would mean every reader of the table had to know about a piece of one process's
%% loop state. The monitors live in `f:tick/3`'s argument, where they are private to
%% the process that owns them.
remember(Collector) ->
    case ets:info(?SUBSCRIBERS, name) of
        undefined ->
            ok;
        _ ->
            _ = ets:insert(?SUBSCRIBERS, {Collector}),
            ok
    end.

forget(Collector) ->
    case ets:info(?SUBSCRIBERS, name) of
        undefined ->
            ok;
        _ ->
            _ = ets:delete(?SUBSCRIBERS, Collector),
            ok
    end.

forget_all(Collectors) ->
    lists:foreach(fun forget/1, Collectors).

-spec start_sampler(pid()) -> ok.
%% Sample once before waiting, so the gauge is populated from the moment the bus
%% is up rather than after a full tick.
%%
%% **A gauge that is absent for its first tick is a fault a reader cannot tell from
%% a fault it is meant to reveal.** `m:i2p_stats:gauges/0` reports a gauge it has
%% never seen as *absent*, which is the correct distinction from "measured, and
%% zero" -- but on the bus that means the read API carries no backlog figure at all
%% for the first 5 seconds of the router's life, and a consumer polling at startup
%% would see nothing. One immediate sample costs one `persistent_term` put at boot
%% and makes the key's absence mean what it is supposed to mean: the sampler died.
%%
%% **The old sampler is stopped first, and synchronously**, because the new one owns
%% the registry table by name and two processes cannot own one named table. See
%% *Why the sampler is a spawn and not a child spec* above for what happens if this
%% is skipped.
start_sampler(Bus) ->
    ok = stop_sampler(),
    _ = spawn(fun() -> sample_loop(Bus) end),
    ok.

%% Exit when the bus goes, and own the registry while it lives.
%%
%% **The table is created here rather than in `f:start_link/0`** because the creating
%% process is its owner, and the owner is what makes it die with the bus: a restarted
%% manager comes back with zero handlers, and a registry that outlived it would list
%% subscribers no longer receiving anything.
sample_loop(Bus) ->
    %% **`named_table` is required, and without it the table silently has no name.**
    %% Measured on OTP 28.5: `ets:new(Name, [set, public])` yields
    %% `ets:info(Name, size) =:= undefined` and `ets:info(Tid, named_table) =:= false`,
    %% while `ets:info(Tid, name)` cheerfully reports the atom -- so the table works,
    %% holds rows, and is unreachable by the name every other function here uses. Add
    %% `named_table` and all three answer. An earlier version of this omitted it, and
    %% the symptom was a registry that was always empty rather than an error.
    _ = ets:new(?SUBSCRIBERS, [set, public, named_table, {read_concurrency, true}]),
    _ = sample_backlog(),
    true = register(?SAMPLER, self()),
    tick(Bus, erlang:monitor(process, Bus), #{}).

%% The bus is monitored once, outside the loop, so that a subscriber's death cannot
%% replace it.
%%
%% **The \`after\` is restarted by a \`'DOWN'\`,** because a \`receive\` with a timeout
%% restarts its timeout on every message it takes. With \`?BACKLOG_TICK_MS\` at 5s that
%% costs a gauge refresh only when subscribers are dying more than once every five
%% seconds, which is a status service crash-looping rather than a router at work --
%% and the alternative is a deadline threaded through the loop to avoid it.
tick(Bus, BusRef, Watched0) ->
    %% **Reconciled on every pass, not once at startup.** `f:sample_loop/1` calls this
    %% once, and nothing else does: a subscriber that arrives later would never be
    %% watched, and its row would outlive it exactly as before -- which is what the
    %% first version did, and what `m:i2p_events_tests`'s
    %% `a_dead_collector_is_forgotten_without_unsubscribing/0` caught. Reconciling on
    %% each pass is what makes "the next tick picks it up" true, and it costs one ETS
    %% read per pass.
    Watched = reconcile(Watched0),
    receive
        {'DOWN', BusRef, process, Bus, _Reason} ->
            ok;
        stop ->
            ok;
        {'DOWN', MRef, process, Collector, _Reason} ->
            tick(Bus, BusRef, forget_gone(Collector, MRef, Watched))
    after ?BACKLOG_TICK_MS ->
        _ = sample_backlog(),
        tick(Bus, BusRef, Watched)
    end.

%% %%%%% %%% Why the sampler watches every subscriber %%%%% %%%
%%
%% ## The registry outlives its handler, and nothing else would notice
%%
%% **A forwarder whose collector has died now takes itself off the bus**
%% (\`m:i2p_events_forward\` does it, and #DN82Z7J carries the measurement). That is the
%% bus's half of the question -- *should it keep calling this pid* -- answered in the
%% one process that can answer it without an rpc, since every \`gen_event\` call has no
%% timeout and none of them work against a wedged bus.
%%
%% This is the other half: *is the pid still a subscriber*. The registry row outlives
%% the handler, because the forwarder has no way to drop it -- \`f:forget/1\` is private
%% to this module, and a core forwarder reaching back into the bus's bookkeeping for
%% it is exactly the coupling this module's notes argue against. Left alone, the row
%% survives a collector's death for the life of the router, and \`f:subscribers/0\` --
%% which promises "every subscriber attached to this bus" -- answers with a pid that
%% has been gone since the last status-service restart.
%%
%% **A monitor, not a liveness probe, and that is the whole reason this is cheap.**
%% The alternative for a *local* pid is \`is_process_alive/1\`, which would be fine; the
%% alternative for a *remote* pid is the \`erpc\` round trip \`f:sample_far_backlog/0\`
%% already makes, once per subscriber per tick, forever, for a question with a one-word
%% answer. A monitor is free, works across a node boundary, and answers exactly that --
%% including when the far node itself has gone, where it fires with \`noconnection\`
%% rather than going unanswered. Measured on OTP 28.5, this build.
%%
%% ## It is installed from the table rather than announced
%%
%% **The registry is the list, so the sampler reads the list.** Asking for a monitor at
%% \`f:attach/1\` time would need a message to the sampler and would lose the ask if the
%% sampler was replaced between the write and the send -- the same replacement that
%% \`f:stop_sampler/0\` exists to survive. Reconciling against ETS cannot: whatever the
%% table says, the next tick watches all of it, and a monitor installed on a pid that
%% has already died fires immediately rather than never.
%%
%% **The map is the loop's argument and not a table**, because there is exactly one
%% reader and it is this process: a second table would be a second thing to create,
%% own and prune, in a process whose whole justification is that it is small enough to
%% keep working when the bus does not.

%% Watch every registered subscriber this process is not already watching, and release
%% every monitor on a collector that is no longer registered.
%%
%% **Both directions, because a forward-only reconcile leaks.** The obvious shape --
%% add a monitor for each row we are not watching, leave the rest alone -- holds a
%% monitor on a collector that has unsubscribed for as long as that collector lives,
%% because nothing ever drops it from the map: it is still alive, so no DOWN arrives,
%% and it is gone from ETS, so no row says to release it. `m:i2p_ssu2_reachability`
%% unsubscribes in `f:terminate/2`, so this is not hypothetical.
%%
%% **The new map is built from the registry rather than edited into the old one**, so
%% "what this loop watches" is "what is registered" by construction, and a map entry
%% can only survive by being re-derived from a row that still exists.
%%
%% **Runs once per `?BACKLOG_TICK_MS` and once per subscription, not once per event.**
%% A collector that subscribed since the last tick is watched by the next one, so a dead
%% one is dropped within a tick even if nothing is ever announced again; and the bus
%% answers `f:notify/1` far more often than either, which is the point -- this is
%% bookkeeping, and it must not be in the dispatch path.
reconcile(Watched) ->
    Registered = subscribers(),
    release_all(maps:values(maps:without(Registered, Watched))),
    lists:foldl(
        fun(Collector, Acc) -> carry_or_watch(Collector, Watched, Acc) end, #{}, Registered
    ).

%% Carry a collector's existing monitor across, or make one.
%%
%% **The lookup is in `Previous`, not in the map being built, and the first version got
%% that wrong in a way only a failing test caught.** Consulting the accumulator means
%% only the collectors already folded in are found, so nothing is ever found and every
%% collector is re-monitored on every pass: the sampler's monitor set grew without
%% bound, and -- worse -- the `'DOWN'` that finally arrived carried a *stale* MRef,
%% which `f:forget_gone/3` correctly refused to match, so the row was never dropped.
%% Symptom, measured: five subscribers attaching and dying left **four** rows behind
%% rather than none, while the sampler held a monitor per subscriber per tick.
%%
%% **Carrying the monitor across is what makes `f:forget_gone/3`'s check sound.** It
%% compares the monitor in the `'DOWN'` against the one this loop believes it holds; a
%% second monitor on the same collector would deliver a second `'DOWN'` for one death
%% and leave that check the only thing between it and a live subscriber's row going.
carry_or_watch(Collector, Previous, Watched) ->
    case maps:find(Collector, Previous) of
        {ok, MRef} -> Watched#{Collector => MRef};
        error -> Watched#{Collector => erlang:monitor(process, Collector)}
    end.

%% Hand back every monitor on a collector that is no longer registered.
%%
%% **`maps:values/1` and not `maps:foreach/2`,** because the map is keyed by collector
%% and `maps:foreach/2` calls its fun with *both* key and value. A `release/1` handed
%% straight to it is an arity error raised inside the sampler on its first
%% unsubscribe -- which takes the registry table down with it, because the sampler owns
%% that table. Measured, not reasoned: every registry case in `m:i2p_events_tests` went
%% red on it, and the first symptom was `ets:info(i2p_events_subscribers, name)`
%% answering `undefined`.
release_all(MRefs) ->
    lists:foreach(fun release/1, MRefs),
    ok.

%% A collector that unsubscribed is not a subscriber any more, and its monitor is ours
%% to hand back.
%%
%% **`[flush]` because the DOWN may already be in the mailbox.** A monitor that has
%% already fired is not released by `demonitor/2`, so without the flush the message
%% would arrive later for a collector this loop has stopped watching -- harmless, since
%% `f:forget_gone/3` checks the monitor before deleting a row, but it would be a
%% message in this process's mailbox answering a question nobody asked.
release(MRef) ->
    _ = erlang:demonitor(MRef, [flush]),
    ok.

%% A collector's \`'DOWN'\`, and the one question the table can answer about it.
%%
%% **Matching the monitor before deleting anything**, because the \`'DOWN'\` may belong
%% to a subscriber this process has already stopped watching: \`f:forget_gone/3\` is
%% reached from a bare \`'DOWN'\` clause, and a row deleted on a monitor that is not
%% this one's current monitor would remove a *live* subscriber's registration.
%%
%% **The handler is not deleted here.** \`m:i2p_events_forward\` has already taken itself
%% off by the time this runs -- both are driven by the same monitor firing, and the
%% manager sees its own first because the handler is inside it. So this answers only
%% the table's half, which is what a caller reaching into another module's bookkeeping
%% could not do.
forget_gone(Collector, MRef, Watched) ->
    case maps:take(Collector, Watched) of
        {MRef, Rest} ->
            ok = forget(Collector),
            Rest;
        _ ->
            Watched
    end.

%% Make sure no sampler is left, so the next start creates the registry rather than
%% colliding with it.
%%
%% **Kill rather than ask, and wait.** A polite `stop` would be undone by a sampler
%% that is already mid-tick and about to recurse; `kill` is immediate, and the
%% `'DOWN'` wait is what makes the handover synchronous. Without the wait the new
%% sampler's `ets:new` races the old table and the bus fails to start -- a crash
%% loop on a *restart*, which is the worst place to introduce one.
stop_sampler() ->
    case whereis(?SAMPLER) of
        undefined ->
            ok;
        Pid ->
            MRef = monitor(process, Pid),
            exit(Pid, kill),
            receive
                {'DOWN', MRef, process, Pid, _Reason} -> ok
            after ?SAMPLER_STOP_MS ->
                ok
            end
    end.

%% `undefined` and `catch` rather than a bare match, because the manager can die
%% between the `whereis` above and this read. Reporting that as depth 0 would make
%% a dead bus look like a healthy idle one, which is the one thing this gauge exists
%% to distinguish.
depth() ->
    case whereis(?MODULE) of
        undefined ->
            0;
        Pid ->
            case catch process_info(Pid, message_queue_len) of
                {message_queue_len, N} -> N;
                _ -> 0
            end
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
%% The reach is the router, not the bus. `m:i2per_sup` lists `stats_child()` then
%% `events_child()` ahead of `reachability_child()`, so a bus wedged when
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
    ok = gen_event:add_handler(?MODULE, {i2p_events_forward, Collector}, [Collector]),
    ok = remember(Collector).

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
    Result = gen_event:delete_handler(?MODULE, {i2p_events_forward, Collector}, [Collector]),
    ok = forget(Collector),
    case Result of
        {error, module_not_found} -> ok;
        Other -> Other
    end.
