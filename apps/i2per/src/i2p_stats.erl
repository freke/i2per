-module(i2p_stats).

-moduledoc """
Counter home for the router, and the clock the counters are measured against.

Every number the router reports about itself is a `counters` reference owned
here. Nothing else in the tree owns a counter, so "since start" has exactly one
answer and it does not depend on whether anybody was watching.

## Why a process owns this when nothing messages it

`f:add/2` and `f:snapshot/0` both read the counter reference out of
`persistent_term` and touch it directly. This process is in neither path: it
never receives a read, and a counter update is an atomic add on shared memory,
not a message to a server. The process exists to *own* the reference — to create
it at one point in the tree's life, build the name registry once, and tear it
down if the router stops — which is a job, not a request queue.

Keeping it a process rather than side effects in someone's `init/1` is what lets
the router's supervision tree say what is running, and what makes a counter
reference outliving a crashed process impossible to leave behind: `f:terminate/2`
erases the term.

## Volatile, and the clock moves with it

Counters are not persisted. A restart zeroes them, and the boot time is recorded
in the same breath, so a cumulative total and the uptime beside it always tell
the same story. A counter that survived a restart while the uptime reset would
make the first rate derived after that restart wrong, and wrong in a way that
looks like a burst of traffic.

`f:uptime_ms/0` is derived from a **monotonic** reading, so an NTP step or an
operator changing the wall clock cannot produce a negative uptime.
`f:boot_time/0` is the wall clock at start, which is the thing a human correlates
against a log file.

## Timer-free, on purpose

There is no periodic process and no sampling loop here, and a test asserts
that. The router publishes cumulative totals and its boot time; a consumer that
wants a rate samples twice and differences them itself. That division is what
makes this module cheap enough to sit under the hot paths, and it is why a
counter can move without ever waking a process.

## Adding a counter

Add its name to `f:counters/0` and call `f:add/2` from the path that should move
it. That is the whole procedure: the read API reports whatever is registered, so
no caller and no consumer changes, and a name that is not registered raises on
use rather than silently discarding the count.

## Usage

```erlang
ok = i2p_stats:add(events_notified, 1),
#{events_notified := 1} = maps:get(counters, i2p_status_data:view()).
```
""".

-behaviour(gen_server).

-export([start_link/0, add/2, snapshot/0, uptime_ms/0, boot_time/0, counters/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% One term, written once at start. `persistent_term` rather than ETS because the
%% read happens on packet paths: this is a read with no copy, no lock and no
%% message, where an ETS lookup would show up in a profile.
-define(PT_KEY, {?MODULE, state}).

%% Reported when the router is not running this process. A distinct answer
%% rather than a plausible one: 0ms uptime reads as "just started", which is a
%% different fault from "nothing is counting".
-define(NO_BOOT, undefined).

%% `underspecs` is off for this one function, deliberately. The spec is the
%% promise — "a list of registered counter names" — while the success typing is
%% today's literal list. Narrowing the spec to match would make it a fourth copy
%% of the registry that has to be edited whenever a counter is added, which is
%% the maintenance this module exists to remove. The test that reads this list is
%% what enforces agreement with `f:snapshot/0`.
-dialyzer({no_underspecs, [counters/0]}).

-doc """
The registered counter names, in index order.

The single source of truth for what the router counts. The registry built from
it is what `f:snapshot/0` reports, and the test pinning this list reads it, so
a counter cannot reach the read API without appearing here.
""".
-spec counters() -> [atom()].
counters() ->
    [
        %% Announcements made on the status bus. Not an obvious operational
        %% figure, but it is the one that answers "is anything instrumented
        %% yet", which is the first question when a status page looks empty.
        events_notified,

        %% %%%%% Bytes at the transport boundary %%%%%
        %%
        %% What is counted is what crossed the socket, in each direction, per
        %% transport. That is the useful figure for a network operator, and it is
        %% also the only one that can be taken at a single point per direction.
        %%
        %% Consequences worth stating, because a reader comparing these to a
        %% payload count will find them different:
        %%
        %%   - a **retransmit counts**, and a resend of an unacknowledged SSU2
        %%     packet counts a second time. The alternative — counting distinct
        %%     payload — needs state per peer per packet number, on a path that
        %%     cannot afford it, to produce a number that answers "how much
        %%     useful data moved" rather than "how busy was the link".
        %%   - NTCP2's outbound figure is the framed length handed to the
        %%     socket, so it includes the 16-byte header and MAC on every frame
        %%     and so runs slightly ahead of the payload total. Its inbound
        %%     figure is the raw socket read, which may hold part of a frame or
        %%     several of them; either way it is exactly what arrived.
        %%   - SSU2's figures are exact datagram sizes, since UDP preserves
        %%     message boundaries.
        %%
        %% Per-peer and per-tunnel breakdown is deliberately absent: SSU2's send
        %% carries an endpoint rather than a router hash, and the transport
        %% boundary has no tunnel identity to attribute bytes to. See #VZVB7X8.
        ntcp2_bytes_out,
        ntcp2_bytes_in,
        ssu2_bytes_out,
        ssu2_bytes_in,

        %% %%%%% SSU2 session %%%%%
        %%
        %% **Received Data packet numbers that arrived too old to record.**
        %%
        %% An SSU2 session keeps a window of the packet numbers it has received
        %% so it can recognise a retransmission and build the ACK block. The
        %% window is bounded by what an ACK block can *name*: its `acnt` field
        %% is one byte and each `{nack, ack}` pair is two, so no ACK this router
        %% sends can reach further than a fixed distance below the highest
        %% number received. A packet number below that reach is therefore
        %% unrecordable — the spec also requires retransmission to use a *fresh*
        %% number, so nothing legitimate lands there.
        %%
        %% So this counter is a fault signal, not a throughput figure, and it is
        %% the only way the condition is visible: the packet is still processed
        %% (block handling is idempotent by message identity, so a duplicate is
        %% harmless) but it can no longer be recognised as one. A peer that
        %% drives this above zero is retransmitting numbers the protocol does
        %% not permit reusing. See `m:i2p_ssu2_recv` and #7GP4A4K.
        %%
        %% Named for what the session calls the condition (`stale`) rather than
        %% for the window it fell out of: the read API reserves "window" for
        %% sliding values, and this is a plain cumulative total.
        ssu2_stale_packets,

        %% %%%%% Dials parked on SSU2 %%%%%
        %%
        %% **An outbound dial sat on SSU2, gave up, and went to NTCP2 instead.**
        %%
        %% Not a rate and not an incident: the dial's own cost is the point, and
        %% the dial recovers, so on a healthy router with a dead UDP path this is
        %% simply "the number of peers we had to fall back for". What makes it
        %% worth counting is that before it existed the cost was invisible — the
        %% dial was in `connecting`, not in backoff, and `peer_connect_failed`
        %% fires only once *both* legs have failed, so a router whose UDP was
        %% blocked everywhere looked exactly like one that was merely slow.
        %%
        %% Its own counter rather than a field on the connect failure for that
        %% reason. A peer that connects over NTCP2 never reports a failure at
        %% all, and that peer is precisely the one whose SSU2 attempt was thrown
        %% away.
        %%
        %% **Counted only when something was actually parked.** A dial that never
        %% tried SSU2 — the transport off at boot, no listener up, or the remote
        %% publishing none — is `not_attempted` and moves nothing here. Counting it
        %% would make this a count of dials, and a total that grows in proportion
        %% to traffic says nothing about UDP.
        %%
        %% Which *kind* of park is not in this number but in the bus event of the
        %% same name, which carries the reason: a `{protocol_error, _}` is a
        %% datagram that arrived and could not be used, and so is proof that UDP
        %% works that way, while a `{handshake_timeout, _}` is silence. Read
        %% across peers, the second outnumbering the first everywhere is "our UDP
        %% is blocked", which is the one an operator can act on. See #1Q4JREN.
        ssu2_dials_parked,

        %% %%%%% Dials that stopped reporting %%%%%
        %%
        %% **A peer had to be released from `connecting` because its dial never
        %% said what happened.** Expected to stay at zero. It counts three
        %% situations that are one operator fact — a dial that produced no
        %% outcome — and the bus event of the same moment carries which:
        %% `{dial_died, _}` for a dial process that ended (abnormally, or normally
        %% having sent nothing), `dial_deadline` for one that outlived
        %% `f:i2p_peer:dial_deadline_ms/0`.
        %%
        %% This is not a connect failure, and the distinction is the point. Every
        %% leg of a dial bounds itself — the SSU2 handshake by its retransmit
        %% count, the introducer leg by `f:i2p_ssu2_conn`'s redirect wait, NTCP2
        %% by its handshake timeout — and each reports when it gives up, so
        %% `peer_connect_failed` is a statement about the remote. A dial that goes
        %% silent is a statement about *this* router: a raise on the dial path, or
        %% a blocking call that stopped honouring its own bound. Before these
        %% escapes existed the symptom was a peer at `connecting` for the life of
        %% the process, which `f:sweep_peers/1` deliberately never evicts, so the
        %% router would carry on as though that peer were still being dialled.
        %%
        %% One counter rather than two, because the two causes are not separately
        %% actionable and would only be told apart by eye. A non-zero value is the
        %% evidence that the backstop is what ended a dial, which is what makes it
        %% worth looking at rather than a healthy router's normal life. See #8V1Z06A.
        dials_escaped,

        %% %%%%% Bytes carried for other routers %%%%%
        %%
        %% **These are wire bytes, not client bytes, and the difference is not an
        %% approximation — it is unknowable.** A transit hop never decrypts the
        %% tunnel data it carries, so the payload inside the frame belongs to two
        %% parties who are not this router and who have not told it what is in
        %% there. The honest figure is therefore what crossed the relay, which is
        %% the full tunnel-data frame: 1028 bytes on the wire, of which the great
        %% majority is a tunnel id, an IV and a layered cipher.
        %%
        %% So these two numbers are an *upper bound* on the client traffic a
        %% router has carried, and they are not comparable with the transport
        %% figures above, which do measure real payload framing. A router that
        %% relays heavily will show transit figures orders of magnitude larger
        %% than its transport figures, and that is correct rather than a bug.
        %%
        %% Charged on acceptance and on forwarding respectively. A frame the token
        %% bucket refused is charged to neither, because it was not carried. A
        %% frame that was accepted but could not be forwarded is charged inbound
        %% only, which is the honest asymmetry. On a transit hop the two are
        %% equal frame for frame, because the hop does not alter the body.
        transit_bytes_in,
        transit_bytes_out,

        %% %%%%% Transit frames with nowhere to go %%%%%
        %%
        %% Frames we accepted, counted in `transit_bytes_in`, and then had no
        %% route for because the next hop was not in the NetDb. So it answers
        %% "why is my inbound figure not equal to my outbound figure", which is
        %% otherwise a question the two byte counters cannot answer between them.
        %%
        %% Its own counter rather than an event: this is a steady state on a
        %% transit router whose next hop has expired, and an event per 1028-byte
        %% frame would drown the bus. The peer manager owns reconnection, so a
        %% frame counted here is not recoverable and not retried.
        transit_frames_dropped_no_route,

        %% %%%%% Our own outbound, undeliverable %%%%%
        %%
        %% One operator question with two causes, so one section: what did *we*
        %% fail to deliver after successfully routing it. The section above is the
        %% opposite -- frames that had nowhere to go at all. An operator needs
        %% both to tell a routing fault from a delivery fault, and they belong
        %% next to each other so the read API presents them as one question
        %% rather than three counters to correlate by hand.
        %%
        %% **Messages, not frames, and the distinction is not cosmetic.** Both are
        %% counted at the injection point, where a whole I2NP message is about to
        %% be handed to `m:i2p_tunnel_srv`. No frame exists yet --
        %% `f:outbound_frames/4` runs *after* the tunnel is found, so a message
        %% that fails here was never fragmented at all. Calling either a frame
        %% would name a unit that does not exist, and would tie these to the
        %% transit one they exist to be told apart from.
        %%
        %% `no_tunnel` and **not** `no_route`, because a route *was* resolved in
        %% both cases: a pinned outbound tunnel has since gone. That is a
        %% different cause from "no route" and collapsing them would lose
        %% exactly the distinction this section was written to keep.
        %%
        %% Counters rather than events, for the reason the section above gives: a
        %% route whose tunnel has gone fails **every** subsequent send until the
        %% route is re-resolved, so these are per-message rates on live paths
        %% rather than incidents.
        client_messages_dropped_no_tunnel,
        %% The same loss on the other side of the router: a reply we owed another
        %% router, injected into a lookup outbound tunnel that went away between
        %% picking it and sending on it. **Its own counter, not a shared one.**
        %% A lost client send is our user waiting on their own traffic; a lost
        %% lookup reply is *another router* waiting on an answer we had. One is
        %% our user's experience, the other is our usefulness to the network, and
        %% an operator cannot act on the sum. Sharing would also make
        %% `client_messages_dropped_no_tunnel` a lie by name, which is the same
        %% category of error as calling it `frames`.
        %%
        %% Expected to stay at zero, and that is a claim about the code rather
        %% than about traffic: both lookups resolve through the same pool map, so
        %% the id a pick returns is still present when the send re-resolves it
        %% unless a tick retires the tunnel in between. See #MCVQ6D6 -- and note
        %% that the path is **not deterministically constructible in a test**,
        %% which is why this is a counter reached through an exported helper
        %% rather than a case that races the window.
        lookup_replies_dropped_no_tunnel,

        %% %%%%% Peer manager: bounded structures %%%%%
        %%
        %% The peer manager holds three structures that would grow without bound
        %% if nothing reclaimed them. Each has a bound now, and each of these
        %% counts a *different* reason an entry went away, because "the peer
        %% manager shed something" is not an operator fact on its own.
        %%
        %% A frame dropped for want of queue space is a different fact from one
        %% dropped for want of a route above. This router routed the frame and
        %% could not deliver it; `transit_frames_dropped_no_route` says the
        %% opposite. A queue that is silently truncating is the thing this
        %% board has twice had to find after the fact.
        pending_sends_dropped_depth,
        %% A queued frame that aged past `?PENDING_SEND_MAX_AGE_MS` and was
        %% dropped unsent. **Distinct from the depth drop above**: a frame lost
        %% to age is a peer that was never going to be reachable in time, so
        %% this counter is the evidence that a bound, rather than congestion,
        %% is what the peer set is running into.
        pending_sends_expired,
        %% A RouterInfo evicted from the dialable set by `?MAX_KNOWN`. Non-zero
        %% on a busy router is normal; a count climbing without bound while the
        %% peer count stays low means RouterInfos are arriving faster than they
        %% are being used, which is the NetDb's story rather than this one's.
        known_evicted,
        %% A peer entry evicted by `?MAX_PEERS`. Should be rare: the cap sits well
        %% above the connection limits, so a router that evicts here is holding
        %% more peers than it can use.
        peers_evicted,

        %% %%%%% Connections and sessions refused at a cap %%%%%
        %%
        %% **Three counters for one operator question: which of my three caps am
        %% I hitting?** They are not one shared total because the three bounds
        %% different things and are fixed by three different keys, so a single
        %% number cannot be acted on — the fix for a SAM session refused at
        %% `max_sam_sessions` is nothing like the fix for a peer connection
        %% refused at `max_ntcp2_connections`.
        %%
        %% Expected to stay at zero. A non-zero value is not a fault in itself:
        %% the cap did its job. It is the evidence that the cap is the thing
        %% standing between this router and a peer set or a client, and before
        %% these existed the only symptom was a connection that did not happen —
        %% indistinguishable from a peer that refused us, a NetDb that had no
        %% address, or a handshake that failed.
        %%
        %% Charged in `m:i2p_admission`, on the refusal, by the process that owns
        %% the cap, rather than by each caller: three call sites to remember is
        %% three chances to forget one, and a cap nobody counts is a cap an
        %% operator can only infer.
        %%
        %% A rate rather than an incident, which is why these are counters: at
        %% the cap the refusal fires on every inbound accept and on every
        %% reconnect attempt, so an event each time would drown the bus. The
        %% same reasoning as `transit_frames_dropped_no_route`.
        ntcp2_connections_refused_limit,
        ssu2_sessions_refused_limit,
        sam_sessions_refused_limit,

        %% %%%%% Tunnel lifecycle %%%%%
        %%
        %% Cumulative since router start, and **not** a ratio: the ratio is the
        %% consumer's to compute, by dividing these, which is what keeps this
        %% module free of a timer. Both directions are kept apart, and each
        %% failure reason gets its own counter rather than one `failed` total —
        %% a build a hop declined and a build whose records did not survive
        %% processing are different facts, and a reader who cannot tell them
        %% apart cannot act on the number.
        %%
        %% These used to live in the separate status application, zero-initialised
        %% when it started, which is why the success ratio was answerable only
        %% from the moment something attached to watch. They are here so "since
        %% start" has one answer that does not depend on who is listening.
        %%
        %% The names are derived from the event vocabulary by `m:i2p_tunnel_outcome`;
        %% this list is the authority on what exists, and a test asserts the
        %% derived set is contained here.
        tunnels_built_inbound,
        tunnels_built_outbound,
        tunnels_failed_inbound_invalid,
        tunnels_failed_inbound_rejected,
        tunnels_failed_outbound_invalid,
        tunnels_failed_outbound_rejected,
        tunnels_expired_inbound,
        tunnels_expired_outbound
    ].

-doc """
Add to a registered counter.

Input: a name from `f:counters/0` and a non-negative amount. Output: `ok`.

This is on packet paths, so it is a lock-free atomic add and nothing else: no
message, no allocation, no lock. A name that is not registered raises, which is
the intent — counting something nobody declared is a bug, and dropping the count
would hide it.

Returns `ok` when this process is not running, for the same reason
`m:i2p_events:notify/1` always does: telemetry must not be able to crash a
working connection. Suites that start part of the tree rely on that.
""".
-spec add(atom(), non_neg_integer()) -> ok.
add(Name, Amount) ->
    %% `counters:add/3` does not validate its amount: a negative one is applied
    %% as a subtraction and returns `ok`. That is worth catching here, because a
    %% cumulative counter that goes *backwards* is the signal a differencing
    %% consumer reads as "the router restarted", so one underflowed length
    %% difference would look exactly like a restart and poison every rate
    %% derived after it. Enforcing the spec's own claim turns a silently wrong
    %% total into a crash on the path that produced it.
    true = is_integer(Amount) andalso Amount >= 0,
    case state() of
        undefined ->
            ok;
        #{ref := Ref, index := Index} ->
            counters:add(Ref, maps:get(Name, Index), Amount)
    end.

-doc """
Every registered counter, by name.

Output: a map from counter name to a non-negative total since the router
started. Empty when this process is not running. A counter is reported whether
or not it has ever moved, so a consumer distinguishes "not measured yet" (the
name is absent) from "measured, and zero" (the name is present and the value is
zero).
""".
-spec snapshot() -> #{atom() => non_neg_integer()}.
snapshot() ->
    case state() of
        undefined -> #{};
        State -> read_all(State)
    end.

-doc """
Milliseconds since the router's stats process started.

Output: a non-negative integer, or `0` when this process is not running. Derived
from a monotonic clock, so a wall-clock adjustment cannot make it go backwards.
""".
-spec uptime_ms() -> non_neg_integer().
uptime_ms() ->
    case state() of
        undefined -> 0;
        #{boot_mono := Boot} -> erlang:monotonic_time(millisecond) - Boot
    end.

-doc """
Wall-clock time the router's stats process started, in epoch milliseconds.

Output: an integer, or `undefined` when this process is not running. This is the
figure a human matches against a log file; use `f:uptime_ms/0` for arithmetic.
""".
-spec boot_time() -> integer() | undefined.
boot_time() ->
    case state() of
        undefined -> ?NO_BOOT;
        #{boot_wall := Boot} -> Boot
    end.

-doc "Start the counter home. Registered locally as `m:i2p_stats`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% %%%%% %%% gen_server %%%%% %%%

init([]) ->
    Names = counters(),
    Ref = counters:new(length(Names), []),
    State = #{
        ref => Ref,
        names => Names,
        index => maps:from_list(lists:zip(Names, lists:seq(1, length(Names)))),
        boot_wall => erlang:system_time(millisecond),
        boot_mono => erlang:monotonic_time(millisecond)
    },
    persistent_term:put(?PT_KEY, State),
    {ok, State}.

%% No work arrives here, and that is the design rather than an omission: reads
%% go straight to the counter reference instead of through a message, so a busy
%% monitoring client cannot make the router's own process queue grow.
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

%% Leave nothing behind. A stale term would keep a counter reference alive whose
%% creating process is gone, and the next start would overwrite it — leaving a
%% window where a counter silently accumulates into an orphaned reference.
terminate(_Reason, _State) ->
    persistent_term:erase(?PT_KEY),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% %%%%% %%% Internal %%%%% %%%

state() ->
    persistent_term:get(?PT_KEY, undefined).

%% `counters` has a per-index read and no bulk read, so this is N calls. That is
%% the right way round: the hot path is `f:add/2`, which is a single atomic, and
%% the read happens once per snapshot. Reading the whole array in one go would
%% be a saving nobody needs at the cost of a second API nobody wants to depend on.
read_all(#{ref := Ref, names := Names}) ->
    maps:from_list(lists:zip(Names, [counters:get(Ref, I) || I <- lists:seq(1, length(Names))])).
