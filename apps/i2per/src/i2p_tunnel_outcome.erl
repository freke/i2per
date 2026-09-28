-module(i2p_tunnel_outcome).

-moduledoc """
Announce a tunnel lifecycle outcome, and count it.

Announcing on the bus and charging the counter are the same fact observed once,
so they are done together here. Six call sites across two modules previously
announced tunnel outcomes directly, and a lifetime tally added alongside them
would have been a second, hand-maintained description of the same events — free
to drift, and silent when it did. Routing every announcement through this module
makes that impossible: the only way to announce an outcome is to count it.

## What the counters mean

`m:i2p_stats` holds cumulative totals since router start. A tunnel success
ratio is **not** computed here — the core supplies totals and a consumer
differences and divides them, which is what keeps the counter home free of a
timer. See #0HSTTVC for the tally and #7YP3QZ4 for the ratio.

The failure reason is kept in the counter's name rather than folded into one
`tunnels_failed` figure, so a ratio can be read next to *why* builds fail. A
rejected build and an invalid one are different facts: the first means a hop
declined, the second means the records did not survive processing. Collapsing
them would make the number useless for diagnosis, which is the only reason to
have it.

## Counter names are derived, not listed

`f:counter_name/1` turns an event into the counter it charges, and
`f:counter_names/0` derives the whole set from the same three clauses. The
registry in `m:i2p_stats` is the authority on what exists; a test asserts the
derived set is contained in it, so a new direction or a new failure reason fails
the build rather than a production send.
""".

-export([built/2, failed/2, expired/1, counter_name/1, counter_names/0]).

-doc """
Announce a tunnel that reached the point of being usable.

Input: the direction and the number of real hops. Output: `ok`.

Counted before the announcement, so a counter can never lag its own event: if the
counter is not running the announcement still happens, because telemetry must not
be able to drop a state change.
""".
-spec built(i2p_events:direction(), non_neg_integer()) -> ok.
built(Direction, Hops) ->
    ok = i2p_stats:add(counter_name({tunnel_built, Direction, Hops}), 1),
    i2p_events:notify({tunnel_built, Direction, Hops}).

-doc """
Announce a tunnel build that did not produce a usable tunnel.

Input: the direction and why it failed (`rejected` when a hop declined, `invalid`
when the records did not survive processing). Output: `ok`.
""".
-spec failed(i2p_events:direction(), rejected | invalid) -> ok.
failed(Direction, Why) ->
    ok = i2p_stats:add(counter_name({tunnel_failed, Direction, Why}), 1),
    i2p_events:notify({tunnel_failed, Direction, Why}).

-doc """
Announce a tunnel the expiry sweep is about to drop.

Input: the direction. Output: `ok`.

Counted alongside the built and failed totals because a success ratio without it
is a misleading number to put on a page: a router can build nine tunnels in ten
and have every one of them expire, and a reader shown only the ratio would
conclude it is healthy.
""".
-spec expired(i2p_events:direction()) -> ok.
expired(Direction) ->
    ok = i2p_stats:add(counter_name({tunnel_expired, Direction}), 1),
    i2p_events:notify({tunnel_expired, Direction}).

-doc """
The counter an event charges.

Input: a tunnel outcome event. Output: the counter name, as the flat atom
`m:i2p_stats` registers. Exported so the mapping has exactly one definition, and
so a test can check the whole vocabulary at once rather than one call site at a
time.

Eight clauses rather than a mechanical flattening of a tuple, because
`{tunnels_built, outbound}` and `tunnels_built_outbound` are two spellings of one
thing and having both in the source is how they drift. Deriving the name instead
would mean building atoms at runtime from event data.
""".
-spec counter_name(i2p_events:event()) ->
    tunnels_built_inbound
    | tunnels_built_outbound
    | tunnels_failed_inbound_invalid
    | tunnels_failed_inbound_rejected
    | tunnels_failed_outbound_invalid
    | tunnels_failed_outbound_rejected
    | tunnels_expired_inbound
    | tunnels_expired_outbound.
counter_name({tunnel_built, inbound, _Hops}) -> tunnels_built_inbound;
counter_name({tunnel_built, outbound, _Hops}) -> tunnels_built_outbound;
counter_name({tunnel_failed, inbound, invalid}) -> tunnels_failed_inbound_invalid;
counter_name({tunnel_failed, inbound, rejected}) -> tunnels_failed_inbound_rejected;
counter_name({tunnel_failed, outbound, invalid}) -> tunnels_failed_outbound_invalid;
counter_name({tunnel_failed, outbound, rejected}) -> tunnels_failed_outbound_rejected;
counter_name({tunnel_expired, inbound}) -> tunnels_expired_inbound;
counter_name({tunnel_expired, outbound}) -> tunnels_expired_outbound.

%% `underspecs` is off here, deliberately, for the same reason it is off on the
%% read API: the spec is the promise ("every counter name this module can
%% charge") and the success typing is today's literal list of eight. Narrowing
%% the spec to match would make it a hand-maintained copy that has to be edited
%% whenever a direction or a failure reason is added — which is precisely the
%% maintenance the derivation below exists to remove. The test that pins the
%% derived set against the registry is what enforces agreement.
-dialyzer({no_underspecs, [counter_names/0]}).

-doc """
Every counter name this module can charge, derived from `f:counter_name/1`.

Output: the sorted, deduplicated set of counter names, obtained by mapping the
whole outcome vocabulary through the clauses rather than by listing names. A
clause added for a new direction or a new failure reason changes this set
automatically, and a test asserts the set and the registry agree.
""".
-spec counter_names() -> [atom()].
counter_names() ->
    Vocabulary =
        [{tunnel_built, D, 0} || D <- [inbound, outbound]] ++
            [{tunnel_failed, D, W} || D <- [inbound, outbound], W <- [rejected, invalid]] ++
            [{tunnel_expired, D} || D <- [inbound, outbound]],
    lists:usort([counter_name(E) || E <- Vocabulary]).
