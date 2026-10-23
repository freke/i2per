-module(i2p_datagram_replay).

-moduledoc """
Bounded replay window for Datagram2.

A pure, stateful cache of recently seen datagrams, keyed by a caller-chosen
key (the datagram's signature or a hash of the full datagram). The window
has a fixed capacity that an attacker cannot grow: inserting into a full
window evicts the oldest entry, and the capacity never changes. Replay
detection is by key equality.

Time and ordering are explicit (FIFO eviction), so the window is a pure
function of its inputs and tests are fully deterministic. Counters for
accepted, replayed and evicted datagrams live in the window state itself;
a consumer that wants router-lifetime tallies folds them into `i2p_counters`.

## Usage

```erlang
W0 = i2p_datagram_replay:new(2),
{accepted, W1} = i2p_datagram_replay:check(W0, Key1),
{replay,   W2} = i2p_datagram_replay:check(W1, Key1),
{accepted, W3} = i2p_datagram_replay:check(W2, Key2),
{accepted, W4} = i2p_datagram_replay:check(W3, Key3),  % evicts Key1
#{accepted := 3, replayed := 1, evicted := 1} =
    i2p_datagram_replay:stats(W4).
```
""".

-export([
    new/1,
    check/2,
    seen/2,
    admit/2,
    accept/2,
    stats/1,
    size/1,
    capacity/1,
    keys/1
]).

-export_type([window/0, key/0]).

-type key() :: term().
-type window() :: #{
    capacity := pos_integer(),
    keys := [key()],
    seen := sets:set(key()),
    accepted := non_neg_integer(),
    replayed := non_neg_integer(),
    evicted := non_neg_integer()
}.

-doc "Create an empty replay window with the given fixed `Capacity`.".
-spec new(pos_integer()) -> window().
new(Capacity) when is_integer(Capacity), Capacity > 0 ->
    #{
        capacity => Capacity,
        keys => [],
        seen => sets:new([{version, 2}]),
        accepted => 0,
        replayed => 0,
        evicted => 0
    }.

-doc """
Test `Key` against the window.

Returns `{accepted, Window1}` when `Key` has not been seen: the key is
recorded (evicting the oldest entry when the window is full) and the
`accepted` counter moves. Returns `{replay, Window}` when `Key` is already
present: nothing is recorded and the `replayed` counter moves.
""".
-spec check(window(), key()) -> {accepted, window()} | {replay, window()}.
check(#{seen := Seen, capacity := Cap, keys := Keys} = W, Key) ->
    case sets:is_element(Key, Seen) of
        true ->
            {replay, W#{replayed => maps:get(replayed, W) + 1}};
        false ->
            {Keys1, Evicted} =
                case length(Keys) >= Cap of
                    true ->
                        [_Oldest | Rest] = Keys,
                        {Rest ++ [Key], 1};
                    false ->
                        {Keys ++ [Key], 0}
                end,
            Seen1 = sets:add_element(Key, Seen),
            %% When evicting, drop the oldest key from the seen set too.
            Seen2 =
                case Evicted of
                    1 ->
                        [Oldest | _] = Keys,
                        sets:del_element(Oldest, Seen1);
                    0 ->
                        Seen1
                end,
            W1 = W#{
                keys => Keys1,
                seen => Seen2,
                accepted => maps:get(accepted, W) + 1,
                evicted => maps:get(evicted, W) + Evicted
            },
            {accepted, W1}
    end.

-doc "Alias for `f:check/2` returning `{true, Window}` for a replay and `{false, Window}` for a fresh key.".
-spec seen(window(), key()) -> {boolean(), window()}.
seen(W, Key) ->
    case check(W, Key) of
        {replay, W1} -> {true, W1};
        {accepted, W1} -> {false, W1}
    end.

-doc "Alias for `f:check/2` returning `{ok, Window}` for a fresh key.".
-spec admit(window(), key()) -> {ok, window()} | {replay, window()}.
admit(W, Key) ->
    case check(W, Key) of
        {accepted, W1} -> {ok, W1};
        {replay, W1} -> {replay, W1}
    end.

-doc "Alias for `f:check/2` returning `{ok, Window}` for a fresh key.".
-spec accept(window(), key()) -> {ok, window()} | {replay, window()}.
accept(W, Key) ->
    admit(W, Key).

-doc "Return the window's counters.".
-spec stats(window()) ->
    #{accepted := non_neg_integer(), replayed := non_neg_integer(), evicted := non_neg_integer()}.
stats(#{accepted := A, replayed := R, evicted := E}) ->
    #{accepted => A, replayed => R, evicted => E}.

-doc "Number of keys currently held.".
-spec size(window()) -> non_neg_integer().
size(#{keys := Keys}) ->
    length(Keys).

-doc "Fixed capacity of the window.".
-spec capacity(window()) -> pos_integer().
capacity(#{capacity := Cap}) ->
    Cap.

-doc "Current keys in eviction order (oldest first).".
-spec keys(window()) -> [key()].
keys(#{keys := Keys}) ->
    Keys.
