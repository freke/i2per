-module(i2p_netdb_writer).

-moduledoc """
The process that writes the NetDb's store to disk.

The NetDb process serves every NetDb read: `f:closest/3` per lookup round,
`f:closest_floodfills/4` per tunnel build, and `f:has_router/2` per relayed
frame. Serialising the store for `netdb.bin` measures **8403 us** at the shipped
capacity of 5000 routers, and that work has no business running in the process
those readers queue behind.

So it runs here instead. What this process receives is **not the store** but a
description of what to serialise — `m:i2p_netdb:snapshot/1` — carrying the
capacity, the router hashes in recency order, and the LeaseSets. The RouterInfos
themselves are never copied: the NetDb's table is `protected`, so any process may
read it, and `m:i2p_netdb:serialize/1` looks each entry up as it walks the list.

The read process therefore pays about **49 us** to hand the work over instead of
8403 us to do it, and the copy that remains is the key list, which at 205 us is
most of that 49 and is the cheapest way available to name what to serialise.

## Why the generation matters here

A key list handed over is a **promise about the table**, and the NetDb can break
that promise while this process is still reading it: an evicted key is no longer
in the table, and looking it up would raise a `badmatch` rather than return a
clean miss.

`f:generation/1` makes the promise checkable, and there are two checks because
two things can go wrong:

- **`{error, {stale, Key}}` from `f:serialize/1`.** The key was in the snapshot
  and is not in the table. Caught during the walk, before any bytes exist.
- **A generation that moved.** The table was written while the snapshot was being
  serialised, so the bytes are a mixture of two stores. Caught after the walk,
  which is the case the key check cannot see — a router stored mid-walk is in the
  table but was never in the snapshot, and its presence alone does not invalidate
  anything.

Either way the bytes are **discarded and the save retried with a fresh snapshot**,
never written. A file that describes a store which never existed is worse than no
file: the next boot would load it and believe it.

Retries are **bounded** (`?MAX_ATTEMPTS`). An unbounded retry between a writer and
a busy reader is a livelock waiting for load, and a skipped save cycle is a far
better outcome than a save that never completes. The next timer tick tries again.

## What this process does not do

It never writes the table. The NetDb process owns it, and the expiry sweep's
deletes stay there — see `m:i2p_netdb:remove_expired/3`, whose cost is addressed
separately.
""".

-behaviour(gen_server).

-export([start_link/0, save/2, save_async/2, stats/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(NETDB_FILE, "netdb.bin").

%% How many times one save cycle will re-snapshot a moved key list before giving up.
%%
%% A save is ~8.4 ms of serialisation and the NetDb is written only by an accepted
%% `f:store/3`, so a collision needs a store to land inside that window. At a
%% realistic rate that is rare, and three attempts is generous.
%%
%% The bound is not there because collisions are likely. It is there because a loop
%% that retries until the reader is quiet is not a save — it is a way to stop
%% saving, discovered under load rather than in a test.
-define(MAX_ATTEMPTS, 3).

-record(state, {
    %% Where `netdb.bin` lives, or `undefined` when no `data_dir` is configured.
    %% Resolved once at init rather than per save: `application:get_env/2` on the
    %% save path would be a second cost hiding behind the first, and the answer
    %% cannot change without a restart.
    dir :: undefined | file:filename_all(),
    %% Monotonic, for naming temp files. Not a generation: two saves in the same
    %% millisecond must not collide on a temp path.
    serial = 0 :: non_neg_integer(),
    saves = 0 :: non_neg_integer(),
    retries = 0 :: non_neg_integer(),
    abandoned = 0 :: non_neg_integer(),
    failed = 0 :: non_neg_integer()
}).

-doc "Start the disk writer, registered locally as `i2p_netdb_writer`.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
Ask for the store to be written to disk, and wait for it.

Input: `Snapshot` — from `m:i2p_netdb:snapshot/1`; `ReportTo` — a pid to receive
`{save_result, Result}` on, or `undefined`.
Output: `ok` when the file was written or the cycle was deliberately abandoned,
`{error, Reason}` on an I/O failure.

For an operator who asked to save and wants the file to exist when the call
returns, and for shutdown — where the writer is about to be stopped, so handing it
work asynchronously would race that.
""".
-spec save(i2p_netdb:snapshot(), pid() | undefined) -> ok | {error, term()}.
save(Snapshot, ReportTo) ->
    gen_server:call(?MODULE, {save, Snapshot, ReportTo}, infinity).

-doc """
Ask for the store to be written to disk, and return immediately.

Input: `Snapshot` — from `m:i2p_netdb:snapshot/1`; `ReportTo` — a pid to receive
`{save_result, Result}` on, or `undefined`.
Output: `ok`.

This is the 15-minute timer path. The caller's cost is the snapshot, about
**49 us** at the shipped capacity of 5000 routers, against the **8403 us** that
serialising in the read-serving process cost. Everything after the send happens
here.
""".
-spec save_async(i2p_netdb:snapshot(), pid() | undefined) -> ok.
save_async(Snapshot, ReportTo) ->
    gen_server:cast(?MODULE, {save, Snapshot, ReportTo}).

-doc """
Counters for diagnostics.

Output: a map with `saves` (files written), `retries` (snapshots re-taken because
the table moved), `abandoned` (cycles given up after `?MAX_ATTEMPTS`), and
`failed` (I/O errors).

`abandoned` is the one to watch: a non-zero value means the store was being
written faster than a snapshot could be taken, which is a load problem worth
knowing about rather than a save that quietly did not happen.
""".
-spec stats() -> #{atom() => non_neg_integer()}.
stats() ->
    gen_server:call(?MODULE, stats).

init([]) ->
    {ok, #state{dir = data_dir()}}.

handle_call({save, Snapshot, ReportTo}, _From, State) ->
    {State2, Result} = write_snapshot(Snapshot, ReportTo, State),
    {reply, Result, State2};
handle_call(stats, _From, State) ->
    {reply, counters(State), State};
handle_call(_Msg, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({save, Snapshot, ReportTo}, State) ->
    %% **`{noreply, State2}`, not the `{State, Result}` that `f:write_snapshot/3`
    %% returns.** The cast handler has to hand back a gen_server return, so the pair
    %% has to be taken apart. Returning it whole passes a `{Record, Result}` tuple
    %% where a state record is expected, which `f:counters/1` then fails to match --
    %% a crash on the first autosave rather than a wrong counter.
    {State2, _Result} = write_snapshot(Snapshot, ReportTo, State),
    {noreply, State2};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

counters(#state{saves = S, retries = R, abandoned = A, failed = F}) ->
    #{saves => S, retries => R, abandoned => A, failed => F}.

%% ---- the save itself -----------------------------------------------------------

write_snapshot(_Snapshot, ReportTo, #state{dir = undefined} = State) ->
    %% No data_dir means no file to write. Not an error: an in-memory router is a
    %% supported configuration, and the NetDb asked because its timer fired.
    %% Reported as `ok` because from the caller's side nothing went wrong.
    {report(State, ok, ReportTo), ok};
write_snapshot(Snapshot, ReportTo, State) ->
    {State2, Result} = attempt(Snapshot, ReportTo, State, ?MAX_ATTEMPTS),
    {report(State2, Result, ReportTo), Result}.

report(_State, _Result, undefined) ->
    ok;
report(State, Result, Pid) when is_pid(Pid) ->
    Pid ! {save_result, Result},
    State.

%% One attempt: serialise, then check the table did not move under us.
%%
%% The generation is read back from the STORE rather than from the table directly,
%% so this compares "what generation did I start from" against "what generation
%% does the store claim now" — equal exactly when no mutation completed in
%% between.
attempt(_Snapshot, _ReportTo, State, 0) ->
    %% Out of attempts. The store is being written faster than a snapshot can be
    %% taken, which is a load problem, not something to retry forever inside a
    %% timer tick. The next tick tries again with a fresh list.
    {State#state{abandoned = State#state.abandoned + 1}, ok};
attempt(Snapshot, ReportTo, State, Attempts) ->
    %% **The two `{error, ...}` shapes are exhaustive.** `f:serialize/1` returns
    %% `{ok, Bin}` or `{error, {stale, Key}}` and nothing else, so dialyzer rejects a
    %% catch-all `{error, _}` clause as unreachable. That is the type system earning
    %% its keep: if a future `f:serialize/1` grows a new failure, this stops
    %% compiling rather than silently reporting it as a stale key and retrying
    %% forever.
    case i2p_netdb:serialize(Snapshot) of
        {error, {stale, _Key}} ->
            %% A key in the snapshot is gone from the table. Same conclusion as a
            %% moved generation — these bytes describe nothing — but caught first,
            %% because `f:serialize/1` looks each key up rather than copying a whole
            %% RouterInfo before discovering it is absent.
            retry(ReportTo, State, Attempts);
        {ok, Bin} ->
            case i2p_netdb_srv:generation_now() =:= maps:get(generation, Snapshot) of
                true ->
                    case write_private_atomic(Bin, State) of
                        ok ->
                            {State#state{saves = State#state.saves + 1}, ok};
                        {error, _} = Err ->
                            {State#state{failed = State#state.failed + 1}, Err}
                    end;
                false ->
                    %% The table was written while the snapshot was being
                    %% serialised. These bytes describe a store that never existed,
                    %% so they are discarded — not written, and not an error, since
                    %% the right response is to try again with a fresh key list.
                    _ = Bin,
                    retry(ReportTo, State, Attempts)
            end
    end.

%% Ask the NetDb for a fresh key list and try again.
%%
%% A `gen_server:call/1` on purpose: it blocks THIS process, not the reader, which
%% is the whole reason the writer exists. If the NetDb is gone — shutdown, say —
%% there is nothing to re-snapshot from, so the cycle is abandoned rather than
%% looping on a key list known to be stale.
retry(ReportTo, State, Attempts) ->
    case catch i2p_netdb_srv:snapshot() of
        Fresh when is_map(Fresh) ->
            State2 = State#state{retries = State#state.retries + 1},
            attempt(Fresh, ReportTo, State2, Attempts - 1);
        _ ->
            {State#state{abandoned = State#state.abandoned + 1}, ok}
    end.

%% ---- the atomic private write ---------------------------------------------------

write_private_atomic(Bin, #state{dir = Dir} = State) ->
    Path = filename:join(Dir, ?NETDB_FILE),
    Serial = State#state.serial + 1,
    TmpPath = Path ++ ".tmp." ++ integer_to_list(Serial),
    case filelib:ensure_dir(Path) of
        ok -> do_write(Bin, Path, TmpPath);
        {error, _} = Err -> Err
    end.

do_write(Bin, Path, TmpPath) ->
    %% `exclusive` so two writes cannot share a temp path. The serial counter makes
    %% that unlikely within this process, and this makes it impossible -- including
    %% against a stale temp file left by a crashed predecessor.
    case file:open(TmpPath, [write, binary, exclusive]) of
        {ok, Fd} ->
            case file:write(Fd, Bin) of
                ok ->
                    finish_write(Fd, TmpPath, Path);
                {error, _} = Err ->
                    _ = file:close(Fd),
                    _ = file:delete(TmpPath),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

finish_write(Fd, TmpPath, Path) ->
    %% `sync` before `close`, so the bytes are durable before the rename makes them
    %% visible. A crash between the two leaves a temp file, which is recoverable; a
    %% crash after a rename without a sync leaves a `netdb.bin` that is short.
    case file:sync(Fd) of
        ok ->
            case file:close(Fd) of
                ok ->
                    chmod_and_rename(TmpPath, Path);
                {error, _} = Err ->
                    _ = file:delete(TmpPath),
                    Err
            end;
        {error, _} = Err ->
            _ = file:close(Fd),
            _ = file:delete(TmpPath),
            Err
    end.

%% 0600 before the rename, so the file is never briefly readable by anyone else at
%% its final path. Chmod-then-rename, not rename-then-chmod: the other order has a
%% window where `netdb.bin` is world-readable, and this file holds every router
%% hash the router has seen.
chmod_and_rename(TmpPath, Path) ->
    case file:change_mode(TmpPath, 8#600) of
        ok ->
            case file:rename(TmpPath, Path) of
                ok ->
                    ok;
                {error, _} = Err ->
                    _ = file:delete(TmpPath),
                    Err
            end;
        {error, _} = Err ->
            _ = file:delete(TmpPath),
            Err
    end.

data_dir() ->
    case application:get_env(i2per, data_dir) of
        {ok, Dir} when is_list(Dir) -> Dir;
        _ -> undefined
    end.
