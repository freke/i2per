-module(i2p_addressbook).

-moduledoc """
The address book maps `.i2p` hostnames to destination base64 strings.

Two sources feed the mapping:

- **hosts.txt** — when app env `i2per` -> `data_dir` is set, the book loads
  `<data_dir>/hosts.txt` at startup and appends every new entry back to it
  (`name.i2p=base64destination`, one per line, `#` comments). Without a data
  dir the book is memory-only.
- **Subscriptions** — fetched hosts.txt content merged in via `f:add/2` by
  the fetcher (`m:i2p_addressbook_subs`).

Names are case-insensitive: lookups normalise to lowercase, so `Example.I2P`
and `example.i2p` are one entry.

## Usage

```erlang
i2p_addressbook:add(<<"stats.i2p">>, DestB64),
{ok, DestB64} = i2p_addressbook:resolve(<<"STATS.i2p">>),
{error, not_found} = i2p_addressbook:resolve(<<"nope.i2p">>).
```
""".

-behaviour(gen_server).

-export([
    start_link/1,
    resolve/1,
    add/2,
    hosts_file_for/1,
    snapshot/0,
    dump/1,
    stop/0
]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(FILENAME, <<"hosts.txt">>).

-doc """
Start the address book.

Input: `FilePath` — hosts.txt path to load and persist to (built from app env
`data_dir` by the supervisor), or `undefined` for memory-only operation.
""".
-spec start_link(file:filename_all() | undefined) -> {ok, pid()} | {error, term()}.
start_link(FilePath) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [FilePath], []).

-doc """
Resolve a hostname to its destination base64 string.

Input: `Name` — hostname such as `<<"stats.i2p">>` (case-insensitive).
Output: `{ok, DestB64}`, or `{error, not_found}` (also when the service is
not running).
""".
-spec resolve(binary()) -> {ok, binary()} | {error, not_found}.
resolve(Name) ->
    case whereis(?MODULE) of
        undefined ->
            {error, not_found};
        _Pid ->
            gen_server:call(?MODULE, {resolve, normalise(Name)})
    end.

-doc """
Add or replace an entry, persisting it when hosts.txt is configured.

Input: `Name` — hostname (case-insensitive); `DestB64` — destination base64
string.
Output: `ok`.
""".
-spec add(binary(), binary()) -> ok.
add(Name, DestB64) ->
    case whereis(?MODULE) of
        undefined -> ok;
        _Pid -> gen_server:call(?MODULE, {add, normalise(Name), DestB64})
    end.

-doc "Stop the address book.".
-spec stop() -> ok.
stop() ->
    gen_server:stop(?MODULE).

-doc """
Snapshot the current merged book.
Output: `{ok, map()}` from the server, or `{error, not_running}` if the
address book is not running.
""".
-spec snapshot() -> {ok, map()} | {error, not_running}.
snapshot() ->
    case whereis(?MODULE) of
        undefined ->
            {error, not_running};
        _Pid ->
            gen_server:call(?MODULE, snapshot)
    end.

-doc """
Dump the merged book to `Path` in hosts.txt format.
Output: `ok` on success, or `{error, term()}` on failure.
""".
-spec dump(file:filename_all()) -> ok | {error, term()}.
dump(Path) ->
    case snapshot() of
        {ok, Entries} ->
            write_snapshot(Path, Entries);
        {error, not_running} ->
            {error, not_running}
    end.

-spec init([file:filename_all() | undefined]) -> {ok, map()}.
init([FilePath]) ->
    Entries =
        lists:foldl(
            fun(Line, Acc) ->
                case entry_of(Line) of
                    {K, V} -> maps:put(K, V, Acc);
                    skip -> Acc
                end
            end,
            #{},
            load_lines(FilePath)
        ),
    {ok, #{file => FilePath, entries => Entries}}.

-spec handle_call(term(), gen_server:from(), map()) -> {reply, term(), map()}.
handle_call({resolve, Key}, _From, State) ->
    case maps:find(Key, maps:get(entries, State)) of
        {ok, DestB64} -> {reply, {ok, DestB64}, State};
        error -> {reply, {error, not_found}, State}
    end;
handle_call({add, Name, DestB64}, _From, State) ->
    Entries = maps:put(Name, DestB64, maps:get(entries, State)),
    append_line(maps:get(file, State), Name, DestB64),
    {reply, ok, State#{entries := Entries}};
handle_call(snapshot, _From, State) ->
    {reply, {ok, maps:get(entries, State)}, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec handle_cast(term(), map()) -> {noreply, map()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), map()) -> {noreply, map()}.
handle_info(_Info, State) ->
    {noreply, State}.

%%%%%%% %%% Internal %%%%%%%

normalise(Name) when is_binary(Name) ->
    lowercase(Name).

lowercase(Bin) ->
    <<<<(lower_char(C))>> || <<C>> <= Bin>>.

lower_char(C) when C >= $A, C =< $Z -> C + 32;
lower_char(C) -> C.

load_lines(undefined) ->
    [];
load_lines(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> binary:split(Bin, <<"\n">>, [global]);
        {error, _enoent} -> []
    end.

entry_of(RawLine) ->
    Size = byte_size(RawLine),
    Line =
        case RawLine of
            <<Body:(Size - 1)/binary, $\r>> when Size >= 1 -> Body;
            _ -> RawLine
        end,
    case Line of
        <<$#, _/binary>> ->
            skip;
        _ ->
            case binary:split(Line, <<"=">>) of
                [Name, Dest] when Name =/= <<>>, Dest =/= <<>> ->
                    {lowercase(Name), Dest};
                _ ->
                    skip
            end
    end.

append_line(undefined, _Name, _DestB64) ->
    ok;
append_line(Path, Name, DestB64) ->
    Line = <<Name/binary, "=", DestB64/binary, "\n">>,
    case file:write_file(Path, Line, [append]) of
        ok ->
            ok;
        {error, Reason} ->
            exit({addressbook_write_failed, Path, Reason})
    end.

write_snapshot(Path, Entries) ->
    Keys = lists:sort(maps:keys(Entries)),
    Bin =
        lists:foldl(
            fun(Key, Acc) ->
                Dest = maps:get(Key, Entries),
                <<Acc/binary, Key/binary, "=", Dest/binary, "\n">>
            end,
            <<>>,
            Keys
        ),
    Dir = filename:dirname(Path),
    _ = filelib:ensure_dir(filename:join(Dir, "hosts.txt")),
    Tmp = Path ++ ".tmp",
    case file:write_file(Tmp, Bin) of
        ok ->
            case file:rename(Tmp, Path) of
                ok ->
                    ok;
                {error, _} = Err ->
                    _ = file:delete(Tmp),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

-doc "The hosts.txt path for `DataDir`, or `undefined` without persistence.".
-spec hosts_file_for(binary() | undefined) -> file:filename_all() | undefined.
hosts_file_for(undefined) ->
    undefined;
hosts_file_for(DataDir) ->
    filename:join(DataDir, ?FILENAME).
