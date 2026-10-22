-module(i2p_addressbook_pub).

-moduledoc """
Publishes the merged addressbook to a configured path.

Writes the full merged book in hosts.txt format (dump, not append) to
`addressbook => #{hosts_file => Path}` from the `i2per` application
environment. Re-dumps on a timer and on change signals; counters and events
are emitted alongside each publish attempt per the instrumentation
convention.
""".

-behaviour(gen_server).

-export([start_link/1, stop/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-include_lib("kernel/include/logger.hrl").

-define(DEFAULT_INTERVAL_MS, 60_000).

-doc "Start the addressbook publisher with parsed options.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Opts], []).

-doc "Stop the publisher.".
-spec stop() -> ok.
stop() ->
    case whereis(?MODULE) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

-spec init([map(), ...]) ->
    {ok, #{path := term(), interval := non_neg_integer(), timer := reference() | undefined}}.
init([Opts]) ->
    Path = maps:get(hosts_file, Opts),
    Interval = maps:get(interval_ms, Opts, ?DEFAULT_INTERVAL_MS),
    self() ! dump,
    {ok, #{path => Path, interval => Interval, timer => undefined}}.

-spec handle_call(term(), gen_server:from(), map()) -> {reply, term(), map()}.
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec handle_cast(term(), map()) -> {noreply, map()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), map()) -> {noreply, map()}.
handle_info(dump, State = #{path := Path, interval := Interval}) ->
    do_dump(Path),
    Timer = erlang:send_after(Interval, self(), dump),
    {noreply, State#{timer := Timer}};
handle_info(_Info, State) ->
    {noreply, State}.

do_dump(Path) ->
    case i2p_addressbook:dump(Path) of
        ok ->
            case i2p_addressbook:snapshot() of
                {ok, Entries} ->
                    Count = maps:size(Entries),
                    catch i2p_counters:add(addressbook_published, 1),
                    catch i2p_events:notify({addressbook_published, Count});
                _ ->
                    catch i2p_counters:add(addressbook_published, 1),
                    catch i2p_events:notify({addressbook_published, 0})
            end;
        {error, Reason} ->
            catch i2p_counters:add(addressbook_publish_failed, 1),
            catch i2p_events:notify({addressbook_publish_failed, Reason}),
            ?LOG_WARNING(#{what => addressbook_publish_failed, path => Path, reason => Reason}),
            ok
    end.
