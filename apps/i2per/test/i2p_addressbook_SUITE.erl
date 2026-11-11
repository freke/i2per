%% Address-book integration tests. The cases cover hosts.txt loading, name
%% resolution, persistence, subscription fetching, and response ingestion.
%% Subscription traffic uses a controlled local destination and real streaming
%% packets; waits are deadline-bounded.

-module(i2p_addressbook_SUITE).

-export([all/0, init_per_testcase/2]).

-export([
    hosts_txt_roundtrip/1,
    duplicate_add_does_not_grow_file/1,
    changed_dest_appends_and_reloads/1,
    naming_lookup_via_book/1,
    subscription_fetch/1,
    a_refused_fetch_does_not_take_the_fetcher_down/1,
    completion_releases_the_conn_and_ignores_the_old_one/1
]).

-define(APP, i2per).
-define(RECV_ID, 700).

all() ->
    [
        hosts_txt_roundtrip,
        duplicate_add_does_not_grow_file,
        changed_dest_appends_and_reloads,
        naming_lookup_via_book,
        subscription_fetch,
        a_refused_fetch_does_not_take_the_fetcher_down,
        completion_releases_the_conn_and_ignores_the_old_one
    ].

init_per_testcase(Case, Config) ->
    Timeout =
        case Case of
            hosts_txt_roundtrip -> 10_000;
            duplicate_add_does_not_grow_file -> 10_000;
            changed_dest_appends_and_reloads -> 10_000;
            naming_lookup_via_book -> 15_000;
            subscription_fetch -> 25_000;
            a_refused_fetch_does_not_take_the_fetcher_down -> 15_000;
            completion_releases_the_conn_and_ignores_the_old_one -> 30_000
        end,
    [{timetrap, Timeout} | Config].

%% --------------------------------------------------------------------------
%% Store + persistence
%% --------------------------------------------------------------------------

hosts_txt_roundtrip(_Config) ->
    Dir = temp_dir(),
    Path = i2p_addressbook:hosts_file_for(Dir),
    ok = file:write_file(Path, <<"# comment\nstats.i2p=AAA1\nother.i2p=BBB2\n">>),
    start_book(Path),
    try
        {ok, <<"AAA1">>} = i2p_addressbook:resolve(<<"stats.i2p">>),
        %% Case-insensitive.
        {ok, <<"AAA1">>} = i2p_addressbook:resolve(<<"STATS.I2P">>),
        {error, not_found} = i2p_addressbook:resolve(<<"missing.i2p">>),
        %% Adds persist through restarts of the book.
        ok = i2p_addressbook:add(<<"fresh.i2p">>, <<"CCC3">>),
        stop_book(),
        start_book(Path),
        {ok, <<"CCC3">>} = i2p_addressbook:resolve(<<"fresh.i2p">>),
        {ok, Stored} = file:read_file(Path),
        {_, _} = binary:match(Stored, <<"fresh.i2p=CCC3\n">>)
    after
        stop_book()
    end.

%% --------------------------------------------------------------------------
%% Store + persistence
%% --------------------------------------------------------------------------

duplicate_add_does_not_grow_file(_Config) ->
    Dir = temp_dir(),
    Path = i2p_addressbook:hosts_file_for(Dir),
    ok = file:write_file(Path, <<"stats.i2p=AAA1\n">>),
    start_book(Path),
    try
        ok = i2p_addressbook:add(<<"stats.i2p">>, <<"AAA1">>),
        ok = i2p_addressbook:add(<<"stats.i2p">>, <<"AAA1">>),
        {ok, Stored} = file:read_file(Path),
        %% Still exactly one data line.
        Lines = [L || L <- binary:split(Stored, <<"\n">>, [global]), L =/= <<>>],
        1 = length(Lines)
    after
        stop_book()
    end.

changed_dest_appends_and_reloads(_Config) ->
    Dir = temp_dir(),
    Path = i2p_addressbook:hosts_file_for(Dir),
    ok = file:write_file(Path, <<"stats.i2p=AAA1\n">>),
    start_book(Path),
    try
        ok = i2p_addressbook:add(<<"stats.i2p">>, <<"BBB2">>),
        stop_book(),
        start_book(Path),
        {ok, <<"BBB2">>} = i2p_addressbook:resolve(<<"stats.i2p">>)
    after
        stop_book()
    end.

%% --------------------------------------------------------------------------
%% SAM integration
%% --------------------------------------------------------------------------

naming_lookup_via_book(_Config) ->
    setup_app(),
    process_flag(trap_exit, true),
    try
        start_book(undefined),
        start_sam_sup(),
        {ok, Listener} = i2p_sam_listener:listen(#{
            port => free_port(), local => undefined
        }),
        Port = i2p_sam_listener:port(Listener),
        {ok, Sock} = connect_sam(Port),
        send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
        _ = recv_line(Sock),
        ok = i2p_addressbook:add(<<"eepsite.i2p">>, <<"ZZZ9">>),
        send_cmd(Sock, <<"NAMING LOOKUP NAME=eepsite.i2p">>),
        Reply = recv_line(Sock),
        {_, _} = binary:match(Reply, <<"RESULT=OK">>),
        {_, _} = binary:match(Reply, <<"VALUE=ZZZ9">>),
        gen_tcp:close(Sock)
    after
        kill_sam_sup(),
        stop_book(),
        app_teardown()
    end.

%% --------------------------------------------------------------------------
%% Subscription fetch
%% --------------------------------------------------------------------------

subscription_fetch(_Config) ->
    setup_app(),
    process_flag(trap_exit, true),
    try
        %% The "eepsite": a destination WE hold keys for.
        Site = i2p_keys:generate_with_privkeys(),
        SiteIdent = maps:get(identity, Site),
        SiteB64 = i2p_keys:encode_b64(i2p_keys:dest_blob(Site)),
        NowSec = erlang:system_time(second),
        LocalHash = get(local_hash),
        LS =
            i2p_leaset:build(
                SiteIdent,
                NowSec,
                7,
                [#{gateway => LocalHash, tunnel_id => 4321, end_date => (NowSec + 3600) * 1000}],
                maps:get(sign_priv, Site)
            ),
        added = i2p_netdb_srv:store_ls(LS, NowSec),

        start_sam_sup(),
        application:set_env(?APP, addressbook, #{
            subscriptions => [#{host => <<"mysite.i2p">>, dest_b64 => SiteB64}]
        }),
        start_book(undefined),
        SubsOpts = #{subscriptions => [#{host => <<"mysite.i2p">>, dest_b64 => SiteB64}]},
        {ok, _} = i2p_addressbook_subs:start_link(SubsOpts),

        %% Transport leg: trigger the pipeline; the fetcher opens a stream
        %% toward the site and emits a signed SYN whose replay hash binds
        %% the site's hash.
        ok = i2p_addressbook_subs:fetch_now(),
        {SynPkt, _Seen} = await_syn(maps:get(crypto_priv, Site)),
        true = i2p_streaming:has_flag(SynPkt, i2p_streaming:flag_synchronize()),
        SiteHash = i2p_keys:hash(SiteIdent),
        {ok, SiteHash} = i2p_streaming:replay_hash(SynPkt),

        %% Ingestion leg: a fetched hosts.txt response merges into the book.
        Response =
            iolist_to_binary([
                <<"HTTP/1.0 200 OK\r\n">>,
                <<"Content-Length: 35\r\n\r\n">>,
                <<"fetched.i2p=DDDD4\nsecond.i2p=EEEE5\n">>
            ]),
        2 = i2p_addressbook_subs:ingest_response(Response),
        {ok, <<"DDDD4">>} = i2p_addressbook:resolve(<<"fetched.i2p">>),
        {ok, <<"EEEE5">>} = i2p_addressbook:resolve(<<"second.i2p">>)
    after
        catch i2p_addressbook_subs:stop(),
        kill_sam_sup(),
        stop_book(),
        app_teardown()
    end.

%% --------------------------------------------------------------------------
%% The cap, on the fetch path
%% --------------------------------------------------------------------------

%% **This is the third of the three `f:i2p_sam_sup:start_stream_conn/1` call
%% sites, and the only one that could not survive a refusal.**
%%
%% `f:i2p_addressbook_subs:start_http_conn/3` matched `{ok, Conn} = ...`. The other
%% two call sites -- the SAM STREAM CONNECT path and the server-tunnel relay path --
%% were already a `case` with an answer for `{error, _}`, so a cap on streaming
%% connections cost them a refused dial. Here it raised `{badmatch, {error,
%% stream_limit}}` inside the fetcher, taking down the process that also owns the
%% refresh timer for every *other* subscription: one router at its stream cap
%% would have stopped all of them, silently, until the next router start.
%%
%% The cap is at zero and the fetch is a subscription whose route resolves, so the
%% refusal is certain rather than racy. What is asserted is that the fetcher is
%% **still running** and still answering -- the pipeline must move on to the next
%% subscription, and the process must survive to do it.
a_refused_fetch_does_not_take_the_fetcher_down(_Config) ->
    setup_app(),
    process_flag(trap_exit, true),
    Site = i2p_keys:generate_with_privkeys(),
    SiteIdent = maps:get(identity, Site),
    SiteB64 = i2p_keys:encode_b64(i2p_keys:dest_blob(Site)),
    NowSec = erlang:system_time(second),
    LS =
        i2p_leaset:build(
            SiteIdent,
            NowSec,
            7,
            [#{gateway => get(local_hash), tunnel_id => 4321, end_date => (NowSec + 3600) * 1000}],
            maps:get(sign_priv, Site)
        ),
    added = i2p_netdb_srv:store_ls(LS, NowSec),

    start_sam_sup(),
    %% A second subscription after the refused one: it is what proves the
    %% pipeline moved on rather than merely not crashing.
    Other = i2p_keys:generate_with_privkeys(),
    OtherB64 = i2p_keys:encode_b64(i2p_keys:dest_blob(Other)),
    Subs = [
        #{host => <<"capped.i2p">>, dest_b64 => SiteB64},
        #{host => <<"after.i2p">>, dest_b64 => OtherB64}
    ],
    application:set_env(?APP, addressbook, #{subscriptions => Subs}),
    %% Cap must be in place before the fetcher starts: its init/1 schedules an
    %% automatic fetch on the next scheduler slot (timeout 0), and that fetch
    %% must see the cap too, otherwise it can open a stream connection before
    %% we ever call fetch_now/0.
    application:set_env(?APP, max_stream_connections, 0),
    start_book(undefined),
    {ok, Fetcher} = i2p_addressbook_subs:start_link(#{subscriptions => Subs}),

    MRef = erlang:monitor(process, Fetcher),
    Baseline = i2p_sam_sup:stream_conn_count(),
    try
        ok = i2p_addressbook_subs:fetch_now(),
        assert_fetcher_alive(Fetcher, MRef),
        ok = i2p_addressbook_subs:fetch_now(),
        assert_fetcher_alive(Fetcher, MRef),
        %% fetch_now/0 is asynchronous: the gen_server:call only schedules the
        %% pipeline. Wait for it to drain before reading the count, otherwise
        %% the assertion races the fetcher and can observe a stale value.
        wait_fetcher_idle(Fetcher, 5000),
        %% And nothing was admitted against the cap it refused at.
        Baseline = i2p_sam_sup:stream_conn_count()
    after
        erlang:demonitor(MRef, [flush]),
        application:unset_env(?APP, max_stream_connections),
        catch i2p_addressbook_subs:stop(),
        kill_sam_sup(),
        stop_book(),
        app_teardown()
    end.

%% --------------------------------------------------------------------------
%% One fetch finishing does not disturb the next
%% --------------------------------------------------------------------------

%% A fetch that completes by Content-Length closes its own connection instead of
%% waiting for the peer's FIN, so the stream admission slot comes back before the
%% next subscription starts. And once that connection is gone, traffic that was
%% queued behind it -- a data fragment, a half-closed notification, a fired
%% timeout -- cannot finish or abort the subscription that is current now.
%%
%% This is the end-to-end version of #94XG2E0's unit cases: two live
%% `i2p_stream_conn` processes, one per subscription, a real HTTP response
%% delivered through the streaming stack, and the admission count read from the
%% supervisor rather than inferred.
completion_releases_the_conn_and_ignores_the_old_one(_Config) ->
    setup_app(),
    process_flag(trap_exit, true),
    SiteA = subscription_site(<<"first.i2p">>, <<"AAAA1">>),
    SiteB = subscription_site(<<"second.i2p">>, <<"BBBB2">>),
    Subs = [
        #{host => <<"first.i2p">>, dest_b64 => maps:get(b64, SiteA)},
        #{host => <<"second.i2p">>, dest_b64 => maps:get(b64, SiteB)}
    ],
    start_sam_sup(),
    application:set_env(?APP, addressbook, #{subscriptions => Subs}),
    start_book(undefined),
    {ok, Fetcher} = i2p_addressbook_subs:start_link(#{subscriptions => Subs}),
    try
        Baseline = i2p_sam_sup:stream_conn_count(),
        %% --- subscription 1 ---
        {Conn1, SynA, SeenA} = start_fetch(Fetcher, SiteA),
        %% The slot is held while the fetch is in flight, not before and not after.
        1 = i2p_sam_sup:stream_conn_count() - Baseline,
        SiteConnA = start_site_conn(SiteA, SynA),
        reset_site_accumulators(),
        SeenA1 = pump_until(Fetcher, SiteConnA, maps:get(priv, SiteA), SeenA, fun() ->
            binary:match(site_buf(), <<"\r\n\r\n">>) =/= nomatch
        end),
        %% A Content-Length response is what the fetcher completes on.
        ok = i2p_stream_conn:send(
            SiteConnA,
            http_response(<<"first.i2p=AAAA1\n">>)
        ),
        _SeenA2 = pump_until(Fetcher, SiteConnA, maps:get(priv, SiteA), SeenA1, fun() ->
            site_closed() andalso not is_process_alive(Conn1)
        end),
        {ok, <<"AAAA1">>} = i2p_addressbook:resolve(<<"first.i2p">>),
        %% The fetcher closed its own side on completion, so the process is gone
        %% and the slot it held is back.
        false = is_process_alive(Conn1),
        %% --- subscription 2 starts on its own; do not kick the pipeline again ---
        {SynB, _} = await_syn(maps:get(priv, SiteB)),
        Conn2 = await_fetch_conn(Fetcher, 5000),
        true = Conn2 =/= Conn1,
        %% Everything the finished fetch left behind arrives now, while the next
        %% subscription is in flight.
        Fetcher ! {stream_data, Conn1, <<"stale.i2p=ZZZZ9\n">>},
        Fetcher ! {stream_closed, Conn1},
        Fetcher ! {timeout, make_ref(), fetch_timeout},
        #{fetch := #{conn := Conn2}} = sys:get_state(Fetcher),
        SiteConnB = start_site_conn(SiteB, SynB),
        reset_site_accumulators(),
        SeenB = max_frame_n(),
        SeenB1 = pump_until(Fetcher, SiteConnB, maps:get(priv, SiteB), SeenB, fun() ->
            binary:match(site_buf(), <<"\r\n\r\n">>) =/= nomatch
        end),
        ok = i2p_stream_conn:send(
            SiteConnB,
            http_response(<<"second.i2p=BBBB2\n">>)
        ),
        _SeenB2 = pump_until(Fetcher, SiteConnB, maps:get(priv, SiteB), SeenB1, fun() ->
            site_closed() andalso i2p_sam_sup:stream_conn_count() =:= Baseline
        end),
        %% The second fetch finished with its own body, and the stale traffic from
        %% the first never reached it.
        {ok, <<"BBBB2">>} = i2p_addressbook:resolve(<<"second.i2p">>),
        {error, not_found} = i2p_addressbook:resolve(<<"stale.i2p">>),
        ok
    after
        catch i2p_addressbook_subs:stop(),
        kill_sam_sup(),
        stop_book(),
        app_teardown()
    end.

%% A site we hold keys for, published as a LeaseSet whose gateway is our own
%% inbound tunnel, so `route_to` resolves it.
subscription_site(Host, Dest) ->
    Site = i2p_keys:generate_with_privkeys(),
    Ident = maps:get(identity, Site),
    NowSec = erlang:system_time(second),
    LS =
        i2p_leaset:build(
            Ident,
            NowSec,
            7,
            [#{gateway => get(local_hash), tunnel_id => 4321, end_date => (NowSec + 3600) * 1000}],
            maps:get(sign_priv, Site)
        ),
    added = i2p_netdb_srv:store_ls(LS, NowSec),
    #{
        host => Host,
        dest => Dest,
        b64 => i2p_keys:encode_b64(i2p_keys:dest_blob(Site)),
        dest_bin => i2p_keys:to_binary(Ident),
        hash => i2p_keys:hash(Ident),
        priv => maps:get(crypto_priv, Site),
        seed => maps:get(sign_priv, Site)
    }.

%% Wait for the fetcher's own pipeline to open a connection to `Site`, and
%% return that connection together with the SYN the accept side needs. The
%% pipeline is not kicked here: a second `fetch_now/0` would open a second
%% connection beside the one already in flight.
start_fetch(Fetcher, Site) ->
    {SynPkt, _Seen} = await_syn(maps:get(priv, Site)),
    Conn = await_fetch_conn(Fetcher, 5000),
    {Conn, SynPkt, max_frame_n()}.

await_fetch_conn(Fetcher, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    await_fetch_conn_loop(Fetcher, Deadline).

await_fetch_conn_loop(Fetcher, Deadline) ->
    case catch sys:get_state(Fetcher) of
        #{fetch := #{conn := Conn}} ->
            Conn;
        _ ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    ct:fail(fetch_conn_not_started);
                false ->
                    timer:sleep(10),
                    await_fetch_conn_loop(Fetcher, Deadline)
            end
    end.

%% The other end: an accept-role connection owned by this test process, whose
%% outbound packets are posted to us as `{site_wire, Pid, Wire}` rather than
%% going through the router.
start_site_conn(Site, SynPkt) ->
    Parent = self(),
    {ok, Conn} = i2p_stream_conn:start_link(#{
        role => accept,
        syn => SynPkt,
        owner => Parent,
        send_fn => fun(Wire) -> Parent ! {site_wire, self(), Wire} end,
        local_seed => maps:get(seed, Site),
        local_dest_bin => maps:get(dest_bin, Site),
        local_dest_hash => maps:get(hash, Site)
    }),
    Conn.

http_response(Body) ->
    iolist_to_binary([
        <<"HTTP/1.0 200 OK\r\nContent-Length: ">>,
        integer_to_binary(byte_size(Body)),
        <<"\r\n\r\n">>,
        Body
    ]).

reset_site_accumulators() ->
    put(site_buf, <<>>),
    put(site_closed, false).

site_buf() ->
    case get(site_buf) of
        undefined -> <<>>;
        Buf -> Buf
    end.

site_closed() ->
    get(site_closed) =:= true.

%% Drive both directions until `Pred` holds. Every iteration pumps the fetcher's
%% outbound frames into the site connection, forwards the site's frames to the
%% fetcher, and folds the site's owner messages into the accumulators.
pump_until(Fetcher, SiteConn, Priv, Seen, Pred) ->
    Pumped = pump_step(Fetcher, SiteConn, Priv, Seen),
    case Pred() of
        true ->
            Pumped;
        false ->
            timer:sleep(10),
            pump_until(Fetcher, SiteConn, Priv, Pumped, Pred)
    end.

pump_step(Fetcher, SiteConn, Priv, Seen) ->
    ok = collect_site_messages(Fetcher, SiteConn),
    pump_frames(SiteConn, Priv, Seen).

collect_site_messages(Fetcher, SiteConn) ->
    receive
        {site_wire, SiteConn, Wire} ->
            Fetcher ! {stream_data, Wire},
            collect_site_messages(Fetcher, SiteConn);
        {site_wire, _OtherConn, _Wire} ->
            collect_site_messages(Fetcher, SiteConn);
        {stream_data, SiteConn, Data} ->
            put(site_buf, <<(site_buf())/binary, Data/binary>>),
            collect_site_messages(Fetcher, SiteConn);
        {stream_closed, SiteConn} ->
            put(site_closed, true),
            collect_site_messages(Fetcher, SiteConn);
        {stream_reset, SiteConn} ->
            put(site_closed, true),
            collect_site_messages(Fetcher, SiteConn);
        {stream_started, SiteConn, _Id} ->
            collect_site_messages(Fetcher, SiteConn);
        {stream_established, SiteConn, _Hash} ->
            collect_site_messages(Fetcher, SiteConn)
    after 0 ->
        ok
    end.

%% Feed every frame this site has not seen yet, unwrapped from the garlic the
%% fetcher addressed to it, into the site connection.
pump_frames(SiteConn, Priv, Seen) ->
    lists:foldl(
        fun
            ({N, _Hash, Body}, Last) when N > Last ->
                case unwrap_wire(Body, Priv) of
                    {ok, Wire} -> ok = i2p_stream_conn:handle_packet(SiteConn, Wire);
                    false -> ok
                end,
                N;
            (_Frame, Last) ->
                Last
        end,
        Seen,
        lists:sort(ets:tab2list(ab_frames))
    ).

max_frame_n() ->
    case [N || {N, _Hash, _Body} <- ets:tab2list(ab_frames)] of
        [] -> 0;
        Ns -> lists:max(Ns)
    end.

%% The liveness assertion, named so the failure says what was being claimed. A
%% `gen_server:call` to a process that has just died exits the caller, so the bare
%% match on `ok` above already turns a badmatch into a failed case; this makes the
%% case *name* the defect rather than reporting an exit from an unrelated-looking
%% line.
assert_fetcher_alive(Fetcher, MRef) ->
    receive
        {'DOWN', MRef, process, Fetcher, Reason} ->
            ct:fail({fetcher_died_at_the_stream_cap, Reason})
    after 0 ->
        true = is_process_alive(Fetcher),
        ok
    end.

%% Wait for the fetcher's asynchronous pipeline to drain (its `fetch` field
%% goes back to `undefined`). Polls rather than sleeping once, so a slow
%% pipeline cannot make the subsequent count assertion race it.
wait_fetcher_idle(Fetcher, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_fetcher_idle_loop(Fetcher, Deadline).

wait_fetcher_idle_loop(Fetcher, Deadline) ->
    case (catch sys:get_state(Fetcher)) of
        #{fetch := undefined} ->
            ok;
        _ ->
            Now = erlang:monotonic_time(millisecond),
            if
                Now >= Deadline ->
                    ct:fail({fetcher_did_not_drain, 5000});
                true ->
                    timer:sleep(25),
                    wait_fetcher_idle_loop(Fetcher, Deadline)
            end
    end.
%% --------------------------------------------------------------------------
%% Harness
%% --------------------------------------------------------------------------

setup_app() ->
    case whereis(i2p_netdb_srv) of
        undefined -> ok;
        StaleNetDb -> gen_server:stop(StaleNetDb)
    end,
    case whereis(i2per_sup) of
        undefined -> ok;
        _Sup -> application:stop(?APP)
    end,
    {ok, _} = application:ensure_all_started(?APP),
    Router = make_router(),
    Local = #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => maps:get(hash, Router),
        iv => crypto:strong_rand_bytes(16),
        ri => maps:get(ri, Router)
    },
    put(local_hash, maps:get(hash, Local)),
    HopKeys = hop_keys(),
    put(hop_keys, HopKeys),
    Hop1 = make_router(),
    Hop1Hash = i2p_router_info:hash(maps:get(ri, Hop1)),
    put(hop1_hash, Hop1Hash),
    {ok, _} = i2p_netdb_srv:store_binary(
        i2p_router_info:to_binary(maps:get(ri, Hop1)), erlang:system_time(millisecond)
    ),
    {ok, _} = i2p_tunnel_srv:start_link(Local),
    %% A crashed case in this or another suite may have left the frame table
    %% or the fake peer registered: clear both before (re)creating.
    case ets:whereis(ab_frames) of
        undefined -> ok;
        _ -> ets:delete(ab_frames)
    end,
    ets:new(ab_frames, [named_table, bag, public]),
    case whereis(i2p_peer) of
        undefined -> ok;
        _Pid -> unregister(i2p_peer)
    end,
    PeerPid =
        spawn(fun F() ->
            receive
                {'$gen_cast', {send_when_ready, Hash, Msg}} ->
                    ets:insert(
                        ab_frames,
                        {
                            erlang:unique_integer([positive, monotonic]),
                            Hash,
                            maps:get(body, Msg)
                        }
                    ),
                    F();
                _Other ->
                    F()
            end
        end),
    true = register(i2p_peer, PeerPid),
    inject_inbound_entry(?RECV_ID, maps:get(hash, Local)),
    inject_outbound_entry(500, #{
        tunnel_ids => [500, 501, 502],
        router_hashes => [Hop1Hash, Hop1Hash, Hop1Hash],
        layers => HopKeys,
        built_at => erlang:system_time(second)
    }),
    ok.

app_teardown() ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            unregister(i2p_peer),
            exit(Pid, kill)
    end,
    stop_tunnel_srv(),
    catch ets:delete(ab_frames),
    application:unset_env(?APP, addressbook),
    application:stop(?APP),
    erase(local_hash),
    erase(hop1_hash),
    erase(hop_keys),
    ok.

start_book(Path) ->
    {ok, _} = i2p_addressbook:start_link(Path),
    ok.

stop_book() ->
    case whereis(i2p_addressbook) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

start_sam_sup() ->
    case whereis(i2p_sam_sup) of
        undefined ->
            {ok, _} = i2p_sam_sup:start_link(),
            ok;
        _Alive ->
            ok
    end.

kill_sam_sup() ->
    case whereis(i2p_sam_sup) of
        undefined ->
            ok;
        Sup ->
            unregister(i2p_sam_sup),
            exit(Sup, kill),
            %% Monitor the reap so a slow stop cannot race the next test's
            %% start_sam_sup; fail loudly rather than silently proceeding.
            MRef = erlang:monitor(process, Sup),
            receive
                {'DOWN', MRef, process, Sup, _} -> ok
            after 5000 ->
                erlang:error(sam_sup_reap_timeout)
            end
    end.

stop_tunnel_srv() ->
    case whereis(i2p_tunnel_srv) of
        undefined -> ok;
        _Pid -> i2p_tunnel_srv:stop()
    end.

temp_dir() ->
    Dir =
        filename:join(
            "/tmp", "ab-" ++ integer_to_list(erlang:unique_integer([positive, monotonic]))
        ),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

hop_keys() ->
    [
        #{layer_key => crypto:strong_rand_bytes(32), iv_key => crypto:strong_rand_bytes(32)}
     || _ <- lists:seq(1, 3)
    ].

make_router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, free_port(), StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        iv => IV,
        seed => Seed,
        identity => Identity,
        ri => RI,
        hash => i2p_router_info:hash(RI)
    }.

free_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    gen_tcp:close(L),
    Port.

inject_inbound_entry(RecvID, GwHash) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{inbound := Inbound} = State) ->
        State#{
            inbound :=
                maps:put(
                    RecvID,
                    #{
                        tunnel_ids => [RecvID],
                        router_hashes => [GwHash],
                        layers => [],
                        frag_map => #{},
                        built_at => erlang:system_time(second)
                    },
                    Inbound
                )
        }
    end),
    ok.

inject_outbound_entry(TunID, Entry) ->
    sys:replace_state(i2p_tunnel_srv, fun(#{tunnels := Tunnels} = State) ->
        State#{tunnels := maps:put(TunID, Entry, Tunnels)}
    end),
    ok.

%% Wait for a SYN addressed to one site. The garlic is unlocked with that
%% site's own key, so another site's SYN -- still sitting in `ab_frames` -- is
%% passed over rather than mistaken for this one.
await_syn(Priv) ->
    Deadline = erlang:monotonic_time(millisecond) + 6000,
    await_syn(Priv, 0, Deadline).

await_syn(Priv, Seen, Deadline) ->
    All = lists:sort(ets:tab2list(ab_frames)),
    Unseen = [{N, H, B} || {N, H, B} <- All, N > Seen],
    case first_syn(Unseen, Priv) of
        {ok, SynPkt, Consumed} ->
            {SynPkt, Seen + Consumed};
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true ->
                    error({frames_timeout, length(Unseen)});
                false ->
                    timer:sleep(25),
                    await_syn(Priv, Seen, Deadline)
            end
    end.

first_syn([{_N, _H, Body} | Rest], Priv) ->
    case unwrap_wire(Body, Priv) of
        {ok, Wire} ->
            case i2p_streaming:decode(Wire) of
                {ok, Pkt} ->
                    case i2p_streaming:has_flag(Pkt, i2p_streaming:flag_synchronize()) of
                        true -> {ok, Pkt, 1};
                        false -> first_syn(Rest, Priv)
                    end;
                _ ->
                    first_syn(Rest, Priv)
            end;
        false ->
            first_syn(Rest, Priv)
    end;
first_syn([], _Priv) ->
    false.

%% Unwrap one outbound (garlic-wrapped) frame back to the streaming wire that was
%% sealed into it. `false` when this frame is not addressed to `Priv`.
unwrap_wire(Body, Priv) ->
    case reassemble(Body) of
        [First | _] ->
            case maps:get(type, First) of
                first ->
                    case i2p_i2np:decode_std(maps:get(data, First)) of
                        {ok, #{body := GarlicBody}} ->
                            case i2p_client:unwrap_payload(Priv, GarlicBody) of
                                {ok, Wire} -> {ok, Wire};
                                error -> false
                            end;
                        _ ->
                            false
                    end;
                _ ->
                    false
            end;
        [] ->
            false
    end.

reassemble(Body) ->
    Final =
        lists:foldl(
            fun(Hop, M) ->
                {ok, M1} = i2p_tunnel:process_tunnel_data(M, Hop, 500, <<0, 0, 0, 0>>),
                M1
            end,
            Body,
            get(hop_keys)
        ),
    <<_:32/big, IV:16/binary, Plain:1008/binary>> = Final,
    {ok, Frags, _Fm} = i2p_tunnel:parse_tunnel_data(Plain, IV, #{}),
    Frags.

connect_sam(Port) ->
    {ok, Sock} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}]),
    {ok, Sock}.

send_cmd(Sock, Cmd) ->
    ok = gen_tcp:send(Sock, <<Cmd/binary, "\n">>).

recv_line(Sock) ->
    recv_line(Sock, 5000).

recv_line(Sock, Timeout) ->
    recv_line(Sock, Timeout, <<>>).

recv_line(Sock, Timeout, Acc) ->
    case binary:match(Acc, <<"\n">>) of
        {_, _} ->
            Acc;
        nomatch ->
            case gen_tcp:recv(Sock, 0, Timeout) of
                {ok, Data} -> recv_line(Sock, Timeout, <<Acc/binary, Data/binary>>);
                {error, Reason} -> erlang:error({recv_failed, Reason})
            end
    end.
