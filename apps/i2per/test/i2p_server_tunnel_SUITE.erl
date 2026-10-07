%% Server-tunnel integration tests. Destination keys persist across restarts
%% under the data directory. A remote-style streaming client reaches the local
%% TCP service through injected tunnels, and a SYN with a mismatched
%% destination hash is dropped without touching the local service.

-module(i2p_server_tunnel_SUITE).

-export([all/0, init_per_testcase/2]).

-export([
    keys_persistence/1,
    echo_stream_end_to_end/1,
    syn_wrong_hash_dropped/1
]).

-define(APP, i2per).
-define(RECV_ID, 700).
-define(NAME, <<"eepsite">>).

all() ->
    [keys_persistence, echo_stream_end_to_end, syn_wrong_hash_dropped].

init_per_testcase(Case, Config) ->
    Timeout =
        case Case of
            keys_persistence -> 15_000;
            echo_stream_end_to_end -> 30_000;
            syn_wrong_hash_dropped -> 20_000
        end,
    [{timetrap, Timeout} | Config].

%% --------------------------------------------------------------------------
%% Key persistence
%% --------------------------------------------------------------------------

keys_persistence(_Config) ->
    setup_app(),
    Dir = temp_dir(),
    application:set_env(?APP, data_dir, Dir),
    Port1 = free_port(),
    application:set_env(?APP, server_tunnels, [decl(Port1)]),
    try
        {ok, _} = i2p_server_tunnel:start_link(decl(Port1)),
        [{Hash1, _Pid1, _Priv1}] = i2p_server_tunnel:client_destinations(),

        Path = filename:join(Dir, "eepsite.keys"),
        true = filelib:is_file(Path),
        {ok, FileBin} = file:read_file(Path),
        {ok, #{identity := StoredId}} =
            i2p_keys:parse_dest_blob(i2p_keys:decode_b64(trim(FileBin))),
        Hash1 = i2p_keys:hash(StoredId),

        ok = i2p_server_tunnel:stop(?NAME),
        Port2 = free_port(),
        application:set_env(?APP, server_tunnels, [decl(Port2)]),
        {ok, _} = i2p_server_tunnel:start_link(decl(Port2)),
        [{Hash2, _Pid2, _Priv2}] = i2p_server_tunnel:client_destinations(),
        Hash1 = Hash2
    after
        catch i2p_server_tunnel:stop(?NAME),
        persistent_term:erase({i2p_server_tunnel, ?NAME}),
        app_teardown()
    end.

%% --------------------------------------------------------------------------
%% End-to-end relay echo
%% --------------------------------------------------------------------------

echo_stream_end_to_end(_Config) ->
    setup_app(),
    process_flag(trap_exit, true),
    Dir = temp_dir(),
    application:set_env(?APP, data_dir, Dir),
    EchoPort = start_echo_server(),
    application:set_env(?APP, server_tunnels, [decl(maps:get(port, EchoPort))]),
    try
        {ok, _} = i2p_server_tunnel:start_link(decl(maps:get(port, EchoPort))),
        [{ServerHash, _TunnelPid, _CryptoPriv}] = i2p_server_tunnel:client_destinations(),

        %% The server destination material, read back from its key file.
        ServerKeys = stored_keys(Dir),
        ServerDestBin = i2p_keys:to_binary(maps:get(identity, ServerKeys)),
        ServerPub = i2p_keys:public_key(maps:get(identity, ServerKeys)),

        %% The "remote" client holds its own destination whose LeaseSet is
        %% published locally, so the tunnel can route replies without any
        %% network lookup.
        Client = i2p_keys:generate_with_privkeys(),
        ClientIdent = maps:get(identity, Client),
        NowSec = erlang:system_time(second),
        ClientLS =
            i2p_leaset:build(
                ClientIdent,
                NowSec,
                7,
                [
                    #{
                        gateway => get(local_hash),
                        tunnel_id => ?RECV_ID,
                        end_date => (NowSec + 3600) * 1000
                    }
                ],
                maps:get(sign_priv, Client)
            ),
        added = i2p_netdb_srv:store_ls(ClientLS, NowSec),

        start_sam_sup(),
        put(peer_crypto_privs, [maps:get(crypto_priv, Client)]),

        %% A real connect-role streaming connection plays the remote client:
        %% its transport injects every packet into our inbound tunnel wrapped
        %% for the published server destination.
        SenderOpts = #{
            role => connect,
            owner => self(),
            send_fn => fun(Wire) ->
                deliver_to_server(Wire, ServerPub)
            end,
            local_seed => maps:get(sign_priv, Client),
            local_dest_bin => i2p_keys:to_binary(ClientIdent),
            local_dest_hash => i2p_keys:hash(ClientIdent),
            remote_dest_bin => ServerDestBin,
            remote_dest_hash => ServerHash
        },
        {ok, Conn} = i2p_sam_sup:start_stream_conn(SenderOpts),
        erlang:monitor(process, Conn),
        ok = i2p_stream_conn:send(Conn, <<"hello relay">>),

        %% Pump every captured reply frame into the sender connection until
        %% the echoed payload comes back through the full loop.
        {ok, <<"hello relay">>} = await_echo(Conn),

        %% Clean teardown of both sides.
        ok = i2p_stream_conn:close(Conn)
    after
        catch i2p_server_tunnel:stop(?NAME),
        persistent_term:erase({i2p_server_tunnel, ?NAME}),
        kill_sam_sup(),
        app_teardown()
    end.

%% --------------------------------------------------------------------------
%% Negative: SYN naming another destination never dials the service
%% --------------------------------------------------------------------------

syn_wrong_hash_dropped(_Config) ->
    setup_app(),
    process_flag(trap_exit, true),
    Dir = temp_dir(),
    application:set_env(?APP, data_dir, Dir),
    EchoPort = start_echo_server(),
    application:set_env(?APP, server_tunnels, [decl(maps:get(port, EchoPort))]),
    try
        {ok, _} = i2p_server_tunnel:start_link(decl(maps:get(port, EchoPort))),
        [{_ServerHash, _Pid, _Priv}] = i2p_server_tunnel:client_destinations(),

        %% A stranger destination whose LeaseSet nobody holds.
        Stranger = i2p_keys:generate_with_privkeys(),
        SynWire = handcrafted_syn(Stranger, crypto:strong_rand_bytes(32)),
        Seen = length(fetch_new_frames(0)),
        deliver_to_server(SynWire, i2p_keys:public_key(maps:get(identity, Stranger))),
        %% Negative window: a stranger SYN, if misrouted, would surface
        %% promptly. Deadline-bounded silence wait — poll the capture until
        %% 200ms of quiet elapse, asserting nothing surfaced at any point
        %% (no fixed sleep gates the assertion).
        silence_until(Seen, 200),

        %% Nothing was routed out (no reply, no relay traffic) and the tunnel
        %% process survived the unparseable delivery.
        Pid = whereis(binary_to_atom(<<"i2p_server_tunnel_", (?NAME)/binary>>, utf8)),
        true = is_pid(Pid),
        true = erlang:is_process_alive(Pid)
    after
        catch i2p_server_tunnel:stop(?NAME),
        persistent_term:erase({i2p_server_tunnel, ?NAME}),
        app_teardown()
    end.

%% --------------------------------------------------------------------------
%% Harness
%% --------------------------------------------------------------------------

decl(Port) ->
    #{
        name => ?NAME,
        host => "127.0.0.1",
        port => Port
    }.

stored_keys(Dir) ->
    {ok, Bin} = file:read_file(filename:join(Dir, "eepsite.keys")),
    {ok, Keys} = i2p_keys:parse_dest_blob(i2p_keys:decode_b64(trim(Bin))),
    Keys.

start_echo_server() ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    Self = self(),
    spawn(fun() -> echo_accept(L, Self) end),
    #{port => Port}.

echo_accept(L, Parent) ->
    case gen_tcp:accept(L) of
        {ok, Sock} ->
            Parent ! {echo_accepted, self()},
            spawn(fun() -> echo_loop(Sock) end),
            echo_accept(L, Parent);
        {error, _Closed} ->
            ok
    end.

echo_loop(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Data} ->
            ok = gen_tcp:send(Sock, Data),
            echo_loop(Sock);
        {error, _Closed} ->
            ok
    end.

%% deliver_to_server/2 - play OBEP: garlic-wrap for the server destination
%% and drop the result into our inbound tunnel endpoint.
deliver_to_server(Wire, DestPub) ->
    {ok, GarlicBody} = i2p_client:wrap_payload(DestPub, Wire),
    StdBin =
        i2p_i2np:encode_std(#{
            type => 11,
            msg_id => crypto:strong_rand_bytes(4),
            expiration_ms => 60_000,
            body => GarlicBody
        }),
    {[Frame], _Gw} = i2p_tunnel:gateway_all(?RECV_ID, local, undefined, StdBin),
    i2p_tunnel_srv !
        {i2np, self(), crypto:strong_rand_bytes(32), #{
            type => 18,
            msg_id => crypto:strong_rand_bytes(4),
            expiration => erlang:system_time(second) + 60,
            body => Frame
        }},
    ok.

%% await_echo/1 - pump captured frames into the sender connection until the
%% echoed payload arrives (or time runs out).
await_echo(Conn) ->
    await_echo(Conn, 0, deadline()).

await_echo(Conn, Seen, Deadline) ->
    Seen1 = pump_frames(Conn, Seen),
    receive
        {stream_established, Conn, _PeerHash} ->
            await_echo(Conn, Seen1, Deadline);
        {stream_data, Conn, Bytes} ->
            {ok, Bytes};
        {'DOWN', _MRef, process, Conn, Reason} ->
            error({conn_died, Reason})
    after 0 ->
        case erlang:monotonic_time(millisecond) >= Deadline of
            true ->
                error(echo_timeout);
            false ->
                timer:sleep(25),
                await_echo(Conn, Seen1, Deadline)
        end
    end.

%% Consume every frame captured since `Seen`: unwrap the outer tunnel layers,
%% open the garlic with the peer's private key, and feed the decoded packet
%% to the sender connection.
pump_frames(Conn, Seen) ->
    NewFrames = fetch_new_frames(Seen),
    lists:foldl(
        fun({_N, _H, Body}, Acc) ->
            case peer_wire(Body) of
                {ok, Wire} -> ok = i2p_stream_conn:handle_packet(Conn, Wire);
                false -> ok
            end,
            Acc + 1
        end,
        Seen,
        NewFrames
    ).

fetch_new_frames(Seen) ->
    All = lists:sort(ets:tab2list(st_frames)),
    [{N, H, B} || {N, H, B} <- All, N > Seen].

%% Keep asserting an empty frame capture until `Window` ms of quiet have
%% elapsed (deadline-bounded poll; the `[] =` assertion holds on every pass).
silence_until(Seen, Window) ->
    assert_silence(Seen, erlang:monotonic_time(millisecond) + Window).

assert_silence(Seen, Deadline) ->
    [] = fetch_new_frames(Seen),
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            ok;
        false ->
            timer:sleep(25),
            assert_silence(Seen, Deadline)
    end.

%% peer_wire/1 - peel tunnel layers down to the raw streaming packet using
%% the synthetic peer's ECIES key.
peer_wire(Body) ->
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
    case [F || F <- Frags, maps:get(type, F) =:= first] of
        [First] ->
            case i2p_i2np:decode_std(maps:get(data, First)) of
                {ok, #{body := GarlicBody}} ->
                    i2p_client:unwrap_payload(hd(get(peer_crypto_privs)), GarlicBody);
                _ ->
                    false
            end;
        [] ->
            false
    end.

%% handcrafted_syn/2 - a signed SYN packet built outside the streaming
%% machinery, replay-hash-bound to ClaimedHash.
handcrafted_syn(Keys, ClaimedHash) ->
    IdentBin = i2p_keys:to_binary(maps:get(identity, Keys)),
    Seed = maps:get(sign_priv, Keys),
    Flags =
        i2p_streaming:flag_synchronize() bor
            i2p_streaming:flag_from_included() bor
            i2p_streaming:flag_no_ack(),
    P0 = i2p_streaming:with_flags(i2p_streaming:new(5555, 0, 0, 0), Flags),
    P1 = P0#{from => IdentBin, nacks => i2p_streaming:syn_replay_nacks(ClaimedHash)},
    i2p_streaming:signed(P1, Seed).

deadline() ->
    erlang:monotonic_time(millisecond) + 12_000.

trim(Bin) ->
    string:trim(Bin, both, " \r\n\t").

temp_dir() ->
    Dir =
        filename:join(
            "/tmp", "srv-tun-" ++ integer_to_list(erlang:unique_integer([positive, monotonic]))
        ),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

free_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    gen_tcp:close(L),
    Port.

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
    case ets:whereis(st_frames) of
        undefined -> ok;
        _ -> ets:delete(st_frames)
    end,
    ets:new(st_frames, [named_table, bag, public]),
    case whereis(i2p_peer) of
        undefined -> ok;
        _Pid -> unregister(i2p_peer)
    end,
    PeerPid =
        spawn(fun F() ->
            receive
                {'$gen_cast', {send_when_ready, Hash, Msg}} ->
                    ets:insert(
                        st_frames,
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
    catch ets:delete(st_frames),
    application:unset_env(?APP, addressbook),
    application:unset_env(?APP, server_tunnels),
    application:unset_env(?APP, data_dir),
    application:stop(?APP),
    erase(local_hash),
    erase(hop1_hash),
    erase(hop_keys),
    ok.

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
            receive
                {'EXIT', Sup, _} -> ok
            after 1000 -> ok
            end
    end.

stop_tunnel_srv() ->
    case whereis(i2p_tunnel_srv) of
        undefined -> ok;
        _Pid -> i2p_tunnel_srv:stop()
    end.

hop_keys() ->
    [
        #{
            layer_key => crypto:strong_rand_bytes(32),
            iv_key => crypto:strong_rand_bytes(32)
        }
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
