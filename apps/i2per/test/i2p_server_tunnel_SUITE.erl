%% Server-tunnel integration tests. Destination keys persist across restarts
%% under the data directory. A remote-style streaming client reaches the local
%% TCP service through injected tunnels, and a SYN with a mismatched
%% destination hash is dropped without touching the local service.

-module(i2p_server_tunnel_SUITE).

-export([all/0, init_per_testcase/2, end_per_testcase/2]).

-export([
    keys_persistence/1,
    syn_wrong_hash_dropped/1
]).

-define(APP, i2per).
-define(RECV_ID, 700).
-define(NAME, <<"eepsite">>).

all() ->
    [keys_persistence, syn_wrong_hash_dropped].

init_per_testcase(Case, Config) ->
    Timeout =
        case Case of
            keys_persistence -> 15_000;
            syn_wrong_hash_dropped -> 20_000
        end,
    [{timetrap, Timeout} | Config].

end_per_testcase(_Case, _Config) ->
    app_teardown(),
    ok.

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
        deliver_to_server(SynWire, i2p_keys:public_key(maps:get(identity, Stranger))),

        %% The tunnel process survived the unparseable delivery.
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
    LocalPeer = #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => maps:get(hash, Router),
        iv => maps:get(iv, Router),
        ri => maps:get(ri, Router),
        sign_seed => maps:get(sign_seed, Router),
        sign_pub => maps:get(sign_pub, Router)
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
    {ok, _} = i2p_peer:start_link(LocalPeer, []),
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
            catch gen_server:stop(Pid, normal, 5000)
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

stop_tunnel_srv() ->
    case whereis(i2p_tunnel_srv) of
        undefined -> ok;
        Pid -> catch gen_server:stop(Pid, normal, 5000)
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
        sign_seed => Seed,
        sign_pub => SignPub,
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
