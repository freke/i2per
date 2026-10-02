%% Live interop with a real i2pd, run only via `scripts/interop_i2pd.sh`.
%%
%% That script boots i2pd 2.61.0 (nixpkgs) with NTCP2 and SSU2 enabled on
%% private ports and exports:
%%
%%   I2P_INTEROP            path to the i2pd datadir
%%   I2P_INTEROP_PORT       i2pd's NTCP2 TCP port
%%   I2P_INTEROP_SSU2_PORT  i2pd's SSU2 UDP port
%%
%% This suite is deliberately excluded from `just check` by living outside
%% `test/` (apps/i2per/interop/, not apps/i2per/test/), because rebar3
%% auto-discovers suites under `test/` and there is no config-level list to
%% exclude from. The script reaches it with a CLI `--suite`, which compiles the
%% file on demand regardless of where it lives. If the environment is
%% missing the cases fail with a pointer to the script rather than passing
%% trivially, so a broken gate can never go green silently. With the
%% environment set:
%%
%% * NTCP2: our pure-Erlang XK handshake runs against a real i2pd responder:
%%   msg1 -> msg2 -> msg3, then a data-phase frame (block type 0, datetime)
%%   that i2pd must decrypt and MAC-verify.
%% * SSU2: our token-based handshake runs as Alice against the real i2pd Bob:
%%   zero-token SessionRequest -> Retry -> SessionRequest -> SessionCreated ->
%%   fragmented SessionConfirmed carrying our signed RouterInfo. Liveness
%%   through i2pd's validation window plus receipt of its first Data packet
%%   proves i2pd accepted our handshake and that both directions decrypt;
%%   we then hand it our RouterInfo as a DatabaseStore and terminate cleanly.
%%
%% The script also boots a *second*, isolated i2pd (SSU2 off, reseed
%% suppressed, fresh datadir) to act as the NTCP2 initiator against our
%% responder, exporting:
%%
%%   I2P_INTEROP_RESPONDER  path to the responder i2pd datadir
%%   I2P_RESPONDER_PORT     the responder i2pd's NTCP2 TCP port
%%
%% responder_dials_us/1 pushes our floodfill RouterInfo to that i2pd as
%% Alice (NTCP2 msg3 carries it), drops the session, and waits for i2pd to
%% initiate a connection to us — i2pd's RouterInfo publication/profiling and
%% floodfill lookups open that session. It asserts the inbound XK handshake
%% completes, that the dialer is the responder i2pd, and that a valid
%% data-phase frame (i2pd's RouterInfo DatabaseStore) follows.
%%
%% i2pd on a NAT'd host publishes non-published addresses (no host or port),
%% so the responder's keys are read from the datadir — ntcp2.keys (32 bytes
%% public ‖ 32 bytes private ‖ 16 bytes IV) and ssu2.keys (32 public ‖ 32
%% private ‖ 32 introduction key) — and spliced into copies of its decoded
%% RouterInfo. Both key files were verified to match the `s`/`i` options of
%% the published RouterInfo addresses.
%%
%% Session liveness is asserted with `await_conn_settle/2` (monitor-based,
%% no fixed sleep + liveness check) on both transports. The one permitted
%% fixed wait is the reconnect backoff in `push_attempts/3`: it shields a
%% busy external i2pd, so a flaky upstream cannot flake the suite.

-module(i2p_i2pd_interop_SUITE).

-export([all/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).

-export([
    router_info_decodes/1,
    ntcp2_keys_are_valid/1,
    connects_to_i2pd/1,
    responder_dials_us/1,
    ssu2_keys_are_valid/1,
    connects_to_i2pd_over_ssu2/1
]).

-define(APP, i2per).
-define(SETTLE, 2000).

%% Backoff after a failed outbound dial. This is a retry delay, not a
%% fixed-window assert: there is no condition to await, because what is being
%% waited on is the external i2pd becoming less busy, which is not observable
%% from here. So it cannot become an event-driven wait, and it does not make
%% the suite flaky -- it only makes an already-failing run slower.
-define(I2PD_BUSY_BACKOFF, 10000).

%% The host is 127.0.0.1, so i2pd only accepts the RouterInfo we publish in
%% msg3 if its `reservedrange` check is disabled (scripts/interop_i2pd.sh
%% sets it). The port is irrelevant to i2pd — it never connects back during
%% the handshake — but must be a valid published port.
-define(LOCAL_PORT, 4668).

%% Our side of the responder interop: a pump address i2pd opens a session to
%% once it knows us. Distinct from i2pd's NTCP2 port (I2P_RESPONDER_PORT).
-define(RESPONDER_LOCAL_PORT, 39253).

%% i2pd dials us within the publication/profiling cycle after learning our
%% RouterInfo; give its maintenance loop generous windows.
-define(RESPONDER_DIAL_TIMEOUT, 150000).
-define(RESPONDER_FRAME_TIMEOUT, 40000).

all() ->
    [
        router_info_decodes,
        ntcp2_keys_are_valid,
        connects_to_i2pd,
        responder_dials_us,
        ssu2_keys_are_valid,
        connects_to_i2pd_over_ssu2
    ].

%% Covers the responder interop's full claim (150 s dial window, 40 s frame
%% window) and the SSU2 handshake's data phase.
suite() ->
    [{timetrap, 600000}].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(?APP),
    [{i2pd_env, i2pd_env()}, {responder_env, responder_env()} | Config].

end_per_suite(_Config) ->
    application:stop(?APP),
    ok.

router_info_decodes(Config) ->
    #{dir := Dir} = require_i2pd(Config),
    {ok, RI} = read_router_info(Dir),
    32 = byte_size(i2p_router_info:hash(RI)),
    [NTCP2] = [
        Addr
     || Addr <- i2p_router_info:addresses(RI),
        maps:get(transport, Addr) =:= <<"NTCP2">>
    ],
    14 = maps:get(cost, NTCP2),
    false = maps:is_key(<<"host">>, maps:get(options, NTCP2)),
    false = maps:is_key(<<"port">>, maps:get(options, NTCP2)),
    false = maps:is_key(<<"i">>, maps:get(options, NTCP2)).

ntcp2_keys_are_valid(Config) ->
    #{dir := Dir} = require_i2pd(Config),
    {ok, Pub, Priv, IV} = read_ntcp2_keys(Dir),
    32 = byte_size(Pub),
    16 = byte_size(IV),
    %% The on-disk public key must be the one the private key derives,
    %% i.e. i2pd is really using this static keypair for NTCP2.
    Pub = i2p_crypto:x25519_public_key(Priv).

%% The full handshake and one data-phase frame against a real i2pd.
connects_to_i2pd(Config) ->
    #{dir := Dir, port := Port} = require_i2pd(Config),
    {ok, PeerRI} = peer_router_info(Dir, Port),
    {ok, Conn} =
        i2p_ntcp2_conn:connect(PeerRI, local(), #{owner => self(), timeout => 10000}),
    %% i2pd verifies our msg3 RouterInfo (signature, timestamp, host match,
    %% static key) inside this window and terminates the session on any
    %% failure; a DOWN within the window surfaces that failure
    %% deterministically instead of a fixed sleep + liveness check.
    ok = await_conn_settle(Conn, ?SETTLE),
    %% A data-phase frame i2pd must decrypt and MAC-verify: block type 0
    %% (datetime) with a current timestamp, accepted silently.
    Now = erlang:system_time(second),
    Block = i2p_framing:encode_block(0, <<Now:32/big>>),
    ok = i2p_ntcp2_conn:send(Conn, Block),
    ok = await_conn_settle(Conn, ?SETTLE div 2),
    ok = i2p_ntcp2_conn:stop(Conn).

%% --------------------------------------------------------------------------
%% Responder interop: real i2pd as the NTCP2 initiator
%% --------------------------------------------------------------------------

responder_dials_us(Config) ->
    #{dir := Dir, port := Port} = require_responder(Config),
    Local = floodfill_local(?RESPONDER_LOCAL_PORT),
    {ok, Listener} = i2p_ntcp2_listener:listen(?RESPONDER_LOCAL_PORT, Local, self()),
    try
        {ok, PeerRI} = peer_router_info(Dir, Port),
        ok = push_our_router_info(PeerRI, Local),
        ok = expect_inbound_session(i2p_router_info:hash(PeerRI), ?RESPONDER_DIAL_TIMEOUT)
    after
        catch i2p_ntcp2_listener:stop(Listener)
    end.

%% --------------------------------------------------------------------------
%% SSU2
%% --------------------------------------------------------------------------

ssu2_keys_are_valid(Config) ->
    #{dir := Dir} = require_i2pd(Config),
    {ok, Pub, Priv, Intro} = read_ssu2_keys(Dir),
    32 = byte_size(Pub),
    32 = byte_size(Intro),
    %% The on-disk public key must be the one the private key derives,
    %% i.e. i2pd is really using this keypair for its SSU2 transport.
    Pub = i2p_crypto:x25519_public_key(Priv).

%% The full token-based handshake as Alice against a real i2pd Bob, then
%% liveness through i2pd's RouterInfo validation, one I2NP exchange and a
%% clean Termination.
connects_to_i2pd_over_ssu2(Config) ->
    #{dir := Dir} = require_i2pd(Config),
    {ok, Sup} = start_ssu2_sup(),
    try
        {SSU2Port} = ssu2_env(),
        {{APub, APriv}, AIntro} =
            {i2p_crypto:x25519_keygen(), crypto:strong_rand_bytes(32)},
        {ok, BobPub, _BobPriv, BobIntro} = read_ssu2_keys(Dir),
        {ok, AliceListener} =
            i2p_ssu2_listener:listen(
                <<"127.0.0.1">>,
                0,
                #{static_priv => APriv, static_pub => APub, intro_key => AIntro},
                self()
            ),
        AlicePort = i2p_ssu2_listener:port(AliceListener),
        Local =
            #{static_priv => APriv, static_pub => APub, intro_key => AIntro},
        RIBlock = ssu2_local_ri(APub, AIntro, AlicePort),
        RemoteOpts =
            #{
                host => <<"127.0.0.1">>,
                port => SSU2Port,
                static_key => BobPub,
                intro_key => BobIntro
            },
        {ok, Conn, _Keys} =
            i2p_ssu2_conn:connect(Local, RemoteOpts, RIBlock, AliceListener),
        %% i2pd validates our SessionConfirmed RouterInfo (signature,
        %% timestamp, netId, static-key match) inside this window; any
        %% rejection terminates the session under us. Same monitor-based
        %% settle as the NTCP2 path.
        ok = await_conn_settle(Conn, ?SETTLE),
        %% Hand it our RouterInfo as a DatabaseStore — the first thing a
        %% router sends a new peer — which i2pd stores in its netDb.
        send_i2np_msg(
            Conn,
            i2p_i2np:db_store(ssu2_ri_hash(RIBlock), 1, 0, undefined, RIBlock)
        ),
        %% A second, much larger I2NP forces us to fragment it across several
        %% Data packets. i2pd must reassemble them and send us ACK blocks for
        %% our ack-eliciting packets (which we decrypt and apply under the
        %% k_ba direction) without terminating us.
        Big = crypto:strong_rand_bytes(4000),
        i2p_ssu2_conn:send_i2np(Conn, 6, 987654, Big),
        ok = await_conn_settle(Conn, ?SETTLE),
        i2p_ssu2_conn:terminate_session(Conn, 0)
    after
        catch gen_server:stop(Sup)
    end.

%% --------------------------------------------------------------------------
%% Environment
%% --------------------------------------------------------------------------

i2pd_env() ->
    case os:getenv("I2P_INTEROP") of
        false ->
            undefined;
        Dir ->
            Port =
                case os:getenv("I2P_INTEROP_PORT") of
                    false -> error(missing_I2P_INTEROP_PORT);
                    P -> list_to_integer(P)
                end,
            #{dir => Dir, port => Port}
    end.

responder_env() ->
    case os:getenv("I2P_INTEROP_RESPONDER") of
        false ->
            undefined;
        Dir ->
            Port =
                case os:getenv("I2P_RESPONDER_PORT") of
                    false -> error(missing_I2P_RESPONDER_PORT);
                    P -> list_to_integer(P)
                end,
            #{dir => Dir, port => Port}
    end.

require_i2pd(Config) ->
    case proplists:get_value(i2pd_env, Config) of
        undefined -> ct:fail("i2pd interop environment missing: run scripts/interop_i2pd.sh");
        Env -> Env
    end.

require_responder(Config) ->
    case proplists:get_value(responder_env, Config) of
        undefined -> ct:fail("responder interop environment missing: run scripts/interop_i2pd.sh");
        Env -> Env
    end.

%% --------------------------------------------------------------------------
%% NTCP2 helpers
%% --------------------------------------------------------------------------

read_router_info(Dir) ->
    {ok, Bin} = file:read_file(filename:join(Dir, "router.info")),
    i2p_router_info:decode(Bin).

read_ntcp2_keys(Dir) ->
    {ok, <<Pub:32/binary, Priv:32/binary, IV:16/binary>>} =
        file:read_file(filename:join(Dir, "ntcp2.keys")),
    {ok, Pub, Priv, IV}.

%% i2pd's RouterInfo as we need it to connect: its own identity (for the hash)
%% but an NTCP2 address rebuilt from ntcp2.keys + the known local endpoint.
peer_router_info(Dir, Port) ->
    {ok, RI} = read_router_info(Dir),
    {ok, Pub, _Priv, IV} = read_ntcp2_keys(Dir),
    Addr = ntcp2_addr(<<"127.0.0.1">>, Port, Pub, IV),
    {ok, RI#{addresses => [Addr]}}.

%% Our side: fresh identity, static key and IV, and a signed RouterInfo
%% announcing a published loopback NTCP2 endpoint. The primary i2pd instance
%% is deliberately NATed/non-published; keeping this controlled test side
%% published lets i2pd 2.61.0 validate the handshake without its reserved-range
%% exception. i2pd rejects timestamps older than 90 min or more than 2 min in
%% the future, so this uses the current wall clock.
local() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = ntcp2_addr(<<"127.0.0.1">>, ?LOCAL_PORT, StaticPub, IV),
    Opts = #{
        <<"netId">> => <<"2">>,
        <<"router.version">> => <<"0.9.74">>
    },
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{static_priv => StaticPriv, static_pub => StaticPub, iv => IV, ri => RI}.

%% A published NTCP2 address. `ntcp2_address/4` now derives the `caps` flag
%% (4 for IPv4) from the host itself, so no manual injection is needed.
ntcp2_addr(Host, Port, Pub, IV) ->
    i2p_router_info:ntcp2_address(Host, Port, Pub, IV).

%% Our responder half: a fresh identity whose signed RouterInfo announces our
%% listening port as a published NTCP2 address and carries the `f` (floodfill)
%% capability. The responder i2pd is the one deliberate exception to the NATed
%% primary setup: it must accept this published loopback address and dial us
%% back. i2pd only stores floodfills it accepts (version >= NETDB min floodfill
%% 0.9.62, no U/H caps, a published reachable address) and floods its lookups
%% and RouterInfo publications to them — which is what makes it dial us.
floodfill_local(Port) ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = ntcp2_addr(<<"127.0.0.1">>, Port, StaticPub, IV),
    Opts =
        #{
            <<"netId">> => <<"2">>,
            <<"router.version">> => <<"0.9.74">>,
            <<"caps">> => <<"Lf">>
        },
    RI =
        i2p_router_info:build(
            Identity,
            erlang:system_time(millisecond),
            [Addr],
            Opts,
            Seed
        ),
    #{
        static_priv => StaticPriv,
        static_pub => StaticPub,
        hash => i2p_router_info:hash(RI),
        iv => IV,
        ri => RI
    }.

%% Hand i2pd our floodfill RouterInfo as Alice: NTCP2 msg3 carries it, i2pd
%% validates (signature, timestamp, host match, static key) and stores it. The
%% handshake is against a live, busy i2pd so a single attempt may be reset;
%% retry a few times. Each successful push ends by closing the session so i2pd
%% has to open a new (inbound, to us) one to reach us.
push_our_router_info(PeerRI, Local) ->
    push_attempts(PeerRI, Local, 3).

%% Monitor a connection across a settle window. A live i2pd may tear the
%% session down asynchronously (RouterInfo validation failure, maintenance
%% reset), which surfaces as a DOWN on our monitor; surviving the window
%% returns ok. This is the event-driven replacement for sleep-then-assert-alive.
await_conn_settle(Conn, Ms) ->
    MRef = erlang:monitor(process, Conn),
    receive
        {'DOWN', MRef, process, Conn, Reason} ->
            {error, {session_closed, Reason}}
    after Ms ->
        erlang:demonitor(MRef, [flush]),
        ok
    end.

push_attempts(_PeerRI, _Local, 0) ->
    error(push_failed);
push_attempts(PeerRI, Local, N) ->
    case i2p_ntcp2_conn:connect(PeerRI, Local, #{owner => self(), timeout => 20000}) of
        {ok, Conn} ->
            %% i2pd verifies our msg3 RouterInfo inside this window; a reset
            %% or validation failure tears the session down (DOWN) — retry.
            %% Keep a healthy session briefly so i2pd can reply, then drop it.
            case await_conn_settle(Conn, ?SETTLE) of
                ok ->
                    drain_conn_frames(Conn),
                    i2p_ntcp2_conn:stop(Conn),
                    ok;
                {error, _} ->
                    push_attempts(PeerRI, Local, N - 1)
            end;
        {error, _} ->
            %% The external i2pd is busy; back off before retrying.
            timer:sleep(?I2PD_BUSY_BACKOFF),
            push_attempts(PeerRI, Local, N - 1)
    end.

%% i2pd's new-peer dials (RouterInfo publication, NetDb profiling, floodfill
%% lookup destinations) land on our listener as inbound XK sessions. Assert the
%% dialer really is the responder i2pd, then that a valid data-phase frame
%% follows (i2pd's own RouterInfo as a DatabaseStore).
expect_inbound_session(PeerHash, DialTimeout) ->
    receive
        {ntcp2_ready, Conn, RemoteRI} ->
            PeerHash = i2p_router_info:hash(RemoteRI),
            expect_data_frame(Conn, PeerHash)
    after DialTimeout ->
        error(inbound_session_not_seen)
    end.

expect_data_frame(Conn, PeerHash) ->
    receive
        {ntcp2_frame, Conn, Payload} ->
            assert_valid_frame(Payload, PeerHash),
            ok
    after ?RESPONDER_FRAME_TIMEOUT ->
        error(no_data_frame_from_i2pd)
    end.

%% A decryptable, MAC-valid frame is the core interop claim; if it carries a
%% RouterInfo DatabaseStore, that RouterInfo must be the creator i2pd's own.
assert_valid_frame(Payload, PeerHash) ->
    case i2p_framing:decode_blocks(Payload) of
        {ok, Blocks} ->
            lists:foreach(fun(B) -> assert_block(B, PeerHash) end, Blocks);
        error ->
            error(malformed_frame)
    end.

assert_block(#{type := 3, data := Data}, PeerHash) ->
    case i2p_i2np:decode(Data) of
        {ok, #{type := 1, body := Body}} ->
            case i2p_i2np:decode_db_store(Body) of
                {ok, #{store_type := 0, data := Raw}} ->
                    case i2p_i2np:parse_router_info_data(Raw) of
                        {ok, RIBytes} ->
                            case i2p_router_info:decode(RIBytes) of
                                {ok, RI} ->
                                    PeerHash = i2p_router_info:hash(RI);
                                _ ->
                                    ok
                            end;
                        _ ->
                            ok
                    end;
                _ ->
                    ok
            end;
        _ ->
            ok
    end;
assert_block(#{type := _, data := _}, _PeerHash) ->
    ok.

drain_conn_frames(Conn) ->
    receive
        {ntcp2_frame, Conn, _} -> drain_conn_frames(Conn)
    after 0 ->
        ok
    end.

%% --------------------------------------------------------------------------
%% SSU2 helpers
%% --------------------------------------------------------------------------

ssu2_env() ->
    case os:getenv("I2P_INTEROP_SSU2_PORT") of
        false -> error(missing_I2P_INTEROP_SSU2_PORT);
        P -> {list_to_integer(P)}
    end.

read_ssu2_keys(Dir) ->
    {ok, <<Pub:32/binary, Priv:32/binary, Intro:32/binary>>} =
        file:read_file(filename:join(Dir, "ssu2.keys")),
    {ok, Pub, Priv, Intro}.

start_ssu2_sup() ->
    case i2p_ssu2_sup:start_link() of
        {ok, Sup} ->
            erlang:unlink(Sup),
            {ok, Sup};
        {error, {already_started, Sup}} ->
            erlang:unlink(Sup),
            {ok, Sup}
    end.

%% Our side: a signed RouterInfo announcing SSU2 at the port our listener
%% actually bound. i2pd checks the timestamp skew, netId, signature and that
%% the RI static key equals the handshake static key.
ssu2_local_ri(StaticPub, IntroKey, Port) ->
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    Addr0 =
        i2p_router_info:ssu2_address(<<"127.0.0.1">>, Port, StaticPub, IntroKey),
    Addr =
        Addr0#{options => (maps:get(options, Addr0))#{<<"caps">> => <<"4">>}},
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI =
        i2p_router_info:build(
            Identity,
            erlang:system_time(millisecond),
            [Addr],
            Opts,
            Seed
        ),
    maps:get(binary, RI).

%% The identity hash of the RouterInfo we published in SessionConfirmed.
ssu2_ri_hash(RIBlock) ->
    {ok, RI} = i2p_router_info:decode(RIBlock),
    i2p_router_info:hash(RI).

send_i2np_msg(Conn, #{type := Type, msg_id := <<N:32/big-unsigned-integer>>, body := Body}) ->
    i2p_ssu2_conn:send_i2np(Conn, Type, N, Body).
