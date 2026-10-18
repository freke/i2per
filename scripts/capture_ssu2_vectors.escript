#!/usr/bin/env escript
%%! -pa _build/default/lib/i2per/ebin -pa _build/default/lib/telemetry/ebin

%% Capture SSU2 data-phase wire bytes from a real i2pd into a committed fixture.
%%
%% `scripts/capture_i2pd_vectors.sh` boots i2pd, waits for its SSU2 listener and
%% runs this; it is the only thing that writes the fixture, and it is never run by
%% the test gate. What CI runs is `apps/i2per/test/i2p_ssu2_vectors_SUITE.erl`,
%% which replays the committed bytes with no i2pd anywhere.
%%
%% **Why a relay.** The datagrams have to be the ones that crossed a socket, not
%% the ones our session believed it sent, so the session's peer address is the
%% relay and the relay re-originates towards i2pd. Two sockets, not one: each leg
%% keeps its own source port, which matters because the SSU2 pending-session map
%% is keyed by endpoint and a single re-originating socket would collapse Alice's
%% and Bob's legs into one.
%%
%% **What is recorded is one direction.** Only Bob -> Alice (`ba`) datagrams are
%% recorded. The `ab` leg is sealed under i2pd's introduction key for header mask
%% 1, so replaying it would mean committing i2pd's key too; the `ba` leg needs
%% only our own introduction key, which is ours to publish.
%%
%% **What makes the keys replayable.** `i2p_ssu2:decode_data/4` is pure — its
%% whole input is the session's four data keys, the receiving direction, our
%% introduction key and the datagram. Packet-number replay tracking is the
%% session layer's job, so the committed list can be replayed in order, and no
%% socket or process stands between the fixture and the decoder.
%%
%% Usage:
%%   escript scripts/capture_ssu2_vectors.escript <i2pd-datadir> <ssu2-port> <out>
%%
%% `<out>` is overwritten with Erlang consult terms. The shell driver supplies
%% all three; nothing here discovers i2pd, and a missing or unusable i2pd is a
%% non-zero exit rather than a fixture written from a partial session.

-mode(compile).

%% Where the relay posts the datagrams it saw. A registered name rather than a
%% pid because the relay is spawned before it can be told anything, and the
%% collector is this process.
-define(COLLECTOR, i2per_capture_collector).

%% Big enough that the session cannot put it in one data packet, which is the
%% point: i2pd has to reassemble several fragments before it has anything to
%% acknowledge, so its ACKs name several distinct packet numbers.
-define(FRAGMENTING_BODY, 4000).

%% Upper bound on one capture's datagrams. A hang guard on a misbehaving peer,
%% not a policy: the drain window ends a healthy run long before this.
-define(MAX_DATAGRAMS, 512).

%% How many of our own data packets the relay swallows. One is enough to leave a
%% hole in i2pd's packet-number run and make it emit an ACK with a NACK range,
%% which is the ACK shape congestion control has to read correctly; more than one
%% would only add a second hole of the same kind.
-define(DROPPED_PACKETS, 1).

-define(RELAY_READY_TIMEOUT, 5000).

%% Read until the relay has been idle for a whole drain window. Bounded on both
%% ends: the idle window is what ends it, and the counter is what stops a
%% pathological peer from growing this without limit.
%%
%% How *long* a capture is is not fixed, and deliberately so: it is however much
%% NetDb traffic i2pd happens to emit after our exchange, which varies with what
%% its throwaway router finds to do. The suite's assertions are relational --
%% packet numbers contiguous, ACK sets nested, the NACK set equal to the packet
%% we dropped -- so a capture of a different length is a different capture of the
%% same claims, not a weaker one. A window long enough to outlast a burst of
%% lookups is all that is asked for here.
-define(DRAIN_MS, 4000).

main([DataDir, Ssu2Port, Out]) ->
    true = register(?COLLECTOR, self()),
    {ok, _} = application:ensure_all_started(i2per),
    _ = start_ssu2_sup(),
    BobPort = list_to_integer(Ssu2Port),
    {BobPub, BobIntro} = read_ssu2_keys(DataDir),
    Relay = start_relay(BobPort),
    try
        capture(Relay, BobPub, BobIntro, Out)
    after
        stop_relay(Relay)
    end.

%% ---------------------------------------------------------------------------
%% The session and the exchange that makes i2pd acknowledge something
%% ---------------------------------------------------------------------------

capture(Relay, BobPub, BobIntro, Out) ->
    {{AlicePub, AlicePriv}, AliceIntro} =
        {i2p_crypto:x25519_keygen(), crypto:strong_rand_bytes(32)},
    {ok, Listener} =
        i2p_ssu2_listener:listen(
            <<"127.0.0.1">>,
            0,
            #{static_priv => AlicePriv, static_pub => AlicePub, intro_key => AliceIntro},
            self()
        ),
    Local = #{static_priv => AlicePriv, static_pub => AlicePub, intro_key => AliceIntro},
    RI = local_router_info(AlicePub, AliceIntro, i2p_ssu2_listener:port(Listener)),
    Remote = #{
        host => <<"127.0.0.1">>,
        port => relay_port(Relay),
        static_key => BobPub,
        intro_key => BobIntro
    },
    {ok, Conn, _Keys} = i2p_ssu2_conn:connect(Local, Remote, RI, Listener),
    #{keys := Keys} = sys:get_state(Conn),
    arm_drop(Relay, ?DROPPED_PACKETS),
    provoke_acks(Conn, RI),
    Captured = data_phase_packets(Keys, AliceIntro, drain()),
    true = (Captured =/= []) orelse erlang:error(no_data_phase_packets_captured),
    true =
        has_ack_block(Keys, AliceIntro, Captured) orelse
            erlang:error(no_ack_block_captured),
    i2p_ssu2_conn:terminate_session(Conn, 0),
    write_fixture(Out, Keys, AliceIntro, Captured).

%% i2pd only acknowledges packets it has processed, and it only processes what is
%% worth processing, so the exchange has to carry traffic.
%%
%% How much traffic is the part worth fixing. The capture's length depends on
%% how much NetDb chatter i2pd happens to emit, which varies run to run — but
%% the *ACK progression* is driven by how many packets we send, and that is ours
%% to choose. So the exchange is a fixed number of messages rather than one:
%% enough that i2pd emits a run of ACKs covering a real range of packet numbers,
%% which is what congestion control will be reading.
%%
%% The first is our own RouterInfo as a DatabaseStore, the first thing a router
%% offers a new peer. The rest are large enough to fragment across several data
%% packets, so the packet numbers i2pd acknowledges are not merely consecutive
%% either.
-define(EXCHANGE_MESSAGES, 6).

provoke_acks(Conn, RI) ->
    #{type := Type, msg_id := <<MsgId:32/big>>, body := Body} =
        i2p_i2np:db_store(router_info_hash(RI), 1, 0, undefined, RI),
    i2p_ssu2_conn:send_i2np(Conn, Type, MsgId, Body),
    send_bulk(Conn, 1, ?EXCHANGE_MESSAGES).

send_bulk(_Conn, N, N) ->
    ok;
send_bulk(Conn, N, Count) ->
    i2p_ssu2_conn:send_i2np(
        Conn, 6, 16#0F0F0F00 + N, crypto:strong_rand_bytes(?FRAGMENTING_BODY)
    ),
    send_bulk(Conn, N + 1, Count).

%% Read until the relay has been idle for a whole drain window. Bounded on both
%% ends: the idle window is what ends it, and the counter is what stops a
%% pathological peer from growing this without limit.
drain() -> drain(?DRAIN_MS, 0, []).

drain(_Idle, N, Acc) when N >= ?MAX_DATAGRAMS ->
    lists:reverse(Acc);
drain(Idle, N, Acc) ->
    receive
        {captured, Datagram} ->
            drain(Idle, N + 1, [Datagram | Acc])
    after Idle ->
        lists:reverse(Acc)
    end.

%% ---------------------------------------------------------------------------
%% The recording relay
%% ---------------------------------------------------------------------------

%% Two sockets, because each leg has to keep its own source port: i2pd keys its
%% pending outgoing sessions by endpoint, and the SSU2 spec's SessionCreated leg
%% is addressed back to the source port of the SessionRequest. One re-originating
%% socket would answer on the same port it sent from and Alice's own
%% SessionRequest would come straight back at her.
start_relay(BobPort) ->
    Owner = self(),
    Pid = spawn_link(fun() -> relay_init(Owner, BobPort) end),
    Port = receive
        {relay_ready, P} -> P
    after ?RELAY_READY_TIMEOUT -> erlang:error(relay_not_ready)
    end,
    #{pid => Pid, port => Port}.

relay_port(#{port := Port}) -> Port.

%% Arm the drop on the Alice -> Bob leg. Recording is already on; the arm only
%% says how many of our packets the relay swallows.
%%
%% The drop is what makes this worth more than a plain tap. An ACK covering a
%% contiguous run of packet numbers has an empty range list; it is the *gapped*
%% ACK, the one carrying NACK/ACK runs, that exercises the ACK accounting
%% congestion control will read. Making a real i2pd produce one on demand means
%% making it miss a packet, and it is deterministic: `connect/4` returns only
%% once the session is established, so the very next datagram on that leg is the
%% first data packet and the arm is consumed by it.
arm_drop(#{pid := Pid}, Drops) ->
    Pid ! {drop_ab, Drops},
    ok.

stop_relay(#{pid := Pid}) ->
    Pid ! stop,
    ok.

%% Recording is on from the first datagram, because the capture cannot know in
%% advance which ones it wants: i2pd's first data packets arrive during the
%% handshake, before `connect/4` returns. What separates them from the Retry and
%% SessionCreated is decided at emission time by whether they open under the
%% session's data keys — see `data_phase_packets/3`.
-define(RELAY_STATE, #{
    alice => none, recording => true, drops_left => 0
}).

relay_init(Owner, BobPort) ->
    {ok, ToAlice} = gen_udp:open(0, [binary, {active, true}]),
    {ok, AlicePort} = inet:port(ToAlice),
    {ok, ToBob} = gen_udp:open(0, [binary, {active, true}]),
    Owner ! {relay_ready, AlicePort},
    relay(ToAlice, ToBob, BobPort, ?RELAY_STATE).

relay(ToAlice, ToBob, BobPort, State) ->
    receive
        {drop_ab, N} ->
            relay(ToAlice, ToBob, BobPort, State#{drops_left := N});
        {udp, ToAlice, IP, Port, Datagram} ->
            relay_to_bob(ToAlice, ToBob, BobPort, State, IP, Port, Datagram);
        {udp, ToBob, _IP, _Port, Datagram} ->
            relay_to_alice(ToAlice, ToBob, BobPort, State, Datagram);
        stop ->
            ok
    end.

relay_to_bob(ToAlice, ToBob, BobPort, State, IP, Port, Datagram) ->
    Seen = State#{alice => {IP, Port}},
    case maps:get(drops_left, Seen) of
        0 ->
            ok = gen_udp:send(ToBob, {127, 0, 0, 1}, BobPort, Datagram),
            relay(ToAlice, ToBob, BobPort, Seen);
        Left ->
            relay(ToAlice, ToBob, BobPort, Seen#{drops_left => Left - 1})
    end.

%% A Bob datagram with no Alice endpoint yet cannot be routed: it predates any
%% datagram we sent, so there is nowhere to send it. That is not a recovery
%% decision — there is no second behaviour to choose between.
relay_to_alice(ToAlice, ToBob, BobPort, State, Datagram) ->
    case maps:get(alice, State) of
        none ->
            relay(ToAlice, ToBob, BobPort, State);
        {IP, Port} ->
            ok = gen_udp:send(ToAlice, IP, Port, Datagram),
            maybe_record(State, Datagram),
            relay(ToAlice, ToBob, BobPort, State)
    end.

maybe_record(#{recording := true}, Datagram) ->
    ?COLLECTOR ! {captured, Datagram},
    ok;
maybe_record(#{recording := false}, _Datagram) ->
    ok.

%% ---------------------------------------------------------------------------
%% Fixture emission
%% ---------------------------------------------------------------------------

%% Keep only the datagrams that open under the session's data keys.
%%
%% That is the whole of "is this a data-phase packet", and it is asked here
%% rather than guessed from arrival time: the Retry and SessionCreated that
%% precede establishment are sealed under the *handshake* keys, so they fail to
%% open and are dropped, while every data packet — including the ACK of our
%% SessionConfirmed, which i2pd sends before `connect/4` returns — opens. A
%% session that failed to establish yields nothing here, which is why
%% `capture/4` insists on a non-empty result before writing anything.
data_phase_packets(Keys, AliceIntro, Datagrams) ->
    [
        Datagram
     || Datagram <- Datagrams,
        {ok, _} <- [i2p_ssu2:decode_data(Keys, ba, AliceIntro, Datagram)]
    ].

%% The fixture is worthless without an ACK in it — congestion control reads
%% `AckThrough`, and the whole reason this capture exists is to pin the ACK
%% accounting against real bytes. A capture that recorded traffic but no
%% acknowledgement has captured the wrong thing, and writing the fixture anyway
%% would let a later run discover it by failing to assert what it does not hold.
%%
%% The decode is matched rather than rescued: every datagram reaching here has
%% already opened in `data_phase_packets/3`, so a second one failing is a bug in
%% this script, not a fact about the peer.
has_ack_block(Keys, AliceIntro, Datagrams) ->
    lists:any(
        fun(Datagram) ->
            {ok, #{blocks := Blocks}} =
                i2p_ssu2:decode_data(Keys, ba, AliceIntro, Datagram),
            lists:keymember(ack, 1, Blocks)
        end,
        Datagrams
    ).

%% Consult terms, not `term_to_binary`: the fixture is wire data a reviewer has
%% to be able to open, and a diff over a committed binary blob shows that
%% something changed without showing what. Hex, because a datagram contains bytes
%% that consult would refuse as a literal.
write_fixture(Out, Keys, AliceIntro, Datagrams) ->
    ok = filelib:ensure_dir(Out),
    Terms =
        fixture_terms(Keys, AliceIntro, Datagrams),
    Text = [io_lib:format("~p.~n", [Term]) || Term <- Terms],
    ok = file:write_file(Out, Text),
    io:format(
        "captured ~p i2pd data packets into ~ts (~p bytes)~n",
        [length(Datagrams), Out, lists:sum([byte_size(D) || D <- Datagrams])]
    ).

fixture_terms(Keys, AliceIntro, Datagrams) ->
    [
        {fixture, i2pd_ssu2_data_phase},
        {comment, "SSU2 data-phase datagrams sent by a real i2pd to our session."},
        {comment, "Replayed by apps/i2per/test/i2p_ssu2_vectors_SUITE.erl."},
        {comment, "Regenerated by scripts/capture_i2pd_vectors.sh; see docs/parity.md."},
        {i2pd_version, i2pd_version()},
        {our_intro_key, hex(AliceIntro)},
        {data_keys, [{Name, hex(Value)} || {Name, Value} <- sorted_keys(Keys)]},
        {packets, [{Num, hex(Datagram)} || {Num, Datagram} <- numbered(Datagrams)]}
    ].

%% Consult has no map syntax, so the keys become an ordered list of pairs. The
%% order is fixed here rather than left to map iteration so that regenerating the
%% fixture against the same i2pd produces an identical file.
sorted_keys(Keys) ->
    lists:sort(maps:to_list(Keys)).

%% Packet numbers are not read from the wire — they are sealed inside the AEAD —
%% so they are assigned in capture order, which is the order i2pd sent them.
numbered(Datagrams) -> lists:zip(lists:seq(0, length(Datagrams) - 1), Datagrams).

hex(Bin) -> binary:encode_hex(Bin).

i2pd_version() ->
    case os:getenv("I2PD_VERSION") of
        false -> "unknown";
        V -> V
    end.

%% ---------------------------------------------------------------------------
%% i2pd's identity, and ours
%% ---------------------------------------------------------------------------

%% `ssu2.keys` is `public || private || introduction`. Only the public half and
%% the introduction key are needed: the session is ours to open, so i2pd's
%% private key never enters this process.
read_ssu2_keys(DataDir) ->
    {ok, <<Pub:32/binary, _Priv:32/binary, Intro:32/binary>>} =
        file:read_file(filename:join(DataDir, "ssu2.keys")),
    {Pub, Intro}.

%% i2pd validates the RouterInfo carried in SessionConfirmed: signature,
%% timestamp skew, netId, and that the static key matches the handshake's. A
%% published loopback SSU2 address with the `4` (IPv4) caps bit is the shape it
%% accepts from a peer that i2pd itself dialled.
local_router_info(StaticPub, IntroKey, Port) ->
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    Addr0 = i2p_router_info:ssu2_address(<<"127.0.0.1">>, Port, StaticPub, IntroKey),
    Addr = Addr0#{options => (maps:get(options, Addr0))#{<<"caps">> => <<"4">>}},
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    maps:get(binary, RI).

router_info_hash(RIData) ->
    {ok, RI} = i2p_router_info:decode(RIData),
    i2p_router_info:hash(RI).

%% The SSU2 supervisor is a child of `i2per_sup` only when app env
%% `i2per` -> `ssu2` configures a transport, which a capture does not: there is
%% no identity and no listener here, only an outgoing session. Start it by hand
%% and unlink, so stopping it at the end does not take the escript with it.
start_ssu2_sup() ->
    {ok, Sup} = case i2p_ssu2_sup:start_link() of
        {ok, Pid} -> {ok, Pid};
        {error, {already_started, Pid}} -> {ok, Pid}
    end,
    erlang:unlink(Sup),
    Sup.
