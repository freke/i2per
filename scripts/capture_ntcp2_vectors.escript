#!/usr/bin/env escript
%%! -pa _build/default/lib/i2per/ebin -pa _build/default/lib/telemetry/ebin

%% Capture the NTCP2 XK handshake and a data phase from a real i2pd into a
%% committed fixture.
%%
%% `scripts/capture_i2pd_vectors.sh` boots i2pd and runs this beside
%% `scripts/capture_ssu2_vectors.escript`; it is one of the two things that
%% write `apps/i2per/test/fixtures/`, and the test gate runs neither. What CI
%% runs is `apps/i2per/test/i2p_ntcp2_vectors_SUITE.erl`, which replays the
%% committed bytes with no i2pd and no network.
%%
%% **Why this capture needs no relay.** The SSU2 capture puts two sockets
%% between us and i2pd because a UDP session is keyed by endpoint and our
%% datagrams have to be re-originated to look like a peer's. NTCP2 is a stream
%% we dial: the bytes `gen_tcp:send` writes are the bytes i2pd reads, so
%% everything we send is recorded as we send it, and everything i2pd sends is
%% recorded by the same byte source the handshake itself reads through. One
%% socket, and no traffic is invented or rewritten on the way past.
%%
%% **What makes the bytes replayable.** Noise XK is replayable from key
%% material alone: our static keypair, our ephemeral private key, and the
%% peer's published static key, IV and router hash rebuild Alice's state, so
%% msg1 and msg3 can be re-created and msg2 opened from it. The data phase
%% falls out of the handshake's own `{ck, h}`, so the frames i2pd sent decrypt
%% under keys the replay derives — no socket, no process, no peer.
%%
%% **Every private key in the fixture is ours.** i2pd's static *private* key
%% never enters this process: `ntcp2.keys` is read for its public half and the
%% IV, and both are published in its RouterInfo anyway. A fixture that carried
%% the peer's secrets would be a fixture nobody could hand out.
%%
%% Usage:
%%   escript scripts/capture_ntcp2_vectors.escript <i2pd-datadir> <ntcp2-port> <out>
%%
%% `<out>` is overwritten with Erlang consult terms. The shell driver supplies
%% all three; nothing here discovers i2pd, and a missing or unusable i2pd is a
%% non-zero exit rather than a fixture written from a handshake that did not
%% complete.

-mode(compile).

%% Our published NTCP2 endpoint in the msg3 RouterInfo. i2pd never connects
%% back during the handshake — it checks that the host in msg3 matches the
%% address we dialed from, and nothing else — so this port is announced rather
%% than bound, and it is off the capture's own ports so nothing here can
%% collide with i2pd's listeners.
-define(LOCAL_PORT, 39525).

%% One read timeout for the handshake, where a stall is a peer that stopped
%% answering mid-message.
-define(RECV_TIMEOUT_MS, 10000).

%% The drain window ends a capture whose peer has gone quiet; the cap ends one
%% whose peer never does. Both bound the same read: an idle peer stops the run
%% at DRAIN_IDLE, a chatty one at DRAIN_CAP.
-define(DRAIN_IDLE_MS, 4000).
-define(DRAIN_CAP_MS, 30000).
-define(MAX_FRAMES, 64).

main([DataDir, Ntcp2Port, Out]) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, PeerRIBytes} = file:read_file(filename:join(DataDir, "router.info")),
    {ok, PeerRI} = i2p_router_info:decode(PeerRIBytes),
    {ok, PeerStatic, PeerIV} = read_peer_keys(DataDir, PeerRI),
    Alice = alice_local(),
    Port = list_to_integer(Ntcp2Port),
    {ok, Sock} = gen_tcp:connect(
        "127.0.0.1",
        Port,
        [binary, {packet, raw}, {active, false}, {nodelay, true}],
        10000
    ),
    try
        capture(Sock, Out, Alice, PeerRIBytes, PeerRI, PeerStatic, PeerIV)
    after
        gen_tcp:close(Sock)
    end.

%% ---------------------------------------------------------------------------
%% The handshake, recorded as it happens
%% ---------------------------------------------------------------------------

capture(Sock, Out, Alice, PeerRIBytes, PeerRI, PeerStatic, PeerIV) ->
    #{static_priv := Priv, static_pub := Pub, ri := LocalRI} = Alice,
    PeerHash = i2p_router_info:hash(PeerRI),
    S0 = i2p_ntcp2:alice_init(PeerStatic, PeerHash, PeerIV, Priv, Pub),
    EphPriv = element(1, i2p_crypto:x25519_keygen()),
    Msg1Pad = random_pad(),
    Payload = i2p_router_info:m3p2_block(LocalRI),
    Opts1 = #{padlen => byte_size(Msg1Pad), m3p2len => byte_size(Payload) + 16, ts => now_ts()},
    {ok, Msg1, S1} = i2p_ntcp2:create_msg1(S0, EphPriv, Opts1, Msg1Pad),
    ok = gen_tcp:send(Sock, Msg1),
    %% msg2's padding length lives inside msg2's own encrypted options, so
    %% nothing outside the reader can know how much of the stream the message
    %% covers — which is exactly why the source records what it was handed
    %% rather than what the caller asked for.
    {ok, Opts2, S2} =
        case i2p_ntcp2:receive_msg2_stream(S1, recording_recv(Sock)) of
            {ok, _, _} = Ok -> Ok;
            error -> erlang:error(msg2_not_accepted_by_i2pd)
        end,
    Msg2 = iolist_to_binary(collect_recorded()),
    {ok, Msg3, S3} = i2p_ntcp2:create_msg3(S2, Payload),
    ok = gen_tcp:send(Sock, Msg3),
    Keys = i2p_ntcp2:data_phase_keys(S3),
    AbFrame = send_keepalive(Sock, Keys),
    BaFrames = drain_frames(Sock, Keys),
    true = (BaFrames =/= []) orelse erlang:error(no_data_phase_frames_captured),
    true = lists:any(fun({_Frame, P}) -> decode(P) =/= [] end, BaFrames) orelse
        erlang:error(no_blocks_in_the_captured_frames),
    write_fixture(Out, #{
        peer_ri => PeerRIBytes,
        peer_static => PeerStatic,
        peer_iv => PeerIV,
        alice => Alice,
        opts1 => Opts1,
        opts2 => Opts2,
        msg1_pad => Msg1Pad,
        msg3_payload => Payload,
        eph_priv => EphPriv,
        msg1 => Msg1,
        msg2 => Msg2,
        msg3 => Msg3,
        ab_frame => AbFrame,
        ba_frames => BaFrames
    }).

%% A datetime block, the same frame `i2p_ntcp2_conn` sends as a keepalive. It
%% is in the fixture so the replay covers both directions: the ab frame is ours
%% to re-encode, and a re-encoding that differs from these bytes is a send path
%% that no longer agrees with the receive path it is paired with.
send_keepalive(Sock, Keys) ->
    Now = erlang:system_time(second),
    Payload = i2p_framing:encode_block(0, <<Now:32/big>>),
    send_frame(Sock, maps:get(k_ab, Keys), 0, Payload, maps:get(sip_ab, Keys)).

%% One call, not two. `encrypt_frame/4` masks the length with the SipHash state
%% it is *handed* and returns the state the frame advanced into -- the same
%% state the receiver derives before it reads the next frame. Advancing the
%% state first (`obfuscate_length/2` on its own) and then passing the result
%% here masks the length against one digest too many: the wire bytes no longer
%% open under the state a peer would hold, and i2pd would drop the frame. This
%% is how the production sender does it (`m:i2p_ntcp2_conn`, one `encrypt_frame`
%% per frame), and the replay suite re-encoding the captured ab frame to the
%% same bytes is what keeps the two in step.
send_frame(Sock, Key, MsgNum, Payload, Sip) ->
    {Frame, _Sip1} = i2p_framing:encrypt_frame(Key, MsgNum, Payload, Sip),
    ok = gen_tcp:send(Sock, i2p_framing:frame_bytes(Frame)),
    i2p_framing:frame_bytes(Frame).

%% ---------------------------------------------------------------------------
%% The data phase, read frame by frame
%% ---------------------------------------------------------------------------

%% Read until the peer has been idle for a whole drain window or the cap has
%% run out. Each entry is the frame exactly as it came off the wire — obfuscated
%% length included — because that is what the replay feeds `i2p_stream:push/2`;
%% the plaintext rides along only so this script can refuse to write a fixture
%% whose frames it could not itself open.
drain_frames(Sock, Keys) ->
    drain_frames(Sock, maps:get(k_ba, Keys), maps:get(sip_ba, Keys), 0, ?DRAIN_CAP_MS, []).

drain_frames(_Sock, _Key, _Sip, N, _Remaining, _Acc) when N >= ?MAX_FRAMES ->
    erlang:error(too_many_frames);
drain_frames(_Sock, _Key, _Sip, _N, Remaining, Acc) when Remaining =< 0 ->
    lists:reverse(Acc);
drain_frames(Sock, Key, Sip, N, Remaining, Acc) ->
    Started = erlang:monotonic_time(millisecond),
    Idle = erlang:min(?DRAIN_IDLE_MS, Remaining),
    case recv_exact(Sock, 2, Idle) of
        {ok, <<ObfLen:16/big>>} ->
            case i2p_framing:deobfuscate_length(ObfLen, Sip) of
                {ok, FrameLen, _Sip1} ->
                    {ok, Sealed} = recv_exact(Sock, FrameLen, ?RECV_TIMEOUT_MS),
                    Frame = <<ObfLen:16/big, Sealed/binary>>,
                    case i2p_framing:decrypt_frame(Key, N, Frame, Sip) of
                        {ok, Payload, Sip2} ->
                            Elapsed = erlang:monotonic_time(millisecond) - Started,
                            drain_frames(
                                Sock,
                                Key,
                                Sip2,
                                N + 1,
                                Remaining - Elapsed,
                                [{Frame, Payload} | Acc]
                            );
                        error ->
                            erlang:error({data_frame_did_not_open, N})
                    end;
                error ->
                    erlang:error({frame_length_out_of_range, N, ObfLen})
            end;
        timeout ->
            lists:reverse(Acc);
        closed ->
            lists:reverse(Acc)
    end.

%% ---------------------------------------------------------------------------
%% Recording byte source for the handshake
%% ---------------------------------------------------------------------------

%% The handshake's own reader, wrapped so every byte it is handed is also sent
%% to this process. msg2's length is not on the wire — it is read out of msg2's
%% decrypted options — so the only place that knows where the message ended is
%% the source that was asked one byte count at a time.
recording_recv(Sock) ->
    fun(N) ->
        case recv_exact(Sock, N, ?RECV_TIMEOUT_MS) of
            {ok, Bin} ->
                self() ! {recorded, Bin},
                {ok, Bin};
            _ ->
                error
        end
    end.

collect_recorded() ->
    receive
        {recorded, Bin} -> [Bin | collect_recorded()]
    after 0 ->
        []
    end.

%% gen_tcp may hand back fewer bytes than were asked for; the handshake readers
%% assume an exact read, so the loop is here rather than in three places.
recv_exact(Sock, N, Timeout) -> recv_exact(Sock, N, Timeout, <<>>).

recv_exact(_Sock, 0, _Timeout, Acc) ->
    {ok, Acc};
recv_exact(Sock, N, Timeout, Acc) ->
    case gen_tcp:recv(Sock, N, Timeout) of
        {ok, Bin} -> recv_exact(Sock, N - byte_size(Bin), Timeout, <<Acc/binary, Bin/binary>>);
        {error, timeout} -> timeout;
        {error, _} -> closed
    end.

%% ---------------------------------------------------------------------------
%% Fixture emission
%% ---------------------------------------------------------------------------

write_fixture(Out, F) ->
    ok = filelib:ensure_dir(Out),
    Text = [io_lib:format("~p.~n", [Term]) || Term <- fixture_terms(F)],
    ok = file:write_file(Out, Text),
    io:format(
        "captured NTCP2 handshake + ~p data frames into ~ts (i2pd ~ts)~n",
        [length(maps:get(ba_frames, F)), Out, i2pd_version()]
    ).

fixture_terms(#{
    peer_ri := PeerRI,
    peer_static := PeerStatic,
    peer_iv := PeerIV,
    alice := #{static_priv := Priv, static_pub := Pub},
    opts1 := #{padlen := PadLen1, m3p2len := M3P2Len, ts := Ts1},
    opts2 := #{padlen := PadLen2, ts := Ts2},
    msg1_pad := Msg1Pad,
    msg3_payload := Payload,
    eph_priv := EphPriv,
    msg1 := Msg1,
    msg2 := Msg2,
    msg3 := Msg3,
    ab_frame := AbFrame,
    ba_frames := BaFrames
}) ->
    [
        {fixture, i2pd_ntcp2_handshake},
        {comment, "An NTCP2 XK handshake and the data phase that followed it, from a real i2pd."},
        {comment, "Replayed by apps/i2per/test/i2p_ntcp2_vectors_SUITE.erl."},
        {comment, "Regenerated by scripts/capture_i2pd_vectors.sh; see docs/parity.md."},
        {i2pd_version, i2pd_version()},
        {peer, [
            {router_info, hex(PeerRI)},
            {static_pub, hex(PeerStatic)},
            {iv, hex(PeerIV)}
        ]},
        {alice, [
            {static_priv, hex(Priv)},
            {static_pub, hex(Pub)},
            {ephemeral_priv, hex(EphPriv)},
            {msg1_pad, hex(Msg1Pad)},
            {msg1_opts, {PadLen1, M3P2Len, Ts1}},
            {msg3_payload, hex(Payload)}
        ]},
        {msg1, hex(Msg1)},
        {msg2, hex(Msg2)},
        {msg3, hex(Msg3)},
        {msg2_opts, {PadLen2, Ts2}},
        {ab_frames, [hex(AbFrame)]},
        {ba_frames, [{hex(Frame), hex(Plain)} || {Frame, Plain} <- BaFrames]}
    ].

hex(Bin) -> binary:encode_hex(Bin).

i2pd_version() ->
    case os:getenv("I2PD_VERSION") of
        false -> "unknown";
        V -> V
    end.

%% ---------------------------------------------------------------------------
%% Identities
%% ---------------------------------------------------------------------------

%% `ntcp2.keys` is `public || private || iv`. Only the public half and the IV
%% are needed — the session is ours to open, and i2pd's private key has no
%% business in a committed file.
%%
%% The public half is checked against the RouterInfo before it is used: both
%% are i2pd's claims about the same key, and a fixture whose two copies of the
%% peer's identity disagree would replay against whichever one a later reader
%% happened to pick. The address is published with its static key even when the
%% transport is not, which is what makes the check possible at all.
read_peer_keys(DataDir, PeerRI) ->
    {ok, <<Pub:32/binary, _Priv:32/binary, IV:16/binary>>} =
        file:read_file(filename:join(DataDir, "ntcp2.keys")),
    Published = [
        Options
     || Addr <- i2p_router_info:addresses(PeerRI),
        maps:get(transport, Addr) =:= <<"NTCP2">>,
        Options <- [maps:get(options, Addr)],
        maps:is_key(<<"s">>, Options)
    ],
    case Published of
        [#{<<"s">> := S} | _] ->
            case i2p_keys:decode_b64(S) of
                Pub ->
                    ok;
                Other ->
                    erlang:error({peer_static_key_mismatch, Pub, Other})
            end;
        [] ->
            erlang:error(peer_router_info_has_no_ntcp2_static_key)
    end,
    {ok, Pub, IV}.

%% Our side: a fresh identity, static keypair and IV, and a signed RouterInfo
%% announcing a published loopback NTCP2 endpoint. i2pd rejects a msg3
%% RouterInfo whose host is not the address the connection came from, so this
%% is the loopback address it will see — and, with `reservedrange = false`
%% (scripts/capture_i2pd_vectors.sh), the one it admits.
alice_local() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, ?LOCAL_PORT, StaticPub, IV),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(Identity, erlang:system_time(millisecond), [Addr], Opts, Seed),
    #{static_priv => StaticPriv, static_pub => StaticPub, iv => IV, ri => RI}.

random_pad() -> crypto:strong_rand_bytes(rand:uniform(33) - 1).

now_ts() -> erlang:system_time(second) band 16#FFFFFFFF.

%% Block payloads from a live peer: at least one frame has to carry something
%% this script can parse, or the fixture records a data phase nobody has looked
%% at. This is a parse, not a claim about the blocks' meaning — that is the
%% replay suite's job, against bytes it did not just read off a socket.
decode(Payload) ->
    case i2p_framing:decode_blocks(Payload) of
        {ok, Blocks} -> Blocks;
        error -> []
    end.
