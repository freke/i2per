%% Replay of an NTCP2 XK handshake and the data phase after it, captured from a
%% real i2pd.
%%
%% This is the other half of the hermetic protocol gate. The half that runs on
%% every push replays committed bytes; the half that never runs in the gate is
%% `scripts/capture_i2pd_vectors.sh`, which boots i2pd 2.61.0, drives a live
%% handshake and writes `apps/i2per/test/fixtures/i2pd_ntcp2_handshake.term`.
%% That script needs an i2pd binary and a throwaway router; this suite needs
%% nothing but the file, which is the whole point of keeping the capture.
%%
%% **What makes a handshake replayable.** Noise XK is a function of key material
%% and nothing else. Given our static keypair, our ephemeral private key, and the
%% peer's published static key and IV, `m:i2p_ntcp2:alice_init/5` plus
%% `create_msg1/4` rebuild the exact bytes that went on the wire, and
%% `receive_msg2/2` opens what i2pd answered with. No socket, no process, no
%% second router -- the messages are the state transitions, and the fixture is
%% the bytes they produced.
%%
%% **Every private key here is ours.** i2pd's static *private* key is not in the
%% fixture. Its public half and its IV are in its RouterInfo in any case, so the
%% file records a peer's published identity, never a peer's secret.
%%
%% **Why this is stronger than a round trip.** Our encoder and our decoder will
%% always agree with each other; a wire format nobody else speaks round-trips
%% perfectly. These bytes were produced and accepted by a router we do not
%% control, so the AES-CBC obfuscation, both AEAD frames, the `h`/`ck` mix
%% sequence, the data-phase KDF and the SipHash length masking are all checked
%% against i2pd rather than against a second copy of ourselves.
%%
%% This suite deliberately does *not* match the `interop|i2pd` guard in
%% `scripts/ct-suites.sh`. That guard keeps a suite that needs a **live** i2pd
%% out of the gate; this one needs only committed bytes.
-module(i2p_ntcp2_vectors_SUITE).

-export([all/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).

-export([
    fixture_is_a_committed_capture/1,
    the_handshake_opens_against_the_peer/1,
    msg1_re_encodes_to_the_captured_bytes/1,
    msg3_re_encodes_to_the_captured_bytes/1,
    the_captured_msg2_decodes/1,
    the_peer_router_info_is_decodable/1,
    msg3_payload_carries_our_router_info/1,
    the_data_phase_frames_open_under_the_derived_keys/1,
    the_keepalive_re_encodes_to_the_captured_bytes/1
]).

all() ->
    [
        fixture_is_a_committed_capture,
        the_handshake_opens_against_the_peer,
        msg1_re_encodes_to_the_captured_bytes,
        msg3_re_encodes_to_the_captured_bytes,
        the_captured_msg2_decodes,
        the_peer_router_info_is_decodable,
        msg3_payload_carries_our_router_info,
        the_data_phase_frames_open_under_the_derived_keys,
        the_keepalive_re_encodes_to_the_captured_bytes
    ].

suite() ->
    [{timetrap, 30000}].

%% Replay once, here, so every case asserts against the same reconstructed
%% session and the crypto is only paid for once. A replay that fails is not a
%% case failing: it is the fixture being unreadable, which would otherwise make
%% every case below report a failure about the wrong thing.
init_per_suite(Config) ->
    Path = fixture_path(i2p_ct_helpers:project_root()),
    Terms = consult(Path),
    Replay = replay(Terms),
    [{fixture_terms, Terms}, {replay, Replay} | Config].

end_per_suite(_Config) ->
    ok.

fixture_path(Root) ->
    filename:join([Root, "apps", "i2per", "test", "fixtures", "i2pd_ntcp2_handshake.term"]).

%% ---------------------------------------------------------------------------
%% The replay itself
%% ---------------------------------------------------------------------------

%% Rebuild Alice's side from key material alone and re-derive every byte the
%% fixture holds. What comes out is the reconstructed session plus the two
%% messages we produced, which the cases below compare against the capture.
%%
%% The order matters and it is the protocol's: msg1 establishes the chaining key
%% and hash that msg2 opens under, msg2 carries the ephemeral that msg3 mixes,
%% and the data-phase keys fall out of msg3's own KDF. Each step is handed the
%% state the previous one returned, exactly as `m:i2p_ntcp2_conn` does it live.
replay(Terms) ->
    PeerRI = unhex(required(peer, path(router_info), Terms)),
    {ok, PeerRIParsed} = i2p_router_info:decode(PeerRI),
    PeerStatic = unhex(required(peer, path(static_pub), Terms)),
    PeerIV = unhex(required(peer, path(iv), Terms)),
    AlicePriv = unhex(required(alice, path(static_priv), Terms)),
    AlicePub = unhex(required(alice, path(static_pub), Terms)),
    EphPriv = unhex(required(alice, path(ephemeral_priv), Terms)),
    Msg1Pad = unhex(required(alice, path(msg1_pad), Terms)),
    {PadLen1, M3P2Len, Ts1} = required(alice, path(msg1_opts), Terms),
    Msg3Payload = unhex(required(alice, path(msg3_payload), Terms)),
    Msg1 = unhex(required(msg1, Terms)),
    Msg2 = unhex(required(msg2, Terms)),
    Msg3 = unhex(required(msg3, Terms)),
    PeerHash = i2p_router_info:hash(PeerRIParsed),
    S0 = i2p_ntcp2:alice_init(PeerStatic, PeerHash, PeerIV, AlicePriv, AlicePub),
    Opts1 = #{padlen => PadLen1, m3p2len => M3P2Len, ts => Ts1},
    {ok, Msg1Reencoded, S1} = i2p_ntcp2:create_msg1(S0, EphPriv, Opts1, Msg1Pad),
    {ok, Opts2, S2} = i2p_ntcp2:receive_msg2(S1, Msg2),
    {ok, Msg3Reencoded, S3} = i2p_ntcp2:create_msg3(S2, Msg3Payload),
    Keys = i2p_ntcp2:data_phase_keys(S3),
    #{
        peer_ri => PeerRIParsed,
        peer_ri_bytes => PeerRI,
        msg1 => Msg1,
        msg1_reencoded => Msg1Reencoded,
        msg2 => Msg2,
        msg2_opts => Opts2,
        msg3 => Msg3,
        msg3_reencoded => Msg3Reencoded,
        msg3_payload => Msg3Payload,
        keys => Keys
    }.

%% ---------------------------------------------------------------------------
%% The capture is real and it is the one the tree claims to have
%% ---------------------------------------------------------------------------

%% Two claims that are cheap to check and expensive to discover are false: that
%% there is a capture at all, and that it says which i2pd it came from. The
%% second matters because the README and docs/parity.md tie protocol claims to
%% this file, and an unattributed capture cannot be re-derived when i2pd is
%% bumped.
fixture_is_a_committed_capture(Config) ->
    Terms = terms(Config),
    %% A string, not a binary: the capture writes the version as a term literal,
    %% so `file:consult/1` reads it back as a list of characters.
    "2." ++ _ = proplists:get_value(i2pd_version, Terms),
    i2pd_ntcp2_handshake = proplists:get_value(fixture, Terms),
    ok.

%% ---------------------------------------------------------------------------
%% The handshake
%% ---------------------------------------------------------------------------

%% The load-bearing case. That msg2 opens at all means the AES-CBC chaining from
%% i2pd's IV, the `es`/`ee` DH sequence, the AEAD frames and the `h` mix order
%% are all correct against a router we do not control -- a decode failure is
%% reported from `replay/1` in `init_per_suite`, before any case runs.
the_handshake_opens_against_the_peer(Config) ->
    #{msg2_opts := #{padlen := PadLen2, ts := Ts2}, keys := Keys} =
        replay_state(Config),
    true = is_integer(PadLen2),
    true = is_integer(Ts2),
    %% The data-phase keys are 32-byte ChaCha20-Poly1305 keys and two SipHash
    %% states; a KDF that produced the wrong shape would fail here rather than
    %% as an opaque AEAD error in the frame case.
    true = byte_size(maps:get(k_ab, Keys)) =:= 32,
    true = byte_size(maps:get(k_ba, Keys)) =:= 32,
    ok.

%% msg1 is fully determined by the pinned ephemeral and padding, so it must come
%% back byte-for-byte. This is the case that says "our encoder produces what i2pd
%% read", and it is the one a change to the option encoding or the `es` mix
%% order breaks.
msg1_re_encodes_to_the_captured_bytes(Config) ->
    #{msg1 := Msg1, msg1_reencoded := Msg1Reencoded} = replay_state(Config),
    Msg1 = Msg1Reencoded,
    ok.

%% msg3 is the same claim for the second message, and it covers the part msg1
%% does not: the `se` DH against i2pd's ephemeral, the msg3 part-1 KDF, and the
%% payload framing. The payload itself is captured rather than regenerated --
%% it embeds our RouterInfo signature and the capture's own timestamps -- so
%% what is asserted is that our encoding of it matches i2pd's reading of it.
msg3_re_encodes_to_the_captured_bytes(Config) ->
    #{msg3 := Msg3, msg3_reencoded := Msg3Reencoded} = replay_state(Config),
    Msg3 = Msg3Reencoded,
    ok.

%% i2pd's msg2 is read back out of the fixture and parsed. The options are
%% i2pd's own claims -- its padding length and timestamp -- and they are checked
%% to be sane rather than pinned: pinning them would tie the fixture to one
%% capture run for no gain, since the replay already proves the frame
%% authenticated.
the_captured_msg2_decodes(Config) ->
    #{msg2 := Msg2, msg2_opts := Opts2} = replay_state(Config),
    %% msg2 is AES-CBC(Y) 32 bytes, the options frame 32 bytes, then padding.
    true = byte_size(Msg2) >= 64,
    ct:pal("msg2 options: ~p", [Opts2]),
    ok.

%% The peer identity in the fixture is one i2pd actually published: its NTCP2
%% address is in the RouterInfo the capture recorded, with the static key and IV
%% the replay dials against. Decoding it and hashing it is what separates "a real
%% router said this" from "a fixture that only proves our own encoder
%% round-trips".
the_peer_router_info_is_decodable(Config) ->
    #{peer_ri := PeerRI, peer_ri_bytes := Bytes} = replay_state(Config),
    true = byte_size(Bytes) > 0,
    32 = byte_size(i2p_router_info:hash(PeerRI)),
    true = lists:any(fun is_ntcp2/1, i2p_router_info:addresses(PeerRI)),
    ok.

is_ntcp2(#{transport := <<"NTCP2">>}) -> true;
is_ntcp2(_) -> false.

%% And the msg3 payload i2pd accepted names *us*: it is the type-2 block wrapping
%% our signed RouterInfo, and its identity must be the one the replay built from
%% the pinned static key. A fixture whose payload carried someone else's identity
%% would still re-encode, so the payload is decoded rather than only compared --
%% and the `s` option is compared against the pinned static key, not just its
%% presence, because a payload carrying another router's RouterInfo on loopback
%% would otherwise pass every assertion here.
msg3_payload_carries_our_router_info(Config) ->
    #{msg3_payload := Payload} = replay_state(Config),
    AlicePub = unhex(required(alice, path(static_pub), terms(Config))),
    {ok, Blocks} = i2p_framing:decode_blocks(Payload),
    [#{type := 2, data := <<0:8, Data/binary>>} | _] = Blocks,
    {ok, PayloadRI} = i2p_router_info:decode(Data),
    [#{transport := <<"NTCP2">>, options := #{<<"host">> := <<"127.0.0.1">>, <<"s">> := S}} | _] =
        [A || A = #{transport := <<"NTCP2">>} <- i2p_router_info:addresses(PayloadRI)],
    AlicePub = i2p_keys:decode_b64(S),
    ok.

%% ---------------------------------------------------------------------------
%% The data phase
%% ---------------------------------------------------------------------------

%% The frames i2pd sent open under keys the replay derived from the handshake's
%% own `{ck, h}`. That is the end of the story the handshake started: a KDF that
%% agreed through msg3 but diverged afterward would leave every frame here
%% unopenable, and the fixture's frames are i2pd's, not ours.
%%
%% Frame numbers start at zero in the receive direction and advance by one per
%% frame, because the number is the AEAD nonce -- a peer that reused one would be
%% a peer whose later frames cannot be read at all.
the_data_phase_frames_open_under_the_derived_keys(Config) ->
    #{keys := Keys} = replay_state(Config),
    BaFrames = required(ba_frames, terms(Config)),
    [_ | _] = BaFrames,
    Sip0 = maps:get(sip_ba, Keys),
    {Opened, _Sip} =
        lists:foldl(
            fun({FrameHex, PlainHex}, {Acc, Sip}) ->
                Frame = unhex(FrameHex),
                {ok, Plain, Sip1} = i2p_framing:decrypt_frame(
                    maps:get(k_ba, Keys), length(Acc), Frame, Sip
                ),
                Plain = unhex(PlainHex),
                {ok, Blocks} = i2p_framing:decode_blocks(Plain),
                ct:pal("frame ~p: ~p bytes -> ~p", [
                    length(Acc), byte_size(Frame), [kind(B) || B <- Blocks]
                ]),
                {[Blocks | Acc], Sip1}
            end,
            {[], Sip0},
            BaFrames
        ),
    true = Opened =/= [],
    ok.

%% The keepalive we sent is in the fixture, and re-encoding it must reproduce
%% those bytes. It is the only frame in the file that is ours, so it is what
%% pairs our send path against the receive path above: an encoder that masked
%% the length against the wrong SipHash state would encrypt a frame i2pd could
%% not read, and only the captured bytes say so.
%%
%% The length is masked against the SipHash state *ahead* of the frame, so the
%% encoder is handed that state and the plaintext, and the state the frame
%% advances into is the mask source the receiver also derives. Re-encoding from
%% what the frame opened to is therefore the whole claim: same keys, same
%% message number, same state, same bytes -- and the two states are compared
%% rather than discarded, because an encoder that advanced into a different
%% state would still produce this frame and only fail on the next one, where the
%% mistake would surface as an opaque AEAD error.
the_keepalive_re_encodes_to_the_captured_bytes(Config) ->
    #{keys := Keys} = replay_state(Config),
    [AbHex] = required(ab_frames, terms(Config)),
    AbFrame = unhex(AbHex),
    Sip = maps:get(sip_ab, Keys),
    {ok, Payload, SipAfterFrame} = i2p_framing:decrypt_frame(
        maps:get(k_ab, Keys), 0, AbFrame, Sip
    ),
    {Frame, SipAfterEncode} = i2p_framing:encrypt_frame(maps:get(k_ab, Keys), 0, Payload, Sip),
    SipAfterFrame = SipAfterEncode,
    AbFrame = i2p_framing:frame_bytes(Frame),
    ok.

%% ---------------------------------------------------------------------------
%% Reading the fixture
%% ---------------------------------------------------------------------------

terms(Config) -> proplists:get_value(fixture_terms, Config).

replay_state(Config) -> proplists:get_value(replay, Config).

kind(#{type := Type}) -> Type;
kind(B) when is_tuple(B) -> element(1, B);
kind(B) -> B.

%% Fixture terms are nested proplists, so `peer.static_pub` is read as a path
%% rather than three separate lookups at the call site.
path(Key) -> [Key].

required(Key, Terms) ->
    case proplists:lookup(Key, Terms) of
        {Key, Value} -> Value;
        none -> erlang:error({fixture_missing, Key})
    end.

required(Section, [Key], Terms) ->
    required(Key, required(Section, Terms)).

consult(Path) ->
    {ok, Terms} = file:consult(Path),
    Terms.

%% Hex, because the capture writes bytes consult would refuse as a literal.
%% Pairs, not nibbles: `decode_hex/1` is the one that turns two characters into
%% one byte.
unhex(Hex) -> binary:decode_hex(Hex).
