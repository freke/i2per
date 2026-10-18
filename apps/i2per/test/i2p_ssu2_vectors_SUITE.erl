%% Replay of SSU2 data-phase wire bytes captured from a real i2pd.
%%
%% This is the half of the hermetic protocol gate that runs on every push. The
%% other half is `scripts/capture_i2pd_vectors.sh`, which boots i2pd 2.61.0 and
%% writes `apps/i2per/test/fixtures/i2pd_ssu2_data_phase.term`. That script is
%% never run by the gate, needs an i2pd binary, and needs a network-free
%% throwaway router. This suite needs nothing but the committed file.
%%
%% **What makes a captured datagram replayable at all.** `i2p_ssu2:decode_data/4`
%% is pure -- its entire input is the session's four data keys, the receiving
%% direction, our own introduction key, and the datagram. Packet-number replay
%% tracking is explicitly the session layer's job, so a list of datagrams from a
%% session that no longer exists replays in order with no process and no socket.
%% The fixture is therefore not a transcript and not a summary: it is the bytes,
%% plus the four keys and one key that make them readable.
%%
%% **What the bytes are for.** Congestion control and RTT estimation
%% (#RC68AGE) read `AckThrough` and nothing else, because an SSU2 ACK block
%% carries no timestamp on the wire. That makes the ACK block the whole oracle,
%% and it is the part of the data phase that no amount of self-consistent
%% round-tripping would validate: a decoder that mis-reads `AckThrough` or
%% `Acnt` still round-trips perfectly against another copy of itself. These
%% bytes are somebody else's, produced by a router we do not control, so an
%% accounting bug shows up here as a mismatch instead of hiding.
%%
%% **What is deliberately not asserted.** No timing. The capture records no
%% timestamps, because there is nothing to time: an ACK's meaning is entirely in
%% its packet numbers, and a gap between two packets in the file is an artefact
%% of when the capture ran, not a property of the protocol.
%%
%% This suite deliberately does *not* match the `interop|i2pd` guard in
%% `scripts/ct-suites.sh`. That guard keeps a suite that needs a **live** i2pd
%% out of the gate; this one needs only committed bytes, which is the whole
%% point of the capture.
-module(i2p_ssu2_vectors_SUITE).

-export([all/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).

-export([
    fixture_is_a_committed_capture/1,
    every_packet_opens_under_the_session_keys/1,
    packet_numbers_are_contiguous_from_zero/1,
    ack_blocks_name_only_packets_i2pd_received/1,
    a_dropped_packet_stays_a_nack_range/1,
    immediate_ack_marks_the_blocks_that_need_one/1,
    i2pd_puts_its_own_router_info_on_the_wire/1,
    i2np_messages_decode/1
]).

%% The packet the capture deliberately lost. The capture sends a DatabaseStore
%% first, then six large I2NP messages, so the first datagram after the handshake
%% is the store and the drop lands on packet 2. That is a property of the
%% capture, not of the protocol, and it is what makes the literal below
%% meaningful: the packet i2pd is missing is packet 2, and the NACK range names
%% exactly one packet number, which is that one.

%% The direction the fixture was captured in. Every datagram in it is one i2pd
%% sent to us, so every decode below is `ba`: `decode_data/4` takes the
%% direction of the packets *arriving*, which for Bob's is `ba`.
-define(RECV_DIR, ba).

all() ->
    [
        fixture_is_a_committed_capture,
        every_packet_opens_under_the_session_keys,
        packet_numbers_are_contiguous_from_zero,
        ack_blocks_name_only_packets_i2pd_received,
        a_dropped_packet_stays_a_nack_range,
        immediate_ack_marks_the_blocks_that_need_one,
        i2pd_puts_its_own_router_info_on_the_wire,
        i2np_messages_decode
    ].

suite() ->
    [{timetrap, 30000}].

%% Decode once, here, so every case asserts against the same bytes and the AEAD
%% is only paid for once. A decode that fails is not a case failing: it is the
%% fixture being unreadable, which would otherwise make every case below report
%% a failure about the wrong thing.
init_per_suite(Config) ->
    Fixture = fixture_path(i2p_ct_helpers:project_root()),
    Packets = decode_all(Fixture),
    [{fixture, Fixture}, {packets, Packets} | Config].

end_per_suite(_Config) ->
    ok.

fixture_path(Root) ->
    filename:join([Root, "apps", "i2per", "test", "fixtures", "i2pd_ssu2_data_phase.term"]).

%%% --------------------------------------------------------------------------
%%% The capture is real and it is the one the tree claims to have
%%% --------------------------------------------------------------------------

%% Two claims that are cheap to check and expensive to discover are false: that
%% there is a capture at all, and that it says which i2pd it came from. The
%% second matters because the README ties protocol claims to this file, and an
%% unattributed capture cannot be re-derived when i2pd is bumped.
fixture_is_a_committed_capture(Config) ->
    %% A string, not a binary: the capture writes the version as a term literal,
    %% so `file:consult/1` reads it back as a list of characters.
    "2." ++ _ = proplists:get_value(i2pd_version, consult(fixture(Config))),
    [{_, _, _} | _] = proplists:get_value(packets, Config),
    ok.

%%% --------------------------------------------------------------------------
%%% Every datagram decodes
%%% --------------------------------------------------------------------------

%% The load-bearing case. `decode_data/4` succeeding means the two header masks,
%% the AEAD, the key derivation and the block walker all still agree with a
%% router we do not control. A round-trip test cannot see this: our encoder and
%% our decoder would happily agree on a wire format nobody else speaks.
every_packet_opens_under_the_session_keys(Config) ->
    [_ | _] = Packets = packets(Config),
    lists:foreach(
        fun({_Index, Datagram, #{pkt_num := PktNum, blocks := [_ | _] = Blocks}}) ->
            true = is_binary(Datagram),
            true = byte_size(Datagram) > 16,
            ct:pal("~p bytes -> pkt ~p ~p", [
                byte_size(Datagram), PktNum, [kind(B) || B <- Blocks]
            ])
        end,
        Packets
    ).

%% Packet numbers are the AEAD nonce counter, so a peer that reused or skipped
%% one would be a peer whose later packets cannot be read at all. i2pd numbers
%% its data packets from zero without gaps, which is also what makes the
%% fixture's own index meaningful -- see `every_packet_opens_under_the_session_keys`.
packet_numbers_are_contiguous_from_zero(Config) ->
    Expected = lists:seq(0, length(packets(Config)) - 1),
    Expected = [PktNum || {_, _, #{pkt_num := PktNum}} <- packets(Config)],
    ok.

%%% --------------------------------------------------------------------------
%%% ACK accounting
%%% --------------------------------------------------------------------------

%% The heart of it. Every ACK block is read back into the set of packet numbers
%% it says i2pd received, and each of those sets has to be a superset of the one
%% before it: a receiver that has seen more packets cannot un-see one.
%%
%% This is what catches an accounting bug. If `AckThrough`, `Acnt` or a range's
%% NACK/ACK split were decoded wrongly, the packet numbers would still look
%% plausible and the round trip would still work; the only symptom would be that
%% we credit a packet we never received -- so we stop retransmitting something
%% the peer never got, or never notice something it did.
ack_blocks_name_only_packets_i2pd_received(Config) ->
    [First | Rest] = ack_sets(Config),
    lists:foldl(
        fun(Set, Seen) ->
            %% Monotone accumulation is the whole claim, and it is written
            %% `Seen -- Set` rather than `Set -- Seen`: the failure mode is i2pd
            %% *un*-acknowledging a packet it had already acknowledged, so the
            %% direction that matters is "nothing already seen has gone".
            [] = Seen -- Set,
            Set
        end,
        First,
        Rest
    ),
    ok.

%% The ACK block carries `AckThrough`, `Acnt` and a list of `{Nack, Ack}` runs,
%% and the packet numbers it names are reconstructed from all three together --
%% which is exactly why a decoder that reads the first two correctly and the
%% third wrong produces a plausible-looking answer that the case above rejects.
%%
%% Walk it downward from `AckThrough`: the packet itself, then `Acnt`
%% consecutive below it, then each range in turn -- `Nack` missing, then `Ack`
%% received, then the next range.
%%
%% Both halves come back, because they are opposites and both are claims. The
%% received set is what congestion control attributes a sample to; the NACKed
%% set is how the capture proves the loss happened at all, and a walk that
%% folded the NACK run into the received set would pass every accounting
%% assertion while inverting the one fact the capture exists for.
ack_split(AckThrough, Acnt, Ranges) ->
    Received = [AckThrough | lists:seq(AckThrough - Acnt, AckThrough - 1)],
    walk(AckThrough - Acnt - 1, Ranges, Received, []).

walk(_Next, [], Received, Nacked) ->
    {lists:sort(Received), lists:sort(Nacked)};
walk(Next, [{Nack, Ack} | Rest], Received, Nacked) ->
    NackedNow = lists:seq(Next - Nack + 1, Next),
    ReceivedNow = lists:seq(Next - Nack - Ack + 1, Next - Nack),
    walk(Next - Nack - Ack, Rest, ReceivedNow ++ Received, NackedNow ++ Nacked).

%%% --------------------------------------------------------------------------
%%% The capture is a loss, and the loss stays a loss
%%% --------------------------------------------------------------------------

%% The relay swallows one of our data packets so i2pd emits an ACK with a NACK
%% range in it: an ACK over a contiguous run has an empty range list, and the
%% gapped case is the one that exercises the accounting.
%%
%% **Which packet number it is.** The capture sends a DatabaseStore first, then
%% six large I2NP messages, so the first datagram after the handshake is the
%% store and the drop lands on packet 2. That is a property of the capture, not
%% of the protocol, and it is what makes the literal below meaningful: the
%% packet i2pd is missing is packet 2, and the NACK range names exactly one
%% packet number, which is that one.
%%
%% **The ACK shape.** Every gapped ACK in this capture carries `{1, 2}`:
%% one packet NACKed, two received below it (packets 1 and 0). Both numbers
%% are pinned below, because a decoder that swapped the NACK and ACK counts
%% would still produce a well-formed, monotone, disjoint set -- the only way
%% to catch it is to say which count is which.
%%
%% Four claims, in order of how much they would catch:
%%
%%   1. **The ACK block names the loss correctly.** NACK count 1, ACK count 2,
%%      and the NACKed set is exactly `{2}`. This is the whole encoding in one
%%      line, and it is the one a walk that folds the NACK run into the received
%%      set fails -- the received set would then contain 2 as well.
%%   2. **A packet reported lost is never reported received.** Cumulative over
%%      the whole capture, the complement of (1), and the claim that actually
%%      matters for retransmission.
%%   3. **The hole is never reclaimed.** i2pd does not forget a packet number it
%%      has skipped, so the NACK sets are nested. A receiver that reclaims a
%%      hole would silently drop packets it is still missing.
%%   4. **A range list is present at all.** Without one the capture no longer
%%      contains the loss it was taken to produce.
-define(DROPPED_PACKET, 2).

a_dropped_packet_stays_a_nack_range(Config) ->
    Splits = ack_splits(Config),
    %% (1) Every gapped ACK carries {1, 2}, and the NACKed set is {2}.
    [_ | _] = Gapped = [R || {ack, _, _, [_ | _] = R} <- ack_blocks(Config)],
    true = lists:all(fun(R) -> R =:= [{1, 2}] end, Gapped),
    CumulativeNacked = lists:usort(lists:append([N || {_R, N} <- Splits])),
    [?DROPPED_PACKET] = CumulativeNacked,
    %% (2)
    CumulativeReceived = lists:usort(lists:append([R || {R, _N} <- Splits])),
    CumulativeNacked = CumulativeNacked -- CumulativeReceived,
    %% (3)
    lists:foldl(
        fun({_Received, Nacked}, Seen) ->
            [] = Seen -- Nacked,
            lists:usort(Seen ++ Nacked)
        end,
        [],
        Splits
    ),
    %% (4)
    [_ | _] = [N || {_Received, [_ | _] = N} <- Splits],
    ct:pal("~p ACK blocks; i2pd never received ~p", [
        length(ack_blocks(Config)), CumulativeNacked
    ]),
    ok.

%%% --------------------------------------------------------------------------
%%% What else i2pd puts in a data packet
%%% --------------------------------------------------------------------------

%% The immediate-ack flag asks the peer for an acknowledgement now rather than
%% with its next traffic. i2pd sets it when the packet carries something the
%% peer has to act on -- an I2NP message -- and not when the packet is only
%% telling the peer what it already sent.
%%
%% Asserted against i2pd's behaviour, not ours, and the RouterInfo packet is the
%% interesting one: i2pd leaves the flag clear on a packet carrying only its
%% RouterInfo, so a reader must not assume "carries a block" means "needs an
%% ack". That is a fact about the reference implementation, which is the only
%% kind of thing this suite can be the source of -- and it is a divergence from
%% `m:i2p_ssu2_conn:ack_eliciting/1`, which counts a router_info block.
immediate_ack_marks_the_blocks_that_need_one(Config) ->
    lists:foreach(
        fun({_Index, Datagram, #{immediate_ack := Flag, blocks := Blocks}}) ->
            Expected = lists:any(fun needs_ack/1, Blocks),
            Expected = Flag,
            ct:pal("~p bytes immediate_ack=~p ~p", [
                byte_size(Datagram), Flag, [kind(B) || B <- Blocks]
            ])
        end,
        packets(Config)
    ),
    ok.

needs_ack({i2np, _, _, _, _}) -> true;
needs_ack(_) -> false.

%% Proof the bytes came from a peer rather than from us: i2pd publishes its own
%% RouterInfo in its first data packet, and a RouterInfo we built would carry our
%% identity. Decoding it and hashing it is what separates "a real router said
%% this" from "a fixture that only proves our own encoder round-trips".
i2pd_puts_its_own_router_info_on_the_wire(Config) ->
    [First | _] = RIs = [Data || {router_info, _, Data} <- blocks(Config)],
    ct:pal("~p RouterInfos, first ~p bytes", [length(RIs), byte_size(First)]),
    lists:foreach(
        fun(Data) ->
            {ok, RI} = i2p_router_info:decode(Data),
            32 = byte_size(i2p_router_info:hash(RI)),
            [_ | _] = i2p_router_info:addresses(RI)
        end,
        RIs
    ),
    ok.

%% And that what it carries is protocol traffic, not padding. i2pd spends its
%% first packets on NetDb lookups and RouterInfo stores; decoding them is what
%% makes the capture a fixture about SSU2's payload rather than about its header.
i2np_messages_decode(Config) ->
    [First | _] =
        Messages = [{Type, MsgId, Body} || {i2np, Type, MsgId, _, Body} <- blocks(Config)],
    {FirstType, _, FirstBody} = First,
    ct:pal("~p I2NP messages, first type ~p ~p bytes", [
        length(Messages), FirstType, byte_size(FirstBody)
    ]),
    lists:foreach(
        fun({Type, MsgId, Body}) ->
            true = is_integer(Type),
            true = is_integer(MsgId),
            true = is_binary(Body),
            true = byte_size(Body) > 0
        end,
        Messages
    ),
    ok.

%%% --------------------------------------------------------------------------
%%% Reading the fixture
%%% --------------------------------------------------------------------------

fixture(Config) -> proplists:get_value(fixture, Config).
packets(Config) -> proplists:get_value(packets, Config).

%% Every block of every packet, flattened, so a case can select by block shape
%% without repeating the two-level walk.
blocks(Config) ->
    lists:append([Blocks || {_, _, #{blocks := Blocks}} <- packets(Config)]).

ack_blocks(Config) -> [B || {ack, _, _, _} = B <- blocks(Config)].

ack_splits(Config) -> [ack_split(AT, Acnt, R) || {ack, AT, Acnt, R} <- ack_blocks(Config)].

ack_sets(Config) -> [Received || {Received, _} <- ack_splits(Config)].

kind({ack, AckThrough, Acnt, Ranges}) -> {ack, AckThrough, Acnt, Ranges};
kind(B) when is_tuple(B) -> element(1, B);
kind(B) -> B.

consult(Path) ->
    {ok, Terms} = file:consult(Path),
    Terms.

decode_all(Path) ->
    Terms = consult(Path),
    Keys = maps:from_list([{Name, unhex(Hex)} || {Name, Hex} <- required(data_keys, Terms)]),
    Intro = unhex(required(our_intro_key, Terms)),
    [entry(Keys, Intro, Index, Hex) || {Index, Hex} <- required(packets, Terms)].

%% An AEAD failure or a non-Data message is `error`, and it becomes a failure
%% here rather than being left for each case to interpret: "this datagram does
%% not open" is a property of the fixture as a whole, and a case that had to
%% notice it would be able to forget.
%%
%% The datagram is kept alongside the decode because a case that only reports on
%% the decoded shape cannot say how big the bytes it rejected were, and "the
%% decode failed" on a 1-byte datagram is a different failure from the same on a
%% 1500-byte one.
entry(Keys, Intro, Index, Hex) ->
    Datagram = unhex(Hex),
    {ok, Decoded} = i2p_ssu2:decode_data(Keys, ?RECV_DIR, Intro, Datagram),
    {Index, Datagram, Decoded}.

%% Hex, because the capture writes bytes consult would refuse as a literal.
%% Pairs, not nibbles: `decode_hex/1` is the one that turns two characters into
%% one byte.
unhex(Hex) -> binary:decode_hex(Hex).

required(Key, Terms) ->
    case proplists:lookup(Key, Terms) of
        {Key, Value} -> Value;
        none -> erlang:error({fixture_missing, Key})
    end.
