%% Deterministic SSU2 session-admission and recovery tests. The two
%% fault-injection cases drive a bare `i2p_ssu2_conn:connect/4` through an
%% in-test UDP proxy that controls the SessionCreated leg:
%%
%%   - `dial_survives_created_delay`: the reply is delayed 3500 ms, later than
%%     Alice's 1000 ms retransmit interval but inside the handshake budget.
%%   - `dial_survives_created_loss`: the first SessionCreated is dropped;
%%     Alice's retransmitted SessionRequest makes Bob re-answer, and the dial
%%     completes on the re-answer.
%%
%% The cases use fixed injected faults and assert the public `connect/4`
%% result. The data-path twin, `data_survives_dropped_packet`, drops an
%% established Data packet in each direction and verifies the sender's
%% resend timer restores the exact body through the public owner-mailbox seam.
-module(i2p_ssu2_handshake_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    session_limit_rejects_new_child/1,
    dial_survives_created_delay/1,
    dial_survives_created_loss/1,
    data_survives_dropped_packet/1,
    created_with_peertest_type_byte_is_delivered/1,
    a_truncated_datagram_does_not_kill_the_socket_owner/1,
    classification_spends_one_pass_per_claimed_datagram/1
]).

-define(APP, i2per).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        session_limit_rejects_new_child,
        dial_survives_created_delay,
        dial_survives_created_loss,
        data_survives_dropped_packet,
        created_with_peertest_type_byte_is_delivered,
        a_truncated_datagram_does_not_kill_the_socket_owner,
        classification_spends_one_pass_per_claimed_datagram
    ].

init_per_testcase(_Case, Config) ->
    i2p_ct_helpers:start_ssu2_trace(),
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, 30000} | Config].

end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    i2p_ct_helpers:stop_ssu2_trace(),
    ok.

session_limit_rejects_new_child(_Config) ->
    application:set_env(?APP, max_ssu2_sessions, 0),
    try
        {error, session_limit} =
            i2p_ssu2_sup:start_session(i2p_ssu2_sup:session_child(#{}))
    after
        application:unset_env(?APP, max_ssu2_sessions)
    end.

%% A datagram that stops inside its own Poly1305 tag must not take the socket
%% owner with it.
%%
%% This is the consequence the library-level case in `i2p_ssu2_tests` cannot
%% show: the listener is the only process holding the UDP socket, its child spec
%% is `restart => temporary`, so when it died it did not come back and every SSU2
%% session lost its send path for good. The trigger is remote and needs no
%% credential a stranger lacks -- the introduction key is in our own RouterInfo --
%% and the length that works depends on the key, so for any key roughly one
%% datagram in 256 of each length from ?MIN_PACKET to 47 is enough.
%%
%% The assertion is the listener's own liveness after each length, checked from
%% outside, because that is the property that matters and a codec returning
%% `error` could still be followed by a crash somewhere on the way out.
a_truncated_datagram_does_not_kill_the_socket_owner(_Config) ->
    Local = peer_local(),
    IntroKey = maps:get(intro_key, Local),
    {ok, Listener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, Local, self()),
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    try
        LPort = i2p_ssu2_listener:port(Listener),
        %% Both header types the listener hands to a symmetric decoder: the
        %% out-of-session PeerTest on the unowned path, and the TokenRequest the
        %% handshake fallback tries first. Either alone was enough.
        Types = [{peertest, 7}, {token_request, 10}],
        Killed = [
            {Name, Size}
         || {Name, Type} <- Types,
            Size <- lists:seq(40, 47),
            begin
                ok = gen_udp:send(
                    Sock,
                    {127, 0, 0, 1},
                    LPort,
                    truncated_datagram(IntroKey, Type, Size)
                ),
                %% Long enough for the datagram to have been classified, handled
                %% and answered-or-dropped, and short enough not to be a race
                %% against the assertion itself.
                timer:sleep(50),
                not is_process_alive(Listener)
            end
        ],
        [] = Killed,
        true = is_process_alive(Listener),
        %% And the socket still works: a real handshake through it, which is what
        %% a dead socket owner costs. Without this the case would pass on a
        %% listener that survived the probes but could no longer bind.
        {ok, Dialed, _Keys} = dial_through_proxy({delay, 0}),
        gen_server:cast(Dialed, {terminate, 0}),
        ok
    after
        gen_udp:close(Sock),
        i2p_ssu2_listener:stop(Listener)
    end.

%% Sealed for real and then cut short, so the masks are the ones the listener
%% will actually derive and the header really does present as `Type`. Match
%% rather than an EUnit macro, since this is a CT suite: a size that drifted away
%% from the datagram would otherwise make the case test nothing.
truncated_datagram(IntroKey, Type, Size) ->
    Trailing = Size - 32,
    Plain = <<16#AABBCCDDEEFF0011:64, 1:32, Type:8, 2:8, 2:8, 0:8, 0:64, 0:64, 0:(Trailing * 8)>>,
    Sealed = i2p_ssu2:seal_long(Plain, IntroKey, IntroKey),
    Size = byte_size(Sealed),
    Sealed.

%% ---------------------------------------------------------------------------
%% What the socket owner costs, in ChaCha20 passes
%% ---------------------------------------------------------------------------

%% A datagram a session or a pending dialer has claimed costs the socket owner
%% **one** ChaCha20 pass; one that nothing claimed costs three. Not read off the
%% module doc -- counted, so the figure cannot drift away from the code the way a
%% comment can.
%%
%% The claim is the point of #YNBT5ZD. Routing used to open the whole 32-byte long
%% header up front, which is three passes, and then re-open it twice more in the
%% handshake fallback -- nine passes to decide to drop a datagram, and three on
%% the hot path, which is what a working router spends its time on. Two of those
%% three were spent recovering bytes nobody read.
%%
%% `f:i2p_crypto:chacha20_crypt/4` is the seam because it is the primitive every
%% unmask pass ends at: each of the two tail-derived header masks, and the
%% decryption of header bytes 16..31. So counting calls to it counts passes
%% exactly, which is the unit the module doc quotes -- counting `f:header_mask/2`
%% instead would miss the third-section pass and under-report the handshake path.
%%
%% The trace pattern is global, so it is installed and removed inside the case.
%% CT runs suites in sequence here, so no other process is deriving masks while it
%% is up; if that ever stops being true this case would need a narrower seam, not
%% a bigger allowance.
classification_spends_one_pass_per_claimed_datagram(_Config) ->
    Local = peer_local(),
    IntroKey = maps:get(intro_key, Local),
    {ok, Listener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, Local, self()),
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    try
        LPort = i2p_ssu2_listener:port(Listener),
        %% A claimed connection id, registered in the session table exactly as a
        %% real session registers its own, so the datagram takes the step-1 path.
        ConnId = 16#0BADF00DDEADBEEF,
        true = ets:insert(i2p_ssu2_sessions, {ConnId, self()}),
        Claimed = sealed_datagram(IntroKey, ConnId, 7, 1472),
        %% An unclaimed one from an endpoint nothing is waiting on, shaped so it is
        %% neither a probe nor a handshake: the listener drops it, so the only crypto
        %% spent on it is classification -- one pass to route, two more to learn the
        %% type byte says drop.
        Unclaimed = sealed_datagram(IntroKey, 16#1111222233334444, 99, 1472),
        [
            {claimed, 1, [Claimed]},
            {unclaimed, 3, []}
        ] =
            [
                {Name, Passes, Delivered}
             || {Name, Dgram} <- [{claimed, Claimed}, {unclaimed, Unclaimed}],
                {Passes, Delivered} <- [measure(Listener, Sock, LPort, Dgram)]
            ],
        ok
    after
        gen_udp:close(Sock),
        i2p_ssu2_listener:stop(Listener)
    end.

%% Send one datagram and report how many ChaCha20 passes the listener spent on it,
%% together with whatever it delivered to this process.
%%
%% `code:ensure_loaded/1` first because a trace pattern only matches a loaded
%% module, and nothing has to have called `i2p_crypto` yet for this case to work.
%% `[local]` is what makes the pattern match the same-module calls too: without
%% it only cross-module calls are traced, and this one would silently count zero.
measure(Listener, Sock, LPort, Dgram) ->
    {module, i2p_crypto} = code:ensure_loaded(i2p_crypto),
    1 = erlang:trace_pattern({i2p_crypto, chacha20_crypt, 4}, true, [local]),
    1 = erlang:trace(Listener, true, [call]),
    try
        ok = gen_udp:send(Sock, {127, 0, 0, 1}, LPort, Dgram),
        {Passes, Delivered} = collect(Listener, 0, []),
        {Passes, Delivered}
    after
        1 = erlang:trace(Listener, false, [call]),
        1 = erlang:trace_pattern({i2p_crypto, chacha20_crypt, 4}, false, [local])
    end.

%% Ends on a quiet period rather than a fixed sleep: the listener is another process
%% and the datagram has to cross a socket, so when it is finished with it is not this
%% process's to predict. A regression that added a pass therefore reports the wrong
%% count and fails on the number, instead of timing out.
collect(Listener, Passes, Delivered) ->
    receive
        {trace, Listener, call, {i2p_crypto, chacha20_crypt, _Args}} ->
            collect(Listener, Passes + 1, Delivered);
        {trace, Listener, call, _NotAPass} ->
            collect(Listener, Passes, Delivered);
        {ssu2_packet, Dgram} ->
            collect(Listener, Passes, Delivered ++ [Dgram])
    after 250 ->
        {Passes, Delivered}
    end.

%% A sealed datagram of `Size` bytes whose opened header says connection id
%% `ConnId` and type `Type`, padded out to `Size` -- the shape a real one has.
sealed_datagram(IntroKey, ConnId, Type, Size) ->
    Header = <<ConnId:64, 1:32, Type:8, 2:8, 2:8, 0:8, 0:64, 0:64>>,
    %% Padded *before* sealing, since the masks are derived from the tail: padding
    %% afterwards would leave the header sealed under masks computed from other bytes,
    %% and the datagram would not present as `Type` at all.
    Body = binary:copy(crypto:strong_rand_bytes(Size - byte_size(Header)), 1),
    i2p_ssu2:seal_long(<<Header/binary, Body/binary>>, IntroKey, IntroKey).

%% ---------------------------------------------------------------------------
%% Fault-injected bare dials
%% ---------------------------------------------------------------------------

%% The SessionCreated must arrive well past Alice's first retransmits without
%% stranding the handshake: a reply later than the retransmit interval is a
%% slow network, not a dead peer.
dial_survives_created_delay(_Config) ->
    {ok, Pid, _Keys} = dial_through_proxy({delay, 3500}),
    gen_server:cast(Pid, {terminate, 0}),
    ok.

%% One lost SessionCreated must be recovered by Bob re-answering on Alice's
%% retransmitted SessionRequest — not by Alice exhausting the handshake
%% budget with a duplicate SessionRequest rotting in Bob's fragment buffer.
dial_survives_created_loss(_Config) ->
    {ok, Pid, _Keys} = dial_through_proxy({drop_ba_first, 1}),
    gen_server:cast(Pid, {terminate, 0}),
    ok.

%% A handshake response from a pending endpoint must reach that pending
%% session even when the datagram's masked type byte happens to read
%% ?TYPE_PEER_TEST.
%%
%% Bytes 8..15 of a handshake datagram are masked with the session's header
%% protection key, which the listener does not hold, so the type byte at offset
%% 12 decodes to noise there. The listener used to compare that noise against
%% ?TYPE_PEER_TEST and, on a match, divert the datagram into the Charlie
%% responder -- which cannot decode a SessionCreated and drops it. The peer then
%% burns all its retransmits and exits {handshake_timeout, session_request}.
%% Because the noise is key- and tail-derived, that happened for roughly one
%% datagram in 256 and presented as an unreproducible flake (ZWHH3TX and its
%% predecessors W6QCGA9 and KSM00CK were all attempts to paper over it).
%%
%% So build the collision on purpose: search random payloads for one that really
%% does decode to ?TYPE_PEER_TEST at offset 12 under an intro-key-only unmask,
%% assert such a payload was actually found so the case cannot pass vacuously,
%% and then assert the listener still routes it to the pending session.
created_with_peertest_type_byte_is_delivered(_Config) ->
    Local = peer_local(),
    IntroKey = maps:get(intro_key, Local),
    {ok, Listener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, Local, self()),
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, SrcPort} = inet:port(Sock),
        LPort = i2p_ssu2_listener:port(Listener),
        Payload = colliding_payload(IntroKey),
        %% Register this test process as the pending dialer for the endpoint the
        %% datagram will arrive from, exactly as a dialling session does.
        gen_server:cast(Listener, {register_pending, self(), {{127, 0, 0, 1}, SrcPort}}),
        ok = gen_udp:send(Sock, {127, 0, 0, 1}, LPort, Payload),
        receive
            {ssu2_packet, Payload} -> ok
        after 5000 ->
            ct:pal("payload head=~0p", [binary:part(Payload, 0, 16)]),
            error(pending_session_created_dropped)
        end
    after
        gen_udp:close(Sock),
        i2p_ssu2_listener:stop(Listener)
    end.

%% A datagram that an intro-key-only unmask presents as an out-of-session
%% PeerTest: offset 12 must read ?TYPE_PEER_TEST (7, private to i2p_ssu2).
%% Match rather than use an EUnit macro, since this is a CT suite, and fail
%% loudly if the collision was not found so the case cannot pass vacuously.
colliding_payload(IntroKey) ->
    Payload = search_collision(IntroKey, 20000, crypto:strong_rand_bytes(96)),
    {ok, <<_:12/binary, 7:8, _/binary>>} = opened(Payload, IntroKey),
    Payload.

search_collision(_IntroKey, 0, _Last) ->
    error(no_collision_found);
search_collision(IntroKey, N, Last) ->
    case opened(Last, IntroKey) of
        {ok, <<_:12/binary, 7:8, _/binary>>} ->
            Last;
        _ ->
            search_collision(IntroKey, N - 1, crypto:strong_rand_bytes(96))
    end.

opened(Payload, IntroKey) ->
    i2p_ssu2:open_long(Payload, IntroKey, IntroKey).

%% Data-phase recovery: after a full pair is established, a Data packet is
%% dropped on the wire in each direction in turn. The sender's data-resend
%% timer (2 s) re-transmits it under a fresh packet number and the peer
%% still reassembles the exact body. The proxy is re-armed
%% between the two drops so each drop target is a known Data packet, never an
%% in-flight ACK.
data_survives_dropped_packet(_Config) ->
    {APid, BPid, Proxy} = establish_pair_through_proxy(),
    ABody = <<"hello through the drop">>,
    proxy_set_mode(Proxy, {drop_ab_first, 1}),
    ok = i2p_ssu2_conn:send_i2np(APid, 6, 101, ABody),
    ok = wait_data(BPid, 101, ABody),
    %% Bob's ACK for the recovered 101 is sent within the same callback as the
    %% forward above; leave it time to clear the proxy so the re-arm below can
    %% only consume the 202 Data packet.
    timer:sleep(100),
    BBody = <<"reply through the drop">>,
    proxy_set_mode(Proxy, {drop_ba_first, 1}),
    ok = i2p_ssu2_conn:send_i2np(BPid, 6, 202, BBody),
    ok = wait_data(APid, 202, BBody),
    proxy_stop(Proxy),
    ok.

dial_through_proxy(ProxyMode) ->
    {BobLocal, _BobRIBlock} = bob_local(),
    {ok, BobListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    BobPort = i2p_ssu2_listener:port(BobListener),
    {ok, Proxy} = proxy_start({127, 0, 0, 1}, BobPort, ProxyMode),
    ProxyPort = proxy_port(Proxy),
    {AliceLocal, AliceRIBlock} = alice_local(),
    {ok, AliceListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, AliceLocal, self()),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => ProxyPort,
            static_key => maps:get(static_pub, BobLocal),
            intro_key => maps:get(intro_key, BobLocal)
        },
    Result = i2p_ssu2_conn:connect(AliceLocal, RemoteOpts, AliceRIBlock, AliceListener),
    proxy_stop(Proxy),
    Result.

%% Stand up an Alice and a Bob session routed through the proxy (kept running)
%% and hand back both session pids plus the proxy handle. Both owners are the
%% test process, so the Bob-ready wait below drains Alice's own ready (it
%% arrives before `connect/4` returns and must not be matched).
establish_pair_through_proxy() ->
    {BobLocal, _BobRIBlock} = bob_local(),
    {ok, BobListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    BobPort = i2p_ssu2_listener:port(BobListener),
    {ok, Proxy} = proxy_start({127, 0, 0, 1}, BobPort, pass),
    ProxyPort = proxy_port(Proxy),
    {AliceLocal, AliceRIBlock} = alice_local(),
    {ok, AliceListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, AliceLocal, self()),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => ProxyPort,
            static_key => maps:get(static_pub, BobLocal),
            intro_key => maps:get(intro_key, BobLocal)
        },
    {ok, APid, _Keys} = i2p_ssu2_conn:connect(AliceLocal, RemoteOpts, AliceRIBlock, AliceListener),
    BPid =
        i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_ready, P, _KeysB, _RemoteRI}) when P =/= APid -> {true, P};
                (_) -> false
            end,
            15000
        ),
    {APid, BPid, Proxy}.

%% Wait for `FromPid`'s session to deliver the I2NP message `MsgId`/`Body` to
%% the owner mailbox; non-matching session mail is drained.
wait_data(FromPid, MsgId, Body) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= FromPid ->
                case lists:keyfind(i2np, 1, Blocks) of
                    {i2np, _, MsgId, _, Body} -> {true, ok};
                    _ -> false
                end;
            (_) ->
                false
        end,
        15000
    ).

%% ---------------------------------------------------------------------------
%% In-test UDP proxy: forwards Alice <-> Bob on two sockets so each leg keeps
%% its own source port (a single re-originating socket would collide with the
%% pending-endpoint routing and echo the SessionRequest back to Alice). Modes
%% are per leg and re-armable mid-flight via `proxy_set_mode/2`:
%%   - `pass`: forward everything.
%%   - `{delay, Ms}`: hold Bob->Alice datagrams Ms ms (SessionCreated leg).
%%   - `{drop_ba_first, N}`: drop the next N Bob->Alice datagrams.
%%   - `{drop_ab_first, N}`: drop the next N Alice->Bob datagrams.
%% The `drop` slots are consumed by exactly the next N datagrams on that leg;
%% the caller arms a drop only when the very next datagram on that leg is the
%% one it wants lost (never an in-flight ACK), so the fault is deterministic.
%% ---------------------------------------------------------------------------

proxy_start(BobHost, BobPort, Mode) ->
    Caller = self(),
    Pid =
        spawn(fun() ->
            case gen_udp:open(0, [binary, {active, true}]) of
                {ok, SockA} ->
                    {ok, PA} = inet:port(SockA),
                    case gen_udp:open(0, [binary, {active, true}]) of
                        {ok, SockB} ->
                            {ok, PB} = inet:port(SockB),
                            ct:log(
                                "proxy up: alice_port=~p bob_sock_port=~p (bob ~p), mode=~p",
                                [PA, PB, BobPort, Mode]
                            ),
                            Caller ! {proxy_ready, PA},
                            try
                                proxy_loop(SockA, SockB, BobHost, BobPort, Mode, none)
                            catch
                                Class:Reason:Stack ->
                                    ct:pal("proxy crashed ~p:~p~n~p", [Class, Reason, Stack]),
                                    erlang:raise(Class, Reason, Stack)
                            end;
                        {error, Reason} ->
                            exit({proxy_open_failed, Reason})
                    end;
                {error, Reason} ->
                    exit({proxy_open_failed, Reason})
            end
        end),
    _ = erlang:monitor(process, Pid),
    Port =
        receive
            {proxy_ready, P} -> P
        after 2000 ->
            erlang:error(proxy_not_ready)
        end,
    {ok, #{pid => Pid, port => Port}}.

proxy_port(#{port := Port}) ->
    Port.

proxy_set_mode(#{pid := Pid}, Mode) ->
    Pid ! {proxy_set_mode, Mode},
    ok.

proxy_stop(#{pid := Pid}) ->
    %% Killing the process closes both sockets (they are its ports).
    catch exit(Pid, kill),
    ok.

proxy_loop(SockA, SockB, BobHost, BobPort, Mode, AliceEp) ->
    receive
        {proxy_set_mode, NewMode} ->
            ct:log("proxy: mode -> ~p", [NewMode]),
            proxy_loop(SockA, SockB, BobHost, BobPort, NewMode, AliceEp);
        {udp, SockA, IP, Port, Datagram} ->
            ct:log("proxy: alice ~p:~p (~p B) -> bob", [IP, Port, byte_size(Datagram)]),
            case apply_ab_mode(Mode, Datagram) of
                drop ->
                    ct:log("proxy: dropped alice -> bob (~p B)", [byte_size(Datagram)]),
                    proxy_loop(SockA, SockB, BobHost, BobPort, next_mode(Mode), AliceEp);
                {send, 0} ->
                    ok = gen_udp:send(SockB, BobHost, BobPort, Datagram),
                    proxy_loop(SockA, SockB, BobHost, BobPort, Mode, {IP, Port})
            end;
        {udp, SockB, _IP, _Port, Datagram} ->
            case AliceEp of
                none ->
                    ct:log(
                        "proxy: bob -> alice (~p B) dropped, alice endpoint unknown",
                        [byte_size(Datagram)]
                    ),
                    proxy_loop(SockA, SockB, BobHost, BobPort, Mode, none);
                {AIP, APort} ->
                    case apply_ba_mode(Mode, Datagram) of
                        drop ->
                            ct:log("proxy: dropped bob -> alice (~p B)", [byte_size(Datagram)]),
                            proxy_loop(
                                SockA,
                                SockB,
                                BobHost,
                                BobPort,
                                next_mode(Mode),
                                AliceEp
                            );
                        {send, HoldMs} ->
                            deliver_after(HoldMs, SockA, AIP, APort, Datagram),
                            proxy_loop(SockA, SockB, BobHost, BobPort, Mode, AliceEp)
                    end
            end
    end.

%% Alice->Bob leg: only the ab drop modes consume; every other mode (including
%% ba-leg modes on overlap from in-flight handshake datagrams) passes through.
apply_ab_mode(Mode, _Datagram) ->
    case Mode of
        {drop_ab_first, 0} -> {send, 0};
        {drop_ab_first, _N} -> drop;
        _ -> {send, 0}
    end.

%% Bob->Alice leg: delay holds (SessionCreated), ba drops consume; every other
%% mode (including ab-leg modes, which can overlap in-flight data from the
%% other direction) passes through.
apply_ba_mode({delay, Ms}, _Datagram) ->
    {send, Ms};
apply_ba_mode(drop_done, _Datagram) ->
    {send, 0};
apply_ba_mode({drop_ba_first, 0}, _Datagram) ->
    {send, 0};
apply_ba_mode({drop_ba_first, _N}, _Datagram) ->
    drop;
apply_ba_mode(_Mode, _Datagram) ->
    {send, 0}.

next_mode({drop_ba_first, 1}) ->
    drop_done;
next_mode({drop_ba_first, N}) ->
    {drop_ba_first, N - 1};
next_mode({drop_ab_first, 1}) ->
    drop_done;
next_mode({drop_ab_first, N}) ->
    {drop_ab_first, N - 1};
next_mode(Mode) ->
    Mode.

deliver_after(0, SockA, AIP, APort, Datagram) ->
    ok = gen_udp:send(SockA, AIP, APort, Datagram),
    ct:log("proxy: bob -> alice ~p:~p (~p B) delivered", [AIP, APort, byte_size(Datagram)]);
deliver_after(Ms, SockA, AIP, APort, Datagram) ->
    Ref = make_ref(),
    erlang:send_after(Ms, self(), {hold, Ref}),
    receive
        {hold, Ref} -> ok
    end,
    ok = gen_udp:send(SockA, AIP, APort, Datagram),
    ct:log("proxy: bob -> alice ~p:~p (~p B) delivered after ~p ms", [
        AIP, APort, byte_size(Datagram), Ms
    ]).

%% ---------------------------------------------------------------------------
%% Fixtures (same key/RouterInfo builders as the peertest suite)
%% ---------------------------------------------------------------------------

alice_local() ->
    {APub, APriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(APub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19150, APub, IntroKey),
    Opts = #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr],
        Opts,
        Seed
    ),
    ALocal = #{static_priv => APriv, static_pub => APub, intro_key => IntroKey},
    {ALocal#{sign_seed => Seed, sign_pub => SignPub}, maps:get(binary, RI)}.

bob_local() ->
    #{ri := RI} = Local = peer_local(),
    {Local, maps:get(binary, RI)}.

peer_local() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19151, Pub, IntroKey),
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr, i2p_router_info:ntcp2_address(<<"127.0.0.1">>, 9152, Pub, <<0:128>>)],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        Seed
    ),
    #{
        static_priv => Priv,
        static_pub => Pub,
        intro_key => IntroKey,
        sign_seed => Seed,
        sign_pub => SignPub,
        hash => i2p_router_info:hash(RI),
        ri => RI
    }.
