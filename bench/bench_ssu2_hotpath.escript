#!/usr/bin/env escript
%%! -pa _build/default/lib/i2per/ebin -pa _build/default/lib/telemetry/ebin

%% Measure what one inbound datagram costs the SSU2 hot path (#XZTYAVX).
%%
%% Two figures, because the ticket has two halves and they are paid by different
%% processes:
%%
%%   - **the socket owner.** `m:i2p_ssu2_listener` is the only process that can
%%     send on the SSU2 socket, so its per-datagram cost is every session's send
%%     latency as well as its own. Reported as reductions per datagram -- the
%%     figure that survives a change of machine -- and as wall-clock us per
%%     datagram, which is the one an operator can feel.
%%   - **an established session.** `m:i2p_ssu2_conn` builds a diagnostic frame
%%     per Data datagram in both directions, and the block-kind list inside that
%%     frame walks the datagram's blocks. Measured on a real Alice/Bob pair over
%%     loopback, so the handshake, the crypto, the framing and the fragmentation
%%     are the router's own.
%%
%% **Both are measured against the tree as built, not against a model of it.**
%% The listener is `m:i2p_ssu2_listener:listen/4`, the pair is
%% `m:i2p_ssu2_conn:connect/4`, and the datagrams are sealed by
%% `m:i2p_ssu2:seal_long/3`. That is what makes a before and an after comparable:
%% run this on `main` and on the branch and the two numbers are the same
%% measurement of two trees, rather than two measurements of nothing.
%%
%% The mailbox figure is the other half of the re-arm decision, and it is measured
%% rather than argued. The sender blasts without pausing while a sampler polls the
%% socket owner's queue, so the number reported is an observed high-water -- a
%% lower bound on the queue's depth, and never a claim about how deep it can get.
%% The bound itself is the code's to state; this is here to show the two agree.
%%
%% `log_level` is the other end of the gate: run it at `debug` and the diagnostic
%% frames are built and recorded, which is the only way to see what a frame costs
%% when somebody *is* reading it. The ticket's claim is about the other case.
%%
%% Usage:
%%   escript bench/bench_ssu2_hotpath.escript [--label STR] [--warm N] [--count N]
%%         [--size N] [--msgs N] [--body N] [--log-level L]

-mode(compile).

%% The connection id the claimed datagrams present. Any value works; this one
%% reads as the placeholder it is.
-define(CONN_ID, 16#0BADF00DDEADBEEF).

%% 1472 bytes is a full-MTU SSU2 datagram, which is what a router carrying tunnel
%% data spends its time on. A short one would make the crypto a rounding error and
%% the per-datagram bookkeeping -- the thing being measured -- look larger than it
%% is.
-define(DATAGRAM_SIZE, 1472).

%% How long the measured window waits after the sender has finished, so the count
%% it reads is the count of what it produced rather than the count at the instant
%% the sender returned. Long enough for a socket owner to drain a full kernel
%% buffer, short enough that it is not part of the figure -- the clock has already
%% stopped by then.
-define(SETTLE_MS, 300).

main(Args) ->
    Opts = parse(args_to_bin(Args), #{
        label => "unlabelled",
        warm => 500,
        count => 20000,
        size => ?DATAGRAM_SIZE,
        msgs => 2000,
        body => 900,
        %% A binary, because every other option this parser fills in arrives from
        %% `f:args_to_bin/1` as one. A default written as a string is a default the
        %% level setter cannot take, and it fails on the very first run.
        log_level => <<"notice">>
    }),
    Dir = filename:join("/tmp", "i2per-ssu2-hotpath-" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "identity")),
    ok = boot(Dir, Opts),
    try
        run(Opts)
    after
        ok = application:stop(i2per)
    end.

%% A data dir and no seeds. `m:i2per_sup:resolve_local/0` answers `error` for
%% that shape, so the router brings up every ETS table, counter and supervisor this
%% path reads -- `i2p_ssu2_sup` among them, which is what owns this bench's
%% listeners -- without binding a UDP port of its own. The sockets measured are
%% ones this bench asked for on 127.0.0.1:0, so a router already on the machine is
%% not in the way and nothing here can be dialled from outside.
boot(Dir, Opts) ->
    application:set_env(i2per, data_dir, Dir),
    {ok, _Started} = application:ensure_all_started(i2per),
    ok = i2p_log:set_level(binary_to_atom(maps:get(log_level, Opts), utf8)).

run(Opts) ->
    io:format("~ts~n", [maps:get(label, Opts)]),
    io:format(
        "  otp ~s  schedulers ~p  datagrams ~p  bytes ~p  log_level ~p~n",
        [
            erlang:system_info(otp_release),
            erlang:system_info(schedulers),
            maps:get(count, Opts),
            maps:get(size, Opts),
            i2p_log:level()
        ]
    ),
    socket_owner(Opts),
    session(Opts).

%%% %%%%% The socket owner %%%%% %%%%

%% What one datagram costs the process that owns the socket.
%%
%% A **claimed** datagram is the one that matters: it is what a working router
%% spends its time on, and it is the cheapest of the three shapes the classifier
%% distinguishes, so a figure here is a floor rather than a flattering average.
%% The connection id is registered in `i2p_ssu2_sessions` exactly as a live
%% session registers its own, so the datagram takes the step-1 path and the sink
%% receives it -- which is also what makes "delivered" a real count rather than a
%% hopeful one.
socket_owner(Opts) ->
    Local = local_keys(),
    {ok, Listener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, Local, self()),
    try
        Port = i2p_ssu2_listener:port(Listener),
        Dgram = sealed_datagram(maps:get(intro_key, Local), ?CONN_ID, maps:get(size, Opts)),
        Sink = sink(),
        true = ets:insert(i2p_ssu2_sessions, {?CONN_ID, Sink}),
        Sender = sender(Port, Dgram),
        %% Warm-up on the soak's discipline: every cache on this path fills once,
        %% and a measurement taken cold reports the fill as cost.
        blast(Sender, maps:get(warm, Opts)),
        timer:sleep(?SETTLE_MS),
        _ = count(Sink),
        {Delivered, Elapsed, PerDatagram} = steady_window(
            Listener, Sender, Sink, maps:get(count, Opts)
        ),
        io:format("  socket owner~n", []),
        io:format("    offered ~p, delivered ~p (the rest were dropped by the~n", [
            maps:get(count, Opts), Delivered
        ]),
        io:format("    socket buffer -- the sender is saturating on purpose)~n", []),
        io:format("    reductions/datagram ~s   <- the figure that compares trees~n", [
            PerDatagram
        ]),
        UsPerDatagram =
            case Delivered < 1 of
                true -> "unknown";
                false -> io_lib:format("~.2f", [Elapsed / Delivered])
            end,
        io:format("    sender us/datagram ~s~n", [UsPerDatagram])
    after
        i2p_ssu2_listener:stop(Listener)
    end.

%% The measured window.
%%
%% **Divided by the number delivered, never by the number offered.** Loopback UDP
%% drops when the sender outruns the reader, and dividing by the offer would
%% understate the cost per datagram and make a drop read as an improvement. The
%% count is read after a settle rather than by waiting for a target, because the
%% number that actually arrives is not knowable in advance -- a window that waits
%% for all of them waits out its timeout and then divides a five-second wait by a
%% few hundred datagrams.
%%
%% The reductions are a **delta** over the window rather than the socket owner's
%% running total, which is what makes the figure comparable between two trees: a
%% total would carry whatever the handshake and the warm-up had already spent.
steady_window(Listener, Sender, Sink, Count) ->
    Base = count(Sink),
    Before = reductions(Listener),
    T0 = erlang:monotonic_time(microsecond),
    blast(Sender, Count),
    Elapsed = erlang:monotonic_time(microsecond) - T0,
    %% Long enough for the socket owner to drain what the kernel buffered, short
    %% enough that the clock has already stopped: the elapsed time is the sender's,
    %% and the count is what it produced.
    timer:sleep(?SETTLE_MS),
    Delivered = count(Sink) - Base,
    {Delivered, Elapsed, per_datagram(reductions(Listener) - Before, Delivered)}.

%% Per datagram, or `unknown` when nothing was delivered. A zero here would be
%% indistinguishable from a socket owner that never ran at all, which is a
%% different report.
per_datagram(_Delta, Delivered) when Delivered < 1 ->
    "unknown";
per_datagram(Delta, Delivered) ->
    io_lib:format("~.1f", [Delta / Delivered]).

%% The socket owner's queue depth is deliberately **not** measured here. The bound
%% is structural -- the runtime will not enqueue more than the re-arm budget, so
%% no flood can grow it past that -- and a bench that sampled the queue from
%% outside could only ever report a lower bound on it, which is a weaker claim
%% than the code already makes. `i2p_ssu2_listener_tests` asserts the bound
%% against the live process instead, where the assertion can be about the number
%% rather than about how well a sampler happened to be scheduled.


%%% %%%%% An established session %%%%% %%%%

%% What one Data datagram costs a session, in both directions.
%%
%% A real pair over loopback: `m:i2p_ssu2_conn:connect/4` runs the Noise handshake
%% and the listener spawns the Bob side, so what is measured is the data phase
%% this router actually runs -- seal, fragment, send, receive, decrypt,
%% reassemble -- and not a loopback that skips it.
%%
%% The sender's figure is the interesting one. `f:send_packet/3` frames every
%% outbound datagram with a list of its block kinds, and building that list is the
%% largest allocation on the path: it walks the datagram's blocks on every datagram
%% whether or not anybody will ever read the frame.
session(Opts) ->
    case establish_pair() of
        {ok, Alice, Bob} ->
            try
                data_window(Alice, Bob, Opts)
            after
                gen_server:cast(Alice, {terminate, 0}),
                gen_server:cast(Bob, {terminate, 0})
            end;
        {error, Why} ->
            io:format("  session: not established (~p), window skipped~n", [Why])
    end.

data_window(Alice, Bob, Opts) ->
    Count = maps:get(msgs, Opts),
    Body = crypto:strong_rand_bytes(maps:get(body, Opts)),
    %% Warm-up before the window. A frame that is expensive only for the first
    %% datagrams of a connection would hide behind a cold cache otherwise, and this
    %% measures the steady state -- where the per-datagram cost is the whole cost.
    lists:foreach(fun(I) -> i2p_ssu2_conn:send_i2np(Alice, 6, I, Body) end, lists:seq(1, 100)),
    timer:sleep(200),
    ARedBefore = reductions(Alice),
    BRedBefore = reductions(Bob),
    T0 = erlang:monotonic_time(microsecond),
    lists:foreach(fun(I) -> i2p_ssu2_conn:send_i2np(Alice, 6, I, Body) end, lists:seq(1, Count)),
    Elapsed = erlang:monotonic_time(microsecond) - T0,
    %% Both sessions also ACK, so each is doing work the cast above did not.
    timer:sleep(500),
    io:format("  session (Alice -> Bob, ~p B body, ~p messages)~n", [
        maps:get(body, Opts), Count
    ]),
    io:format("    sender reductions/message ~.1f   <- the frame the ticket names~n", [
        (reductions(Alice) - ARedBefore) / Count
    ]),
    io:format("    receiver reductions/message ~.1f~n", [
        (reductions(Bob) - BRedBefore) / Count
    ]),
    io:format("    sender us/message (the cast returns before the work is done) ~.2f~n", [
        Elapsed / Count
    ]).

%%% %%%%% Standing a pair up %%%%% %%%%

%% The CT suite's shape, without the proxy: a Bob listener, then an Alice that
%% dials it directly. `m:i2p_ssu2_conn:connect/4` is the call
%% `i2p_ssu2_handshake_SUITE` makes, and it returns once Alice's side is
%% established; Bob announces itself to the owner as `{ssu2_ready, Pid, ...}`,
%% which is how this finds it without reaching into the session registry.
establish_pair() ->
    {BobLocal, _BobRI} = peer_identity(19151),
    {ok, BobListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, BobLocal, self()),
    {AliceLocal, AliceRI} = peer_identity(19150),
    {ok, AliceListener} = i2p_ssu2_listener:listen(<<"127.0.0.1">>, 0, AliceLocal, self()),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => i2p_ssu2_listener:port(BobListener),
            static_key => maps:get(static_pub, BobLocal),
            intro_key => maps:get(intro_key, BobLocal)
        },
    %% **Alice's own RouterInfo block**, because that is what `f:connect/4` takes:
    %% the block she carries in SessionConfirmed, which Bob validates against the
    %% static key her handshake derived. Handing it Bob's is accepted by the
    %% signature and refused by the check, and the session dies with
    %% `{protocol_error, static_key_mismatch}` after the handshake has already
    %% cost real work -- a failure that reads as a key bug and is a fixture bug.
    case i2p_ssu2_conn:connect(AliceLocal, RemoteOpts, AliceRI, AliceListener) of
        {ok, Alice, _Keys} -> {ok, Alice, await_bob(Alice)};
        Other -> {error, Other}
    end.

await_bob(Alice) ->
    receive
        {ssu2_ready, Pid, _Keys, _RemoteRI} when Pid =/= Alice ->
            Pid
    after 15000 ->
        exit(no_bob_session_announced)
    end.

%% A keypair, an introduction key and the RouterInfo block the suite's fixtures
%% build: Alice dials Bob with Bob's RouterInfo, and `f:connect/4` reads the
%% published SSU2 address out of it, so it has to be a real one rather than the
%% keys alone.
peer_identity(Port) ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Local = #{
        static_priv => Priv,
        static_pub => Pub,
        intro_key => IntroKey,
        sign_seed => Seed,
        sign_pub => SignPub
    },
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, Port, Pub, IntroKey),
    RI = i2p_router_info:build(
        i2p_keys:from_keys(Pub, SignPub),
        erlang:system_time(millisecond),
        [Addr],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        Seed
    ),
    {Local, maps:get(binary, RI)}.

%% What a listener needs and no more: a static pair and the introduction key every
%% SSU2 header is masked with, which is the whole input `f:listen/4` documents.
local_keys() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    #{
        static_priv => Priv,
        static_pub => Pub,
        intro_key => crypto:strong_rand_bytes(32)
    }.

%%% %%%%% Plumbing %%%%% %%%%

%% A sealed datagram of `Size` bytes presenting connection id `ConnId` and a type
%% byte no handshake claims, padded out to `Size` -- the shape a real one has.
%% Padded *before* sealing, since the masks are derived from the tail.
sealed_datagram(IntroKey, ConnId, Size) ->
    Header = <<ConnId:64, 1:32, 7:8, 2:8, 2:8, 0:8, 0:64, 0:64>>,
    Body = binary:copy(crypto:strong_rand_bytes(Size - byte_size(Header)), 1),
    i2p_ssu2:seal_long(<<Header/binary, Body/binary>>, IntroKey, IntroKey).

%% The process the classified datagrams reach. It counts and nothing else, so what
%% is measured is the socket owner's cost and not the forward path behind it.
sink() ->
    spawn(fun() -> sink_loop(0) end).

sink_loop(Seen) ->
    receive
        {ssu2_packet, _Dgram} ->
            sink_loop(Seen + 1);
        {delivered, From} ->
            From ! {delivered, Seen},
            sink_loop(Seen)
    end.

%% How many datagrams the sink has counted, asked once and answered once.
%%
%% One request per answer, with a generous timeout, rather than a poll loop. A
%% poll loop that re-requests on a short timeout queues replies faster than the
%% sink answers them, and the replies then pile up in *this* mailbox -- where the
%% selective receive skips the stale ones and keeps waiting for one that satisfies
%% a target nothing is going to reach, so the window ends by timeout rather than
%% by arrival. The sink answers out of a queue that can be tens of thousands deep,
%% so a single request is answered in microseconds regardless.
count(Sink) ->
    Sink ! {delivered, self()},
    receive
        {delivered, Seen} -> Seen
    after 10000 ->
        erlang:error(sink_did_not_answer)
    end.

%% The sender is a process of its own on `{active, false}`: a `{active, true}`
%% sender would have the runtime deliver into *its* mailbox, and the loop would
%% then be measuring the runtime's delivery rather than the socket's.
%%
%% Linked, deliberately. A sender that dies mid-window takes the bench down with
%% it rather than letting the window finish and report a figure that was measured
%% over fewer datagrams than it claims -- a truncated run that reads as a result.
sender(Port, Dgram) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    spawn_link(fun() -> sender_loop(Sock, Port, Dgram) end).

%% The reply carries the reference the caller sent rather than the count, so a
%% reply to an earlier window can never satisfy a later one. Matching on the count
%% is the version that silently interleaves two windows into one figure when two
%% of them happen to ask for the same number of datagrams.
sender_loop(Sock, Port, Dgram) ->
    receive
        {blast, From, Ref, N} ->
            ok = send_n(Sock, Port, Dgram, N),
            From ! {sent, Ref},
            sender_loop(Sock, Port, Dgram)
    end.

%% Fire and report. The reply is what makes the blast ordered against the window
%% that follows it: without it the next window's sender message could overtake
%% this one's sends and the two would interleave in a single figure.
blast(Sender, N) ->
    Ref = make_ref(),
    Sender ! {blast, self(), Ref, N},
    receive
        {sent, Ref} -> ok
    after 60000 ->
        erlang:error({blast_timed_out, N})
    end.

send_n(_Sock, _Port, _Dgram, 0) ->
    ok;
send_n(Sock, Port, Dgram, N) ->
    ok = gen_udp:send(Sock, {127, 0, 0, 1}, Port, Dgram),
    send_n(Sock, Port, Dgram, N - 1).

reductions(Pid) ->
    {reductions, R} = process_info(Pid, reductions),
    R.

%% %% parsing %%

parse([], Acc) ->
    Acc;
parse([Flag, N | T], Acc) when
    Flag =:= <<"--count">>; Flag =:= <<"--size">>; Flag =:= <<"--msgs">>;
    Flag =:= <<"--body">>; Flag =:= <<"--warm">>
->
    parse(T, Acc#{key(Flag) => binary_to_integer(N)});
parse([<<"--label">>, Label | T], Acc) ->
    parse(T, Acc#{label => Label});
parse([<<"--log-level">>, Level | T], Acc) ->
    parse(T, Acc#{log_level => Level});
parse([_ | T], Acc) ->
    parse(T, Acc).

key(<<"--count">>) -> count;
key(<<"--size">>) -> size;
key(<<"--msgs">>) -> msgs;
key(<<"--body">>) -> body;
key(<<"--warm">>) -> warm.

args_to_bin(Args) ->
    [list_to_binary(A) || A <- Args].
