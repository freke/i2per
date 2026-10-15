%% SSU2 introducer relay tests. The suite covers relay-tag issuance, rejection
%% of an unknown tag, and the complete 15/16 plus 7/8/9 introducer flow. The
%% code under test is `m:i2p_relay_coord`, the listener-owned tag registry,
%% and relay-block plumbing in `m:i2p_ssu2_conn`.
%%
%% Each case owns its process, app lifecycle, and registry rows. Every wait
%% drains non-matching mail through `m:i2p_ct_helpers:wait_msg/2`. Relay
%% blocks are ack-eliciting and use the same bounded receive windows as the
%% peer-test suite.

-module(i2p_ssu2_relay_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    relay_tag_request_handshake/1,
    relay_request_unknown_tag_rejected/1,
    indirect_dial_through_introducer/1,
    indirect_dial_requester_leg_completes/1,
    charlie_accepts_a_verified_intro/1,
    charlie_rejects_an_unverifiable_intro/1,
    charlie_rejects_a_non_punchable_endpoint/1,
    charlie_punch_budget_bounds_the_replays/1
]).

-define(APP, i2per).
-define(DATA_WINDOW, 25000).
-define(RELAY_WINDOW, 30000).

%% The session token Charlie grants in an accept, which Alice presents in the
%% redirect's SessionRequest. Any nonzero value will do; it is fixed so a
%% failure reads the same every run.
-define(TEST_TOKEN, 16#0BADF00DCAFEFEED).

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        relay_tag_request_handshake,
        relay_request_unknown_tag_rejected,
        indirect_dial_through_introducer,
        indirect_dial_requester_leg_completes,
        charlie_accepts_a_verified_intro,
        charlie_rejects_an_unverifiable_intro,
        charlie_rejects_a_non_punchable_endpoint,
        charlie_punch_budget_bounds_the_replays
    ].

%% ---------------------------------------------------------------------------
%% Per-case lifecycle: the full app is started so the SSU2 session/listener
%% tree and the relay-tag registry come up, and stopped at the end so neither
%% a session nor a registry row leaks into the next testcase.
%% ---------------------------------------------------------------------------

init_per_testcase(Case, Config) ->
    i2p_ct_helpers:start_ssu2_trace(),
    start_app(
        Config,
        case Case of
            indirect_dial_through_introducer -> 40000;
            indirect_dial_requester_leg_completes -> 40000;
            _ -> 30000
        end
    ).

start_app(Config, Timetrap) ->
    {ok, _} = application:ensure_all_started(?APP),
    [{timetrap, Timetrap} | Config].

end_per_testcase(_Case, _Config) ->
    application:stop(?APP),
    i2p_ct_helpers:stop_ssu2_trace(),
    ok.

%% ---------------------------------------------------------------------------
%% Relay-tag handshake (blocks 15/16)
%% ---------------------------------------------------------------------------

%% Bob answers an in-session relay-tag request with a fresh nonzero tag (block
%% 16) and records it against the requesting session — the Bob-side session,
%% not the peer's own dial — in the listener-owned registry, with a future
%% expiry. The same tag then authorizes relay requests for that session.
relay_tag_request_handshake(_Config) ->
    {BobLocal, _} = bob_local(),
    {ok, Coord} = i2p_relay_coord:start_link(BobLocal),
    try
        {PeerPid, _Listener, _PeerLocal} = dial_peer(Coord, BobLocal),
        Tag = request_tag(PeerPid),
        true = Tag > 0,

        TaggedSess = i2p_relay_coord:tagged_sess(Coord),
        [{Tag, RegPid, Expires}] = ets:lookup(i2p_ssu2_relay_tags, Tag),
        %% The registry maps the tag to the Bob-side session that holds it…
        true = RegPid =:= TaggedSess,
        true = is_process_alive(RegPid),
        true = RegPid =/= PeerPid,
        %% …with a usable lifetime.
        true = Expires > erlang:system_time(second)
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% ---------------------------------------------------------------------------
%% Rejected relay requests
%% ---------------------------------------------------------------------------

%% A RelayRequest (block 7) targeting a tag no session holds is answered with
%% Bob's "relay tag not found" reject (code 5) — signed by Bob, csz 0, echoing
%% the request nonce — and nothing is served (the registry stays empty).
relay_request_unknown_tag_rejected(_Config) ->
    {BobLocal, _} = bob_local(),
    BobHash = maps:get(hash, BobLocal),
    BobSignPub = maps:get(sign_pub, BobLocal),
    {ok, Coord} = i2p_relay_coord:start_link(BobLocal),
    try
        {ReqPid, ReqListener, ReqLocal} = dial_peer(Coord, BobLocal),
        ReqPort = i2p_ssu2_listener:port(ReqListener),
        ReqIp = <<127, 0, 0, 1>>,
        UnknownTag = 16#0BADC0DE,
        %% Any well-formed request context works here; Bob refuses the tag
        %% before a target hash matters.
        UnknownTarget = crypto:strong_rand_bytes(32),
        Nonce = 16#DEADBEEF,
        Ts = erlang:system_time(second),
        ReqSig = i2p_relay:sign_request(
            BobHash,
            UnknownTarget,
            2,
            Nonce,
            UnknownTag,
            Ts,
            ReqPort,
            ReqIp,
            maps:get(sign_seed, ReqLocal)
        ),
        ok = i2p_ssu2_conn:send_relay(
            ReqPid, i2p_relay:request_block(2, Nonce, UnknownTag, Ts, ReqPort, ReqIp, ReqSig)
        ),

        ok = i2p_ct_helpers:wait_msg(
            fun
                ({ssu2_data, P, Blocks}) when P =:= ReqPid ->
                    case lists:keyfind(relay_response, 1, Blocks) of
                        {relay_response, 0, 5, Nonce, RejTs, 2, 0, <<>>, BobSig, undefined} ->
                            true =
                                i2p_relay:verify_response(
                                    BobHash, 2, Nonce, RejTs, 0, <<>>, BobSig, BobSignPub
                                ),
                            {true, ok};
                        Other ->
                            erlang:error({unexpected_reject, Other})
                    end;
                (_) ->
                    false
            end,
            ?DATA_WINDOW
        ),

        [] = ets:tab2list(i2p_ssu2_relay_tags)
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% ---------------------------------------------------------------------------
%% Indirect dial through the introducer (blocks 15/16 + 7/8/9)
%% ---------------------------------------------------------------------------

%% The end-to-end loopback: the tagged peer (T) earns a tag from Bob; the
%% requester (A) dials Bob, sends a signed RelayRequest, and T — reached only
%% through the introducer — verifies A's signature against the RouterInfo Bob
%% forwarded, replies with a signed accept in block 8, and A then dials T
%% directly. The direct session succeeding is the acceptance proof: no route
%% from A to T existed before the introducer relayed.
indirect_dial_through_introducer(_Config) ->
    {BobLocal, _} = bob_local(),
    BobHash = maps:get(hash, BobLocal),
    {ok, Coord} = i2p_relay_coord:start_link(BobLocal),
    try
        %% -- Tagged peer (T): dials Bob and requests a relay tag.
        {TPid, TListener, TLocal} = dial_peer(Coord, BobLocal),
        Tag = request_tag(TPid),
        true = Tag > 0,
        TRI = maps:get(ri, TLocal),
        THash = i2p_router_info:hash(TRI),
        TPort = i2p_ssu2_listener:port(TListener),
        TIp = <<127, 0, 0, 1>>,

        %% -- Requester (A): dials Bob too. She knows T's RouterInfo only via
        %% the harness's netDb stand-in (the RI map); there is no direct route.
        {APid, AListener, ALocal} = dial_peer(Coord, BobLocal),
        ARIBlock = maps:get(ri_binary, ALocal),
        AHash = i2p_router_info:hash(maps:get(ri, ALocal)),
        ASignPub = maps:get(sign_pub, ALocal),
        ASeed = maps:get(sign_seed, ALocal),
        AIPort = i2p_ssu2_listener:port(AListener),
        AIp = <<127, 0, 0, 1>>,

        Nonce = 16#CAFEBABE,
        Ts = erlang:system_time(second),
        ReqSig = i2p_relay:sign_request(BobHash, THash, 2, Nonce, Tag, Ts, AIPort, AIp, ASeed),
        ok = i2p_ssu2_conn:send_relay(
            APid, i2p_relay:request_block(2, Nonce, Tag, Ts, AIPort, AIp, ReqSig)
        ),

        %% -- T receives A's RouterInfo (forwarded by Bob, no in-session
        %% RouterInfo block was needed) and the RelayIntro, and verifies A's
        %% signature chain end-to-end against her published signing key.
        ok = wait_request_relayed(
            TPid, AHash, ASignPub, BobHash, THash, Nonce, Tag, Ts, false, false
        ),

        %% -- T accepts: a signed block 8 carrying T's reachable endpoint.
        RespTs = erlang:system_time(second),
        RespSig = i2p_relay:sign_response(
            BobHash, 2, Nonce, RespTs, TPort, TIp, maps:get(sign_seed, TLocal)
        ),
        ok = i2p_ssu2_conn:send_relay(
            TPid, i2p_relay:response_block(0, 2, Nonce, RespTs, TPort, TIp, RespSig, undefined)
        ),

        %% -- A receives the relayed block 8 and validates T's signature; the
        %% endpoint it carries matches T's advertised SSU2 address.
        {ok, TOpts} = i2p_router_info:ssu2_address_options(TRI),
        true = maps:get(port, TOpts) =:= TPort,
        ok = wait_relay_response(APid, BobHash, Nonce, maps:get(sign_pub, TLocal), TPort, TIp),

        %% -- The indirect dial: A dials T at her advertised address. No
        %% session between A and T had ever existed up to now.
        {ok, DirectPid, _Keys} = i2p_ssu2_conn:connect(ALocal, TOpts, ARIBlock, AListener),
        unlink(DirectPid)
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% The requester leg itself, through `f:connect_via_introducer/5` rather than
%% by hand. The case above proves the relay blocks are correct; this one proves
%% the **caller** wires them together -- `f:begin_relay/1`, the
%% `requester_relay_response/2` accept branch, `spawn_redirect/4` and
%% `await_ssu2_redirect/2` -- which #98GAVQK found had no coverage at all.
%%
%% Two things are pinned that the blocks-only case cannot reach:
%%
%% * **Charlie's accept must grant a token.** `requester_relay_response/2`
%%   accepts only `is_integer(Token)`, so an accept with no token falls to the
%%   reject branch and the dial fails with `{relay_rejected, 0}` -- an accept
%%   reported as a rejection. `i2p_relay_coord:accept_intro/7` sends
%%   `undefined`, so this is the case that caught it; see the comment on
%%   `charlie_accept_carries_a_granted_token/1`.
%% * **The redirect reaches establishment**, which is only possible if the
%%   requester leg kept `ri_block` for the session `spawn_redirect/4` copies it
%%   into. Clear it and the redirect's own `maybe_created/2` has no RouterInfo
%%   block to send, and this case fails at the handshake.
indirect_dial_requester_leg_completes(_Config) ->
    {BobLocal, _} = bob_local(),
    BobHash = maps:get(hash, BobLocal),
    {ok, Coord} = i2p_relay_coord:start_link(BobLocal),
    try
        %% -- Charlie (T): dials Bob, earns a tag, and publishes the address
        %%    the redirect will actually dial. Unlike the blocks-only case the
        %%    endpoint has to be dialable, so it is her real listener port.
        {TPid, _TListener, TLocal} = dial_peer(Coord, BobLocal),
        Tag = request_tag(TPid),
        true = Tag > 0,
        TRI = maps:get(ri, TLocal),
        THash = i2p_router_info:hash(TRI),
        TPort = published_port(TLocal),
        TIp = <<127, 0, 0, 1>>,

        %% -- Alice (A): her own listener, and the relay material naming Bob,
        %%    Charlie and the tag. This is the map `f:i2p_peer` assembles.
        {AListener, AIPort, ALocal} = listen_full_local(<<"127.0.0.1">>),
        ARIBlock = maps:get(ri_binary, ALocal),
        AHash = i2p_router_info:hash(maps:get(ri, ALocal)),
        ASignPub = maps:get(sign_pub, ALocal),
        Relay = #{
            bob_hash => BobHash,
            charlie_hash => THash,
            charlie_ri => TRI,
            tag => Tag,
            our_port => AIPort,
            our_ip => <<127, 0, 0, 1>>,
            sign_seed => maps:get(sign_seed, ALocal)
        },
        BobOpts = #{
            host => <<"127.0.0.1">>,
            port => i2p_relay_coord:port(Coord),
            static_key => maps:get(static_pub, BobLocal),
            intro_key => maps:get(intro_key, BobLocal)
        },

        %% -- The dial under test. It blocks until the redirect establishes or
        %%    the leg dies, so it runs in its own process and the case plays
        %%    Charlie in the meantime.
        Dialer = spawn_dialer(ALocal, BobOpts, ARIBlock, AListener, Relay),

        %% -- Charlie verifies the forwarded intro and accepts, granting a
        %%    token the redirect will present. The nonce is Alice's, so it is
        %%    read off the intro rather than chosen.
        {Nonce, _Ts} = wait_intro_relayed(TPid, AHash, ASignPub, BobHash, THash, Tag),
        ok = accept_intro(TPid, BobHash, Nonce, TPort, TIp, TLocal, ?TEST_TOKEN),

        %% -- The whole point: the requester leg completes. A live CharliePid
        %%    is an established session, which is what proves `ri_block`
        %%    survived establishment in the config `spawn_redirect/4` copied.
        {ok, BobPid, CharliePid, Keys} = await_dialer(Dialer),
        true = is_pid(BobPid),
        true = is_pid(CharliePid),
        true = CharliePid =/= BobPid,
        true = is_process_alive(CharliePid),
        true = is_map(Keys),
        true = lists:all(fun(K) -> maps:is_key(K, Keys) end, [k_ab, kh2_ab, k_ba, kh2_ba]),

        %% The redirect reuses the introducer leg's connection IDs, so it is
        %% a different session on the wire even though it shares an ID pair.
        unlink(CharliePid),
        unlink(BobPid)
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% ---------------------------------------------------------------------------
%% The Charlie role (blocks 9/8, out-of-session punch)
%% ---------------------------------------------------------------------------

%% The tagged session is not passive: whoever holds a tag is selected as a
%% Charlie, so a RelayIntro on the tagged session is this router being asked to
%% play Charlie. The coordinator here holds Charlie's keys, and the introducer
%% dials it — so the tagged session's own handshake RouterInfo is the
%% introducer's, which is the `bhash` Alice signed against, and this router's
%% own hash is the `chash`. A verified intro earns a signed accept on the wire:
%% code 0, Charlie's own published endpoint, and a signature Alice checks
%% against the RouterInfo she was configured with.
%%
%% **The punch is not observable here, and that is the honest limit of a
%% hermetic test.** Alice asserts a documentation-range address, which the
%% endpoint policy treats as public, so the accept is earned — but the punch
%% datagram is then sent to an address nothing listens on, and a test cannot
%% watch a socket it does not own. What is pinned is the accept on the wire and
%% the payload's shape, the latter in `m:i2p_relay_tests`, where the punch round
%% trips through the decoder under Alice's introduction key.
charlie_accepts_a_verified_intro(_Config) ->
    {CharlieLocal, _} = bob_local(),
    CharlieHash = maps:get(hash, CharlieLocal),
    {ok, Coord} = i2p_relay_coord:start_link(CharlieLocal),
    try
        %% -- The introducer (Bob) dials the coordinator and requests a tag: a
        %%    tag request is what makes a session the tagged one, and the tag
        %%    is the precondition for being selected as a Charlie at all.
        {BobPid, _Listener, BobLocal} = dial_peer(Coord, CharlieLocal),
        Tag = request_tag(BobPid),
        true = Tag > 0,
        BobHash = i2p_router_info:hash(maps:get(ri, BobLocal)),

        %% -- Alice's RouterInfo and the RelayIntro, as the introducer forwards
        %%    them: her RI ahead of the intro, in the same Data message. She
        %%    signs against the introducer's hash and this router's.
        {_AliceListener, _APort, AliceLocal} = listen_full_local(<<"127.0.0.1">>),
        AliceRIBin = maps:get(ri_binary, AliceLocal),
        ASignPub = maps:get(sign_pub, AliceLocal),
        ASeed = maps:get(sign_seed, AliceLocal),
        AHash = i2p_router_info:hash(maps:get(ri, AliceLocal)),
        Nonce = 16#CAFEBABE,
        Ts = erlang:system_time(second),
        %% A documentation-range endpoint: public per the address policy, so
        %% the accept is earned and the punch is attempted at an address
        %% nothing here owns.
        Sig = i2p_relay:sign_request(
            BobHash, CharlieHash, 2, Nonce, Tag, Ts, 49657, <<192, 0, 2, 7>>, ASeed
        ),
        ok = i2p_ssu2_conn:send_router_info(BobPid, 0, AliceRIBin),
        ok = i2p_ssu2_conn:send_relay(
            BobPid,
            i2p_relay:intro_block(
                2, AHash, Nonce, Tag, Ts, 49657, <<192, 0, 2, 7>>, Sig
            )
        ),

        %% -- Charlie's accept: code 0, his own published endpoint, signed with
        %%    his router signing key. Alice's signature verified, which is the
        %%    whole point — an unverified intro is refused, not accepted. The
        %%    endpoint is the published one, which is what Alice dials and not
        %%    the port the listener happened to bind.
        CPort = published_port(CharlieLocal),
        ok = wait_charlie_response(
            BobPid, BobHash, Nonce, 0, ASignPub, CharlieLocal, CPort
        )
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% The punch budget is the bound on the send, not on the accept: `?PUNCH_BURST`
%% punches and then Charlie-side code 66. A tag-holder who replays one intro
%% gets the burst and then nothing, which is what stops this router becoming an
%% amplifier aimed wherever the tag-holder likes.
charlie_punch_budget_bounds_the_replays(_Config) ->
    {CharlieLocal, _} = bob_local(),
    CharlieHash = maps:get(hash, CharlieLocal),
    {ok, Coord} = i2p_relay_coord:start_link(CharlieLocal),
    try
        {BobPid, _Listener, BobLocal} = dial_peer(Coord, CharlieLocal),
        Tag = request_tag(BobPid),
        true = Tag > 0,
        BobHash = i2p_router_info:hash(maps:get(ri, BobLocal)),

        {_AliceListener, _APort, AliceLocal} = listen_full_local(<<"127.0.0.1">>),
        AliceRIBin = maps:get(ri_binary, AliceLocal),
        AHash = i2p_router_info:hash(maps:get(ri, AliceLocal)),
        ASignPub = maps:get(sign_pub, AliceLocal),
        ASeed = maps:get(sign_seed, AliceLocal),
        CPort = published_port(CharlieLocal),

        %% Five verified intros asserting the same public endpoint. The first
        %% four spend the burst; the fifth is denied with code 66.
        Nonces = [16#CAFE0001, 16#CAFE0002, 16#CAFE0003, 16#CAFE0004, 16#CAFE0005],
        lists:foreach(
            fun(Nonce) ->
                Ts = erlang:system_time(second),
                Sig = i2p_relay:sign_request(
                    BobHash, CharlieHash, 2, Nonce, Tag, Ts, 49657, <<192, 0, 2, 7>>, ASeed
                ),
                ok = i2p_ssu2_conn:send_router_info(BobPid, 0, AliceRIBin),
                ok = i2p_ssu2_conn:send_relay(
                    BobPid,
                    i2p_relay:intro_block(2, AHash, Nonce, Tag, Ts, 49657, <<192, 0, 2, 7>>, Sig)
                )
            end,
            Nonces
        ),
        Codes = wait_charlie_codes(BobPid, BobHash, Nonces, ASignPub, CharlieLocal, CPort),
        [0, 0, 0, 0, 66] = Codes
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% A RelayIntro whose signature does not verify is refused, not accepted: code
%% 67 is Charlie's "signature failure", signed by Charlie with no endpoint, and
%% no punch is attempted. This is the edge that makes the coordinator safe to
%% run — without it, any peer holding a tag could make this router emit a
%% datagram at a third party on the strength of an unverified claim.
charlie_rejects_an_unverifiable_intro(_Config) ->
    {CharlieLocal, _} = bob_local(),
    CharlieHash = maps:get(hash, CharlieLocal),
    {ok, Coord} = i2p_relay_coord:start_link(CharlieLocal),
    try
        {BobPid, _Listener, BobLocal} = dial_peer(Coord, CharlieLocal),
        Tag = request_tag(BobPid),
        true = Tag > 0,
        BobHash = i2p_router_info:hash(maps:get(ri, BobLocal)),

        {_AliceListener, _APort, AliceLocal} = listen_full_local(<<"127.0.0.1">>),
        AliceRIBin = maps:get(ri_binary, AliceLocal),
        AHash = i2p_router_info:hash(maps:get(ri, AliceLocal)),
        ASeed = maps:get(sign_seed, AliceLocal),
        Nonce = 16#DEADBEEF,
        Ts = erlang:system_time(second),
        %% Signed against the wrong pair: the bhash is a router that is neither
        %% the introducer nor this one, so the verification cannot succeed.
        WrongPair = crypto:strong_rand_bytes(32),
        Sig = i2p_relay:sign_request(
            WrongPair, CharlieHash, 2, Nonce, Tag, Ts, 49657, <<192, 0, 2, 7>>, ASeed
        ),
        ok = i2p_ssu2_conn:send_router_info(BobPid, 0, AliceRIBin),
        ok = i2p_ssu2_conn:send_relay(
            BobPid, i2p_relay:intro_block(2, AHash, Nonce, Tag, Ts, 49657, <<192, 0, 2, 7>>, Sig)
        ),

        ok = wait_charlie_response(
            BobPid, BobHash, Nonce, 67, maps:get(sign_pub, AliceLocal), CharlieLocal, 0
        )
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% A verified intro asserting an endpoint this router will not punch at is
%% refused with code 65 ("unsupported address") and no punch. Loopback is the
%% case a local test bed produces and the one the hardening exists to refuse:
%% an endpoint on somebody's internal network is not one a public i2per sends
%% datagrams at.
charlie_rejects_a_non_punchable_endpoint(_Config) ->
    {CharlieLocal, _} = bob_local(),
    CharlieHash = maps:get(hash, CharlieLocal),
    {ok, Coord} = i2p_relay_coord:start_link(CharlieLocal),
    try
        {BobPid, _Listener, BobLocal} = dial_peer(Coord, CharlieLocal),
        Tag = request_tag(BobPid),
        true = Tag > 0,
        BobHash = i2p_router_info:hash(maps:get(ri, BobLocal)),

        {_AliceListener, _APort, AliceLocal} = listen_full_local(<<"127.0.0.1">>),
        AliceRIBin = maps:get(ri_binary, AliceLocal),
        AHash = i2p_router_info:hash(maps:get(ri, AliceLocal)),
        ASignPub = maps:get(sign_pub, AliceLocal),
        ASeed = maps:get(sign_seed, AliceLocal),
        Nonce = 16#0BADF00D,
        Ts = erlang:system_time(second),
        Sig = i2p_relay:sign_request(
            BobHash, CharlieHash, 2, Nonce, Tag, Ts, 49657, <<127, 0, 0, 1>>, ASeed
        ),
        ok = i2p_ssu2_conn:send_router_info(BobPid, 0, AliceRIBin),
        ok = i2p_ssu2_conn:send_relay(
            BobPid, i2p_relay:intro_block(2, AHash, Nonce, Tag, Ts, 49657, <<127, 0, 0, 1>>, Sig)
        ),

        ok = wait_charlie_response(
            BobPid, BobHash, Nonce, 65, ASignPub, CharlieLocal, 0
        )
    after
        catch i2p_relay_coord:stop(Coord)
    end.

%% The published SSU2 port of a fixture router's RouterInfo — the endpoint
%% Charlie's accept carries, which is what Alice dials and not the port the
%% listener happened to bind.
published_port(Local) ->
    {ok, #{port := Port}} = i2p_router_info:ssu2_address_options(maps:get(ri, Local)),
    Port.

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

%% Run the indirect dial in its own process: `f:connect_via_introducer/5` blocks
%% until the redirect establishes or the leg dies, and the case has to be free
%% to play Charlie while it waits. Unlinked, so a failing dial does not take the
%% case with it -- the result arrives as a message either way.
spawn_dialer(LocalKeys, BobOpts, RIBlock, Listener, Relay) ->
    Parent = self(),
    spawn(fun() ->
        Parent !
            {indirect_dial_result,
                i2p_ssu2_conn:connect_via_introducer(
                    LocalKeys, BobOpts, RIBlock, Listener, Relay
                )}
    end).

await_dialer(Dialer) ->
    Ref = monitor(process, Dialer),
    receive
        {indirect_dial_result, Result} ->
            erlang:demonitor(Ref, [flush]),
            Result;
        {'DOWN', Ref, process, Dialer, Reason} ->
            erlang:error({dialer_died, Reason})
    after ?RELAY_WINDOW ->
        erlang:error(dialer_timeout)
    end.

%% The two legs Charlie receives, and the RelayIntro's own nonce and timestamp
%% so the accept can echo them. Alice chooses the nonce inside
%% `f:begin_relay/1`, so it cannot be supplied from outside; it is read off the
%% intro and verified as part of her request signature, which is what ties the
%% accept to the request it answers.
wait_intro_relayed(TPid, AHash, ASignPub, BobHash, THash, Tag) ->
    Deadline = erlang:monotonic_time(millisecond) + ?RELAY_WINDOW,
    wait_intro_relayed(TPid, AHash, ASignPub, BobHash, THash, Tag, false, undefined, Deadline).

%% Both legs, not either: the RouterInfo and the intro arrive as separate Data
%% messages in either order, so returning on the RI alone would hand back
%% `undefined` and read as a missing intro on a wire that is merely one message
%% behind.
wait_intro_relayed(_TPid, _AHash, _ASignPub, _BobHash, _THash, _Tag, true, Found, _Deadline) when
    Found =/= undefined
->
    Found;
wait_intro_relayed(TPid, AHash, ASignPub, BobHash, THash, Tag, SeenRI, Found, Deadline) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            erlang:error({no_relay_intro_forwarded, SeenRI});
        false ->
            receive
                {ssu2_data, TPid, Blocks} ->
                    SeenRI1 = SeenRI orelse has_requester_ri(Blocks, AHash, ASignPub),
                    Found1 = found_intro(Blocks, BobHash, THash, Tag, ASignPub, Found),
                    wait_intro_relayed(
                        TPid, AHash, ASignPub, BobHash, THash, Tag, SeenRI1, Found1, Deadline
                    );
                _ ->
                    wait_intro_relayed(
                        TPid, AHash, ASignPub, BobHash, THash, Tag, SeenRI, Found, Deadline
                    )
            after erlang:max(0, Deadline - erlang:monotonic_time(millisecond)) ->
                erlang:error({no_relay_intro_forwarded, SeenRI})
            end
    end.

%% The intro's nonce/timestamp once it has arrived, having verified Alice's
%% signature over them against the key her forwarded RouterInfo publishes.
found_intro(Blocks, BobHash, THash, Tag, ASignPub, undefined) ->
    case lists:keyfind(relay_intro, 1, Blocks) of
        {relay_intro, 0, _AHash, Nonce, Tag, Ts, 2, Port, Ip, Sig} ->
            true = i2p_relay:verify_request(
                BobHash, THash, 2, Nonce, Tag, Ts, Port, Ip, Sig, ASignPub
            ),
            {Nonce, Ts};
        _ ->
            undefined
    end;
found_intro(_Blocks, _BobHash, _THash, _Tag, _ASignPub, Found) ->
    Found.

%% Charlie's accept: her own published endpoint, her own signing key, and a
%% granted token. The token is what the requester dials with, and its absence
%% is what made an accept read as a rejection -- see the case comment.
accept_intro(TPid, BobHash, Nonce, TPort, TIp, TLocal, Token) ->
    Ts = erlang:system_time(second),
    Sig = i2p_relay:sign_response(BobHash, 2, Nonce, Ts, TPort, TIp, maps:get(sign_seed, TLocal)),
    i2p_ssu2_conn:send_relay(
        TPid, i2p_relay:response_block(0, 2, Nonce, Ts, TPort, TIp, Sig, Token)
    ).

dial_peer(Coord, BobLocal) ->
    {PeerListener, _PeerPort, PeerLocal} = listen_full_local(<<"127.0.0.1">>),
    PeerRIBlock = maps:get(ri_binary, PeerLocal),
    BobPort = i2p_relay_coord:port(Coord),
    RemoteOpts =
        #{
            host => <<"127.0.0.1">>,
            port => BobPort,
            static_key => maps:get(static_pub, BobLocal),
            intro_key => maps:get(intro_key, BobLocal)
        },
    {ok, PeerPid, _Keys} = i2p_ssu2_conn:connect(PeerLocal, RemoteOpts, PeerRIBlock, PeerListener),
    unlink(PeerPid),
    {PeerPid, PeerListener, PeerLocal}.

%% Ask the introducer for a relay tag (block 15) and await the RelayTag reply
%% (block 16).
request_tag(PeerPid) ->
    ok = i2p_ssu2_conn:send_relay(PeerPid, relay_tag_request),
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= PeerPid ->
                case lists:keyfind(relay_tag, 1, Blocks) of
                    {relay_tag, Tag} -> {true, Tag};
                    false -> false
                end;
            (_) ->
                false
        end,
        ?DATA_WINDOW
    ).

%% Accumulate the two legs T must receive from the introducer — A's
%% forwarded RouterInfo and the RelayIntro (block 9) — which land as separate
%% Data messages in either order. The intro leg also verifies A's request
%% signature against the key her RouterInfo publishes, closing the
%% sign/forward/verify circle.
wait_request_relayed(TPid, AHash, ASignPub, BobHash, THash, Nonce, Tag, Ts, SeenRI, SeenIntro) ->
    Deadline = erlang:monotonic_time(millisecond) + ?RELAY_WINDOW,
    wait_request_relayed(
        TPid, AHash, ASignPub, BobHash, THash, Nonce, Tag, Ts, SeenRI, SeenIntro, Deadline
    ).

wait_request_relayed(_TPid, _AH, _ASP, _BH, _TH, _Nonce, _Tag, _Ts, true, true, _Deadline) ->
    ok;
wait_request_relayed(
    TPid, AHash, ASignPub, BobHash, THash, Nonce, Tag, Ts, SeenRI, SeenIntro, Deadline
) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            erlang:error({no_relay_request_forwarded, SeenRI, SeenIntro});
        false ->
            receive
                {ssu2_data, TPid, Blocks} ->
                    SeenRI1 = SeenRI orelse has_requester_ri(Blocks, AHash, ASignPub),
                    SeenIntro1 =
                        SeenIntro orelse
                            has_relay_intro(
                                Blocks, BobHash, THash, Nonce, Tag, Ts, ASignPub
                            ),
                    wait_request_relayed(
                        TPid,
                        AHash,
                        ASignPub,
                        BobHash,
                        THash,
                        Nonce,
                        Tag,
                        Ts,
                        SeenRI1,
                        SeenIntro1,
                        Deadline
                    );
                _ ->
                    wait_request_relayed(
                        TPid,
                        AHash,
                        ASignPub,
                        BobHash,
                        THash,
                        Nonce,
                        Tag,
                        Ts,
                        SeenRI,
                        SeenIntro,
                        Deadline
                    )
            after erlang:max(0, Deadline - erlang:monotonic_time(millisecond)) ->
                erlang:error({no_relay_request_forwarded, SeenRI, SeenIntro})
            end
    end.

%% A RelayResponse grants a session token on accept (code 0) and on no other
%% code. The codec only admits a token on an accept, so the reject side is
%% `undefined` by construction -- but it is asserted here rather than assumed,
%% because the two together are the contract `requester_relay_response/2` acts on.
granted_token(0, Token) ->
    is_integer(Token) andalso Token > 0;
granted_token(Code, undefined) when Code =/= 0 ->
    true.

%% The forwarded RouterInfo is A's own: same hash, same published signing key.
has_requester_ri(Blocks, AHash, ASignPub) ->
    case lists:keyfind(router_info, 1, Blocks) of
        {router_info, 0, RIData} ->
            {ok, RI} = i2p_router_info:decode(RIData),
            AHash = i2p_router_info:hash(RI),
            ASignPub = i2p_keys:signing_key(i2p_router_info:identity(RI)),
            true;
        _ ->
            false
    end.

%% The RelayIntro echoes the request (same nonce/tag/timestamp/endpoint) and
%% carries A's request signature, which verifies against A's signing key.
has_relay_intro(Blocks, BobHash, THash, Nonce, Tag, Ts, ASignPub) ->
    case lists:keyfind(relay_intro, 1, Blocks) of
        {relay_intro, 0, _AHash, Nonce, Tag, Ts, 2, Port, Ip, Sig} ->
            true = i2p_relay:verify_request(
                BobHash, THash, 2, Nonce, Tag, Ts, Port, Ip, Sig, ASignPub
            ),
            true;
        _ ->
            false
    end.

%% Charlie's RelayResponse (block 8) as the tagged session answers it: signed by
%% Charlie's own router signing key, code as given, and `csz 0` on a reject.
%% `ExpectPort` is Charlie's own published endpoint on an accept and `0` on a
%% reject, where no endpoint follows.
%%
%% **The token is asserted, not pattern-matched away.** An accept must carry a
%% nonzero granted token and a reject must carry none -- `f:requester_relay_response/2`
%% accepts only `is_integer(Token)`, so a tokenless accept reads downstream as
%% `{relay_rejected, 0}`. Matching `undefined` here as "whatever this is" is what
%% let the coordinator ship an accept no requester could act on; #98GAVQK found
%% it. Pinned in both directions so it cannot regress to either shape.
wait_charlie_response(Pid, CharlieHash, Nonce, Code, ASignPub, CharlieLocal, ExpectPort) ->
    CSignPub = maps:get(sign_pub, CharlieLocal),
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= Pid ->
                case lists:keyfind(relay_response, 1, Blocks) of
                    {relay_response, 0, Code, Nonce, Ts, 2, ExpectPort, CIp, Sig, Token} ->
                        true = i2p_relay:verify_response(
                            CharlieHash, 2, Nonce, Ts, ExpectPort, CIp, Sig, CSignPub
                        ),
                        true = is_binary(ASignPub),
                        true = granted_token(Code, Token),
                        {true, ok};
                    Other ->
                        erlang:error({unexpected_charlie_response, Code, Other})
                end;
            (_) ->
                false
        end,
        ?DATA_WINDOW
    ).

%% The codes of several RelayResponses, one per nonce, in the order they arrive.
%% Each signature is verified against the endpoint the response itself carries,
%% because an accept names Charlie's endpoint and a reject names none — the two
%% are different covered byte strings, and verifying both against one shape
%% would fail the accept.
wait_charlie_codes(Pid, CharlieHash, Nonces, ASignPub, CharlieLocal, _ExpectPort) ->
    CSignPub = maps:get(sign_pub, CharlieLocal),
    Codes = wait_codes(Pid, Nonces, []),
    lists:foreach(
        fun({Nonce, _Code, Ts, Port, Ip, Sig}) ->
            true = i2p_relay:verify_response(CharlieHash, 2, Nonce, Ts, Port, Ip, Sig, CSignPub),
            true = is_binary(ASignPub)
        end,
        Codes
    ),
    [Code || {_Nonce, Code, _Ts, _Port, _Ip, _Sig} <- Codes].

wait_codes(_Pid, [], Acc) ->
    lists:reverse(Acc);
wait_codes(Pid, Nonces, Acc) ->
    {Nonce, Code, Ts, Port, Ip, Sig} = next_charlie_code(Pid, Nonces),
    wait_codes(Pid, lists:delete(Nonce, Nonces), [{Nonce, Code, Ts, Port, Ip, Sig} | Acc]).

next_charlie_code(Pid, Nonces) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= Pid ->
                case lists:keyfind(relay_response, 1, Blocks) of
                    {relay_response, 0, Code, Nonce, Ts, 2, Port, Ip, Sig, _Token} ->
                        case lists:member(Nonce, Nonces) of
                            true -> {true, {Nonce, Code, Ts, Port, Ip, Sig}};
                            false -> false
                        end;
                    false ->
                        false
                end;
            (_) ->
                false
        end,
        ?DATA_WINDOW
    ).

%% The relayed RelayResponse (block 8): T's accept, carrying T's reachable
%% endpoint and signed by T's key.
wait_relay_response(APid, BobHash, Nonce, TSignPub, TPort, TIp) ->
    i2p_ct_helpers:wait_msg(
        fun
            ({ssu2_data, P, Blocks}) when P =:= APid ->
                case lists:keyfind(relay_response, 1, Blocks) of
                    {relay_response, 0, 0, Nonce, ResTs, 2, TPort, TIp, Sig, undefined} ->
                        true =
                            i2p_relay:verify_response(
                                BobHash, 2, Nonce, ResTs, TPort, TIp, Sig, TSignPub
                            ),
                        {true, ok};
                    Other ->
                        erlang:error({unexpected_relay_response, Other})
                end;
            (_) ->
                false
        end,
        ?DATA_WINDOW
    ).

%% ---------------------------------------------------------------------------
%% Fixtures
%% ---------------------------------------------------------------------------

%% A fresh listener-bound peer: static/signing keys, a RouterInfo whose
%% advertised port equals the listener's real port (needed for the final
%% direct dial), plus the full local map (hash, ri, ri_binary).
listen_full_local(Host) ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Base =
        #{
            static_priv => Priv,
            static_pub => Pub,
            intro_key => IntroKey,
            sign_seed => Seed,
            sign_pub => SignPub
        },
    {ok, Listener} = i2p_ssu2_listener:listen(Host, 0, Base, self()),
    Port = i2p_ssu2_listener:port(Listener),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(Host, Port, Pub, IntroKey),
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        Seed
    ),
    Local =
        Base#{
            hash => i2p_router_info:hash(RI),
            ri => RI,
            ri_binary => maps:get(binary, RI)
        },
    {Listener, Port, Local}.

%% Bob's full local map with hash and RI, as `peer_local` provides in the
%% peer-test suite.
bob_local() ->
    {Pub, Priv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    IntroKey = crypto:strong_rand_bytes(32),
    Identity = i2p_keys:from_keys(Pub, SignPub),
    Addr = i2p_router_info:ssu2_address(<<"127.0.0.1">>, 19152, Pub, IntroKey),
    RI = i2p_router_info:build(
        Identity,
        erlang:system_time(millisecond),
        [Addr],
        #{<<"netId">> => <<"2">>, <<"router.version">> => <<"0.9.74">>},
        Seed
    ),
    Local =
        #{
            static_priv => Priv,
            static_pub => Pub,
            intro_key => IntroKey,
            sign_seed => Seed,
            sign_pub => SignPub,
            hash => i2p_router_info:hash(RI),
            ri => RI
        },
    {Local, maps:get(binary, RI)}.
