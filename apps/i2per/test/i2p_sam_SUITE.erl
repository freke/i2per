%% SAM v3 session protocol and tunnel-backed stream integration tests.
%%
%% Two app-lifecycle variants are covered:
%%
%% * App-managed network cases set `i2p_peer` in the `i2per` application
%%   environment, so the router supervisor starts the peer, tunnel, and SAM
%%   services. Each network case owns a fresh listener bound at port 0. The
%%   session-admission case starts the application without opening a listener.
%% * Manually-managed cases start the SAM and tunnel services directly and use
%%   a mock peer to drive the wire.
%%
%% Length demands are checked through the public `i2p_tunnel_srv:demands/0`
%% query. The suite uses deadline-based waits, and no case relies on a fixed
%% sleep to reach an expected state. Narrow `sys:replace_state/2` fixtures create
%% active tunnel entries when the encrypted build path is outside the case's
%% subject.

-module(i2p_sam_SUITE).

-export([all/0, suite/0]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    sam_hello/1,
    sam_listener_binds_loopback/1,
    a_batch_of_inbound_sessions_is_not_accepted_one_per_second/1,
    sam_session_limit_rejects_new_child/1,
    sam_dest_generate/1,
    session_create_transient/1,
    session_create_explicit_dest/1,
    session_create_length_options/1,
    session_create_length_clamp/1,
    session_create_bad_length/1,
    session_create_without_options/1,
    session_create_publishes_ls/1,
    naming_lookup_not_found/1,
    naming_lookup_found/1,
    stream_loopback/1,
    unknown_command/1,
    stream_forward_bad_port/1,
    client_sessions_enumeration/1,
    sam_sup_wiring/1,
    proxy_loopback/1,
    stream_handshake/1,
    full_duplex/1,
    forward_e2e/1
]).

-include_lib("eunit/include/eunit.hrl").

-define(APP, i2per).

%% Group B cases drive the wire through a mock i2p_peer; their bodies need the
%% longer time budget for the streaming handshake round trips.
-define(GROUP_B, [stream_handshake, full_duplex, forward_e2e]).

%% The accept-path batch and its budget, matching the NTCP2 pair in
%% `i2p_ntcp2_conn_SUITE`. Six against two seconds: the defect's floor is
%% (N-1) seconds, so the bound is under half of what one-per-second admission
%% needs for six -- and not a tolerance that happens to clear the real behaviour.
-define(ACCEPT_BATCH, 6).
-define(ACCEPT_BUDGET_MS, 2000).

suite() ->
    [{timetrap, 120000}].

all() ->
    [
        sam_hello,
        sam_listener_binds_loopback,
        a_batch_of_inbound_sessions_is_not_accepted_one_per_second,
        sam_session_limit_rejects_new_child,
        sam_dest_generate,
        session_create_transient,
        session_create_explicit_dest,
        session_create_length_options,
        session_create_length_clamp,
        session_create_bad_length,
        session_create_without_options,
        session_create_publishes_ls,
        naming_lookup_not_found,
        naming_lookup_found,
        stream_loopback,
        unknown_command,
        stream_forward_bad_port,
        client_sessions_enumeration,
        sam_sup_wiring,
        proxy_loopback,
        stream_handshake,
        full_duplex,
        forward_e2e
    ].

%% Group A: set i2p_peer env before starting the app so i2per_sup brings up the
%% peer/tunnel/SAM managers as its children. Group B: bare app start; the case
%% starts the managers itself.
init_per_testcase(Case, Config) ->
    Router = make_router(),
    Local = local_from(Router),
    case lists:member(Case, ?GROUP_B) of
        false ->
            ok = application:set_env(
                ?APP,
                i2p_peer,
                #{local => Local, seeds => [maps:get(ri, Router)]}
            ),
            {ok, _} = application:ensure_all_started(?APP),
            [{local, Local}, {router, Router} | Config];
        true ->
            {ok, _} = application:ensure_all_started(?APP),
            [{local, Local}, {router, Router} | Config]
    end.

end_per_testcase(Case, _Config) ->
    case lists:member(Case, ?GROUP_B) of
        true ->
            %% Group B started these managers itself and is linked to them;
            %% stop them before the app (they are not app children).
            stop_tunnel_srv_quiet(),
            kill_sam_sup_quiet(),
            fd_unmock();
        false ->
            %% Group A: the managers are app children; application:stop
            %% tears them down in the right order.
            ok
    end,
    ok = application:stop(?APP),
    ok = application:unset_env(?APP, i2p_peer),
    ok.

local_from(Router) ->
    #{
        static_priv => maps:get(static_priv, Router),
        static_pub => maps:get(static_pub, Router),
        hash => maps:get(hash, Router),
        iv => maps:get(iv, Router),
        ri => maps:get(ri, Router)
    }.

stop_tunnel_srv_quiet() ->
    case whereis(i2p_tunnel_srv) of
        undefined ->
            ok;
        Pid ->
            %% stop() is an async cast; wait on the DOWN so a follow-up test
            %% module never meets a half-dead manager.
            Ref = erlang:monitor(process, Pid),
            i2p_tunnel_srv:stop(),
            receive
                {'DOWN', Ref, process, Pid, _} ->
                    ok
            after 5000 ->
                erlang:error({stop_timeout, Pid})
            end
    end.

kill_sam_sup_quiet() ->
    case whereis(i2p_sam_sup) of
        undefined ->
            ok;
        Sup ->
            unregister(i2p_sam_sup),
            exit(Sup, kill)
    end.

%%%%%%% Group A: app-managed SAM over TCP %%%%%%%

sam_listener_binds_loopback(_Config) ->
    Port = i2p_ct_helpers:free_port(),
    {ok, Listener} = i2p_sam_listener:listen(#{port => Port, local => undefined}),
    try
        ?assertEqual({127, 0, 0, 1}, i2p_sam_listener:address(Listener))
    after
        ok = i2p_sam_listener:stop(Listener)
    end.

%% --------------------------------------------------------------------------
%% The accept path
%% --------------------------------------------------------------------------

%% A batch of inbound sessions is accepted as a batch.
%%
%% The defect: the accept loop polled its control messages on a **one-second**
%% receive timeout and only called `f:gen_tcp:accept/2` when that timeout expired,
%% so it took at most one inbound session per second no matter how many were
%% waiting. Six simultaneous connections took 6.06 s to drain, read from the kernel's
%% accept queue -- the rate was exactly the timeout, not a load effect. On NTCP2 that
%% is a peer set that rebuilds one peer per second; on SAM it is the rate a *client*
%% sees, since an application opens a connection per session.
%%
%% The bound is a batch, asserted as one. Six connections are opened at the same
%% instant and all six `HELLO` replies have to arrive inside ?ACCEPT_BUDGET_MS, so a
%% regression that admitted five immediately and the sixth a second later fails on
%% the sixth rather than passing on the five. Against the defect the floor is (N-1)
%% seconds -- the last of N cannot be accepted before the Nth tick -- so with N = 6
%% that is 5 s against a 2 s bound, and the bound is not a tolerance that happens to
%% sit above the real behaviour: it is under half of what the defect needed.
%%
%% **What the batch is made of, and why a raw connect is the right thing here.** Each
%% client connects, sends `HELLO VERSION` and reads the reply. That is a stronger
%% witness than a child count: the reply can only exist if a session was started, the
%% socket was transferred, the session set `{active, once}`, read the line and parsed
%% it. A bare `f:gen_tcp:connect` would prove the kernel completed a handshake, which
%% is not the claim, and a session count on its own would be satisfied by sessions
%% that cannot read. Six clients and six replies is also six *distinct* sessions -- a
%% session owns one socket, so a session that answered two clients does not exist.
%%
%% The session count is read too, and against the number of replies rather than
%% against ?ACCEPT_BATCH alone, so "six clients were answered" and "six sessions
%% exist" are one claim stated twice rather than two claims that can drift.
%%
%% The control-message assertion is the part that is easy to lose while fixing the
%% throttle, so it is here rather than in a case of its own. The asker is a separate
%% process that asks while the batch is in flight, which is the only moment the
%% question means anything: a fix that moved the accept back into the process that
%% answers control messages would leave it blocked. It cannot pass slowly --
%% `f:i2p_sam_listener:port/1` has no bound of its own, so the case's deadline is the
%% bound, and a control path stuck behind the accept surfaces here as a wrong answer
%% rather than as a hang. See #YJ0DSAT.
a_batch_of_inbound_sessions_is_not_accepted_one_per_second(_Config) ->
    Port = i2p_ct_helpers:free_port(),
    {ok, Listener} = i2p_sam_listener:listen(#{port => Port, local => undefined}),
    %% Bound before the `try`, because the `after` has to reach it: a client held
    %% by a `try`-bound variable is unreachable from the `after`, so a failure
    %% anywhere in the body would leave six of them holding sockets for the rest of
    %% the run.
    Dialers = [say_hello(Port, self()) || _ <- lists:seq(1, ?ACCEPT_BATCH)],
    try
        Deadline = erlang:monotonic_time(millisecond) + ?ACCEPT_BUDGET_MS,
        Asker = ask_port(self(), Listener),
        ?ACCEPT_BATCH = length(Dialers),
        Replies = collect_replies(?ACCEPT_BATCH, Deadline, []),
        ?ACCEPT_BATCH = length(Replies),
        %% Every one is a real HELLO REPLY, not merely N replies of some shape.
        ?assertEqual(
            [],
            [R || R <- Replies, binary:match(R, <<"HELLO REPLY RESULT=OK">>) =:= nomatch]
        ),
        ?assertEqual(length(Replies), i2p_sam_sup:session_count()),
        {asked, Port} = take_asked(Asker, Deadline)
    after
        %% The clients are released in the `after`, so their sessions are still live
        %% for the count above even if an assertion above it has already failed. A
        %% client that exited on its own would close its socket, its session would
        %% exit with it, and the count would be a race against six process exits --
        %% which is how the first version of this case read 1.
        [Dialer ! finish || Dialer <- Dialers],
        ok = i2p_sam_listener:stop(Listener)
    end,
    ok.

%% One client, in its own process, so all ?ACCEPT_BATCH of them reach the listen
%% socket at the same moment rather than as a queue of sequential handshakes -- a
%% sequential loop would measure a rate the client, not the accept path, was setting.
%%
%% **The client waits to be released.** It has to: a client that returned from this
%% fun would drop its socket, the session would see `{tcp_closed, _}` and exit, and
%% the case's session count would be a race against six process exits rather than a
%% reading. Holding the socket open until the case has looked is what makes
%% `f:session_count/0` mean six live sessions. Releasing them in the `after` is what
%% keeps them from outliving the case.
%%
%% `Parent` is captured by the caller rather than read inside the spawned fun:
%% `self()` there is the client, and a reply sent to the client is a reply nobody is
%% waiting for.
say_hello(Port, Parent) ->
    spawn(fun() ->
        {ok, Sock} = connect_sam(Port),
        send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
        Parent ! {hello_reply, recv_line(Sock)},
        receive
            finish -> ok = gen_tcp:close(Sock)
        end
    end).

%% The asker, with the parent captured by the caller for the reason `say_hello/2`
%% gives.
ask_port(Parent, Listener) ->
    spawn(fun() ->
        Parent ! {asked, i2p_sam_listener:port(Listener)}
    end).

%% The whole batch against one deadline, so the bound is on the batch rather than per
%% connection -- a bound per connection would let the sixth wait five seconds behind
%% five fast ones and still pass.
collect_replies(N, Deadline, Acc) ->
    case length(Acc) of
        N ->
            lists:reverse(Acc);
        _ ->
            collect_replies_next(N, Deadline, Acc)
    end.

collect_replies_next(N, Deadline, Acc) ->
    receive
        {hello_reply, Reply} ->
            collect_replies(N, Deadline, [Reply | Acc])
    after remaining_ms(Deadline) ->
        erlang:error({accept_batch_incomplete, length(Acc)})
    end.

%% The asked answer, or the same failure as the batch: a control message that has not
%% come back by the time the batch did is part of the same defect.
take_asked(Asker, Deadline) ->
    receive
        {asked, Answer} ->
            {asked, Answer}
    after remaining_ms(Deadline) ->
        erlang:error({control_message_unanswered, Asker})
    end.

remaining_ms(Deadline) ->
    erlang:max(0, Deadline - erlang:monotonic_time(millisecond)).

sam_session_limit_rejects_new_child(_Config) ->
    application:set_env(?APP, max_sam_sessions, 0),
    try
        {error, session_limit} =
            i2p_sam_sup:start_session(i2p_sam_sup:session_child(#{}))
    after
        application:unset_env(?APP, max_sam_sessions)
    end.

sam_hello(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"HELLO REPLY RESULT=OK">>) =/= nomatch),
    gen_tcp:close(Sock).

sam_dest_generate(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"DEST GENERATE SIGNATURE_TYPE=7">>),
    DestB64 = recv_line(Sock),
    ?assert(byte_size(DestB64) > 100),
    Blob = i2p_keys:decode_b64(DestB64),
    ?assertEqual(455, byte_size(Blob)),
    gen_tcp:close(Sock).

session_create_transient(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"SESSION CREATE STYLE=STREAM ID=test1">>),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"SESSION STATUS RESULT=OK">>) =/= nomatch),
    ?assert(binary:match(Reply, <<"DESTINATION=">>) =/= nomatch),
    gen_tcp:close(Sock).

session_create_explicit_dest(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"DEST GENERATE SIGNATURE_TYPE=7">>),
    DestB64 = recv_line(Sock),
    Cmd = <<"SESSION CREATE STYLE=STREAM ID=test2 DESTINATION=", DestB64/binary>>,
    send_cmd(Sock, Cmd),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"SESSION STATUS RESULT=OK">>) =/= nomatch),
    gen_tcp:close(Sock).

%% Length options are accepted, clamped into 1..3 hops, and registered as a
%% demand on the tunnel manager for the life of the session.
session_create_length_options(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(
        Sock,
        <<"SESSION CREATE STYLE=STREAM ID=lenopt inbound.length=2 outbound.length=1">>
    ),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"SESSION STATUS RESULT=OK">>) =/= nomatch),
    {ok, {Pid, _DestHash, _Style}} = i2p_sam_sup:session_lookup(<<"lenopt">>),
    Demands = i2p_tunnel_srv:demands(),
    ?assertMatch(#{in_len := 2, out_len := 1}, maps:get(Pid, Demands)),
    gen_tcp:close(Sock).

%% Out-of-range values clamp into the 1..3 hop budget.
session_create_length_clamp(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(
        Sock,
        <<"SESSION CREATE STYLE=DATAGRAM ID=lenclamp inbound.length=9 outbound.length=0">>
    ),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"SESSION STATUS RESULT=OK">>) =/= nomatch),
    {ok, {Pid, _DestHash, datagram}} = i2p_sam_sup:session_lookup(<<"lenclamp">>),
    Demands = i2p_tunnel_srv:demands(),
    ?assertMatch(#{in_len := 3, out_len := 1}, maps:get(Pid, Demands)),
    gen_tcp:close(Sock).

%% A non-integer length is a protocol violation: I2P_ERROR reply and the
%% session process dies.
session_create_bad_length(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"SESSION CREATE STYLE=STREAM ID=badlen inbound.length=abc">>),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"RESULT=I2P_ERROR">>) =/= nomatch),
    ?assertEqual({error, closed}, gen_tcp:recv(Sock, 0, 5000)).

%% Without options no demand is registered.
session_create_without_options(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"SESSION CREATE STYLE=RAW ID=noopts">>),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"SESSION STATUS RESULT=OK">>) =/= nomatch),
    Demands = i2p_tunnel_srv:demands(),
    ?assertEqual(0, maps:size(Demands)),
    gen_tcp:close(Sock).

%% A SESSION CREATE with a destination publishes a LeaseSet2 for it.
session_create_publishes_ls(_Config) ->
    %% An active inbound tunnel so publication has a lease to name
    RecvID = 820,
    GwHash = crypto:strong_rand_bytes(32),
    inject_inbound_entry(RecvID, GwHash),

    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"DEST GENERATE SIGNATURE_TYPE=7">>),
    DestB64 = recv_line(Sock),
    Cmd = <<"SESSION CREATE STYLE=STREAM ID=testLS DESTINATION=", DestB64/binary>>,
    send_cmd(Sock, Cmd),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"SESSION STATUS RESULT=OK">>) =/= nomatch),

    %% The router published a LeaseSet2 for this destination
    <<IdentityBin:391/binary, _/binary>> = i2p_keys:decode_b64(DestB64),
    {ok, Id} = i2p_keys:parse(IdentityBin),
    DestHash = i2p_keys:hash(Id),
    LS = wait_for_ls(DestHash),
    [Lease] = i2p_leaset:leases(LS),
    ?assertEqual(GwHash, maps:get(gateway, Lease)),
    ?assertEqual(RecvID, maps:get(tunnel_id, Lease)),
    gen_tcp:close(Sock).

naming_lookup_not_found(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"NAMING LOOKUP NAME=abcdefghijklmnop.b32.i2p">>),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"NAMING REPLY RESULT=CANT_FIND">>) =/= nomatch),
    gen_tcp:close(Sock).

naming_lookup_found(Config) ->
    Router = get_router(Config),
    {SignPub, SignSeed} = i2p_crypto:ed25519_keygen(),
    DestId = i2p_keys:generate_identity(),
    CryptoPub = i2p_keys:public_key(DestId),
    RealId = i2p_keys:from_keys(CryptoPub, SignPub),
    RouterInfo = maps:get(ri, Router),
    NowSec = erlang:system_time(second),
    Leases = [
        #{
            gateway => i2p_router_info:hash(RouterInfo),
            tunnel_id => 12345,
            end_date => (NowSec + 3600) * 1000
        }
    ],
    LS = i2p_leaset:build(RealId, NowSec, 7, Leases, SignSeed),
    i2p_netdb_srv:store_ls(LS, NowSec),

    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),

    B32Addr = i2p_keys:to_b32(RealId),
    Cmd = <<"NAMING LOOKUP NAME=", B32Addr/binary>>,
    send_cmd(Sock, Cmd),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"NAMING REPLY RESULT=OK">>) =/= nomatch),
    ?assert(binary:match(Reply, <<"VALUE=">>) =/= nomatch),
    gen_tcp:close(Sock).

%% SAM-to-SAM loopback over real sockets (ACCEPT then CONNECT).
stream_loopback(_Config) ->
    Port = start_sam_listener(),

    {ok, SA} = connect_sam(Port),
    send_cmd(SA, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(SA),
    send_cmd(SA, <<"DEST GENERATE SIGNATURE_TYPE=7">>),
    DestA_B64 = recv_line(SA),
    send_cmd(SA, <<"SESSION CREATE STYLE=STREAM ID=sessionA DESTINATION=", DestA_B64/binary>>),
    _ = recv_line(SA),
    send_cmd(SA, <<"STREAM ACCEPT ID=sessionA">>),
    AcceptReply = recv_line(SA),
    ?assert(byte_size(AcceptReply) > 100),

    {ok, SB} = connect_sam(Port),
    send_cmd(SB, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(SB),
    send_cmd(SB, <<"DEST GENERATE SIGNATURE_TYPE=7">>),
    _ = recv_line(SB),
    send_cmd(SB, <<"SESSION CREATE STYLE=STREAM ID=sessionB">>),
    _ = recv_line(SB),

    send_cmd(SB, <<"STREAM CONNECT ID=sessionB DESTINATION=", DestA_B64/binary>>),
    ConnectReply = recv_line(SB),
    ?assert(binary:match(ConnectReply, <<"STREAM STATUS RESULT=OK">>) =/= nomatch),

    %% Reads buffer until the handshake completes, so no settle sleep is
    %% needed before A's first write; the 5s recv timeouts are the guard.
    ok = gen_tcp:send(SA, <<"hello from A\n">>),
    {ok, DataB} = gen_tcp:recv(SB, 0, 5000),
    ?assertEqual(<<"hello from A\n">>, DataB),

    ok = gen_tcp:send(SB, <<"hello from B\n">>),
    {ok, DataA} = gen_tcp:recv(SA, 0, 5000),
    ?assertEqual(<<"hello from B\n">>, DataA),

    gen_tcp:close(SA),
    gen_tcp:close(SB).

unknown_command(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"GARBAGE IN">>),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"I2P_ERROR">>) =/= nomatch),
    gen_tcp:close(Sock).

%% A non-numeric FORWARD port is a protocol violation: I2P_ERROR + close.
stream_forward_bad_port(_Config) ->
    Port = start_sam_listener(),
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"SESSION CREATE STYLE=STREAM ID=fwd1">>),
    _ = recv_line(Sock),
    send_cmd(Sock, <<"STREAM FORWARD ID=fwd1 PORT=notaport">>),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"RESULT=I2P_ERROR">>) =/= nomatch),
    ?assertEqual({error, closed}, gen_tcp:recv(Sock, 0, 5000)).

%% Every session form is a candidate for end-to-end delivery; the owning
%% session dispatches the opened payload by its style.
client_sessions_enumeration(Config) ->
    Hash = i2p_router_info:hash(maps:get(ri, get_router(Config))),
    Priv = element(2, i2p_crypto:x25519_keygen()),
    ?assertEqual([], i2p_sam_sup:client_sessions()),
    true = i2p_sam_sup:session_register(<<"S1">>, self(), Hash, stream, Priv),
    true = i2p_sam_sup:session_register(<<"R1">>, self(), Hash, raw, Priv),
    [{Hash, Pid1, Priv}, {Hash, Pid2, Priv}] = i2p_sam_sup:client_sessions(),
    ?assertEqual(self(), Pid1),
    ?assertEqual(self(), Pid2),
    true = i2p_sam_sup:session_unregister(<<"S1">>),
    ?assertEqual([{Hash, self(), Priv}], i2p_sam_sup:client_sessions()).

%% SAM sup is a child of the app alongside peer + tunnel managers.
sam_sup_wiring(_Config) ->
    SamSup = whereis(i2p_sam_sup),
    ?assert(is_pid(SamSup)),
    ?assert(is_process_alive(SamSup)),
    ?assert(is_integer(ets:info(i2p_sam_sup, size))).

%% HTTP GET through the SAM stream proxy.
proxy_loopback(Config) ->
    %% Generate server identity with private keys
    #{
        identity := ServerId,
        crypto_priv := CryptoPriv,
        sign_priv := SignPriv
    } = i2p_keys:generate_with_privkeys(),

    %% Store LeaseSet in NetDb so NAMING LOOKUP resolves
    RouterInfo = maps:get(ri, get_router(Config)),
    NowSec = erlang:system_time(second),
    Leases = [
        #{
            gateway => i2p_router_info:hash(RouterInfo),
            tunnel_id => 12345,
            end_date => (NowSec + 3600) * 1000
        }
    ],
    LS = i2p_leaset:build(ServerId, NowSec, 7, Leases, SignPriv),
    i2p_netdb_srv:store_ls(LS, NowSec),
    B32Addr = i2p_keys:to_b32(ServerId),

    %% Start SAM listener
    SamPort = start_sam_listener(),

    %% Server: connect, HELLO, SESSION CREATE with that identity, STREAM ACCEPT
    {ok, SA} = connect_sam(SamPort),
    send_cmd(SA, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(SA),
    DestBlob = i2p_keys:dest_blob(#{
        identity => ServerId,
        crypto_priv => CryptoPriv,
        sign_priv => SignPriv
    }),
    DestB64 = i2p_keys:encode_b64(DestBlob),
    send_cmd(SA, [<<"SESSION CREATE STYLE=STREAM ID=server DESTINATION=">>, DestB64]),
    _ = recv_line(SA),
    send_cmd(SA, <<"STREAM ACCEPT ID=server">>),
    _ = recv_line(SA),

    %% Start proxy
    HttpPort = i2p_ct_helpers:free_port(),
    {ok, ProxyPid} = i2p_sam_proxy:start_link(#{port => HttpPort, sam_port => SamPort}),
    ProxyPort = i2p_sam_proxy:port(ProxyPid),
    {127, 0, 0, 1} = i2p_sam_proxy:address(ProxyPid),

    %% Test client: connect to proxy, send HTTP GET
    {ok, ClientSock} = gen_tcp:connect(
        "127.0.0.1",
        ProxyPort,
        [binary, {packet, raw}, {active, false}],
        5000
    ),
    HttpRequest = [
        <<"GET http://">>,
        B32Addr,
        <<"/test HTTP/1.1\r\n">>,
        <<"Host: ">>,
        B32Addr,
        <<"\r\n">>,
        <<"Connection: close\r\n">>,
        <<"\r\n">>
    ],
    ok = gen_tcp:send(ClientSock, HttpRequest),

    %% Server: read forwarded HTTP request from SAM stream
    {ok, ServerRecv} = gen_tcp:recv(SA, 0, 5000),
    ?assert(byte_size(ServerRecv) > 0),

    %% Server: send HTTP response back
    ServerResp = [
        <<"HTTP/1.1 200 OK\r\n">>,
        <<"Content-Length: 8\r\n">>,
        <<"\r\n">>,
        <<"Hello I2P">>
    ],
    ok = gen_tcp:send(SA, ServerResp),

    %% Test client: read HTTP response from proxy
    {ok, ClientRecv} = gen_tcp:recv(ClientSock, 0, 5000),
    ?assert(binary:match(ClientRecv, <<"HTTP/1.1 200 OK">>) =/= nomatch),
    ?assert(binary:match(ClientRecv, <<"Hello I2P">>) =/= nomatch),

    gen_tcp:close(ClientSock),
    gen_tcp:close(SA),
    i2p_sam_proxy:stop(ProxyPid).

%%%%%%% Group B: manual managers, wire driven through the mock peer %%%%%%%

%% CONNECT opens a real streaming connection: the STATUS OK line only
%% appears after a signed SYN has travelled through the outbound tunnel and a
%% SYN-ACK has come back. The remote endpoint is driven by a genuine
%% i2p_stream_conn in accept role; both tunnel legs are simulated locally
%% exactly like the end-to-end streaming cases.
stream_handshake(_Config) ->
    process_flag(trap_exit, true),
    Router = make_router(),
    Local = local_from(Router),
    {ok, _} = i2p_sam_sup:start_link(),
    {ok, _} = i2p_tunnel_srv:start_link(Local),
    try
        %% --- Known client destination with its own inbound tunnel ---
        #{
            identity := CliId,
            crypto_priv := CliDPriv,
            sign_priv := CliSeed
        } = i2p_keys:generate_with_privkeys(),
        CliHash = i2p_keys:hash(CliId),
        CliBlob = i2p_keys:dest_blob(#{
            identity => CliId,
            crypto_priv => CliDPriv,
            sign_priv => CliSeed
        }),
        CliB64 = i2p_keys:encode_b64(CliBlob),
        CliRecvID = 700,
        CliGw = crypto:strong_rand_bytes(32),
        ok = inject_inbound_entry(CliRecvID, CliGw),

        %% --- Remote server destination + LeaseSet + inbound tunnel ---
        {DPub, DPriv} = i2p_crypto:x25519_keygen(),
        {SigPub, SigSeed} = i2p_crypto:ed25519_keygen(),
        ServerId = i2p_keys:from_keys(DPub, SigPub),
        ServerHash = i2p_keys:hash(ServerId),
        RemoteB64 = i2p_keys:encode_b64(i2p_keys:to_binary(ServerId)),
        RecvID = 900,
        GwHash = crypto:strong_rand_bytes(32),
        ok = inject_inbound_entry(RecvID, GwHash),
        EndMs = (erlang:system_time(millisecond) + 60000) band 16#FFFFFFFF,
        LS =
            i2p_leaset:build(
                ServerId,
                erlang:system_time(second),
                1,
                [#{gateway => GwHash, tunnel_id => RecvID, end_date => EndMs}],
                SigSeed
            ),
        ?assertEqual(added, i2p_netdb_srv:store_ls(LS, erlang:system_time(second))),

        %% Outbound tunnel for both directions' injections
        Hop1 = make_router(),
        NowMs = erlang:system_time(millisecond),
        {ok, _} =
            i2p_netdb_srv:store_binary(
                i2p_router_info:to_binary(maps:get(ri, Hop1)), NowMs
            ),
        HopKeys = [
            #{
                layer_key => crypto:strong_rand_bytes(32),
                iv_key => crypto:strong_rand_bytes(32)
            }
         || _ <- lists:seq(1, 3)
        ],
        ok = inject_outbound_entry(500, #{
            tunnel_ids => [500, 501, 502],
            router_hashes => [maps:get(hash, Hop1) || _ <- lists:seq(1, 3)],
            layers => HopKeys,
            built_at => erlang:system_time(second)
        }),

        %% --- SAM client with a published LeaseSet for return traffic ---
        Port = start_sam_listener(),
        {ok, Sock} = connect_sam(Port),
        send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
        _ = recv_line(Sock),
        send_cmd(
            Sock,
            <<"SESSION CREATE STYLE=STREAM ID=cli DESTINATION=", CliB64/binary>>
        ),
        CreateReply = recv_line(Sock),
        ?assert(binary:match(CreateReply, <<"RESULT=OK">>) =/= nomatch),
        ?assertMatch(#{leases := [_]}, wait_for_ls(CliHash)),

        register_mock_peer(self()),

        %% --- CONNECT: no OK until the handshake completes ---
        send_cmd(Sock, <<"STREAM CONNECT ID=cli DESTINATION=", RemoteB64/binary>>),

        %% Capture and play the outbound leg; unwrap the SYN.
        Wires = drain_frames(first_frame()),
        Reassembled = reassemble_first_message(Wires, HopKeys),
        {ok, #{body := SynGarlic}} = i2p_i2np:decode_std(Reassembled),
        {ok, SynWire} = i2p_client:unwrap_payload(DPriv, SynGarlic),
        {ok, SynPkt} = i2p_streaming:decode(SynWire),
        ?assert(i2p_streaming:has_flag(SynPkt, i2p_streaming:flag_synchronize())),
        ?assertEqual({ok, ServerHash}, i2p_streaming:replay_hash(SynPkt)),
        %% The FROM option is the CLIENT destination, signed by it.
        ?assertEqual(i2p_keys:to_binary(CliId), i2p_streaming:from(SynPkt)),
        ?assert(i2p_streaming:verify(SynPkt, i2p_keys:signing_key(CliId))),

        %% --- Remote endpoint: a genuine accept-role stream conn whose
        %% replies are injected into the client's inbound tunnel ---
        TestPid = self(),
        ReplyFun = fun(Wire) ->
            {ok, Garlic} = i2p_client:wrap_payload(i2p_keys:public_key(CliId), Wire),
            StdMsg =
                i2p_i2np:encode_std(#{
                    type => 11,
                    msg_id => crypto:strong_rand_bytes(4),
                    expiration_ms => 60000,
                    body => Garlic
                }),
            {[Frame], _Gw} = i2p_tunnel:gateway_all(CliRecvID, local, undefined, StdMsg),
            i2p_tunnel_srv !
                {i2np, self(), crypto:strong_rand_bytes(32), #{
                    type => 18,
                    msg_id => crypto:strong_rand_bytes(4),
                    expiration => erlang:system_time(second) + 60,
                    body => Frame
                }},
            ok
        end,
        {ok, ServerConn} = i2p_sam_sup:start_stream_conn(#{
            role => accept,
            syn => SynPkt,
            owner => TestPid,
            send_fn => ReplyFun,
            local_seed => SigSeed,
            local_dest_bin => i2p_keys:to_binary(ServerId),
            local_dest_hash => ServerHash
        }),

        %% The SYN-ACK flows back through the client session to its conn;
        %% only then does the socket see RESULT=OK.
        OKLine = recv_line(Sock, 10000),
        ?assert(binary:match(OKLine, <<"RESULT=OK">>) =/= nomatch),

        %% Data: socket bytes become a sequenced data packet on the wire.
        Msg = <<"GET / HTTP/1.0">>,
        ok = gen_tcp:send(Sock, Msg),
        DataWires = drain_frames([]),
        ReassembledData = reassemble_first_message(DataWires, HopKeys),
        {ok, #{body := DataGarlic}} = i2p_i2np:decode_std(ReassembledData),
        {ok, DataWire} = i2p_client:unwrap_payload(DPriv, DataGarlic),
        {ok, DataPkt} = i2p_streaming:decode(DataWire),
        ?assertEqual(Msg, i2p_streaming:payload(DataPkt)),
        ?assertEqual(1, i2p_streaming:seq_num(DataPkt)),
        i2p_stream_conn:handle_packet(ServerConn, DataWire),
        receive
            {stream_data, ServerConn, Msg} -> ok
        after 5000 ->
            erlang:error(server_data_timeout)
        end,

        gen_tcp:close(Sock),
        exit(ServerConn, kill)
    after
        unregister_mock_peer()
    end.

%% Both endpoints are real SAM TCP sessions on one node; every packet between
%% them crosses the actual tunnel machinery. The server side has a pending
%% STREAM ACCEPT when the client's SYN arrives, so the session must spawn an
%% accept-role connection, answer the handshake and pair the socket — after
%% which bytes flow in both directions as ordered, acknowledged streaming
%% packets.
full_duplex(_Config) ->
    process_flag(trap_exit, true),
    Router = make_router(),
    Local = local_from(Router),
    {ok, _} = i2p_sam_sup:start_link(),
    {ok, _} = i2p_tunnel_srv:start_link(Local),
    try
        %% --- Two known destinations, each with an inbound tunnel ---
        #{
            identity := CliId,
            crypto_priv := CliDPriv,
            sign_priv := CliSeed
        } = i2p_keys:generate_with_privkeys(),
        CliHash = i2p_keys:hash(CliId),
        CliB64 = i2p_keys:encode_b64(
            i2p_keys:dest_blob(#{
                identity => CliId,
                crypto_priv => CliDPriv,
                sign_priv => CliSeed
            })
        ),

        #{
            identity := SrvId,
            crypto_priv := SrvDPriv,
            sign_priv := SrvSeed
        } = i2p_keys:generate_with_privkeys(),
        SrvHash = i2p_keys:hash(SrvId),
        SrvB64 = i2p_keys:encode_b64(
            i2p_keys:dest_blob(#{
                identity => SrvId,
                crypto_priv => SrvDPriv,
                sign_priv => SrvSeed
            })
        ),

        CliRecvID = 700,
        ok = inject_inbound_entry(CliRecvID, crypto:strong_rand_bytes(32)),
        SrvRecvID = 900,
        ok = inject_inbound_entry(SrvRecvID, crypto:strong_rand_bytes(32)),

        %% --- Outbound tunnel both sides share for their injections ---
        Hop1 = make_router(),
        {ok, _} =
            i2p_netdb_srv:store_binary(
                i2p_router_info:to_binary(maps:get(ri, Hop1)),
                erlang:system_time(millisecond)
            ),
        HopKeys = [
            #{
                layer_key => crypto:strong_rand_bytes(32),
                iv_key => crypto:strong_rand_bytes(32)
            }
         || _ <- lists:seq(1, 3)
        ],
        ok = inject_outbound_entry(500, #{
            tunnel_ids => [500, 501, 502],
            router_hashes => [maps:get(hash, Hop1) || _ <- lists:seq(1, 3)],
            layers => HopKeys,
            built_at => erlang:system_time(second)
        }),

        %% --- Two SAM sessions over real TCP sockets ---
        Port = start_sam_listener(),
        {ok, CliSock} = sam_session(Port, <<"cli">>, CliB64),
        ?assertMatch(#{leases := [_]}, wait_for_ls(CliHash)),
        {ok, SrvSock} = sam_session(Port, <<"srv">>, SrvB64),
        ?assertMatch(#{leases := [_]}, wait_for_ls(SrvHash)),

        ok = fd_mock(),

        %% Client dials FIRST — with no pending ACCEPT yet, the local pairing
        %% shortcut cannot fire and the SYN takes the tunnel path (what a
        %% two-router deployment looks like).
        send_cmd(CliSock, <<"STREAM CONNECT ID=cli DESTINATION=", SrvB64/binary>>),

        put(fd_keys, [
            {cli, CliDPriv},
            {srv, SrvDPriv}
        ]),

        %% Leg 1: SYN to the server's inbound tunnel.
        {SynWire, Seen1} = pull_packet(HopKeys, SrvDPriv, 0),
        {ok, SynPkt} = i2p_streaming:decode(SynWire),
        ?assert(i2p_streaming:has_flag(SynPkt, i2p_streaming:flag_synchronize())),

        %% Only now does the server announce ACCEPT (reply line echoes its
        %% destination); the queued SYN below must find its listener.
        send_cmd(SrvSock, <<"STREAM ACCEPT ID=srv">>),
        AcceptLine = recv_line(SrvSock),
        ?assertEqual(i2p_keys:encode_b64(i2p_keys:to_binary(SrvId)), AcceptLine),

        inject_via_inbound(SrvRecvID, SynWire, SrvId),

        %% Leg 2: SYN-ACK back through the client's inbound tunnel — spawned
        %% by the server SESSION itself upon the inbound SYN.
        {SynAckWire, Seen2} = pull_packet(HopKeys, CliDPriv, Seen1),
        {ok, SynAckPkt} = i2p_streaming:decode(SynAckWire),
        ?assert(i2p_streaming:has_flag(SynAckPkt, i2p_streaming:flag_synchronize())),
        inject_via_inbound(CliRecvID, SynAckWire, CliId),
        OKLine = recv_line(CliSock, 10000),
        ?assert(binary:match(OKLine, <<"RESULT=OK">>) =/= nomatch),

        %% --- Bidirectional data across the pinned routes ---
        ok = gen_tcp:send(CliSock, <<"ping through the tunnels">>),
        {PingWire, Seen3} = pull_data(HopKeys, SrvDPriv, Seen2),
        {ok, PingPkt} = i2p_streaming:decode(PingWire),
        ?assertEqual(<<"ping through the tunnels">>, i2p_streaming:payload(PingPkt)),
        inject_via_inbound(SrvRecvID, PingWire, SrvId),
        {ok, <<"ping through the tunnels">>} = gen_tcp:recv(SrvSock, 0, 5000),

        ok = gen_tcp:send(SrvSock, <<"pong from the far end">>),
        {PongWire, _Seen4} = pull_data(HopKeys, CliDPriv, Seen3),
        inject_via_inbound(CliRecvID, PongWire, CliId),
        {ok, <<"pong from the far end">>} = gen_tcp:recv(CliSock, 0, 5000),

        gen_tcp:close(CliSock),
        gen_tcp:close(SrvSock),
        ok
    after
        fd_unmock()
    end.

%% The FORWARD session binds a local echo server to its destination and two
%% separate clients CONNECT to it through real tunnel machinery. Unlike ACCEPT,
%% the binding persists: both client streams relay concurrently to fresh local
%% TCP connections while the forward session's control socket stays in line
%% mode.
forward_e2e(_Config) ->
    process_flag(trap_exit, true),
    Router = make_router(),
    Local = local_from(Router),
    {ok, _} = i2p_sam_sup:start_link(),
    {ok, _} = i2p_tunnel_srv:start_link(Local),
    try
        %% --- Three destinations: the forward server + two clients ---
        Fwd = make_dest(),
        Cli1 = make_dest(),
        Cli2 = make_dest(),
        #{b64 := FwdB64} = Fwd,
        FwdRecvID = 900,
        ok = inject_inbound_entry(FwdRecvID, crypto:strong_rand_bytes(32)),
        Cli1R = 700,
        ok = inject_inbound_entry(Cli1R, crypto:strong_rand_bytes(32)),
        Cli2R = 710,
        ok = inject_inbound_entry(Cli2R, crypto:strong_rand_bytes(32)),

        %% --- Outbound tunnel both sides share for their injections ---
        Hop1 = make_router(),
        {ok, _} =
            i2p_netdb_srv:store_binary(
                i2p_router_info:to_binary(maps:get(ri, Hop1)),
                erlang:system_time(millisecond)
            ),
        HopKeys = [
            #{
                layer_key => crypto:strong_rand_bytes(32),
                iv_key => crypto:strong_rand_bytes(32)
            }
         || _ <- lists:seq(1, 3)
        ],
        ok = inject_outbound_entry(500, #{
            tunnel_ids => [500, 501, 502],
            router_hashes => [maps:get(hash, Hop1) || _ <- lists:seq(1, 3)],
            layers => HopKeys,
            built_at => erlang:system_time(second)
        }),

        %% --- Local echo service + SAM sessions ---
        {EchoPort, EchoAcceptor} = echo_server(),
        Port = start_sam_listener(),
        {ok, FwdSock} = sam_session(Port, <<"fwd">>, FwdB64),
        send_cmd(
            FwdSock,
            <<"STREAM FORWARD ID=fwd PORT=", (integer_to_binary(EchoPort))/binary>>
        ),
        ForwardReply = recv_line(FwdSock),
        ?assert(binary:match(ForwardReply, <<"STREAM STATUS RESULT=OK">>) =/= nomatch),
        ?assertMatch(
            {ok, {"127.0.0.1", EchoPort}},
            i2p_sam_sup:forward_lookup(i2p_keys:hash(maps:get(id, Fwd)))
        ),
        %% Control socket stays in line mode after FORWARD.
        send_cmd(FwdSock, <<"NAMING LOOKUP NAME=whatever.b32.i2p">>),
        LineReply = recv_line(FwdSock),
        ?assert(binary:match(LineReply, <<"NAMING REPLY">>) =/= nomatch),

        {ok, Sock1} = sam_session(Port, <<"cli1">>, maps:get(b64, Cli1)),
        ?assertMatch(#{leases := [_]}, wait_for_ls(maps:get(hash, Cli1))),
        {ok, Sock2} = sam_session(Port, <<"cli2">>, maps:get(b64, Cli2)),
        ?assertMatch(#{leases := [_]}, wait_for_ls(maps:get(hash, Cli2))),

        put(fd_keys, [
            {cli1, maps:get(dpriv, Cli1)},
            {cli2, maps:get(dpriv, Cli2)},
            {fwd, maps:get(dpriv, Fwd)}
        ]),
        ok = fd_mock(),

        %% --- Client 1 connects; relay handshake through the tunnels ---
        send_cmd(Sock1, <<"STREAM CONNECT ID=cli1 DESTINATION=", FwdB64/binary>>),
        {OKLine1, SeenH1} = drive_handshake(Sock1, HopKeys, Cli1, Fwd, Cli1R, FwdRecvID, 0),
        ?assert(binary:match(OKLine1, <<"RESULT=OK">>) =/= nomatch),

        %% --- Client 2 dials the same destination while stream one is
        %% established: the binding persists across accepted streams ---
        send_cmd(Sock2, <<"STREAM CONNECT ID=cli2 DESTINATION=", FwdB64/binary>>),
        {OKLine2, SeenH2} = drive_handshake(Sock2, HopKeys, Cli2, Fwd, Cli2R, FwdRecvID, SeenH1),
        ?assert(binary:match(OKLine2, <<"RESULT=OK">>) =/= nomatch),

        %% --- Echo round trips on BOTH streams ---
        ok = gen_tcp:send(Sock1, <<"one for the echo">>),
        {Ping1, SeenA} = pull_data(HopKeys, maps:get(dpriv, Fwd), SeenH2),
        inject_via_inbound(FwdRecvID, Ping1, maps:get(id, Fwd)),
        %% The relay pipes to the local echo service; the echoed bytes come
        %% back over the outbound tunnel and must be delivered to the client.
        {Echo1, SeenB} = pull_data(HopKeys, maps:get(dpriv, Cli1), SeenA),
        inject_via_inbound(Cli1R, Echo1, maps:get(id, Cli1)),
        {ok, <<"one for the echo">>} = gen_tcp:recv(Sock1, 0, 5000),

        ok = gen_tcp:send(Sock2, <<"two for the echo">>),
        {Ping2, SeenC} = pull_data(HopKeys, maps:get(dpriv, Fwd), SeenB),
        inject_via_inbound(FwdRecvID, Ping2, maps:get(id, Fwd)),
        {Echo2, _SeenD} = pull_data(HopKeys, maps:get(dpriv, Cli2), SeenC),
        inject_via_inbound(Cli2R, Echo2, maps:get(id, Cli2)),
        {ok, <<"two for the echo">>} = gen_tcp:recv(Sock2, 0, 5000),

        gen_tcp:close(Sock1),
        gen_tcp:close(Sock2),
        gen_tcp:close(FwdSock),
        exit(EchoAcceptor, kill),
        ok
    after
        fd_unmock()
    end.

%%%%%%% Helpers %%%%%%%%%

get_router(Config) ->
    proplists:get_value(router, Config).

make_router() ->
    {StaticPub, StaticPriv} = i2p_crypto:x25519_keygen(),
    {SignPub, Seed} = i2p_crypto:ed25519_keygen(),
    Identity = i2p_keys:from_keys(StaticPub, SignPub),
    IV = crypto:strong_rand_bytes(16),
    Port = i2p_ct_helpers:free_port(),
    Addr = i2p_router_info:ntcp2_address(<<"127.0.0.1">>, Port, StaticPub, IV),
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

%% make_dest/0 — a known destination with its private keys and derived forms.
make_dest() ->
    #{
        identity := Id,
        crypto_priv := DPriv,
        sign_priv := Seed
    } = i2p_keys:generate_with_privkeys(),
    #{
        id => Id,
        hash => i2p_keys:hash(Id),
        dpriv => DPriv,
        b64 => i2p_keys:encode_b64(
            i2p_keys:dest_blob(#{
                identity => Id,
                crypto_priv => DPriv,
                sign_priv => Seed
            })
        )
    }.

start_sam_listener() ->
    Port = i2p_ct_helpers:free_port(),
    {ok, Listener} = i2p_sam_listener:listen(#{port => Port, local => undefined}),
    true = is_pid(Listener),
    Port.

connect_sam(Port) ->
    gen_tcp:connect("127.0.0.1", Port, [binary, {packet, raw}, {active, false}], 5000).

send_cmd(Sock, Cmd) ->
    ok = gen_tcp:send(Sock, [Cmd, <<"\n">>]).

recv_line(Sock) ->
    recv_line(Sock, <<>>).

recv_line(Sock, Timeout) when is_integer(Timeout) ->
    recv_line(Sock, <<>>, Timeout);
recv_line(Sock, Acc) ->
    recv_line(Sock, Acc, 5000).

recv_line(Sock, Acc, Timeout) ->
    case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Data} ->
            Combined = <<Acc/binary, Data/binary>>,
            case binary:match(Combined, <<"\n">>) of
                {Pos, _} ->
                    binary:part(Combined, 0, Pos);
                nomatch ->
                    recv_line(Sock, Combined, Timeout)
            end;
        {error, Reason} ->
            error(Reason)
    end.

%% Event-driven wait for the LeaseSet publication: polls the NetDb under a
%% deadline instead of sleeping a fixed number of ticks.
wait_for_ls(DestHash) ->
    ok = i2p_ct_helpers:await(
        fun() ->
            i2p_netdb_srv:find_ls(DestHash) =/= not_found
        end
    ),
    {ok, LS} = i2p_netdb_srv:find_ls(DestHash),
    LS.

%% Forge an active inbound tunnel entry for the data-path seam: the entry
%% can only reach the map through the real encrypted build path, which is not
%% this test's subject.
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

%% Play each participant hop (encrypts one layer on forward) and rebuild the
%% standard-header message from the resulting plaintext frames.
reassemble_first_message(Wires, HopKeys) ->
    FragLists =
        lists:map(
            fun(Wire) ->
                Final =
                    lists:foldl(
                        fun(Hop, M) ->
                            {ok, M1} =
                                i2p_tunnel:process_tunnel_data(M, Hop, 500, <<0, 0, 0, 0>>),
                            M1
                        end,
                        Wire,
                        HopKeys
                    ),
                <<_:32/big, IV:16/binary, Plain:1008/binary>> = Final,
                {ok, Fs, _} = i2p_tunnel:parse_tunnel_data(Plain, IV, #{}),
                Fs
            end,
            Wires
        ),
    AllFrags = lists:append(FragLists),
    [First] = [F || F <- AllFrags, maps:get(type, F) =:= first],
    case [F || F <- AllFrags, maps:get(type, F) =:= follow_on] of
        [] ->
            maps:get(data, First);
        FollowOns ->
            Ordered =
                [
                    maps:get(data, F)
                 || N <- lists:seq(1, length(FollowOns)),
                    F <- FollowOns,
                    maps:get(frag_num, F) =:= N
                ],
            iolist_to_binary([maps:get(data, First) | Ordered])
    end.

%% Open a SAM TCP session with a fixed destination; returns the raw socket once
%% SESSION CREATE has been accepted.
sam_session(Port, ID, DestB64) ->
    {ok, Sock} = connect_sam(Port),
    send_cmd(Sock, <<"HELLO VERSION MIN=3.1 MAX=3.1">>),
    _ = recv_line(Sock),
    send_cmd(
        Sock,
        <<"SESSION CREATE STYLE=STREAM ID=", ID/binary, " DESTINATION=", DestB64/binary>>
    ),
    Reply = recv_line(Sock),
    ?assert(binary:match(Reply, <<"RESULT=OK">>) =/= nomatch),
    {ok, Sock}.

%% Deliver one streaming packet to its recipient session by pushing it into
%% that session's inbound tunnel (the OBEP leg). TargetId is the identity
%% whose ECIES key must open the wrapper garlic.
inject_via_inbound(RecvID, Wire, TargetId) ->
    {ok, Garlic} = i2p_client:wrap_payload(i2p_keys:public_key(TargetId), Wire),
    StdMsg =
        i2p_i2np:encode_std(#{
            type => 11,
            msg_id => crypto:strong_rand_bytes(4),
            expiration_ms => 60000,
            body => Garlic
        }),
    {[Frame], _Gw} = i2p_tunnel:gateway_all(RecvID, local, undefined, StdMsg),
    i2p_tunnel_srv !
        {i2np, self(), crypto:strong_rand_bytes(32), #{
            type => 18,
            msg_id => crypto:strong_rand_bytes(4),
            expiration => erlang:system_time(second) + 60,
            body => Frame
        }},
    ok.

%% A dedicated i2p_peer double for forwarding tests: received tunnel frames
%% land in a private ETS bag so nothing can consume them out from under us and
%% no stale traffic from other tests is visible.
fd_mock() ->
    ets:new(fd_frames, [named_table, bag, public]),
    Pid =
        spawn(fun F() ->
            receive
                {'$gen_cast', {send_when_ready, _Hash, Msg}} ->
                    ets:insert(
                        fd_frames,
                        {erlang:unique_integer([positive, monotonic]), maps:get(body, Msg)}
                    ),
                    F();
                _Other ->
                    F()
            end
        end),
    true = register(i2p_peer, Pid),
    ok.

fd_unmock() ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            unregister(i2p_peer),
            exit(Pid, kill)
    end,
    case ets:whereis(fd_frames) of
        undefined -> ok;
        _ -> ets:delete(fd_frames)
    end.

%% Wait until the mock holds enough frames to reassemble one complete I2NP
%% message whose garlic opens under RecvDPriv; returns the unwrapped streaming
%% packet and the frame count consumed so far. Deadline-gated, never a fixed
%% sleep: pull_loop backs off 25ms up to its absolute deadline.
pull_packet(HopKeys, RecvDPriv, AlreadySeen) ->
    Deadline = erlang:monotonic_time(millisecond) + 6000,
    pull_loop(HopKeys, RecvDPriv, AlreadySeen, Deadline).

pull_loop(HopKeys, RecvDPriv, Seen, Deadline) ->
    All = lists:sort(ets:tab2list(fd_frames)),
    Unseen = [Pair || Pair = {N, _B} <- All, N > Seen],
    case unwrap_one(Unseen, HopKeys, RecvDPriv) of
        {ok, Wire, WaterMark} ->
            {Wire, WaterMark};
        false ->
            Now = erlang:monotonic_time(millisecond),
            case Now >= Deadline of
                true ->
                    erlang:error({frames_timeout, length(Unseen)});
                false ->
                    %% Documented load-safe window: 25ms poll backoff
                    %% inside a deadline-bounded loop (6s absolute) — a
                    %% state poll, not a fixed sleep gating an assert.
                    timer:sleep(25),
                    pull_loop(HopKeys, RecvDPriv, Seen, Deadline)
            end
    end.

%% Skip pure acknowledgements (empty payloads): keep consuming until a
%% data-carrying packet arrives.
pull_data(HopKeys, RecvDPriv, Seen) ->
    {Wire, Seen1} = pull_packet(HopKeys, RecvDPriv, Seen),
    case i2p_streaming:decode(Wire) of
        {ok, Pkt} ->
            case i2p_streaming:payload(Pkt) of
                <<>> -> pull_data(HopKeys, RecvDPriv, Seen1);
                _ -> {Wire, Seen1}
            end;
        {error, _} ->
            {Wire, Seen1}
    end.

%% Single frames first (small streaming packets are unfragmented), then
%% growing prefixes for fragmented messages. Frames are {Index, Body} pairs;
%% a match returns the highest consumed index as the new watermark.
unwrap_one(Unseen, HopKeys, RecvDPriv) when Unseen =/= [] ->
    Singles = [[F] || F <- Unseen],
    Prefixes = [lists:sublist(Unseen, K) || K <- lists:seq(2, length(Unseen))],
    first_hit(Singles ++ Prefixes, HopKeys, RecvDPriv);
unwrap_one([], _HopKeys, _RecvDPriv) ->
    false.

first_hit([], _HopKeys, _RecvDPriv) ->
    false;
first_hit([Frames | Rest], HopKeys, RecvDPriv) ->
    Candidate =
        try reassemble_first_message([B || {_N, B} <- Frames], HopKeys) of
            C -> C
        catch
            _:_ -> skip
        end,
    case Candidate of
        skip ->
            first_hit(Rest, HopKeys, RecvDPriv);
        _ ->
            case i2p_i2np:decode_std(Candidate) of
                {ok, #{body := Garlic}} ->
                    case i2p_client:unwrap_payload(RecvDPriv, Garlic) of
                        {ok, Wire} ->
                            {N, _B} = lists:last(Frames),
                            {ok, Wire, N};
                        error ->
                            first_hit(Rest, HopKeys, RecvDPriv)
                    end;
                error ->
                    first_hit(Rest, HopKeys, RecvDPriv)
            end
    end.

%% Play one CONNECT's SYN out of the mock peer, inject it into the forward
%% destination's inbound tunnel, then route the relay's SYN-ACK back into the
%% connecting client's inbound tunnel. Returns the client's STREAM STATUS line
%% and the advanced frame watermark.
drive_handshake(ClientSock, HopKeys, Cli, Fwd, CliRecvID, FwdRecvID, SeenIn) ->
    {SynWire, Seen1} = pull_packet(HopKeys, maps:get(dpriv, Fwd), SeenIn),
    {ok, SynPkt} = i2p_streaming:decode(SynWire),
    ?assert(i2p_streaming:has_flag(SynPkt, i2p_streaming:flag_synchronize())),
    ?assertEqual({ok, maps:get(hash, Fwd)}, i2p_streaming:replay_hash(SynPkt)),
    inject_via_inbound(FwdRecvID, SynWire, maps:get(id, Fwd)),

    {SynAckWire, SeenOut} = pull_packet(HopKeys, maps:get(dpriv, Cli), Seen1),
    {ok, SynAckPkt} = i2p_streaming:decode(SynAckWire),
    ?assert(i2p_streaming:has_flag(SynAckPkt, i2p_streaming:flag_synchronize())),
    inject_via_inbound(CliRecvID, SynAckWire, maps:get(id, Cli)),
    {recv_line(ClientSock, 10000), SeenOut}.

%% First tunnel frame within 3s, then anything else already queued.
drain_frames(Acc) when length(Acc) >= 1 ->
    drain_frames(Acc, 300);
drain_frames(Acc) ->
    receive
        {peer_sent, {send_when_ready, _Hash, Msg}} ->
            drain_frames([maps:get(body, Msg) | Acc])
    after 3000 ->
        erlang:error({frames_timeout, length(Acc)})
    end.

drain_frames(Acc, GraceMs) ->
    receive
        {peer_sent, {send_when_ready, _Hash, Msg}} ->
            drain_frames([maps:get(body, Msg) | Acc], GraceMs)
    after GraceMs ->
        lists:reverse(Acc)
    end.

first_frame() ->
    receive
        {peer_sent, {send_when_ready, _Hash, Msg}} ->
            [maps:get(body, Msg)]
    after 3000 ->
        erlang:error({frames_timeout, 0})
    end.

register_mock_peer(TestPid) ->
    Pid =
        spawn(fun F() ->
            receive
                {'$gen_cast', Cast} ->
                    TestPid ! {peer_sent, Cast},
                    F();
                _Other ->
                    F()
            end
        end),
    true = register(i2p_peer, Pid).

unregister_mock_peer() ->
    case whereis(i2p_peer) of
        undefined ->
            ok;
        Pid ->
            unregister(i2p_peer),
            exit(Pid, kill)
    end.

%% echo_server/0 — a passive TCP echo service on an OS-assigned port; every
%% accepted connection is echoed by its own process until closed.
echo_server() ->
    {ok, L} =
        gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(L),
    Acceptor =
        spawn(fun A() ->
            case gen_tcp:accept(L, 30000) of
                {ok, S} ->
                    spawn(fun() -> echo_loop(S) end),
                    A();
                {error, closed} ->
                    ok
            end
        end),
    {Port, Acceptor}.

echo_loop(S) ->
    case gen_tcp:recv(S, 0, 60000) of
        {ok, Data} ->
            ok = gen_tcp:send(S, Data),
            echo_loop(S);
        _Error ->
            gen_tcp:close(S)
    end.
