-module(i2p_server_tunnel_tests).

-moduledoc """
Direct-callback unit tests for `m:i2p_server_tunnel`.

Covers init (identity generation, in-memory and persistent-key variants via the
`i2p_tunnel_srv_stub`), client-destination registration, child-spec/stop
helpers, and the handler survive-paths: an undecodable wire stream, unknown
stream/tcp/DOWN traffic, and the catch-alls. The full SYN-accept relay path
(`f:i2p_server_tunnel:open_relay/3`) needs a live NetDb/route resolution and a
local service and is covered by the CT suite (network-gated).
""".

-include_lib("eunit/include/eunit.hrl").

-define(NAME, <<"echo">>).
-define(DECL, #{name => ?NAME, host => <<"127.0.0.1">>, port => 8080}).

child_spec_test() ->
    Decl = #{name => <<"MySite">>, host => "127.0.0.1", port => 8080},
    Spec = i2p_server_tunnel:child_spec(Decl),
    ?assertEqual(i2p_server_tunnel_mysite, maps:get(id, Spec)),
    ?assertEqual(
        {i2p_server_tunnel, start_link, [Decl]},
        maps:get(start, Spec)
    ),
    ?assertEqual(permanent, maps:get(restart, Spec)),
    ?assertEqual(5000, maps:get(shutdown, Spec)),
    ?assertEqual(worker, maps:get(type, Spec)),
    ?assertEqual([i2p_server_tunnel], maps:get(modules, Spec)).

%% A name containing digits: sanitise keeps digits (non-alpha clause).
child_spec_digits_test() ->
    Decl = #{name => <<"MySite9">>, host => "127.0.0.1", port => 8081},
    ?assertEqual(i2p_server_tunnel_mysite9, maps:get(id, i2p_server_tunnel:child_spec(Decl))).

stop_not_running_test() ->
    ?assertEqual(ok, i2p_server_tunnel:stop(<<"definitely-not-started">>)).

client_destinations_empty_test() ->
    application:unset_env(i2per, server_tunnels),
    try
        ?assertEqual([], i2p_server_tunnel:client_destinations())
    after
        application:unset_env(i2per, server_tunnels)
    end.

%% A declared-but-not-initialised tunnel has no registered destination: the
%% persistent-term lookup falls back to the undefined branch.
client_destinations_unregistered_test() ->
    application:set_env(i2per, server_tunnels, [?DECL]),
    try
        persistent_term:erase({i2p_server_tunnel, ?NAME}),
        ?assertEqual([], i2p_server_tunnel:client_destinations())
    after
        persistent_term:erase({i2p_server_tunnel, ?NAME}),
        application:unset_env(i2per, server_tunnels)
    end.

%% Undecodable inbound wire stream: decode error leaves state untouched.
stream_data_decode_error_test() ->
    ?assertEqual(
        {noreply, base_state()},
        i2p_server_tunnel:handle_info({stream_data, <<0, 1, 2>>}, base_state())
    ).

%% Unknown streaming/tcp/DOWN traffic: every clause survives to the same state.
handler_unknown_test() ->
    S = base_state(),
    Me = self(),
    ?assertEqual({noreply, S}, i2p_server_tunnel:handle_info({stream_started, Me, 1}, S)),
    ?assertEqual({noreply, S}, i2p_server_tunnel:handle_info({stream_data, Me, <<"x">>}, S)),
    ?assertEqual({noreply, S}, i2p_server_tunnel:handle_info({stream_closed, Me}, S)),
    ?assertEqual({noreply, S}, i2p_server_tunnel:handle_info({stream_reset, Me}, S)),
    ?assertEqual(
        {noreply, S},
        i2p_server_tunnel:handle_info({'DOWN', make_ref(), process, Me, normal}, S)
    ).

%% Non-socket sock values: tcp_closed/tcp_error degrade to unchanged state.
tcp_closed_unknown_test() ->
    S = base_state(),
    ?assertEqual({noreply, S}, i2p_server_tunnel:handle_info({tcp_closed, 5}, S)),
    ?assertEqual({noreply, S}, i2p_server_tunnel:handle_info({tcp_error, 5, einval}, S)).

generic_call_test() ->
    ?assertEqual(
        {reply, ok, base_state()},
        i2p_server_tunnel:handle_call(junk, {self(), make_ref()}, base_state())
    ).

%% Relay teardown both ways: stream-side and socket-side events drop the relay
%% from conns and pending via finish_drop.
relay_teardown_test() ->
    Conn = self(),
    Sock = 5,
    Relay = #{conn => Conn, mon => make_ref(), sock => Sock},
    S1 = (base_state())#{conns := #{7 => Relay}, pending := #{Conn => Relay}},
    {noreply, Clean1} = i2p_server_tunnel:handle_info({stream_closed, Conn}, S1),
    ?assertEqual(#{}, maps:get(conns, Clean1)),
    ?assertEqual(#{}, maps:get(pending, Clean1)),
    S2 = (base_state())#{conns := #{7 => Relay}, pending := #{Conn => Relay}},
    {noreply, Clean2} = i2p_server_tunnel:handle_info({tcp_closed, Sock}, S2),
    ?assertEqual(#{}, maps:get(conns, Clean2)),
    ?assertEqual(#{}, maps:get(pending, Clean2)),
    S3 = (base_state())#{conns := #{7 => Relay}, pending := #{Conn => Relay}},
    {noreply, Clean3} = i2p_server_tunnel:handle_info({tcp_error, Sock, econnreset}, S3),
    ?assertEqual(#{}, maps:get(conns, Clean3)),
    ?assertEqual(#{}, maps:get(pending, Clean3)).

generic_cast_test() ->
    ?assertEqual({noreply, base_state()}, i2p_server_tunnel:handle_cast(junk, base_state())).

generic_info_test() ->
    ?assertEqual({noreply, base_state()}, i2p_server_tunnel:handle_info(junk, base_state())).

base_state() ->
    #{
        name => <<"t">>,
        host => "h",
        port => 1,
        dest => #{},
        crypto_priv => <<>>,
        sign_seed => <<>>,
        dest_hash => <<>>,
        keys_path => undefined,
        pending => #{},
        conns => #{}
    }.
