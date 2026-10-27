-module(i2per_tun_sam_tests).

-include_lib("eunit/include/eunit.hrl").

%% ---------------------------------------------------------------- parsers

parse_hello_ok_test() ->
    ?assertEqual(ok, i2per_tun_sam:parse_hello(<<"HELLO REPLY RESULT=OK VERSION=3.1">>)).

parse_hello_fail_test() ->
    ?assertMatch(
        {error, _}, i2per_tun_sam:parse_hello(<<"HELLO REPLY RESULT=I2P_ERROR MESSAGE=nope">>)
    ).

parse_session_status_test() ->
    ?assertEqual(
        {ok, <<"abc123">>},
        i2per_tun_sam:parse_session_status(<<"SESSION STATUS RESULT=OK DESTINATION=abc123">>)
    ).

parse_naming_reply_test() ->
    ?assertEqual(
        {ok, <<"destb64">>},
        i2per_tun_sam:parse_naming_reply(<<"NAMING REPLY RESULT=OK NAME=foo VALUE=destb64">>)
    ).

parse_stream_status_test() ->
    ?assertEqual(ok, i2per_tun_sam:parse_stream_status(<<"STREAM STATUS RESULT=OK">>)).

%% ---------------------------------------------------------------- mock SAM server conversation

mock_server_conversation_test_() ->
    {"full SAM conversation against a mock server", fun() ->
        {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
        {ok, {_, Port}} = inet:sockname(LSock),
        Server = spawn(fun() -> mock_sam(LSock) end),
        {ok, Sock} = gen_tcp:connect(
            "127.0.0.1", Port, [binary, {packet, raw}, {active, false}], 5000
        ),
        ?assertEqual(ok, i2per_tun_sam:hello(Sock)),
        {ok, _Id, _Dest} = i2per_tun_sam:session_create(Sock),
        ?assertEqual({ok, <<"targetdest">>}, i2per_tun_sam:naming_lookup(Sock, <<"peer.i2p">>)),
        ok = i2per_tun_sam:stream_connect(Sock, <<"tun-1">>, <<"targetdest">>),
        gen_tcp:close(Sock),
        Server ! stop
    end}.

mock_sam(LSock) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            gen_tcp:send(Sock, <<"HELLO REPLY RESULT=OK VERSION=3.1\n">>),
            %% session create
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"SESSION STATUS RESULT=OK DESTINATION=mydest\n">>),
            %% naming lookup
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"NAMING REPLY RESULT=OK NAME=peer.i2p VALUE=targetdest\n">>),
            %% stream connect
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"STREAM STATUS RESULT=OK\n">>),
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            ok
    end.

parse_raw_received_test() ->
    ?assertEqual(
        {ok, 4, <<"srcdest">>},
        i2per_tun_sam:parse_raw_received(<<"RAW RECEIVED SIZE=4 DESTINATION=srcdest">>)
    ).

sam_recv_line_preserves_bytes_after_newline_test() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
    {ok, {_, Port}} = inet:sockname(LSock),
    {ok, Client} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}], 5000),
    {ok, Server} = gen_tcp:accept(LSock, 5000),
    ok = gen_tcp:send(Client, <<"hello\nworld">>),
    ?assertEqual({ok, <<"hello">>}, i2per_tun_sam:sam_recv_line(Server)),
    ?assertEqual({ok, <<"world">>}, gen_tcp:recv(Server, 5, 5000)),
    gen_tcp:close(Client),
    gen_tcp:close(Server),
    gen_tcp:close(LSock).