-module(i2per_proxy_sam_tests).

-include_lib("eunit/include/eunit.hrl").

parse_hello_ok_test() ->
    ?assertEqual(ok, i2per_proxy_sam:parse_hello(<<"HELLO REPLY RESULT=OK VERSION=3.1">>)).

parse_hello_fail_test() ->
    ?assertMatch(
        {error, _}, i2per_proxy_sam:parse_hello(<<"HELLO REPLY RESULT=I2P_ERROR MESSAGE=nope">>)
    ).

parse_session_status_test() ->
    ?assertEqual(
        {ok, <<"abc123">>},
        i2per_proxy_sam:parse_session_status(<<"SESSION STATUS RESULT=OK DESTINATION=abc123">>)
    ).

parse_naming_reply_test() ->
    ?assertEqual(
        {ok, <<"destb64">>},
        i2per_proxy_sam:parse_naming_reply(<<"NAMING REPLY RESULT=OK NAME=foo VALUE=destb64">>)
    ).

parse_stream_status_test() ->
    ?assertEqual(ok, i2per_proxy_sam:parse_stream_status(<<"STREAM STATUS RESULT=OK">>)).

naming_lookup_rejects_injection_test() ->
    ?assertEqual(
        {error, {sam_naming_lookup_failed, invalid_name}},
        i2per_proxy_sam:naming_lookup(
            undefined, <<"x\nSESSION CREATE STYLE=STREAM ID=evil DESTINATION=TRANSIENT">>
        )
    ).

naming_lookup_rejects_space_and_quote_test() ->
    ?assertEqual(
        {error, {sam_naming_lookup_failed, invalid_name}},
        i2per_proxy_sam:naming_lookup(undefined, <<"a b">>)
    ),
    ?assertEqual(
        {error, {sam_naming_lookup_failed, invalid_name}},
        i2per_proxy_sam:naming_lookup(undefined, <<"a\"b">>)
    ).

mock_conversation_test_() ->
    {"full SAM conversation against a mock server", fun() ->
        {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
        {ok, {_, Port}} = inet:sockname(LSock),
        Server = spawn(fun() -> mock_sam(LSock) end),
        {ok, Sock} = gen_tcp:connect(
            "127.0.0.1", Port, [binary, {packet, raw}, {active, false}], 5000
        ),
        ?assertEqual(ok, i2per_proxy_sam:hello(Sock)),
        {ok, _Id, _Dest} = i2per_proxy_sam:session_create(Sock),
        ?assertEqual({ok, <<"targetdest">>}, i2per_proxy_sam:naming_lookup(Sock, <<"peer.i2p">>)),
        ok = i2per_proxy_sam:stream_connect(Sock, <<"proxy-1">>, <<"targetdest">>),
        gen_tcp:close(Sock),
        Server ! stop
    end}.

%% Each reply follows the request it answers. Answering HELLO before reading it
%% lets the client send SESSION CREATE unprompted, and one coalesced segment is
%% then enough to desync the exchange (WD5N85Y).
mock_sam(LSock) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"HELLO REPLY RESULT=OK VERSION=3.1\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"SESSION STATUS RESULT=OK DESTINATION=mydest\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"NAMING REPLY RESULT=OK NAME=peer.i2p VALUE=targetdest\n">>),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            gen_tcp:send(Sock, <<"STREAM STATUS RESULT=OK\n">>),
            gen_tcp:close(Sock),
            ok;
        {error, _} ->
            ok
    end.
