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

%% SAM v3 puts the stream on a second socket: the session socket carries
%% HELLO / SESSION CREATE / NAMING LOOKUP and must stay open, while HELLO and
%% STREAM CONNECT arrive on a fresh connection.
open_stream_uses_two_sockets_test_() ->
    {"open_stream keeps the session socket and opens a second one for the stream", fun() ->
        Mock = i2per_proxy_mock_sam:start(fun(_StreamSock) ->
            %% Hold the stream open so the assertions below see live sockets.
            receive
                release -> ok
            end
        end),
        {_, Port, _} = Mock,
        try
            {ok, SessionSock, StreamSock} =
                i2per_proxy_sam:open_stream(<<"127.0.0.1">>, Port, <<"peer.i2p">>),
            ?assertNotEqual(SessionSock, StreamSock),
            %% The session socket is still open and still in line mode.
            ?assertEqual({error, timeout}, gen_tcp:recv(SessionSock, 0, 100)),
            gen_tcp:close(StreamSock),
            gen_tcp:close(SessionSock)
        after
            i2per_proxy_mock_sam:stop(Mock)
        end
    end}.

%% A failed negotiation closes every socket it opened, so a caller that gives
%% up cannot leak the session socket.
open_stream_closes_the_session_socket_on_failure_test_() ->
    {"open_stream closes the session socket when the handshake fails", fun() ->
        {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}, {reuseaddr, true}]),
        {ok, {_, Port}} = inet:sockname(LSock),
        Self = self(),
        Server = spawn_link(fun() ->
            {ok, Sock} = gen_tcp:accept(LSock, 5000),
            {ok, _} = gen_tcp:recv(Sock, 0, 5000),
            ok = gen_tcp:send(Sock, <<"HELLO REPLY RESULT=I2P_ERROR MESSAGE=nope\n">>),
            %% open_stream/3 must close what it opened.
            Self ! {session_socket, gen_tcp:recv(Sock, 0, 5000)}
        end),
        try
            ?assertMatch(
                {error, _},
                i2per_proxy_sam:open_stream(<<"127.0.0.1">>, Port, <<"peer.i2p">>)
            ),
            receive
                {session_socket, Result} -> ?assertEqual({error, closed}, Result)
            after 5000 ->
                ?assert(false)
            end,
            _ = Server
        after
            gen_tcp:close(LSock)
        end
    end}.
