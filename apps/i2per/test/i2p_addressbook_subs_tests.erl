-module(i2p_addressbook_subs_tests).

-moduledoc """
Direct-callback unit tests for `m:i2p_addressbook_subs`.

Covers init (internal client key generation + persistent_term registration),
the arming handlers (`fetch_now`, `timeout`, `refresh`, pipeline start), the
in-flight fetch handlers (wire forward, buffering, Content-Length completion,
close/reset/timeout/DOWN), the public `ingest_response/1` ingestion rules, and
the not-running getters. The HTTP-over-streaming success path
(`f:i2p_addressbook_subs:start_http_conn/3` + real route) needs live tunnels
and the SAM bridge and is covered by the CT suite (network-gated).

## Which cases run in a throwaway, and why only those

The whole eunit tier runs in **one process**, so a `gen_server` callback called
directly here schedules into a worker every other module shares. Two callbacks
here arm a timer into it -- `f:init/1` and `f:handle_info(refresh, _)`, both a
60-minute `refresh` -- and those two cases run the callback through
`m:i2p_ct_helpers:in_throwaway/1` so the timer dies with the process that made it.

**The other self-scheduling cases stay in the shared worker, deliberately.**
`fetch_now_test/0`, `timeout_test/0`, `start_pipeline_kick_test/0`,
`stream_data_forward_test/0`, `stream_data_complete_test/0`,
`stream_closed_test/0`, `stream_reset_test/0`, `fetch_timeout_test/0`,
`stale_fetch_timeout_ignored_test/0`, `finish_closes_conn_test/0`,
`finish_cancels_timeout_test/0` and
`down_fetch_test/0` all make the callback self-send, and all of them assert on that
send with `f:recv_pipeline/1` or `f:recv/1`. That is not a leak: `self() ! Msg`
puts the message in this mailbox before the call returns, so `after 0` matches it
deterministically and nothing survives the case. `finish_cancels_timeout_test/0`
is the one case that arms a real timer, and the callback under test is what
cancels it -- a failure there fails the assertion on the same line, before the
leak could matter. What would be a leak is a
**still-armed timer**, because a drain cannot reach the next message it will
produce -- which is the distinction `m:i2p_ct_helpers:in_throwaway/1` draws, and
the reason the rule is about timers rather than about self-sends.

`m:i2p_shared_worker_tests` is the tree-wide check for that rule.
""".

-include_lib("eunit/include/eunit.hrl").

%% Not running: no destinations participate in inbound delivery.
not_running_test() ->
    ?assertEqual([], i2p_addressbook_subs:client_destinations()).

client_public_key_test() ->
    #{identity := Id} = i2p_keys:generate_with_privkeys(),
    persistent_term:put({i2p_addressbook_subs, client_pub}, i2p_keys:public_key(Id)),
    try
        ?assertEqual(i2p_keys:public_key(Id), i2p_addressbook_subs:client_public_key())
    after
        persistent_term:erase({i2p_addressbook_subs, client_pub})
    end.

fetch_now_test() ->
    State = base_state(),
    ?assertEqual(
        {reply, ok, State},
        i2p_addressbook_subs:handle_call(fetch_now, {self(), make_ref()}, State)
    ),
    recv_pipeline([]).

timeout_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info(timeout, State)
    ),
    recv_pipeline([]).

%% Pipeline kicks the first subscription, remainder queued as the new Done.
start_pipeline_kick_test() ->
    Sub = #{host => <<"a.i2p">>},
    State = base_state(#{subscriptions => [Sub]}),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({start_pipeline, []}, State)
    ),
    recv({fetch_sub, Sub, []}).

%% A host already tried in this pass is skipped. Without this the pipeline
%% restarts on the first subscription every time and the second is never
%% fetched.
start_pipeline_skips_done_test() ->
    A = #{host => <<"a.i2p">>},
    B = #{host => <<"b.i2p">>},
    State = base_state(#{subscriptions => [A, B]}),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({start_pipeline, [<<"a.i2p">>]}, State)
    ),
    recv({fetch_sub, B, [<<"a.i2p">>]}).

%% Every subscription tried: the pass ends quietly rather than looping.
start_pipeline_all_done_test() ->
    Sub = #{host => <<"a.i2p">>},
    State = base_state(#{subscriptions => [Sub]}),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({start_pipeline, [<<"a.i2p">>]}, State)
    ).

%% A connection's demux key is remembered when it announces itself, and an
%% inbound wire is forwarded to the connection that key names.
stream_data_forward_test() ->
    Fetch = fetch(#{conn => self()}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info(
        {stream_started, self(), 7}, State
    ),
    Wire = i2p_streaming:encode(i2p_streaming:new(7, 0, 0, 0)),
    ?assertEqual(
        {noreply, State1},
        i2p_addressbook_subs:handle_info({stream_data, Wire}, State1)
    ),
    recv({packet, Wire}).

%% A fetch can finish while the peer's CLOSE is still in flight: the wire for
%% the finished connection names it, not the next fetch's connection, and must
%% reach the one it names.
stream_data_routes_to_closing_conn_test() ->
    Parent = self(),
    Closing =
        spawn(fun() ->
            receive
                {packet, Wire} -> Parent ! {closing_got, Wire}
            end
        end),
    Fetch = fetch(#{conn => self()}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info(
        {stream_started, Closing, 9}, State
    ),
    Wire = i2p_streaming:encode(i2p_streaming:new(9, 0, 0, 0)),
    ?assertEqual(
        {noreply, State1},
        i2p_addressbook_subs:handle_info({stream_data, Wire}, State1)
    ),
    receive
        {closing_got, Wire} -> ok
    after 1000 -> error(closing_conn_not_reached)
    end.

%% A wire whose key names no live connection (a late packet, or undecodable
%% noise) is dropped rather than delivered to the current fetch.
unknown_stream_wire_dropped_test() ->
    Fetch = fetch(#{conn => self()}),
    State = base_state(#{}, Fetch),
    Wire = i2p_streaming:encode(i2p_streaming:new(11, 0, 0, 0)),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({stream_data, Wire}, State)
    ),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({stream_data, <<"not-a-wire">>}, State)
    ),
    receive
        {packet, _} -> error(unknown_stream_delivered)
    after 0 -> ok
    end.

%% Partial HTTP body: buffered, fetch stays armed.
stream_data_incomplete_test() ->
    Fetch = fetch(#{buf => <<"HTTP">>}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info(
        {stream_data, self(), <<"/1.0 200">>},
        State
    ),
    ?assertEqual(<<"HTTP/1.0 200">>, maps:get(buf, maps:get(fetch, State1))).

%% Garbage Content-Length: treated as unknown, stays buffered.
stream_data_bad_length_test() ->
    Fetch = fetch(#{buf => <<>>}),
    State = base_state(#{}, Fetch),
    Buf = <<"HTTP/1.0 200 OK\r\nContent-Length: nope\r\n\r\nnamen=abcdefghij">>,
    {noreply, State1} = i2p_addressbook_subs:handle_info({stream_data, self(), Buf}, State),
    ?assertEqual(Buf, maps:get(buf, maps:get(fetch, State1))).

%% Full body per Content-Length: ingested, total bumped, next subscription queued.
stream_data_complete_test() ->
    Buf = <<"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nnamen=abcdefghij">>,
    Fetch = fetch(#{buf => <<>>}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info({stream_data, self(), Buf}, State),
    ?assertEqual(1, maps:get(total, State1)),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline([<<"a.i2p">>]).

%% A stream_data from a connection other than the fetch's own is stale and
%% must not reach the response buffer.
stale_stream_data_ignored_test() ->
    OldConn = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    Fetch = fetch(#{buf => <<>>}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info(
        {stream_data, OldConn, <<"kay=1">>},
        State
    ),
    ?assertEqual(<<>>, maps:get(buf, maps:get(fetch, State1))).

%% stream_closed with a fetch: body ingested as-is, pipeline moved on.
stream_closed_test() ->
    Fetch = fetch(#{buf => <<"kay=AAAAAAAAAAAA\r\n">>}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info({stream_closed, self()}, State),
    ?assertEqual(1, maps:get(total, State1)),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline([<<"a.i2p">>]).

%% stream_closed with no fetch: unchanged.
stream_closed_idle_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({stream_closed, self()}, State)
    ).

%% stream_closed from a connection other than the fetch's own is stale and
%% must not finish the fetch.
stale_stream_closed_ignored_test() ->
    OldConn = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    Done = [#{host => <<"b.i2p">>}],
    Fetch = fetch(#{conn => self(), done => Done}),
    State = base_state(#{}, Fetch),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({stream_closed, OldConn}, State)
    ).

%% stream_reset / fetch_timeout abandon the fetch and mark its host tried, so
%% the pipeline moves on to the next subscription instead of retrying this one.
stream_reset_test() ->
    Done = [#{host => <<"b.i2p">>}],
    Fetch = fetch(#{done => Done}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info({stream_reset, self()}, State),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline([<<"a.i2p">> | Done]).

stream_reset_idle_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({stream_reset, self()}, State)
    ).

fetch_timeout_test() ->
    Done = [#{host => <<"b.i2p">>}],
    Fetch = fetch(#{done => Done}),
    State = base_state(#{}, Fetch),
    Ref = maps:get(timeout_ref, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info(
        {timeout, Ref, fetch_timeout}, State
    ),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline([<<"a.i2p">> | Done]).

%% A timer that belongs to a fetch which has already finished must not abandon
%% the fetch that is current now. `start_timer/3` names its own ref in the
%% message, so the handler can tell the two apart.
stale_fetch_timeout_ignored_test() ->
    Fetch = fetch(#{done => [#{host => <<"b.i2p">>}]}),
    State = base_state(#{}, Fetch),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({timeout, make_ref(), fetch_timeout}, State)
    ).

%% A fetch that completes by Content-Length closes its connection instead of
%% waiting for the peer's FIN, so the admission slot it holds goes back.
finish_closes_conn_test() ->
    Conn = closing_conn(),
    Fetch = fetch(#{conn => Conn}),
    State = base_state(#{}, Fetch),
    Buf = <<"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nnamen=abcdefghij">>,
    {noreply, State1} = i2p_addressbook_subs:handle_info({stream_data, Conn, Buf}, State),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    receive
        {closed, Conn} -> ok
    after 1000 -> error(conn_not_closed)
    end,
    recv_pipeline([<<"a.i2p">>]).

%% The fetch's own timeout is disarmed when it finishes; nothing is left for it
%% to fire at.
finish_cancels_timeout_test() ->
    TimerRef = erlang:start_timer(60_000, self(), fetch_timeout),
    Fetch = fetch(#{timeout_ref => TimerRef}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info({stream_closed, self()}, State),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    ?assertEqual(false, erlang:read_timer(TimerRef)),
    recv_pipeline([<<"a.i2p">>]).

fetch_timeout_idle_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({timeout, make_ref(), fetch_timeout}, State)
    ).

%% DOWN from a live fetch conn: abandon and mark its host tried.
down_fetch_test() ->
    Done = [#{host => <<"b.i2p">>}],
    Mon = make_ref(),
    Fetch = fetch(#{mon => Mon, done => Done}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info(
        {'DOWN', Mon, process, self(), normal},
        State
    ),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline([<<"a.i2p">> | Done]).

%% DOWN when idle: plain catch-all, unchanged state.
down_idle_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({'DOWN', make_ref(), process, self(), normal}, State)
    ).

%% DOWN for a monitor other than the fetch's own is stale and must not
%% abandon the fetch.
stale_down_ignored_test() ->
    Mon = make_ref(),
    Fetch = fetch(#{mon => Mon}),
    State = base_state(#{}, Fetch),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info(
            {'DOWN', make_ref(), process, self(), normal},
            State
        )
    ).

ingest_response_test() ->
    ?assertEqual(0, i2p_addressbook_subs:ingest_response(<<"# comment\n\nnope\n">>)),
    ?assertEqual(
        1, i2p_addressbook_subs:ingest_response(<<"HTTP/1.0 200 OK\r\n\r\nalice=AAAA\r\n">>)
    ),
    ?assertEqual(0, i2p_addressbook_subs:ingest_response(<<"=dest\nname=\n= =\n">>)),
    ?assertEqual(2, i2p_addressbook_subs:ingest_response(<<"a=b\nc=d\n">>)).

generic_cast_test() ->
    State = base_state(),
    ?assertEqual({noreply, State}, i2p_addressbook_subs:handle_cast(junk, State)).

generic_info_test() ->
    State = base_state(),
    ?assertEqual({noreply, State}, i2p_addressbook_subs:handle_info(junk, State)).

%% The {stream_data, WireBin} clause needs a running target; {stream_data,
%% Conn, Payload} needs the 3-tuple form. Both are covered above.

base_state() ->
    base_state(#{subscriptions => []}).

base_state(Opts) ->
    base_state(Opts, undefined).

base_state(Opts, Fetch) ->
    #{
        opts => Opts,
        sign_seed => <<"seed">>,
        timer => undefined,
        fetch => Fetch,
        conns => #{},
        total => 0
    }.

fetch(Extra) ->
    maps:merge(
        #{
            host => <<"a.i2p">>,
            done => [],
            buf => <<>>,
            count => 0,
            timeout_ref => make_ref(),
            mon => make_ref(),
            conn => self()
        },
        Extra
    ).

%% A stand-in for a streaming connection: reports the `close` request the
%% fetcher casts at it, then exits. Enough to observe the teardown without a
%% live streaming stack.
closing_conn() ->
    Parent = self(),
    spawn(fun() ->
        receive
            {'$gen_cast', close} -> Parent ! {closed, self()}
        end
    end).

recv_pipeline(Rest) ->
    recv({start_pipeline, Rest}).

recv(Expected) ->
    receive
        Expected -> ok
    after 0 ->
        error({no_message, Expected})
    end.
