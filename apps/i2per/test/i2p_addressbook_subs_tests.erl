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
`stream_closed_test/0`, `stream_reset_test/0`, `fetch_timeout_test/0` and
`down_fetch_test/0` all make the callback self-send, and all of them assert on that
send with `f:recv_pipeline/1` or `f:recv/1`. That is not a leak: `self() ! Msg`
puts the message in this mailbox before the call returns, so `after 0` matches it
deterministically and nothing survives the case. What would be a leak is a
**still-armed timer**, because a drain cannot reach the next message it will
produce -- which is the distinction `m:i2p_ct_helpers:in_throwaway/1` draws, and
the reason the rule is about timers rather than about self-sends.

`m:i2p_shared_worker_tests` is the tree-wide check for that rule.
""".

-include_lib("eunit/include/eunit.hrl").

%% `f:init/1` arms an hour-long `refresh` into its caller and puts three keys in
%% `persistent_term`, so the two halves of it need opposite handling.
%%
%% The timer is the reason this case runs the callback in
%% `m:i2p_ct_helpers:in_throwaway/1`: the whole eunit tier is one process (measured
%% -- see that helper), so a timer armed here stays armed for every module that
%% runs after this one, and at T+60min it fires `refresh` into whichever module is
%% running by then, which self-sends `{start_pipeline, []}` into a mailbox it does
%% not own. `?assert(is_reference(maps:get(timer, State)))` below is the assertion
%% that `f:init/1` really does schedule, and it is worth keeping -- what it was not
%% worth is *where* that timer was being armed.
%%
%% The `persistent_term` writes are global rather than per-process, so the
%% throwaway does not contain them and the `after` still has to erase all three.
%% Leaving them is the same class of leak one directory away, and it is the reason
%% the `after` is not simply "the throwaway cleans up".
init_test() ->
    Opts = #{subscriptions => []},
    try
        {ok, State, Timeout} = i2p_ct_helpers:in_throwaway(fun() ->
            i2p_addressbook_subs:init([Opts])
        end),
        ?assertEqual(0, Timeout),
        ?assertEqual(Opts, maps:get(opts, State)),
        ?assert(is_binary(maps:get(sign_seed, State))),
        ?assert(is_reference(maps:get(timer, State))),
        ?assertEqual(undefined, maps:get(fetch, State)),
        ?assertEqual(60, maps:get(interval_min, Opts, 60)),
        Pub = i2p_addressbook_subs:client_public_key(),
        ?assertEqual(32, byte_size(Pub))
    after
        persistent_term:erase({i2p_addressbook_subs, identity}),
        persistent_term:erase({i2p_addressbook_subs, client_pub}),
        persistent_term:erase({i2p_addressbook_subs, crypto_priv})
    end.

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

%% `refresh` does both halves of what `f:init/1` does -- it re-arms the hour-long
%% timer *and* self-sends `{start_pipeline, []}` -- so it runs in a throwaway for
%% the reason `init_test/0` does.
%%
%% **The self-send is asserted inside the throwaway, not drained afterwards**, and
%% the distinction is the point. `f:recv_pipeline/1` is an assertion that the
%% callback scheduled work, not cleanup: it matches `{start_pipeline, []}` with
%% `after 0` and fails if nothing is there. Run outside the throwaway it would be
%% reading the shared worker's mailbox, which is the coupling this whole ticket is
%% about -- so it belongs on the far side of the same boundary as the call.
refresh_test() ->
    {State1, ok} = i2p_ct_helpers:in_throwaway(fun() ->
        {noreply, State} = i2p_addressbook_subs:handle_info(refresh, base_state()),
        {State, recv_pipeline([])}
    end),
    ?assert(is_reference(maps:get(timer, State1))),
    ?assertNotEqual(undefined, maps:get(timer, State1)).

%% Pipeline already drained: nothing left to fetch.
start_pipeline_done_test() ->
    Sub = #{host => <<"a.i2p">>},
    State = base_state(#{subscriptions => [Sub]}),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({start_pipeline, [Sub]}, State)
    ).

%% Pipeline kicks the first subscription, remainder queued as the new Done.
start_pipeline_kick_test() ->
    Sub = #{host => <<"a.i2p">>},
    State = base_state(#{subscriptions => [Sub]}),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({start_pipeline, []}, State)
    ),
    recv({fetch_sub, Sub, []}).

%% Subscription whose destination resolves to nothing: skip it, move on.
fetch_sub_no_route_test() ->
    Owner = ensure_netdb(),
    try
        Keys = i2p_keys:generate_with_privkeys(),
        Blob = i2p_keys:encode_b64(i2p_keys:dest_blob(Keys)),
        Sub = #{host => <<"s.i2p">>, dest_b64 => Blob},
        State = base_state(),
        ?assertEqual(
            {noreply, State},
            i2p_addressbook_subs:handle_info({fetch_sub, Sub, []}, State)
        ),
        recv_pipeline([])
    after
        case Owner of
            started -> gen_server:stop(whereis(i2p_netdb_srv));
            existing -> ok
        end
    end.

%% Inbound wire while a fetch is active: forwarded to its streaming conn.
stream_data_forward_test() ->
    Fetch = fetch(#{conn => self()}),
    State = base_state(#{}, Fetch),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({stream_data, <<"WIRE0">>}, State)
    ),
    recv({packet, <<"WIRE0">>}).

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
    recv_pipeline([]).

%% stream_closed with a fetch: body ingested as-is, pipeline moved on.
stream_closed_test() ->
    Fetch = fetch(#{buf => <<"kay=AAAAAAAAAAAA\r\n">>}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info({stream_closed, self()}, State),
    ?assertEqual(1, maps:get(total, State1)),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline([]).

%% stream_closed with no fetch: unchanged.
stream_closed_idle_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({stream_closed, self()}, State)
    ).

%% stream_reset / fetch_timeout abandon the fetch and requeue the rest.
stream_reset_test() ->
    Rest = [#{host => <<"b.i2p">>}],
    Fetch = fetch(#{rest => Rest}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info({stream_reset, self()}, State),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline(Rest).

stream_reset_idle_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({stream_reset, self()}, State)
    ).

fetch_timeout_test() ->
    Rest = [#{host => <<"b.i2p">>}],
    Fetch = fetch(#{rest => Rest}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info(fetch_timeout, State),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline(Rest).

fetch_timeout_idle_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info(fetch_timeout, State)
    ).

%% DOWN from a live fetch conn: abandon and requeue the rest.
down_fetch_test() ->
    Rest = [#{host => <<"b.i2p">>}],
    Fetch = fetch(#{rest => Rest}),
    State = base_state(#{}, Fetch),
    {noreply, State1} = i2p_addressbook_subs:handle_info(
        {'DOWN', make_ref(), process, self(), normal},
        State
    ),
    ?assertEqual(undefined, maps:get(fetch, State1)),
    recv_pipeline(Rest).

%% DOWN when idle: plain catch-all, unchanged state.
down_idle_test() ->
    State = base_state(),
    ?assertEqual(
        {noreply, State},
        i2p_addressbook_subs:handle_info({'DOWN', make_ref(), process, self(), normal}, State)
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
        total => 0
    }.

fetch(Extra) ->
    maps:merge(
        #{
            host => <<"a.i2p">>,
            rest => [],
            buf => <<>>,
            count => 0,
            timeout_ref => make_ref(),
            conn => self()
        },
        Extra
    ).

recv_pipeline(Rest) ->
    recv({start_pipeline, Rest}).

recv(Expected) ->
    receive
        Expected -> ok
    after 0 ->
        error({no_message, Expected})
    end.

ensure_netdb() ->
    case whereis(i2p_netdb_srv) of
        undefined ->
            {ok, _} = i2p_netdb_srv:start_link(),
            started;
        _Pid ->
            existing
    end.
