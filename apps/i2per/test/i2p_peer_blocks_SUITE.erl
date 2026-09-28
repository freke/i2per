%% Peer-manager handling of forwarded SSU2 blocks.
%%
%% `m:i2p_ssu2_conn` forwards more than I2NP messages to the owner: the
%% introducer-relay blocks (7/8/9 and the 15/16 tag exchange), the peer-test
%% blocks (1-4), RouterInfo blocks, and the path-challenge/response pair. The
%% peer manager used to select only `{i2np, …}` tuples and discard the rest with
%% no log, no event and no counter, so a peer could send those blocks forever
%% and nothing anywhere recorded it. These cases pin the replacement: such a
%% block is named on the bus and warned about once per peer and kind, and I2NP
%% messages still take the dispatch path rather than being classified as
%% unhandled.

-module(i2p_peer_blocks_SUITE).

-export([all/0, suite/0, init_per_testcase/2, end_per_testcase/2]).

-export([
    unhandled_blocks_are_named/1,
    i2np_messages_are_not_unhandled/1,
    warn_once_per_peer_and_kind/1
]).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        unhandled_blocks_are_named,
        i2np_messages_are_not_unhandled,
        warn_once_per_peer_and_kind
    ].

init_per_testcase(_Case, Config) ->
    ok = i2p_ct_helpers:stop_app(),
    %% Standalone processes only. Starting the whole application would leave
    %% `i2p_tunnel_srv` running when this suite ends, and the suites that
    %% follow start it themselves — which fails them with `already_started`.
    %% This suite needs the event bus and the peer manager and nothing else;
    %% `f:i2p_peer:init/1` reaches no other process when given no seeds.
    {ok, _Events} = i2p_events:start_link(),
    ok = gen_event:add_handler(i2p_events, i2p_events_forward, [self()]),
    Dir = ?config(priv_dir, Config),
    {ok, Id} = i2p_identity:ensure_identity(Dir),
    Local = i2p_identity:build_local(Id, <<"127.0.0.1">>, 9150, maps:get(sign_seed, Id)),
    {ok, Peer} = i2p_peer:start_link(Local, []),
    [{peer, Peer} | Config].

end_per_testcase(_Case, _Config) ->
    _ = catch gen_event:delete_handler(i2p_events, i2p_events_forward, []),
    _ = catch i2p_peer:stop(),
    _ = catch gen_event:stop(i2p_events),
    ok = i2p_ct_helpers:stop_app(),
    ok.

%% --------------------------------------------------------------------------
%% Cases
%% --------------------------------------------------------------------------

%% Every shape the SSU2 codec forwards to the owner other than an I2NP message
%% is named on the bus. This is the regression: before, none of them produced
%% any observable at all.
unhandled_blocks_are_named(Config) ->
    Peer = ?config(peer, Config),
    Expected = [
        peertest,
        path_challenge,
        path_response,
        relay_intro,
        relay_request,
        relay_response,
        relay_tag,
        relay_tag_request,
        router_info
    ],
    Got = [send_and_await(Kind) || Kind <- Expected],
    ?assertEqual(lists:sort(Expected), lists:sort(Got)),
    ?assert(is_process_alive(Peer)),
    ?assertEqual(lists:sort(Expected), lists:sort(warned_names(Peer))).

%% An I2NP message must still be dispatched rather than classified as unhandled.
%% Type 10 (DeliveryStatus) is the probe because `f:handle_block/4` returns it
%% unchanged, so this case tests the partition and not the NetDb.
i2np_messages_are_not_unhandled(Config) ->
    Peer = ?config(peer, Config),
    Delivery = {i2np, 10, 7, 0, <<>>},
    i2p_peer ! {ssu2_data, self(), [Delivery, block(relay_tag)]},
    %% Exactly one event: the relay block. The I2NP message produced none.
    ?assertEqual([relay_tag], drain(500)),
    ?assertEqual([relay_tag], lists:sort(warned_names(Peer))).

%% The log is a diagnostic, not a firehose. A peer repeating a block must not
%% grow the warned set, or the flood becomes the flood.
warn_once_per_peer_and_kind(Config) ->
    Peer = ?config(peer, Config),
    Intro = block(relay_intro),
    i2p_peer ! {ssu2_data, self(), [Intro, Intro, Intro]},
    ?assertEqual(ok, await_warned(Peer, 1, 5000)),
    %% A different kind from the same peer adds its own key.
    i2p_peer ! {ssu2_data, self(), [block(relay_tag_request)]},
    ?assertEqual(ok, await_warned(Peer, 2, 5000)),
    %% Repeats add nothing.
    i2p_peer ! {ssu2_data, self(), [Intro, Intro]},
    ?assertEqual(ok, await_warned(Peer, 2, 1000)),
    ?assertEqual(2, maps:size(warned(Peer))).

%% --------------------------------------------------------------------------
%% Block fixtures — one representative per shape `f:forward_block/2` forwards.
%% Fragments are deliberately absent: they are reassembled into whole I2NP
%% messages in the session and never reach the owner in that form.
%% --------------------------------------------------------------------------

block(peertest) ->
    {peertest, 3, 0, 0, <<0:256>>, 2, 7, 111, 9150, {127, 0, 0, 1}, <<0:512>>};
block(relay_request) ->
    {relay_request, 0, 7, 9, 111, 2, 9150, {127, 0, 0, 1}, <<0:512>>};
block(relay_response) ->
    {relay_response, 0, 0, 7, 111, 2, 9150, {127, 0, 0, 1}, <<0:512>>, 0};
block(relay_intro) ->
    {relay_intro, 0, <<1:256>>, 7, 9, 111, 2, 9150, {127, 0, 0, 1}, <<0:512>>};
block(relay_tag_request) ->
    relay_tag_request;
block(relay_tag) ->
    {relay_tag, 12345};
block(router_info) ->
    {router_info, 0, <<"ri">>};
block(path_challenge) ->
    {path_challenge, <<"probe">>};
block(path_response) ->
    {path_response, <<"proof">>}.

%% --------------------------------------------------------------------------
%% Helpers
%% --------------------------------------------------------------------------

send_and_await(Kind) ->
    i2p_peer ! {ssu2_data, self(), [block(Kind)]},
    receive
        {event, {ssu2_block_unhandled, Got}} -> Got
    after 5000 ->
        ct:fail({no_unhandled_event, Kind})
    end.

drain(Timeout) ->
    receive
        {event, {ssu2_block_unhandled, Kind}} -> [Kind | drain(Timeout)]
    after Timeout ->
        []
    end.

warned(Peer) ->
    maps:get(unhandled_ssu2_blocks, sys:get_state(Peer), #{}).

warned_names(Peer) ->
    [Name || {{_Identity, Name}, true} <- maps:to_list(warned(Peer))].

await_warned(Peer, N, Timeout) ->
    case maps:size(warned(Peer)) of
        N ->
            ok;
        _ ->
            timer:sleep(50),
            case Timeout =< 0 of
                true -> {error, {warned_size, N, maps:size(warned(Peer))}};
                false -> await_warned(Peer, N, Timeout - 50)
            end
    end.
