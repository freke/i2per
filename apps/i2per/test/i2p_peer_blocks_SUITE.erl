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
    warn_once_per_peer_and_kind/1,
    wedged_subscriber_does_not_block_a_notifier/1
]).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

suite() ->
    [{timetrap, 30000}].

all() ->
    [
        unhandled_blocks_are_named,
        i2np_messages_are_not_unhandled,
        warn_once_per_peer_and_kind,
        wedged_subscriber_does_not_block_a_notifier
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
%% A wedged subscriber does not stall a notifier. **This is already true, and
%% this case is the reason to believe it.**
%%
%% #4F1M83V was filed on the claim that `f:i2p_events:notify/1` is a *call* to
%% the `gen_event` manager and that a slow handler therefore holds every notifier.
%% Read against OTP 28's source it is not. `gen_event:notify/2` is
%% `send(M, {notify, Event})` -- a cast. The synchronous entry point is
%% `f:gen_event:sync_notify/2`, which is `rpc/2`, and the manager replies to it
%% *after* `server_notify/4` has walked the handlers:
%%
%%     {notify, Event}                     -> server_notify(...), loop(...)          % no reply
%%     {_From, Tag, {sync_notify, Event}}  -> server_notify(...), reply(Tag, ok)     % replies after
%%
%% So the notifier is not waiting on anything, and the router's data path is not
%% coupled to a presentation app's handler at all. Both messages below are
%% required: the notifier returning proves it was not held, and the handler
%% reporting entry proves the manager really was inside it, so neither can pass
%% for the wrong reason.
%%
%% **What it is guarding, given the property already holds.** Two plausible
%% regressions, both of which would reintroduce the coupling this ticket feared
%% and neither of which any other case would notice:
%%
%% - someone "fixing" a perceived stall by switching to `f:sync_notify/2`, which
%%   really would make every notifier wait on every handler;
%% - someone wrapping the `send/2` in a `gen_server:call/2` for delivery
%%   confirmation, which has the same effect by another route.
%%
%% **The notifier is a separate process because the property is about the caller.**
%% A caller that has blocked cannot assert that it did not, so the notify runs in
%% a spawned process and the case waits for it to report.
%%
%% **Deliberately not driven through the peer manager.** The obvious version is,
%% and it is unsound: the peer manager also emits a deduplicated warning through
%% `m:i2p_log`, whose stdout backend blocks under CT's captured output. A
%% stacktrace from that version parked the peer manager in
%% `logger_backend:call_handlers/3` -- log backpressure, not the bus -- so a
%% timeout there would have measured the harness and been filed as a defect.
wedged_subscriber_does_not_block_a_notifier(_Config) ->
    ok = gen_event:add_handler(i2p_events, i2p_test_wedged_handler, [self()]),
    %% Bound before the `try`: a variable bound inside a `try` is not visible in
    %% its `after`, and the `after` is what lets the handler go.
    Wedged =
        receive
            {wedged_handler, added, Pid} -> Pid
        after 5000 ->
            ct:fail(wedged_handler_never_started)
        end,
    try
        Me = self(),
        _Notifier = spawn(fun() ->
            Me ! {notified, catch i2p_events:notify({transit_denied, 1, capacity})}
        end),

        receive
            {wedged_handler, entered, Entered} ->
                %% The manager is inside the handler, and this is the one the
                %% `after` releases.
                ?assertEqual(Wedged, Entered)
        after 5000 ->
            ct:fail(wedged_handler_never_entered)
        end,

        receive
            {notified, ok} -> ok;
            {notified, Other} -> ct:fail({notifier_got_a_wrong_answer, Other})
        after 2000 ->
            ct:fail(notifier_was_made_to_wait)
        end
    after
        %% Release before deleting: `delete_handler` is a call to the manager, so
        %% it would queue behind the very handler it is meant to remove.
        Wedged ! release,
        _ = catch gen_event:delete_handler(i2p_events, i2p_test_wedged_handler, []),
        ok
    end.

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
