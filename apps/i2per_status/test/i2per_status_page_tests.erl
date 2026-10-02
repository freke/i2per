-module(i2per_status_page_tests).

-moduledoc """
Tests for the pure HTML rendering of `m:i2per_status_page`: online table,
offline notice, and the `n/a` fallbacks when snapshot sections are missing.
""".

-include_lib("eunit/include/eunit.hrl").

full_snapshot() ->
    #{
        online => true,
        identity => <<"abc123">>,
        peers => #{connected => 3, other => 2},
        tunnels => #{outbound => 1, inbound => 2, transit => 4},
        netdb => #{ri => 9, ls => 0},
        sessions => 5
    }.

online_renders_report_table_test() ->
    Body = render(full_snapshot()),
    asserts(
        [
            <<"identity: <code>abc123</code>">>,
            <<"<tr><td>peers connected</td><td>3</td></tr>">>,
            <<"<tr><td>tunnels outbound</td><td>1</td></tr>">>,
            <<"<tr><td>tunnels inbound</td><td>2</td></tr>">>,
            <<"<tr><td>transit tunnels</td><td>4</td></tr>">>,
            <<"<tr><td>netdb router infos</td><td>9</td></tr>">>,
            <<"<tr><td>netdb leasesets</td><td>0</td></tr>">>,
            <<"<tr><td>SAM sessions</td><td>5</td></tr>">>
        ],
        Body
    ),
    ?assertNotEqual(nomatch, binary:match(Body, <<"</table>">>)).

offline_renders_notice_test() ->
    Body = render(#{online => false}),
    ?assertNotEqual(nomatch, binary:match(Body, <<"<b>router offline</b>">>)).

missing_sections_render_na_test() ->
    %% Every section absent, and no derived block: each metric says `n/a` by name.
    %%
    %% This case used to assert a single total -- "seven `n/a` rows" -- which reads
    %% like a count of the sections and is really a count of the rows. Adding the
    %% derived rows then broke a test that was not about them, which is the wrong
    %% reason for a test to fail. Naming each metric instead says what it means and
    %% survives rows being added.
    Body = render(#{online => true}),
    lists:foreach(
        fun(Metric) ->
            ?assertNotEqual(nomatch, binary:match(Body, metric_row(Metric, <<"n/a">>)))
        end,
        [
            <<"peers connected">>,
            <<"tunnels outbound">>,
            <<"tunnels inbound">>,
            <<"transit tunnels">>,
            <<"netdb router infos">>,
            <<"netdb leasesets">>,
            <<"SAM sessions">>,
            <<"transfer rate">>,
            <<"tunnel success">>
        ]
    ),
    %% And the window row says why, rather than being another bare `n/a`: no
    %% reading at all is a different state from a reading with no window yet.
    ?assertNotEqual(
        nomatch, binary:match(Body, metric_row(<<"rate window">>, <<"no reading yet">>))
    ).

%% A derived block with a real window renders the rate, the ratio, the window, and
%% says the figures are derived. This is the visible half of the ticket: the
%% numbers exist in the snapshot, but an operator reading them needs the window
%% and the provenance beside them or the number is not interpretable.
derived_figures_are_shown_with_their_window_test() ->
    Snap = (full_snapshot())#{
        derived =>
            #{
                window_status => ok,
                window_ms => 5000,
                sampled_at => 1_700_000_000_000,
                transfer_bps => #{ntcp2 => 4000, ssu2 => 1000, transit => 9000, total => 5000},
                tunnel_success_ratio => 0.75,
                tunnels_built => 3,
                tunnels_failed => 1
            }
    },
    Body = render(Snap),
    asserts(
        [
            metric_row(<<"transfer rate">>, <<"5000 B/s">>),
            metric_row(<<"tunnel success">>, <<"75%">>),
            metric_row(<<"tunnels built">>, <<"3">>),
            metric_row(<<"tunnels failed">>, <<"1">>),
            metric_row(<<"rate window">>, <<"5000 ms">>),
            metric_row(<<"figures">>, <<"derived by this client from cumulative counters">>)
        ],
        Body
    ),
    ?assertNotEqual(nomatch, binary:match(Body, <<"2023-11-14">>)).

%% The three discard reasons are distinct states and each is stated. Collapsing
%% them into "n/a" would hide the one an operator has to act on: a router that
%% restarted, which is not the same as a router that has not been sampled twice.
window_discard_reasons_are_distinguished_test() ->
    lists:foreach(
        fun({Status, Expected}) ->
            Snap = (full_snapshot())#{
                derived =>
                    #{
                        window_status => Status,
                        window_ms => undefined,
                        sampled_at => 1_700_000_000_000,
                        transfer_bps => #{
                            ntcp2 => undefined,
                            ssu2 => undefined,
                            transit => undefined,
                            total => undefined
                        },
                        tunnel_success_ratio => 0.5,
                        tunnels_built => 1,
                        tunnels_failed => 1
                    }
            },
            Body = render(Snap),
            ?assertNotEqual(nomatch, binary:match(Body, Expected))
        end,
        [
            {no_previous_sample, <<"one reading so far">>},
            {router_restarted, <<"discarded: the router restarted">>},
            {counter_went_backwards, <<"discarded: a counter decreased">>},
            {zero_window, <<"discarded: both readings have the same uptime">>}
        ]
    ).

%% A ratio of zero over zero has no value, and the page must not render it as
%% "0% successful", which reads as total failure.
ratio_with_no_attempts_renders_na_test() ->
    Snap = (full_snapshot())#{
        derived =>
            #{
                window_status => no_previous_sample,
                window_ms => undefined,
                sampled_at => 1_700_000_000_000,
                transfer_bps => #{
                    ntcp2 => undefined, ssu2 => undefined, transit => undefined, total => undefined
                },
                tunnel_success_ratio => undefined,
                tunnels_built => 0,
                tunnels_failed => 0
            }
    },
    Body = render(Snap),
    ?assertNotEqual(nomatch, binary:match(Body, metric_row(<<"tunnel success">>, <<"n/a">>))),
    ?assertEqual(nomatch, binary:match(Body, <<"0%">>)).

%% The reachability verdict is the reason the `reachability` event is counted, and
%% the reason is visible: a total of reachability events would be a history, and
%% what an operator needs is what the router currently believes.
reachability_verdict_is_shown_test() ->
    Snap = (full_snapshot())#{last_reachability => firewalled},
    Body = render(Snap),
    ?assertNotEqual(nomatch, binary:match(Body, metric_row(<<"reachability">>, <<"firewalled">>))).

%% Before the router has announced one, the page says so rather than guessing.
reachability_verdict_is_na_before_it_is_announced_test() ->
    Body = render(full_snapshot()),
    ?assertNotEqual(nomatch, binary:match(Body, metric_row(<<"reachability">>, <<"n/a">>))).

%% The per-verdict counts are shown beside the verdict, so an operator can tell a
%% settled verdict from one that is still moving.
reachability_verdict_counts_are_shown_test() ->
    Snap = (full_snapshot())#{
        last_reachability => reachable,
        events => #{
            {reachability, reachable} => 4,
            {reachability, firewalled} => 1,
            {reachability, unknown} => 0
        }
    },
    Body = render(Snap),
    ?assertNotEqual(nomatch, binary:match(Body, <<"reachable 4, firewalled 1, unknown 0">>)).

%% A metric and its rendered value, as the page emits them.
metric_row(Metric, Value) ->
    iolist_to_binary(["<tr><td>", Metric, "</td><td>", Value, "</td></tr>"]).

non_integer_sessions_render_na_test() ->
    Snap = (full_snapshot())#{sessions => <<"unknown">>},
    Body = render(Snap),
    ?assertNotEqual(nomatch, binary:match(Body, <<"<td>n/a</td>">>)),
    ?assertEqual(nomatch, binary:match(Body, <<">unknown<</td>">>)).

render(Snap) ->
    iolist_to_binary(i2per_status_page:html(Snap)).

asserts(Needles, Body) ->
    lists:foreach(
        fun(N) -> ?assertNotEqual(nomatch, binary:match(Body, N)) end, Needles
    ).
