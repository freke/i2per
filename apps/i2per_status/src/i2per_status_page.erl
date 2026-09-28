-module(i2per_status_page).

-moduledoc """
Cowboy handler for `GET /`: an HTML dashboard of the observed
router's state.

Renders the offline notice, with status 503, when the router is unreachable.
The notice was already what the body said; 503 makes the code agree with it,
so a consumer that only reads the status is not told a dead router is healthy.
The snapshot server being unavailable is answered the same way — the same
operational fact, and answerable, so it is answered rather than left to crash
into a 500.
""".

-export([init/2, html/1]).

init(Req0, State) ->
    Req =
        case i2per_status_state:fetch() of
            {ok, Snap} ->
                reply(status(Snap), html(Snap), Req0);
            {error, Reason} ->
                logger:warning("status page: no snapshot available: ~0p", [Reason]),
                reply(503, html(offline()), Req0)
        end,
    {ok, Req, State}.

%% 200 only when the router is actually there. The body already said so; the
%% code now agrees with it, so a monitoring consumer is not told a dead router
%% is healthy.
status(#{online := true}) -> 200;
status(_) -> 503.

reply(Status, Body, Req0) ->
    cowboy_req:reply(
        Status,
        #{<<"content-type">> => <<"text/html; charset=utf-8">>},
        Body,
        Req0
    ).

-doc """
Render the complete HTML dashboard from a `t:i2per_status_state:snapshot/0`.

Input: the snapshot returned by `i2per_status_state:snapshot/0`. Output: an
iolist; the offline branch renders the "router offline" notice. Exported so
the pure rendering can be unit-tested without a live Cowboy request.
""".
-spec html(map()) -> iolist().

%% The snapshot to render when there is no snapshot at all. Shaped like the
%% others, so the offline branch of `f:html/1` stays the only place that decides
%% what an answer with no router looks like.
offline() ->
    #{online => false}.
html(#{online := true} = Snap) ->
    [
        <<
            "<!DOCTYPE html><html><head><title>i2per status</title></head><body>"
            "<h1>i2per router</h1>"
            "<p>identity: <code>"
        >>,
        maps:get(identity, Snap, <<"-">>),
        <<
            "</code></p>"
            "<table border=\"1\">"
            "<tr><th>metric</th><th>value</th></tr>"
        >>,
        rows(Snap),
        <<"</table></body></html>">>
    ];
html(_Snap) ->
    [
        <<
            "<!DOCTYPE html><html><head><title>i2per status</title></head><body>"
            "<h1>i2per router</h1><p><b>router offline</b></p></body></html>"
        >>
    ].

rows(Snap) ->
    Flat =
        [
            {"peers connected", count(Snap, peers, connected)},
            {"tunnels outbound", count(Snap, tunnels, outbound)},
            {"tunnels inbound", count(Snap, tunnels, inbound)},
            {"transit tunnels", count(Snap, tunnels, transit)},
            {"netdb router infos", count(Snap, netdb, ri)},
            {"netdb leasesets", count(Snap, netdb, ls)},
            {"SAM sessions", sessions(Snap)}
        ] ++
            [
                {"reachability", reachability(Snap)},
                {"reachability events", reachability_events(Snap)}
            ] ++ derived_rows(Snap),
    [
        ["<tr><td>", K, "</td><td>", V, "</td></tr>"]
     || {K, V} <- Flat
    ].

%% The router's current inbound-reachability verdict, or `n/a` before it has
%% announced one. The single number that says whether anyone can reach this
%% router, and the reason the `reachability` event is counted at all.
reachability(Snap) ->
    case maps:find(last_reachability, Snap) of
        {ok, Verdict} when is_atom(Verdict) -> atom_to_binary(Verdict, utf8);
        _ -> <<"n/a">>
    end.

%% How many times each verdict has been announced, so the operator can see whether
%% the current one is settled or the verdict is still moving.
reachability_events(Snap) ->
    Events = maps:get(events, Snap, #{}),
    case
        [
            {atom_to_binary(V, utf8), maps:get({reachability, V}, Events, 0)}
         || V <- [reachable, firewalled, unknown]
        ]
    of
        [] ->
            <<"n/a">>;
        Pairs ->
            iolist_to_binary(
                lists:join(", ", [
                    <<K/binary, " ", (integer_to_binary(N))/binary>>
                 || {K, N} <- Pairs
                ])
            )
    end.

%% The derived block is absent until the first successful poll, and `undefined`
%% before that, so every reader here tolerates both and says so rather than
%% showing a zero an operator would read as "no traffic".
derived_block(Snap) ->
    case maps:find(derived, Snap) of
        {ok, Derived} when is_map(Derived) -> Derived;
        _ -> undefined
    end.

derived_rows(Snap) ->
    case derived_block(Snap) of
        undefined ->
            [
                {"transfer rate", <<"n/a">>},
                {"tunnel success", <<"n/a">>},
                {"rate window", <<"no reading yet">>}
            ];
        Derived ->
            [
                {"transfer rate", bps(maps:get(total, maps:get(transfer_bps, Derived)))},
                {"tunnel success", ratio(maps:get(tunnel_success_ratio, Derived))},
                {"tunnels built", count_or_na(maps:get(tunnels_built, Derived))},
                {"tunnels failed", count_or_na(maps:get(tunnels_failed, Derived))},
                {"rate window", window_note(Derived)},
                {"last reading", last_reading_note(Derived)},
                %% On the page, not only in the source: a reader comparing this
                %% with another router's monitor should not have to guess whether
                %% the figures are maintained averages or differences of two
                %% samples.
                {"figures", <<"derived by this client from cumulative counters">>}
            ]
    end.

%% The three discard reasons are distinct failures, and collapsing them into "n/a"
%% would hide the one that matters: a router that restarted is a different problem
%% from a router that has not been sampled twice yet.
window_note(Derived) ->
    case maps:get(window_status, Derived) of
        ok ->
            case maps:get(window_ms, Derived) of
                undefined -> <<"n/a">>;
                Ms -> <<(integer_to_binary(Ms))/binary, " ms">>
            end;
        no_previous_sample ->
            <<"one reading so far -- a rate needs two">>;
        router_restarted ->
            <<"discarded: the router restarted, so the counters went backwards">>;
        counter_went_backwards ->
            <<"discarded: a counter decreased within one boot">>;
        zero_window ->
            <<"discarded: both readings have the same uptime">>
    end.

%% An operator reading a rate needs to know when it was taken, in a form they can
%% match against a log file. UTC, so it does not depend on the client's idea of
%% where it is.
last_reading_note(Derived) ->
    case maps:get(sampled_at, Derived, undefined) of
        undefined -> <<"n/a">>;
        Ms -> unix_ms_to_utc(Ms)
    end.

unix_ms_to_utc(Ms) ->
    {{Y, Mo, D}, {H, Mi, Se}} =
        calendar:system_time_to_universal_time(Ms div 1000, second),
    iolist_to_binary(
        io_lib:format("~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0bZ", [Y, Mo, D, H, Mi, Se])
    ).

bps(undefined) ->
    <<"n/a">>;
bps(N) when is_integer(N) ->
    <<(integer_to_binary(N))/binary, " B/s">>.

ratio(undefined) ->
    <<"n/a">>;
ratio(R) when is_float(R) ->
    <<(integer_to_binary(round(R * 100)))/binary, "%">>.

count_or_na(undefined) ->
    <<"n/a">>;
count_or_na(N) when is_integer(N) ->
    integer_to_binary(N).

count(Snap, Section, Key) ->
    case maps:find(Section, Snap) of
        {ok, Sub} -> integer_to_binary(maps:get(Key, Sub, 0));
        error -> <<"n/a">>
    end.

sessions(Snap) ->
    case maps:find(sessions, Snap) of
        {ok, N} when is_integer(N) -> integer_to_binary(N);
        _ -> <<"n/a">>
    end.
