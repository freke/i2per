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
        ],
    [
        ["<tr><td>", K, "</td><td>", V, "</td></tr>"]
     || {K, V} <- Flat
    ].

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
