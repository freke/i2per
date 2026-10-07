#!/usr/bin/env escript
%%! -pa _build/default/lib/i2per/ebin -pa _build/default/lib/telemetry/ebin

%% Soak the TUNNEL and TRANSIT paths of a throwaway i2per router and report what
%% the numbers support.
%%
%% This is `scripts/soak.escript`'s counterpart. The existing soak drives the bus
%% and the listener lifecycle; the run that motivated #KF1MX96 reported flat
%% retention and **every tunnel counter read zero**, which is the failure mode
%% this harness family exists to prevent. So this one drives real builds in both
%% directions and real transit frames, and **asserts** the counters moved rather
%% than assuming it.
%%
%% Usage:
%%   escript scripts/soak_tunnels.escript [--warm MS] [--window MS] [--quiet MS]
%%                                        [--phases N] [--rate N] [--burst N]
%%                                        [--hops N] [--port N] [--top N] [--live]
%%
%% Exits non-zero if a self-check fails, the rate is out of bounds, a tunnel
%% counter stayed at zero, or the run left processes behind.
%%
%% **--phases below 2 is refused rather than run.** One phase has one slope, and
%% the difference between a bounded cache and a structure with no bound is whether
%% the slope continues -- which needs at least two slopes to see.

-mode(compile).

main(Args) ->
    Opts = parse(args_to_bin(Args), #{
        warm => 10000,
        window => 10000,
        quiet => 4000,
        phases => 3,
        rate => 50,
        burst => 10,
        hops => 3,
        top => 5,
        port => 39447,
        live => false
    }),
    Dir = filename:join("/tmp", "i2per-soak-tunnels-" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "identity")),
    Rep = i2p_soak_tunnel:run(to_erlang(Opts, Dir)),
    ok = render(Rep),
    halt(exit_code(Rep)).

exit_code(#{ok := true}) -> 0;
exit_code(#{failures := Failures}) ->
    io:format(standard_error, "tunnel soak failed: ~s~n", [lists:join("; ", Failures)]),
    1.

%% Prose rather than JSON: every field of this report is a sentence somebody has to
%% agree or disagree with, and `json:encode/1` on a map of sentences is a worse
%% way to read one than a paragraph.
render(Rep) ->
    #{self_checks := Checks, verdict := Verdict, offered := Offered} = Rep,
    lists:foreach(
        fun(#{name := Name, ok := Ok, evidence := Evidence}) ->
            io:format("~s ~-40s ~s~n", [mark(Ok), Name, Evidence])
        end,
        Checks
    ),
    io:format("~ntraffic (the router's own counters):~n"),
    io:format("  builds requested    ~p~n", [maps:get(requested, Offered)]),
    io:format("  built inbound       ~p~n", [maps:get(built_inbound, Offered)]),
    io:format("  built outbound      ~p~n", [maps:get(built_outbound, Offered)]),
    io:format("  transit frames      ~p~n", [maps:get(transit_frames, Offered)]),
    render_phases(Rep),
    io:format("~nfixtures:  ~p process(es) left behind~n", [maps:get(fixture_delta, Rep)]),
    io:format("retention: ~p~n", [maps:get(retention, Verdict)]),
    io:format("verdict:   ~ts~n", [maps:get(note, Verdict)]),
    ok.

%% Per phase, because the verdict is a series and a single total hides the shape
%% it was classified from -- which is exactly the thing a reader needs to check.
render_phases(Rep) ->
    Phases = maps:get(phases, Rep),
    io:format("~nphases (retained heap after a forced full GC, across the router's own processes):~n"),
    lists:foreach(
        fun(#{index := N, offered := O, retained_words := W, ets_bytes := E, pools := P}) ->
            io:format(
                "  phase ~p  retained ~s  ets ~s  inbound ~p outbound ~p transit ~p  "
                "requested ~p~n",
                [
                    N,
                    i2p_soak_census:words_mb(W),
                    i2p_soak_census:bytes_mb(E),
                    maps:get(inbound, P),
                    maps:get(outbound, P),
                    maps:get(transit, P),
                    maps:get(requested, O)
                ]
            )
        end,
        Phases
    ).

mark(true) -> "ok  ";
mark(false) -> "FAIL".

to_erlang(Opts, Dir) ->
    #{
        data_dir => Dir,
        port => maps:get(port, Opts),
        warm_ms => maps:get(warm, Opts),
        window_ms => maps:get(window, Opts),
        quiet_ms => maps:get(quiet, Opts),
        phases => maps:get(phases, Opts),
        rate => maps:get(rate, Opts),
        burst => maps:get(burst, Opts),
        hops => maps:get(hops, Opts),
        top => maps:get(top, Opts),
        live => maps:get(live, Opts)
    }.

parse([], Acc) ->
    Acc;
parse([<<"--live">> | T], Acc) ->
    parse(T, Acc#{live => true});
parse([Flag, N | T], Acc) when
    Flag =:= <<"--warm">>; Flag =:= <<"--window">>; Flag =:= <<"--quiet">>;
    Flag =:= <<"--phases">>; Flag =:= <<"--rate">>; Flag =:= <<"--burst">>;
    Flag =:= <<"--hops">>; Flag =:= <<"--port">>; Flag =:= <<"--top">>
->
    parse(T, Acc#{key(Flag) => binary_to_integer(N)});
parse([_ | T], Acc) ->
    parse(T, Acc).

key(<<"--warm">>) -> warm;
key(<<"--window">>) -> window;
key(<<"--quiet">>) -> quiet;
key(<<"--phases">>) -> phases;
key(<<"--rate">>) -> rate;
key(<<"--burst">>) -> burst;
key(<<"--hops">>) -> hops;
key(<<"--port">>) -> port;
key(<<"--top">>) -> top.

args_to_bin(Args) ->
    [list_to_binary(A) || A <- Args].