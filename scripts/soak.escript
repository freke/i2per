#!/usr/bin/env escript
%%! -pa _build/default/lib/i2per/ebin -pa _build/default/lib/telemetry/ebin

%% Soak a throwaway i2per router under metered load and report what the
%% numbers support.
%%
%% Boots a hermetic router (self-seeded, offline; `--live` joins the real
%% network), offers a **bounded** rate of bus announcements for a window, stops
%% offering for a quiet window, and reports:
%%
%%   self_checks   three seeded-fault checks; a run whose instrument cannot show
%%                 it detects a known fault has measured nothing, so these fail
%%                 the run rather than annotate it
%%   verdict       traffic-proportional retention, traffic-independent filling,
%%                 or inconclusive -- and never "leak", which two snapshots
%%                 cannot establish
%%   fixture_delta processes left behind by the reconnect cycle. 0 is the only
%%                 passing answer: `restart => temporary` children are never
%%                 reaped by their supervisor
%%
%% Usage:
%%   escript scripts/soak.escript [--window MS] [--quiet MS] [--rate N]
%%                                [--burst N] [--cycles N] [--port N] [--live]
%%
%% Every parameter is named and bounded. `--rate` outside the bounds is refused
%% rather than clamped: a clamped rate would let the reader believe they asked
%% for something they did not get.
%%
%% Exits non-zero if a self-check fails, the rate is out of bounds, or the
%% reconnect cycle leaked.

-mode(compile).

main(Args) ->
    Opts = parse(args_to_bin(Args), #{
        window => 15000,
        quiet => 5000,
        rate => 500,
        burst => 50,
        cycles => 5,
        port => 39446,
        live => false
    }),
    Dir = filename:join("/tmp", "i2per-soak-" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "identity")),
    Rep = i2p_soak:run(to_erlang(Opts, Dir)),
    ok = render(Rep),
    halt(exit_code(Rep)).

exit_code(#{ok := true}) -> 0;
exit_code(#{failures := Failures}) ->
    io:format(standard_error, "soak failed: ~s~n", [lists:join("; ", Failures)]),
    1.

%% The report is printed as prose rather than JSON: every field of it is a
%% sentence a human has to agree or disagree with, and `json:encode/1` on a map
%% of sentences is a worse way to read one than a paragraph.
render(Rep) ->
    #{self_checks := Checks, verdict := Verdict} = Rep,
    lists:foreach(
        fun(#{name := Name, ok := Ok, evidence := Evidence}) ->
            io:format("~s ~-40s ~s~n", [mark(Ok), Name, Evidence])
        end,
        Checks
    ),
    io:format("~nretention: ~p~n", [maps:get(retention, Verdict)]),
    io:format("offered:   ~p events at ~p/s~n", [
        maps:get(offered_events, Rep), maps:get(rate, Rep)
    ]),
    io:format("fixtures:  ~p process(es) left behind after ~p reconnect cycles~n", [
        maps:get(fixture_delta, Rep), maps:get(cycles, Rep)
    ]),
    io:format("verdict:   ~ts~n", [maps:get(note, Verdict)]),
    lists:foreach(
        fun(Row) -> io:format("~ts~n", [i2p_soak_census:format_table([Row])])
        end,
        maps:get(top_consumers, Rep, [])
    ).

mark(true) -> "ok  ";
mark(false) -> "FAIL".

to_erlang(Opts, Dir) ->
    #{
        data_dir => Dir,
        port => maps:get(port, Opts),
        window_ms => maps:get(window, Opts),
        quiet_ms => maps:get(quiet, Opts),
        rate => maps:get(rate, Opts),
        burst => maps:get(burst, Opts),
        cycles => maps:get(cycles, Opts),
        top => 5,
        live => maps:get(live, Opts)
    }.

parse([], Acc) ->
    Acc;
parse([<<"--live">> | T], Acc) ->
    parse(T, Acc#{live => true});
parse([Flag, N | T], Acc) when
    Flag =:= <<"--window">>; Flag =:= <<"--quiet">>; Flag =:= <<"--rate">>;
    Flag =:= <<"--burst">>; Flag =:= <<"--cycles">>; Flag =:= <<"--port">>
->
    parse(T, Acc#{key(Flag) => binary_to_integer(N)});
parse([_ | T], Acc) ->
    parse(T, Acc).

key(<<"--window">>) -> window;
key(<<"--quiet">>) -> quiet;
key(<<"--rate">>) -> rate;
key(<<"--burst">>) -> burst;
key(<<"--cycles">>) -> cycles;
key(<<"--port">>) -> port.

args_to_bin(Args) ->
    [list_to_binary(A) || A <- Args].