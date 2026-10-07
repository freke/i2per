#!/usr/bin/env escript
%%! -pa _build/default/lib/i2per/ebin -pa _build/default/lib/telemetry/ebin

%% Live-network smoke: boot a throwaway i2per router and emit a JSON report of
%% the four observables that tell an operator whether the instance is really
%% on the network:
%%
%%   peers                     outbound peers connected at the end of the window
%%   dialed                    live inbound sessions (routers that dialed us)
%%   netdb_router_info_growth local NetDb router-info growth after reseed
%%   floodfill_store_accepts  deprecated alias; not remote acceptance proof
%%   transit_relayed_tunnels   transit tunnels handled (0 unless a public addr)
%%
%% Hermetic by default (deterministic, fully offline): the router reseeds
%% nothing and its only seed is *itself* — the boot floodfill-discovery kick
%% fires at t=0 and dials our own NTCP2 listener. Pass `--live` for a real
%% network join: no self seed is supplied, the reseed worker fetches RouterInfos
%% over HTTPS (network must be reachable — `default_hosts/0`), and the command
%% exits non-zero unless a non-self peer connects and lookup-driven NetDb
%% growth is observed after reseed.
%%
%% Usage:
%%   escript scripts/live_smoke.escript [--live] [--window N] [--port N]
%%
%% The router writes its ephemeral identity under /tmp and is stopped after
%% the report.
%%
%% **`telemetry` is on the `%%!` path explicitly.** An escript's code path does
%% not pick up a release's dependencies, so this one listed only `i2per/ebin` and
%% worked until `telemetry` joined `i2per.app.src`'s `applications` (#VH7Z0KJ):
%% `application:ensure_all_started/1` then failed with
%% `{error, {telemetry, {"no such file or directory", "telemetry.app"}}}`.
%% `scripts/soak.escript` needs the same entry.

main(Args) ->
    Opts = parse(args_to_bin(Args), #{window => 15, live => false}),
    Dir = filename:join("/tmp", "i2per-smoke-" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "identity")),
    Rep = i2p_smoke:report(#{
        window_ms => maps:get(window, Opts) * 1000,
        data_dir => Dir,
        port => maps:get(port, Opts, 39443),
        live => maps:get(live, Opts)
    }),
    io:format("~ts~n", [json:encode(Rep)]),
    case maps:get(live, Opts) of
        true -> live_gate(Rep);
        false -> ok
    end.

live_gate(Rep) ->
    Peers = maps:get(<<"peers">>, Rep, 0),
    Growth = maps:get(<<"netdb_router_info_growth">>, Rep, 0),
    case Peers > 0 andalso Growth > 0 of
        true ->
            ok;
        false ->
            io:format(
                standard_error,
                "live smoke failed: peers=~p netdb_router_info_growth=~p (need both > 0)~n",
                [Peers, Growth]
            ),
            halt(1)
    end.

parse([], Acc) ->
    Acc;
parse([<<"--live">> | T], Acc) ->
    parse(T, Acc#{live => true});
parse([<<"--window">>, N | T], Acc) ->
    parse(T, Acc#{window => binary_to_integer(N)});
parse([<<"--port">>, N | T], Acc) ->
    parse(T, Acc#{port => binary_to_integer(N)});
parse([_ | T], Acc) ->
    parse(T, Acc).

args_to_bin(Args) ->
    [list_to_binary(A) || A <- Args].