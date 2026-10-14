#!/usr/bin/env escript
%%! -pa _build/default/lib/i2per/ebin -pa _build/default/lib/telemetry/ebin

%% Measure ingress-path round-trip latency under synthetic transit load, one VM
%% scheduling configuration per invocation. The scheduling flags (+sbwt,
%% +sbwtdcpu, +S) are emulator flags, so they come on the command line BEFORE
%% the script: escript +sbwt very_short bench/bench_sched_latency.escript.
%% scripts/bench_sched_latency.sh runs the whole matrix and interleaves the
%% repetitions, so machine drift cannot read as a flag making a difference.
%%
%% Why this shape (refs #VXRH456):
%%   - The load is the soak's own (m:i2p_soak_tunnel:f:load_window/2): real
%%     inbound and outbound tunnel builds and real 1028-byte transit frames
%%     relayed with real layer crypto, on the soak fabric. Nothing here
%%     reimplements the router's work and nothing here mocks it.
%%   - The probe is a synchronous round trip into the singleton the relay work
%%     also runs in (i2p_tunnel_srv:status/0). Its latency is wake-up plus
%%     queueing plus service on the ingress path -- the figure a scheduler
%%     busy-wait threshold can and cannot move.
%%   - The soak's mock peer forwards build garlics to the process that booted
%%     the fabric, so **the load runs in this process** and the probe loop runs
%%     in a child that reports percentiles back. Splitting it the other way
%%     deadlocks: the garlics pile up in the driver's mailbox, every build
%%     waits for one, and only the timeout moves the run -- measured, it
%%     reported one transit frame per window and read as a broken relay path.
%%   - The VM cannot be asked from inside which flags it was given, so the
%%     label comes in as an argument and is printed beside the online
%%     scheduler and dirty-scheduler counts, which +S and +SDcpu change.
%%
%%   - `--cpu-cost` reports the VM's own CPU (all threads, schedulers included)
%%     across the window, which is the cost half of the busy-wait trade. It is
%%     normally run with `--probe-hz N` so the wake pattern is a realistic
%%     arrival rate rather than a closed loop, and `--rate 0` so the load does
%%     not confound it: escript +S 1 +sbwt medium bench_sched_latency.escript
%%     --rate 0 --probe-hz 100 --cpu-cost.
%%
%% Usage:
%%   escript bench/bench_sched_latency.escript [--label STR] [--rate N]
%%         [--burst N] [--warm-ms N] [--window-ms N] [--port N] [--hops N]
%%         [--probe-hz N] [--cpu-cost]
%%   --rate 0 measures the quiet floor: the probe loop with no load at all.

-mode(compile).

main(Args) ->
    Opts = parse(args_to_bin(Args), #{
        label => "unlabelled",
        rate => 500,
        burst => 10,
        warm_ms => 2000,
        window_ms => 3000,
        probe_hz => 0,
        cpu_cost => false,
        port => 39458,
        hops => 3,
        phases => 3
    }),
    Dir = filename:join("/tmp", "i2per-sched-lat-" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "identity")),
    Fabric = i2p_soak_tunnel:boot(maps:merge(Opts, #{data_dir => Dir, live => false})),
    Opts1 = Opts#{data_dir => Dir},
    try
        %% The warm-up is the soak's own discipline: every cache on this path
        %% fills once, so a measurement taken cold reports the fill as latency.
        _ = probe_window(Fabric, Opts1, maps:get(warm_ms, Opts)),
        Before = i2p_soak_tunnel:counters(),
        CpuBefore = maybe_cpu(Opts),
        Summary = probe_window(Fabric, Opts1, maps:get(window_ms, Opts)),
        CpuAfter = maybe_cpu(Opts),
        After = i2p_soak_tunnel:counters(),
        render(Opts1, Summary, Before, After, {CpuBefore, CpuAfter})
    after
        ok = i2p_soak_tunnel:shutdown()
    end.

%% One measured window: the soak's transit load runs here, in the process the
%% mock peer forwards to, while a child probes the tunnel manager the load is
%% running in. The load is the tree's own instrument rather than a second
%% implementation of "push frames at the router".
probe_window(Fabric, Opts, WindowMs) ->
    case maps:get(rate, Opts) of
        0 ->
            spawn_probe(WindowMs, Opts);
        _ ->
            Summary = spawn_probe(WindowMs, Opts),
            _ = i2p_soak_tunnel:load_window(Fabric, load_opts(Opts, WindowMs)),
            Summary
    end.

spawn_probe(WindowMs, Opts) ->
    Me = self(),
    _ = spawn(fun() -> Me ! {probe_done, probe_loop(WindowMs, Opts)} end),
    receive
        {probe_done, Summary} ->
            Summary
    after 60000 ->
        {0, 0, 0, 0, 0}
    end.

%% The probe loop: sequential synchronous round trips into the process the
%% transit work also runs in. With `--probe-hz N` it paces itself to N probes
%% per second instead of a closed loop, which is what the CPU-cost mode uses to
%% model a wake pattern a real arrival rate produces.
probe_loop(WindowMs, Opts) ->
    Deadline = erlang:system_time(millisecond) + WindowMs,
    probe_until(Deadline, maps:get(probe_hz, Opts), []).

probe_until(Deadline, Hz, Acc) ->
    case erlang:system_time(millisecond) >= Deadline of
        true ->
            summarize(Acc);
        false ->
            T0 = erlang:monotonic_time(microsecond),
            _ = i2p_tunnel_srv:status(),
            T1 = erlang:monotonic_time(microsecond),
            Acc1 = [T1 - T0 | Acc],
            pace(Hz),
            probe_until(Deadline, Hz, Acc1)
    end.

pace(0) ->
    ok;
pace(Hz) ->
    timer:sleep(1000 div Hz).

summarize(Samples) ->
    Sorted = lists:sort(Samples),
    N = length(Sorted),
    {N, at(Sorted, N, 0.5), at(Sorted, N, 0.99), at(Sorted, N, 0.999), lists:last(Sorted)}.

at(Sorted, N, F) ->
    lists:nth(max(1, min(N, round(N * F))), Sorted).

load_opts(Opts, WindowMs) ->
    #{
        data_dir => maps:get(data_dir, Opts),
        port => maps:get(port, Opts),
        warm_ms => 0,
        window_ms => WindowMs,
        quiet_ms => 0,
        phases => 1,
        rate => maps:get(rate, Opts),
        burst => maps:get(burst, Opts),
        hops => maps:get(hops, Opts),
        top => 5
    }.

render(Opts, Summary, Before, After, Cpu) ->
    {N, P50, P99, P999, Max} = Summary,
    Frames = (maps:get(transit_bytes_in, After, 0) - maps:get(transit_bytes_in, Before, 0)) div 1028,
    io:format("~ts~n", [maps:get(label, Opts)]),
    io:format(
        "  otp ~s  schedulers ~p  dirty_cpu ~p  probes ~p  probe_hz ~p  rate ~p  transit_frames ~p~n",
        [
            erlang:system_info(otp_release),
            erlang:system_info(schedulers),
            erlang:system_info(dirty_cpu_schedulers),
            N,
            maps:get(probe_hz, Opts),
            maps:get(rate, Opts),
            Frames
        ]
    ),
    case N of
        0 ->
            io:format("  (no probes completed)~n");
        _ ->
            io:format("  round-trip us:  p50 ~p  p99 ~p  p99.9 ~p  max ~p~n", [P50, P99, P999, Max])
    end,
    render_cpu(Opts, Summary, Cpu),
    ok.

%% The cost side of busy-waiting: the VM's own CPU (all threads, scheduler
%% threads included, from /proc/self/stat) across the measured window, as a
%% share of one core. Linux-only, which is the deployment target anyway. A
%% blank read is reported as unknown rather than silently skipped -- a cost
%% measurement that can go missing is worse than no measurement.
render_cpu(#{cpu_cost := true, window_ms := WindowMs} = _Opts, {N, _, _, _, _}, {Before, After}) when
    is_integer(Before), is_integer(After), N > 0
->
    CpuMs = (After - Before) * 10,
    io:format("  vm_cpu ~p ms of ~p ms  (~.2f% of one core)~n", [
        CpuMs, WindowMs, CpuMs * 100 / WindowMs
    ]),
    ok;
render_cpu(_Opts, _Summary, _Cpu) ->
    ok.

%% 100 ticks per second is the Linux userspace ABI value of SC_CLK_TCK.
maybe_cpu(#{cpu_cost := true}) ->
    vm_cpu_ms();
maybe_cpu(_Opts) ->
    undefined.

vm_cpu_ms() ->
    case file:read_file("/proc/self/stat") of
        {ok, Bin} ->
            tick_sum(tokens_after_comm(Bin));
        _ ->
            undefined
    end.

%% utime and stime are fields 14 and 15 of proc(5); after the parenthesised
%% comm the tokens begin at field 3 (state), and state is dropped here, so the
%% two CPU counters are tokens 11 and 12 of what remains.
tick_sum(Tokens) ->
    lists:nth(11, Tokens) + lists:nth(12, Tokens).

tokens_after_comm(Bin) ->
    Parts = binary:split(Bin, <<")">>, [global]),
    Last = string:trim(lists:last(Parts)),
    [_State | Rest] = binary:split(Last, <<" ">>, [global, trim_all]),
    [binary_to_integer(T) || T <- Rest].

%% %% parsing %%

parse([], Acc) ->
    Acc;
parse([Flag, N | T], Acc) when
    Flag =:= <<"--rate">>; Flag =:= <<"--burst">>; Flag =:= <<"--warm-ms">>;
    Flag =:= <<"--window-ms">>; Flag =:= <<"--port">>; Flag =:= <<"--hops">>;
    Flag =:= <<"--probe-hz">>
->
    parse(T, Acc#{key(Flag) => binary_to_integer(N)});
parse([<<"--label">>, Label | T], Acc) ->
    parse(T, Acc#{label => Label});
parse([<<"--cpu-cost">> | T], Acc) ->
    parse(T, Acc#{cpu_cost => true});
parse([_ | T], Acc) ->
    parse(T, Acc).

key(<<"--rate">>) -> rate;
key(<<"--burst">>) -> burst;
key(<<"--warm-ms">>) -> warm_ms;
key(<<"--window-ms">>) -> window_ms;
key(<<"--port">>) -> port;
key(<<"--hops">>) -> hops;
key(<<"--probe-hz">>) -> probe_hz.

args_to_bin(Args) ->
    [list_to_binary(A) || A <- Args].
