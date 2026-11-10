-module(i2per_tun_datapath_SUITE).

-moduledoc """
Privileged end-to-end TUN datapath case (epiq 091VYQC, item 2).

Skipped by default: opening `/dev/net/tun` needs CAP_NET_ADMIN. Enable with
`I2PER_TUN_PRIVILEGED=1` in the environment. Outside the smoke tier.
""".

-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([device_opens_and_drains/1, destructor_cancels_armed_select/1]).

all() ->
    [device_opens_and_drains, destructor_cancels_armed_select].

init_per_suite(Config) ->
    case os:getenv("I2PER_TUN_PRIVILEGED") of
        "1" ->
            Config;
        _ ->
            {skip, "set I2PER_TUN_PRIVILEGED=1 (needs CAP_NET_ADMIN)"}
    end.



destructor_cancels_armed_select(_Config) ->
    %% Stress the destructor race: create a resource, arm it, drop all
    %% references and force collection without an explicit stop/1, so the
    %% destructor runs while a select is still armed. Repeat many times; any
    %% crash or leaked fd surfaces as a failure or a later open failure.
    N = 200,
    lists:foreach(
        fun(_) ->
            Pid = spawn(fun() ->
                case i2per_tun_tun:open(<<"i2per_stress">>) of
                    {ok, Dev} ->
                        _ = i2per_tun_tun:arm(Dev, self()),
                        %% Drop the reference: let Dev go out of scope so the
                        %% resource becomes collectable while the select is still
                        %% armed.
                        erlang:garbage_collect(),
                        timer:sleep(1),
                        ok;
                    {error, Reason} ->
                        ct:fail({open_failed, Reason})
                end
            end),
            %% Wait for the spawned process to finish.
            Mref = erlang:monitor(process, Pid),
            receive
                {'DOWN', Mref, process, Pid, normal} -> ok;
                {'DOWN', Mref, process, _, Reason} -> ct:fail({worker_died, Reason})
            after 5000 ->
                erlang:demonitor(Mref, [flush]),
                ct:fail(worker_timeout)
            end,
            erlang:garbage_collect()
        end,
        lists:seq(1, N)),
    ok.

end_per_suite(_Config) ->
    ok.

device_opens_and_drains(_Config) ->
    process_flag(trap_exit, true),
    case i2per_tun_dev:start_link() of
        {ok, Pid} ->
            true = is_pid(Pid),
            ok = gen_server:stop(Pid);
        {error, _Reason} ->
            receive
                {'EXIT', _, _} -> ok
            after 0 -> ok
            end,
            ct:fail("TUN device could not be opened")
    end,
    process_flag(trap_exit, false),
    ok.
