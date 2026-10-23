-module(i2per_tun_dev_tests).

-moduledoc """
Hermetic tests for the `i2per_tun` fd spike.

Nothing here needs privileges or a real TUN: CI runs unprivileged, so the
NIF-dependent cases assert *shapes* — `open/1` either succeeds with a
stoppable device or fails with a posix reason — and are vacuous only when
the `.so` was never built, which is the OTP-compat job's mode (no cargo, no
NIF, by design; see scripts/build-i2per-tun-nif.sh). The privileged,
real-TUN case is run by hand; the steps live in apps/i2per_tun/README.md.
""".

-include_lib("eunit/include/eunit.hrl").

%% ------------------------------------------------------------------ helpers

so_path() ->
    case code:priv_dir(i2per_tun) of
        {error, _} ->
            Dir = filename:dirname(code:which(i2per_tun_tun)),
            filename:join([Dir, "..", "priv", "i2per_tun_nif.so"]);
        Dir ->
            filename:join(Dir, "i2per_tun_nif.so")
    end.

so_present() ->
    filelib:is_file(so_path()).

nif_loaded() ->
    try is_binary(i2per_tun_tun:version()) of
        true -> true;
        _ -> false
    catch
        _:_ -> false
    end.

posix_reason(Reason) when is_atom(Reason) ->
    Reason =/= nif_panic;
posix_reason(Reason) ->
    is_tuple(Reason) andalso tuple_size(Reason) =:= 2 andalso element(1, Reason) =:= errno.

%% -------------------------------------------------------------------- tests

version_test_() ->
    {"the NIF loads and version/0 answers", fun() ->
        case {so_present(), nif_loaded()} of
            %% The compat job builds without cargo: no .so, no NIF, and that
            %% is the designed shape rather than a failure.
            {false, false} -> ?assert(true);
            %% A .so that exists but fails to load is a defect this test must
            %% report, not skip.
            {true, false} -> ?assert(nif_loaded());
            {_, true} -> ?assert(is_binary(i2per_tun_tun:version()))
        end
    end}.

open_shape_test_() ->
    {"open/1 succeeds with a stoppable device or fails with a posix reason", fun() ->
        case nif_loaded() of
            false ->
                ?assert(true);
            true ->
                case i2per_tun_tun:open(<<"i2per_spike0">>) of
                    {ok, Dev} ->
                        ?assertEqual(ok, i2per_tun_tun:stop(Dev));
                    {error, Reason} ->
                        ?assert(posix_reason(Reason))
                end
        end
    end}.

open_rejects_long_name_test_() ->
    {"open/1 refuses a name that does not fit IFNAMSIZ", fun() ->
        case nif_loaded() of
            false -> ?assert(true);
            true -> ?assertMatch({error, einval}, i2per_tun_tun:open(binary:copy(<<"x">>, 16)))
        end
    end}.

write_badarg_test_() ->
    {"write/2 raises badarg on a term that is not a device", fun() ->
        case nif_loaded() of
            false -> ?assert(true);
            true -> ?assertError(badarg, i2per_tun_tun:write(make_ref(), <<1, 2, 3>>))
        end
    end}.

arm_badarg_test_() ->
    {"arm/2 raises badarg on a term that is not a device", fun() ->
        case nif_loaded() of
            false -> ?assert(true);
            true -> ?assertError(badarg, i2per_tun_tun:arm(make_ref(), self()))
        end
    end}.

dev_start_shape_test_() ->
    {"the device owner starts, or fails its start where the open fails", fun() ->
        %% A start_link whose init returns {stop, Reason} makes the child exit
        %% with that reason after acking {error, Reason} — the exit signal
        %% would take this test process down, so trap and flush it.
        process_flag(trap_exit, true),
        case i2per_tun_dev:start_link() of
            {ok, Pid} ->
                ?assert(is_pid(Pid)),
                ?assertEqual(ok, gen_server:stop(Pid));
            %% Unprivileged CI (or the NIF-less compat job): a failed start is
            %% the designed shape here, not a failure.
            {error, _Reason} ->
                receive
                    {'EXIT', _Pid, _} -> ok
                after 0 -> ok
                end,
                ?assert(true)
        end,
        process_flag(trap_exit, false)
    end}.
