-module(i2p_counters_tests).

-moduledoc """
Unit tests for the counter home.

The properties that matter here are not arithmetic. They are that a counter
costs an atomic add rather than a message, that the numbers are still readable
when the owning process cannot answer, that nothing in the module wakes up on a
timer, and that every name a call site adds is declared in the registry.
""".

-include_lib("eunit/include/eunit.hrl").

%% %%%%% %%% The registry %%%%% %%%

%% Uniqueness, checked as uniqueness. An earlier version of this case asserted
%% `lists:usort(Names) =:= Names`, which is a *sortedness* check wearing a
%% uniqueness check's clothes: it passed on a one-element registry and failed the
%% moment a second counter arrived, because the registry is grouped by transport
%% and direction rather than alphabetically. A test that only holds while the
%% list has one element is not a test.
counters_are_unique_test() ->
    Owner = ensure_counters(),
    try
        Names = i2p_counters:counters(),
        ?assertEqual(length(Names), length(lists:usort(Names))),
        ?assert(length(Names) > 0)
    after
        case Owner of
            started -> stop_counters();
            existing -> ok
        end
    end.

%% %%%%% %%% Volatility %%%%% %%%

%% A stopped owner must not be able to crash a caller on a packet path. Same
%% reason `i2p_events:notify/1` always succeeds: telemetry is never worth a
%% dropped connection.
add_is_a_no_op_while_the_owner_is_absent_test() ->
    Owner = ensure_counters_absent(),
    try
        ?assertEqual(undefined, whereis(i2p_counters)),
        ?assertEqual(ok, i2p_counters:add(events_notified, 1)),
        ?assertEqual(#{}, i2p_counters:snapshot())
    after
        restore_counters(Owner)
    end.

%% %%%%% %%% Gauges %%%%% %%%

%% A gauge write is a no-op while the owner is absent, for the reason
%% `f:add/2` is: telemetry must not be able to crash a working connection, and the
%% suites that start part of the tree rely on it.
set_gauge_is_a_no_op_while_the_owner_is_absent_test() ->
    Owner = ensure_counters_absent(),
    try
        ?assertEqual(undefined, whereis(i2p_counters)),
        ?assertEqual(ok, i2p_counters:set_gauge(bus_backlog, 999)),
        ?assertEqual(#{}, i2p_counters:gauges())
    after
        restore_counters(Owner)
    end.

%% %%%%% %%% Declared names %%%%% %%%

%% Every literal name passed to `i2p_counters:add/2` under `apps/*/src` is in
%% `f:counters/0`.
%%
%% This is the check the UPnP counters were missing: `add/2` raises on an
%% unregistered name by design, and the call sites wrap the call in `catch`, so a
%% missing declaration becomes a counter that reads zero forever while the
%% feature works. A dynamic name -- `Counter`, `counter_name({...})` -- is
%% skipped, because the question is "is this literal declared", and those sites
%% derive their name from a closed set their module owns.
add_sites_name_declared_counters_test() ->
    Declared = lists:usort(i2p_counters:counters()),
    Sites = add_call_sites(),
    ?assertNotEqual([], Sites),
    Undeclared = [Site || {_, _, Name} = Site <- Sites, not lists:member(Name, Declared)],
    ?assertEqual([], Undeclared).

add_call_sites() ->
    lists:flatmap(fun add_call_sites/1, source_files()).

add_call_sites(File) ->
    {ok, Bin} = file:read_file(File),
    Pattern = "i2p_counters:add\\(\\s*([a-z][a-z0-9_]*)\\s*,",
    case re:run(Bin, Pattern, [global, {capture, all_but_first, index}]) of
        {match, Matches} ->
            [
                {filename:basename(File), line_at(Bin, Offset), name_at(Bin, Offset, Length)}
             || [{Offset, Length}] <- Matches
            ];
        nomatch ->
            []
    end.

line_at(Bin, Offset) ->
    length(binary:matches(binary:part(Bin, 0, Offset), <<"\n">>)) + 1.

%% Through the atom table rather than `binary_to_existing_atom/2`: the literal is
%% a name this repository's own sources chose, and only test runs read it.
name_at(Bin, Offset, Length) ->
    binary_to_atom(binary:part(Bin, Offset, Length), utf8).

source_files() ->
    Root = i2p_ct_helpers:project_root(),
    lists:flatmap(
        fun(App) -> filelib:wildcard(filename:join([App, "src", "*.erl"])) end,
        filelib:wildcard(filename:join([Root, "apps", "*"]))
    ).

%% %%%%% %%% Internal helpers %%%%% %%%

ensure_counters() ->
    case whereis(i2p_counters) of
        undefined ->
            {ok, Pid} = i2p_counters:start_link(),
            true = unlink(Pid),
            started;
        _ ->
            existing
    end.

stop_counters() ->
    case whereis(i2p_counters) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid)
    end.

ensure_counters_absent() ->
    case whereis(i2p_counters) of
        undefined ->
            absent;
        Pid ->
            gen_server:stop(Pid),
            present
    end.

restore_counters(absent) ->
    ok;
restore_counters(present) ->
    {ok, Pid} = i2p_counters:start_link(),
    true = unlink(Pid),
    ok.
