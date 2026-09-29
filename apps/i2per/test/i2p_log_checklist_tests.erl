-module(i2p_log_checklist_tests).

-moduledoc """
ADR 0002's 3am checklist, checked against the tree instead of trusted.

The checklist lives in `m:i2p_log:checklist/0`: each row names a fact, the
instrument that carries it, and -- for a log-carried fact -- the level it is
recorded at. That is the declaration. This module is the other half: it reads the
tree and asserts every declared row is satisfied, so **a declared fact that nothing
records fails `just check`**.

Without it the checklist is a list somebody wrote once. Nothing in the compiler
notices a fact declared and never emitted, because a type is not data and cannot be
enumerated at runtime; nothing notices a row deleted to make a failing build go
away; and nothing notices a bus-carried row whose event has been renamed, which
leaves the checklist quietly claiming a fact that no longer exists. Each of those is
a symptom an operator would report at 3am with no way to answer it.

## Derived, not written out

The set of facts the tree records is **read from the sources**, exactly as
`i2p_events_vocabulary_tests` reads the announced event tags rather than listing
them. A list written beside `f:checklist/0` would be a third copy of the same
declaration, wrong the first time a fact is added -- the duplication this project
refuses, introduced by the very module meant to prevent it.

## The four things asserted

- every declared **log** row has an `m:i2p_log:emit/3` call site naming it, so the
  fact is written on the instrument the row claims;
- every declared **bus** row has an event shape in `m:i2p_events:event/0`, so the
  fact is announced on the bus the row claims, and deleting the event breaks the
  checklist rather than silently emptying it;
- every `emit/3` call site names a fact the checklist declares as **log-carried**,
  so a fact a counter reads cannot also become a log line;
- every `emit/3` call site names its fact as an **atom literal**, because a call
  passing a variable would be invisible to the scan and the scan would then report a
  smaller world than the tree records -- the check passing on incomplete
  information, which is worse than not having the check.

## Reading the event type

`m:i2p_events:event/0` is parsed by `m:i2p_events_vocabulary_tests`, which already
has a reader for it and four cases built on the answer. It is called rather than
re-implemented: a second parser is a second thing to keep in step with a type that
gains a shape every few months, and it would be a copy of a parser that is
deliberately fussy about exactly the details that break quietly.
""".

-include_lib("eunit/include/eunit.hrl").

%% The one call shape this scan can read. Named so the offset past it is derived from
%% the needle rather than counted out by hand: a literal count would silently truncate
%% every fact name, and a truncated fact name reads as a missing fact.
-define(EMIT, <<"i2p_log:emit(">>).

%% How far past the needle to look for the fact name. erlfmt wraps these calls, so
%% three of the eight put the name on the line *after* the `emit(`, and reading only
%% the rest of the line would find nothing there. Generous enough for any plausible
%% indentation, small enough that a comment mentioning another fact cannot be mistaken
%% for this call's argument.
-define(SCAN_BYTES, 400).

%%% %%%%% Every declared fact is recorded, on the instrument it claims %%%%% %%%

%% The whole ticket. Each declared row is checked against the instrument it names, and
%% a row that fails carries the fact, the instrument, what was wanted and where the scan
%% did look -- because a report that only said "a required fact is missing" would send
%% the next person hunting through the wrong tree.
every_declared_fact_is_recorded_on_its_declared_instrument_test() ->
    Unsatisfied = [Row || Row <- rows(), not maps:get(satisfied, Row)],
    ?assertEqual([], Unsatisfied).

%% The other direction, as its own case: a set comparison reports a missing fact and a
%% stray fact identically, and these two are different mistakes with different fixes.
%%
%% A fact the tree records but nobody declared is `f:i2p_log:emit/3`'s
%% `{undeclared_fact, _}` raise waiting to happen on a path with no subscriber -- which
%% is to say, on the path that runs once, at boot.
every_recorded_fact_is_declared_test() ->
    ?assertEqual([], lists:usort(recorded() -- i2p_log:fact_names())).

%% ADR 0002's one-instrument rule, enforced rather than described.
%%
%% The two direction cases above do not catch this, and the gap is worth naming: a fact
%% declared `bus` is satisfied by its event existing, and a fact the tree also writes to
%% the log is a fact that is declared. Both cases stay green. Only this one notices that
%% the same fact is now on two instruments, which is the exact duplication ADR 0002 says
%% costs more the bigger the router gets.
recorded_facts_are_log_carried_test() ->
    OnBoth = [
        {File, Line, Fact, maps:get(Fact, i2p_log:checklist(), undeclared)}
     || {File, Line, Fact} <- emit_call_sites(),
        not log_carried(Fact)
    ],
    ?assertEqual([], OnBoth).

%% Whether the checklist says this fact is written to the log. An undeclared fact
%% counts as not log-carried, so this case also catches one -- though
%% `every_recorded_fact_is_declared_test` names it more usefully.
-spec log_carried(atom()) -> boolean().
log_carried(Fact) ->
    case maps:get(Fact, i2p_log:checklist(), #{instrument => bus}) of
        #{instrument := log} -> true;
        _ -> false
    end.

%% Every call site names its fact as an atom literal. A call passing a variable would be
%% invisible to the scan above, which would then quietly report a smaller world than the
%% tree records -- the check passing on incomplete information. This is the same guard
%% `i2p_events_vocabulary_tests` uses for `i2p_events:notify/1`.
every_emit_call_site_names_its_fact_literally_test() ->
    %% `f:fact_of/1` returns `dynamic` for exactly the call sites it could not read a
    %% name at, so this asks the scanner rather than re-parsing the text a second way.
    Dynamic = [Site || Site = {_File, _Line, Fact} <- emit_call_sites(), Fact =:= dynamic],
    ?assertEqual([], Dynamic).

%% The three boot facts are in the declared set, so the work #KS9ZWER did is *checked*
%% rather than trusted. Named explicitly because they are the rows with no other source
%% of truth: if one is dropped from the checklist nothing else in the tree notices, and
%% an operator loses a symptom with no instrument at all.
the_three_boot_facts_are_declared_log_carried_and_at_notice_test() ->
    lists:foreach(
        fun(Fact) ->
            ?assertEqual(
                #{level => notice, instrument => log}, maps:get(Fact, i2p_log:checklist())
            )
        end,
        [config_in_force, started_as, online]
    ).

%% ADR 0002's table names six symptoms the bus answers. All six are asserted by name and
%% the count is pinned, so a row quietly dropped cannot leave the case green on a
%% shorter but still self-consistent list.
all_six_bus_carried_rows_are_declared_test() ->
    Bus = [Fact || {Fact, #{instrument := bus}} <- maps:to_list(i2p_log:checklist())],
    ?assertEqual(
        [
            db_store_not_stored,
            leaseset_publish_failed,
            lookup_failed,
            peer_connect_failed,
            reachability,
            transit_denied
        ],
        lists:sort(Bus)
    ).

%%% %%%%% The checklist, read against the tree %%%%% %%%

%% One row per declared fact, carrying the verdict and enough context to act on.
-spec rows() -> [map()].
rows() ->
    [row(Fact, Row) || {Fact, Row} <- maps:to_list(i2p_log:checklist())].

-spec row(atom(), map()) -> map().
row(Fact, #{instrument := log}) ->
    Sites = [{File, Line} || {File, Line, F} <- emit_call_sites(), F =:= Fact],
    #{
        fact => Fact,
        instrument => log,
        wanted => "an i2p_log:emit/3 call site in apps/i2per/src naming it",
        found_in =>
            case Sites of
                [] -> "no call site anywhere in apps/i2per/src";
                _ -> Sites
            end,
        satisfied => Sites =/= []
    };
row(Fact, #{instrument := bus}) ->
    Tags = i2p_events_vocabulary_tests:declared_tags(),
    #{
        fact => Fact,
        instrument => bus,
        wanted => "an event shape of that name in i2p_events:event/0",
        found_in =>
            case lists:member(Fact, Tags) of
                true -> "i2p_events:event/0";
                false -> "no such event shape in i2p_events:event/0"
            end,
        satisfied => lists:member(Fact, Tags)
    }.

%% The facts the tree records through `m:i2p_log:emit/3`.
-spec recorded() -> [atom()].
recorded() ->
    lists:usort([Fact || {_File, _Line, Fact} <- emit_call_sites()]).

%%% %%%%% Reading the tree %%%%% %%%

%% Every `i2p_log:emit(` in the core tree, with the fact it names.
%%
%% Read with `binary:matches/2` rather than by walking the decoded text, for the reason
%% `i2p_events_vocabulary_tests` gives: the sources carry em-dashes, so a byte offset
%% and a character index are different numbers, and mixing them cuts in the wrong place
%% on any file with a non-ASCII byte before a call site.
-spec emit_call_sites() -> [{string(), pos_integer(), atom()}].
emit_call_sites() ->
    lists:flatmap(fun scan_file/1, core_source_files()).

-spec scan_file(file:filename_all()) -> [{string(), pos_integer(), atom()}].
scan_file(File) ->
    {ok, Bin} = file:read_file(File),
    lists:flatmap(
        fun({Offset, _Length}) ->
            Start = Offset + byte_size(?EMIT),
            Rest = binary:part(Bin, Start, min(?SCAN_BYTES, byte_size(Bin) - Start)),
            [
                {filename:basename(File), count_lines(Bin, Offset), fact_of(Rest)}
            ]
        end,
        binary:matches(Bin, ?EMIT)
    ).

count_lines(Bin, Offset) ->
    length(binary:matches(binary:part(Bin, 0, Offset), <<"\n">>)) + 1.

%% The fact named by the bytes after `i2p_log:emit(`, or `dynamic` if there is no atom
%% literal there.
-spec fact_of(binary()) -> atom().
fact_of(Rest) ->
    case take_name(skip_blanks(Rest)) of
        %% Through a string rather than `binary_to_atom/3`: same result, and it keeps
        %% this the same shape as `i2p_events_vocabulary_tests`, which does the same.
        %% The atom table grows from names found in this repository's own sources and
        %% nowhere else, and only while the tests are running.
        {ok, Name} -> list_to_atom(binary_to_list(Name));
        error -> dynamic
    end.

%% Leading whitespace *including newlines*: erlfmt wraps these calls, so the argument is
%% frequently on the next line. Reading only the rest of the call's own line would find
%% nothing at three of the eight sites and report three facts as unrecorded.
-spec skip_blanks(binary()) -> binary().
skip_blanks(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t; C =:= $\n; C =:= $\r ->
    skip_blanks(Rest);
skip_blanks(Bin) ->
    Bin.

%% The leading run of atom characters, if it is terminated by something that can end an
%% argument. Requiring the terminator matters: without it a line reading
%% `Fact}` would parse `Fact` as a name, and a `dynamic` call would be read as a fact
%% that merely happened not to be declared.
-spec take_name(binary()) -> {ok, binary()} | error.
take_name(Bin) ->
    {Head, Tail} = take_while_atom_char(Bin, <<>>),
    case {Head, Tail} of
        {<<>>, _} -> error;
        {_, <<>>} -> error;
        {_, <<C, _/binary>>} when C =:= $,; C =:= $\); C =:= $\s; C =:= $\n -> {ok, Head}
    end.

take_while_atom_char(<<C, Rest/binary>>, Acc) ->
    case is_atom_char(C) of
        true -> take_while_atom_char(Rest, <<Acc/binary, C>>);
        false -> {Acc, <<C, Rest/binary>>}
    end;
take_while_atom_char(<<>>, Acc) ->
    {Acc, <<>>}.

-spec is_atom_char(char()) -> boolean().
is_atom_char(C) when C >= $a, C =< $z -> true;
is_atom_char(C) when C >= $A, C =< $Z -> true;
is_atom_char(C) when C >= $0, C =< $9 -> true;
is_atom_char($_) -> true;
is_atom_char($@) -> true;
is_atom_char(_) -> false.

%%% %%%%% Locating the tree %%%%% %%%

%% Regular files only. A glob can return an entry that cannot be read, and
%% `file:read_file/1` failing inside the scan would look like a broken test rather than a
%% broken glob.
-spec core_source_files() -> [file:filename_all()].
core_source_files() ->
    Glob = filename:join(project_root(), "apps/i2per/src/*.erl"),
    [F || F <- filelib:wildcard(Glob), filelib:is_regular(F)].

%% Walk up from this module's beam until the source tree is in sight, so the test does
%% not depend on whichever working directory rebar3 happened to choose.
project_root() ->
    climb(filename:dirname(code:which(?MODULE)), 8).

climb(_Dir, 0) ->
    erlang:error({project_root_not_found_from, code:which(?MODULE)});
climb(Dir, Fuel) ->
    case filelib:is_regular(filename:join([Dir, "apps", "i2per", "src", "i2p_log.erl"])) of
        true -> Dir;
        false -> climb(filename:dirname(Dir), Fuel - 1)
    end.
