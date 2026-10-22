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

## The six things asserted

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
  information, which is worse than not having the check;
- every declared **bus** row also has an `m:i2p_log:debug/2` call site naming it, so
  the bus's copy is not the only one. ADR 0002 permits the second copy at a level
  off by default and this is where that permission stops being a claim;
- no declared **log** row has a `debug/2` shadow beside its `emit/3`, because a fact
  already recorded at its declared level is recorded, and a second line under it
  says nothing the first did not.

## Reading the event type

`m:i2p_events:event/0` is parsed by `m:i2p_events_vocabulary_tests`, which already
has a reader for it and four cases built on the answer. It is called rather than
re-implemented: a second parser is a second thing to keep in step with a type that
gains a shape every few months, and it would be a copy of a parser that is
deliberately fussy about exactly the details that break quietly.
""".

-include_lib("eunit/include/eunit.hrl").

%% `f:debug_call_sites/0` is exported because `i2p_log_tests` answers the other half
%% of the same partition from it -- see the note on the function.
-export([debug_call_sites/0]).

%% The one call shape this scan can read. Named so the offset past it is derived from
%% the needle rather than counted out by hand: a literal count would silently truncate
%% every fact name, and a truncated fact name reads as a missing fact.
-define(EMIT, <<"i2p_log:emit(">>).

%% The off-by-default record beside a bus-carried fact. Its first argument is a
%% `m:i2p_log:label/0`, so at 69 of the sites in the tree today it is a tuple frame
%% and at the ten this module is here to pin it is the fact's name. Both shapes are
%% read by the same scanner: a tuple yields `dynamic`, which is what makes "the fact
%% is named here" a question about atoms rather than about frames.
-define(DEBUG, <<"i2p_log:debug(">>).

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

%% ADR 0002's table names the symptoms the bus answers. Each is asserted by name
%% in a written-out list, which is the pin: a row quietly dropped cannot leave this
%% case green on a shorter but still self-consistent set. The count is deliberately
%% not also written into the case name, because that would be a second number to
%% edit at the same time as this one, and a number nobody reads is a number that
%% stops agreeing with the list.
all_bus_carried_rows_are_declared_test() ->
    Bus = [Fact || {Fact, #{instrument := bus}} <- maps:to_list(i2p_log:checklist())],
    ?assertEqual(
        [
            db_store_not_stored,
            leaseset_publish_failed,
            lookup_failed,
            peer_connect_failed,
            peer_send_stalled,
            reachability,
            transit_denied
        ],
        lists:sort(Bus)
    ).

%%% %%%%% Every bus fact survives the bus's death %%%%% %%%

%% ADR 0002:33-35 permits a bus-carried fact to be written to the log "except at a
%% level that is off by default". That clause is what the bus's own bound rests on:
%% a bound that kills the manager destroys the bus's copy of every fact, so a fact
%% whose only record is the bus is a fact the operator loses at the moment they go
%% looking for it.
%%
%% Until this case existed, the permission was in the ADR and not in the tree --
%% seven declared rows, one log record, and a green build over the gap. The other
%% cases here cannot see it: a `bus` row is satisfied by its event existing, and a
%% missing `debug/2` shadow is not a missing event.
%%
%% The label rather than the call is what is checked, because `f:debug/2` takes a
%% `t:label/0` and 69 of the sites in the tree are frames rather than facts. Naming
%% the fact as the label is what makes the record findable by the fact's name, which
%% is the thing a reader at 3am has.
%%
%% `f:debug_call_sites/0` is scanned once and the verdict is membership, so the report
%% and the check cannot disagree about what was found. A `bus` row with ten records
%% and a row with one both pass, which is right: the promise is that a record
%% survives the bus, not that exactly one does.
every_bus_fact_has_an_off_by_default_record_test() ->
    Recorded = [Fact || {_File, _Line, Fact} <- debug_call_sites()],
    Missing = [
        {Fact, "no i2p_log:debug/2 call site in apps/i2per/src naming it"}
     || Fact <- bus_carried(),
        not lists:member(Fact, Recorded)
    ],
    ?assertEqual([], Missing).

%% The other direction, and the one that keeps the permission from becoming a habit.
%%
%% A `log` row is already recorded at a level an operator sees. A `debug/2` line
%% under it is a second copy of a fact that needed one, which is the duplication
%% ADR 0002 exists to prevent -- and unlike the shadow above, nothing turns it off,
%% because whoever is reading `debug` is reading *everything* at `debug`.
%%
%% This is the case that fails if the shadow is copied sideways onto a `log` row, and
%% it is also the one that would have caught `ssu2_block_unhandled` being given a
%% frame rather than a fact.
no_log_fact_is_shadowed_at_debug_test() ->
    Logged = [Fact || {_File, _Line, Fact} <- emit_call_sites()],
    Shadows = [
        {File, Line, Fact}
     || {File, Line, Fact} <- debug_call_sites(),
        Fact =/= dynamic,
        lists:member(Fact, Logged)
    ],
    OnBoth = [
        {maps:get(Fact, i2p_log:checklist()), {File, Line}}
     || {File, Line, Fact} <- Shadows
    ],
    ?assertEqual([], OnBoth).

%% The bus-carried rows, as facts rather than as checklist entries.
-spec bus_carried() -> [atom()].
bus_carried() ->
    [Fact || {Fact, #{instrument := bus}} <- maps:to_list(i2p_log:checklist())].

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
    Tags = declared_event_tags(),
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
    call_sites(?EMIT).

%% Every `i2p_log:debug(` in the core tree, with the label it names.
%%
%% The same scanner as `f:emit_call_sites/0` over a different needle, because the two
%% questions are the same shape: a call whose first argument names a fact, read from
%% the bytes rather than from a list written beside the call.
%%
%% A tuple label -- 69 of them, one per frame on the wire -- comes back as `dynamic`,
%% which is not a failure here. Unlike a variable in an `emit/3` call, a tuple is
%% *legitimately* not a fact, so there is nothing to report: the check above is "the
%% fact is named", and a frame naming nothing is that check holding, not breaking.
%% Exported because `i2p_log_tests` needs the same scan to answer the other half of
%% the partition: a `debug/2` site naming a checklist fact is a bus fact's record,
%% and one naming anything else is a frame. Two scanners over one needle would be two
%% things to keep in step with `f:debug/2`'s call shape, and this is the shape.
-spec debug_call_sites() -> [{string(), pos_integer(), atom()}].
debug_call_sites() ->
    call_sites(?DEBUG).

-spec call_sites(binary()) -> [{string(), pos_integer(), atom()}].
call_sites(Needle) ->
    lists:flatmap(fun(File) -> scan_file(File, Needle) end, core_source_files()).

-spec scan_file(file:filename_all(), binary()) -> [{string(), pos_integer(), atom()}].
scan_file(File, Needle) ->
    {ok, Bin} = file:read_file(File),
    lists:flatmap(
        fun({Offset, _Length}) ->
            Start = Offset + byte_size(Needle),
            Rest = binary:part(Bin, Start, min(?SCAN_BYTES, byte_size(Bin) - Start)),
            [
                {filename:basename(File), count_lines(Bin, Offset), fact_of(Rest)}
            ]
        end,
        binary:matches(Bin, Needle)
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
    Glob = filename:join(i2p_ct_helpers:project_root(), "apps/i2per/src/*.erl"),
    [F || F <- filelib:wildcard(Glob), filelib:is_regular(F)].

%%% %%%%% Event type tags, read from i2p_events:event/0 %%%%% %%%

%% The tags the event type admits, read out of the type itself rather than listed
%% beside it. Replaces the deleted i2p_events_vocabulary_tests:declared_tags/0.
-spec declared_event_tags() -> [atom()].
declared_event_tags() ->
    Sorted = lists:usort([
        tag_of_shape(Line)
     || Line <- event_type_block(),
        begins_a_shape(Line)
    ]),
    Sorted.

event_type_block() ->
    Source = read_source_lines(filename:join(source_dir(), "i2p_events.erl")),
    {_, After} = lists:splitwith(
        fun(Line) -> not lists:prefix("-type event() ::", trim(Line)) end, Source
    ),
    ?assertNotEqual([], After),
    {Shapes, [Last | _]} = lists:splitwith(
        fun(Line) -> not lists:suffix("}.", trim(Line)) end, lists:nthtail(1, After)
    ),
    ?assertNotEqual([], Shapes),
    Shapes ++ [Last].

tag_of_shape(Line) ->
    {Tag, _Rest} = lists:splitwith(
        fun(C) -> C =/= $} andalso C =/= $, andalso C =/= $| end, shape_body(Line)
    ),
    ?assertNotEqual([], Tag),
    list_to_atom(lists:flatten(Tag)).

shape_body(Line) ->
    Stripped = trim(strip_comment(Line)),
    case Stripped of
        "| " ++ Rest -> lists:nthtail(1, Rest);
        [${ | Rest] -> Rest;
        Other -> Other
    end.

begins_a_shape(Line) ->
    case trim(strip_comment(Line)) of
        "{" ++ _ -> true;
        "| {" ++ _ -> true;
        _ -> false
    end.

source_dir() -> filename:join(i2p_ct_helpers:project_root(), "apps/i2per/src").

read_source_lines(Path) ->
    {ok, Bin} = file:read_file(Path),
    string:split(unicode:characters_to_list(Bin), "\n", all).

strip_comment(Line) ->
    case string:split(Line, "%%", leading) of
        [Before] -> Before;
        [Before | _] -> Before
    end.

trim(S) -> string:trim(S).
