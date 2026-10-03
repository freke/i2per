-module(i2p_events_vocabulary_tests).

-moduledoc """
The bus's event type and the events the router actually announces must agree.

`m:i2p_events:event/0` is the contract: `f:notify/1` is specified in terms of it,
so dialyzer refuses a call site whose shape is not in the type. That is the *inner*
boundary and it is enforced by the build. It says nothing about the *outer* one --
whether the type still describes what the router announces, and whether every tag
somewhere in the tree is a tag the type admits. Both directions drift silently: a
tag added to a call site and not to the type is a dialyzer warning nobody reads
until release, and a tag left in the type after the code stopped announcing it is a
promise the bus no longer keeps.

So the check reads the tree. It is derived rather than hand-written, because a list
written beside the type would be a *third* copy to keep in step, and would be wrong
the first time a tag was added -- which is the same duplication this project exists
to refuse.

What this is not: a runtime test cannot enumerate a type, because a type is not
data. So this compares the two *sides* of the type -- the shapes written in it, and
the shapes the call sites pass -- rather than proving the type itself is correct.
The other half of the guarantee is structural and lives in the status service, where
folding an event is total, so a shape the type does not yet admit would still be
counted and flagged rather than dropped.
""".

-include_lib("eunit/include/eunit.hrl").

%% Exported for `i2p_log_checklist_tests`, which needs to know whether the event type
%% still admits the shapes ADR 0002's checklist declares as bus-carried. It calls this
%% rather than writing a second reader for the type: this parser is deliberately fussy
%% about the details that break silently (comment stripping, the `}.` terminator, wire
%% vs character offsets), and a copy of it would be a copy of exactly that fussiness.
-export([declared_tags/0]).

%% The one call shape the scan below can read. Named so the offset past it is derived
%% from the needle rather than counted out by hand: a literal count here would
%% silently truncate every tag by two characters if the needle ever changed, and a
%% truncated tag reads as a missing event.
-define(NOTIFY, <<"i2p_events:notify(">>).

%% How many shapes `t:i2p_events:event/0` is meant to have. Asserted so a parse that
%% has quietly gone wrong fails loudly rather than agreeing with itself on a
%% smaller world, and so adding a shape without updating it is a decision rather
%% than an accident.
-define(SHAPE_COUNT, 19).

%%% %%%%% The two sides agree %%%%% %%%

shapes_in_the_type_and_at_the_call_sites_agree_test() ->
    Declared = declared_tags(),
    Announced = announced_tags(),
    ?assertEqual([], Announced -- Declared),
    ?assertEqual([], Declared -- Announced).

%% Not a formality: the whole check rests on every call site passing a literal
%% tuple. A dynamic `notify(Event)` would be invisible to the scan, and the scan
%% would then be quietly reporting a smaller world than the router announces. If
%% one is ever introduced this case fails, rather than the agreement above passing
%% on incomplete information.
every_call_site_announces_a_literal_shape_test() ->
    Dynamic = [
        Site
     || Site = {_File, _Line, Rest} <- notify_call_sites(),
        not begins_a_shape(trim(Rest))
    ],
    ?assertEqual([], Dynamic).

%% The failure events are in the type, by name. Asserted so the agreement case above
%% cannot pass on a vocabulary that has quietly shrunk back to something smaller and
%% still self-consistent.
the_three_failure_events_are_in_the_type_test() ->
    Declared = declared_tags(),
    lists:foreach(
        fun(Tag) -> ?assert(lists:member(Tag, Declared)) end,
        [peer_connect_failed, transit_denied, leaseset_publish_failed, lookup_failed]
    ).

%% A peer's connect failure and its disconnect are different facts, and a tunnel
%% the router built and one it refused to carry are opposites. The type keeping them
%% apart is what lets a consumer tell them; a test that only counted tags would not
%% notice them being merged.
failure_and_success_shapes_are_distinct_test() ->
    Declared = declared_tags(),
    lists:foreach(
        fun(Tag) -> ?assert(lists:member(Tag, Declared)) end,
        [
            peer_connected,
            peer_disconnected,
            peer_connect_failed,
            leaseset_published,
            leaseset_publish_failed,
            tunnel_built,
            transit_denied
        ]
    ).

%%% %%%%% The two sides, read from the tree %%%%% %%%

%% The tags the event type admits, read out of the type itself rather than listed
%% beside it.
declared_tags() ->
    Sorted = lists:usort([
        tag_of_shape(Line)
     || Line <- type_block(),
        begins_a_shape(Line)
    ]),
    ?assertEqual(?SHAPE_COUNT, length(Sorted)),
    Sorted.

%% The tags actually passed to `i2p_events:notify/1` anywhere in the router.
announced_tags() ->
    lists:usort([
        tag_of_shape(Line)
     || {_File, _Line, Line} <- notify_call_sites(),
        begins_a_shape(trim(Line))
    ]).

%% The lines of the `event/0` type: every shape, including the last.
%%
%% The terminator is the line that *ends* with `}.`, and that line is itself a
%% shape -- a type is written as a series of `| {tag, ...}` and only the final one
%% carries the closing `}.`. Two things go wrong if this is not careful, and both
%% were: anchoring on a line *starting* with `}.` finds nothing and silently parses
%% the rest of the file, and excluding the terminator drops the last tag.
type_block() ->
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

%% `{tag, ...` at the start of a shape. The opening `|` and `{` are both skipped,
%% because a type writes its shapes as `| {tag, ...}` after the first and a call
%% site writes `{tag, ...}`. Skipping a single character left a leading space on the
%% tag, and `list_to_atom/1` turned that into a *different atom* -- so
%% `config_changed` parsed as `' {config_changed'` and agreed with nothing.
tag_of_shape(Line) ->
    {Tag, _Rest} = lists:splitwith(
        fun(C) -> C =/= $} andalso C =/= $, andalso C =/= $| end, shape_body(Line)
    ),
    ?assertNotEqual([], Tag),
    list_to_atom(lists:flatten(Tag)).

%% Strip whatever opens a shape, leaving the tag: `| {` in a type after the first
%% shape, `{` at the start of one and at a call site.
%%
%% Done by explicit clauses rather than by dropping characters until something is
%% left, because doing both -- dropping the `{` and then also skipping one more --
%% quietly ate the first letter of every tag. `config_changed` came back as
%% `onfig_changed`, which is a *different atom* and so agreed with nothing. A
%% truncation like that is invisible in the failure: it just looks like an event
%% nobody publishes.
shape_body(Line) ->
    Stripped = trim(strip_comment(Line)),
    case Stripped of
        "| " ++ Rest -> lists:nthtail(1, Rest);
        [${ | Rest] -> Rest;
        Other -> Other
    end.

%% A shape line opens with `{` or `| {`. Matched as string prefixes rather than as
%% character lists: the character-list spelling of an opening brace has to be
%% written `${`, which reads as a dollar applied to a brace and silently fails to
%% match the continuation lines -- so the type's shapes came back as one and the
%% check quietly stopped checking.
begins_a_shape(Line) ->
    %% Comments are stripped first so a commented-out shape written in the type's own
    %% style cannot be counted as a shape. A type is heavily commented, and a note
    %% that begins `%% | {tag, ...}` would otherwise read as a real one.
    case trim(strip_comment(Line)) of
        "{" ++ _ -> true;
        "| {" ++ _ -> true;
        _ -> false
    end.

%% Every `i2p_events:notify(` in the tree, with the rest of the line it is on.
%%
%% Matched with `binary:matches/2` rather than by walking the decoded text. The
%% sources are not pure ASCII -- they carry em-dashes -- so a byte offset and a
%% character index are different numbers, and mixing them cuts lines in the wrong
%% place on any file with a non-ASCII byte before a call site. Only the tail of the
%% line is read, since that is all `tag_of_shape/1` needs.
notify_call_sites() ->
    lists:flatmap(
        fun(File) ->
            {ok, Bin} = file:read_file(File),
            [
                {
                    filename:basename(File),
                    count_lines(Bin, Offset),
                    rest_of_line(Bin, Offset + byte_size(?NOTIFY))
                }
             || {Offset, _Length} <- binary:matches(Bin, ?NOTIFY)
            ]
        end,
        source_files()
    ).

count_lines(Bin, Offset) ->
    length(binary:matches(binary:part(Bin, 0, Offset), <<"\n">>)) + 1.

rest_of_line(Bin, Offset) ->
    Rest = binary:part(Bin, Offset, byte_size(Bin) - Offset),
    [Line | _] = binary:split(Rest, <<"\n">>),
    binary_to_list(Line).

%%% %%%%% Locating the tree %%%%% %%%

%% Regular files only. A glob can return an entry that cannot be read, and
%% `file:read_file/1` failing inside the scan would look like a broken test rather
%% than a broken glob.
source_files() ->
    Glob = filename:join(source_dir(), "*.erl"),
    [F || F <- filelib:wildcard(Glob), filelib:is_regular(F)].

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
