-module(i2p_shipped_modules_tests).

-moduledoc """
Every module in `apps/i2per/src/` has a caller that is not a test.

## The seam

The built application. `apps/i2per/src/` is compiled into the application's
`ebin`, relx copies that directory into the release tarball verbatim, and ExDoc
renders its API reference from the same directory. So one module in `src/` is
three claims at once: that the router contains it, that an operator's release
carries it, and that the router can do whatever it is for.

`m:i2p_sam_proxy` is the fixture that would not hold here. It is a 324-line HTTP
GET proxy whose only caller in the repository is `i2p_sam_SUITE`, and all three
claims were live until #EK2KTKP moved it into the test tree.

## Why "has a caller" and not "is not on a list"

A list of known fixtures is right until the day somebody adds the next one, and
until then it reads as though the tree had been checked. **A module in `src/`
that no shipped code and no shipped script calls is a test fixture with a
module's name on it**, and that is derivable, so it is derived.

## What counts as a caller

Everything that is not the test tree: the rest of `apps/i2per/src/`,
`apps/i2per/src/i2per.app.src`, and the repository's `scripts/*.escript`.

The last of those is what keeps `m:i2p_soak`, `m:i2p_smoke` and
`m:i2p_soak_tunnel` out of this case's answer. They are diagnostics driven by
`just soak`, `just live-smoke` and `just soak-tunnel`, they say so in their own
module docs, and that is the "kept in `src/` deliberately, reason written down"
branch of #EK2KTKP's last acceptance criterion -- not an exception added here.
Whether `scripts/` itself reaches the tarball is a separate packaging question;
what these cases assert is that each module has a caller.

## Two shapes, because a child is not a call

A supervisor child and a `gen_event` handler name their module as an atom in a
tuple, never as `m:f(...)`:

```erlang
{mod, {i2per_app, []}}                          % the only mention of iper_app
start => {i2p_reseed_srv, start_link, [Opts]}
gen_event:add_handler(Collector, {i2p_events_forward, Coll}, [Coll])
```

So the scan reads `Module:` and `{Module,`. Dropping either shape reports three
modules the router genuinely uses.

## Comments are removed first, because a comment is not a caller

`i2per_sup.erl` mentions `m:i2p_reseed_srv` in prose and names it in a child
spec, and this repository has already shipped two branches kept alive by prose
alone. A scan that counted comment text would pass `m:i2p_sam_proxy` the moment
somebody described it in a module doc, which is the failure this case exists to
prevent.

**Stated rather than implied:** a line whose first non-blank character is `%` is
dropped, and a trailing comment on a line that also carries code is not. Every
comment in this tree is on its own line, so nothing is missed today; a
convention that changes makes this case read a comment as a caller, which fails
closed on the other side -- it reports a module as having a caller it does not
have.

## It fails closed

If the source tree were unreadable the module set would come back empty and
every case would pass on no information. So the read is asserted before it is
trusted, and the needle is checked against a module the tree certainly calls.
""".

-include_lib("eunit/include/eunit.hrl").

%% The shipped core sources. `i2per_status` is deliberately absent: rebar.config
%% keeps it out of the release, so a module there ships no further than one in
%% the test tree does.
-define(SRC, "apps/i2per/src/*.erl").

%% The application descriptor. It is where `iper_app` is named -- as
%% `{mod, {i2per_app, []}}`, a shape no source file carries -- so excluding it
%% would report the application callback module as an orphan.
-define(APP_SRC, "apps/i2per/src/i2per.app.src").

%% A module that certainly is called from the shipped tree, used to prove the
%% scan can still see anything at all. Without it a needle that stopped matching
%% -- a renamed helper, a stripped comment rule -- would report a clean tree.
%%
%% A string, not an atom, because a module name arrives here from
%% `filename:basename/2` and converting it to an atom would put an unbounded
%% atom in a table built out of whatever the tree happens to contain.
-define(KNOWN_CALLER, "i2p_reseed_srv").

%%%%%%%%%% The property %%%%%%%%%%

%% The whole ticket. The answer names the file as well as the module, because
%% "i2p_sam_proxy has no caller" is a question and "apps/i2per/src/i2p_sam_proxy.erl
%% is only ever called by a test" is the answer, including where to move it.
%%
%% The two guards carry no message because eunit has no `?assert/2`, and a bare
%% `?assert` failing here means the read broke rather than the tree being wrong.
%% Those are different failures with different fixes, and the module doc says
%% which is which.
every_shipped_module_has_a_caller_outside_the_test_tree_test() ->
    ?assert(shipped_sources() =/= []),
    ?assert(has_caller_outside_the_test_tree(?KNOWN_CALLER, none)),
    Orphans = [
        {filename:basename(File, ".erl"), relative(File)}
     || File <- shipped_sources(),
        not has_caller_outside_the_test_tree(filename:basename(File, ".erl"), File)
    ],
    ?assertEqual([], Orphans).

%%%%%%%%%% What is shipped %%%%%%%%%%

%% Every file the read is taken over. Excluding `Self` is the one thing that
%% makes this a caller scan rather than a substring search: a module always
%% mentions itself, in its own docs and in `moduledoc` cross-references.
shipped_sources() ->
    filelib:wildcard(filename:join(root(), ?SRC)).

root() ->
    i2p_ct_helpers:project_root().

%% A binary, so the failure above prints `apps/i2per/src/i2p_sam_proxy.erl` rather
%% than the same thing wrapped in a list by `string:replace/3`.
relative(Path) ->
    unicode:characters_to_binary(string:replace(Path, root() ++ "/", "")).

%%%%%%%%%% Has a caller %%%%%%%%%%

%% Whether `Module` is referenced from anywhere in the tree except its own source
%% and the test tree. The excluded file is an argument because the caller already
%% has it, and re-deriving it here would be a second answer to the same question.
has_caller_outside_the_test_tree(Module, none) ->
    lists:any(fun(File) -> scan_finds(Module, File) end, readers());
has_caller_outside_the_test_tree(Module, Self) ->
    lists:any(
        fun(File) -> File =/= Self andalso scan_finds(Module, File) end,
        readers()
    ).

%% The shipped sources, the application descriptor, and the repository's
%% escripts. A module that no shipped source and no shipped script names has
%% nobody to call it.
readers() ->
    filelib:wildcard(filename:join(root(), ?SRC)) ++
        [filename:join(root(), ?APP_SRC)] ++
        filelib:wildcard(filename:join(root(), "scripts/*.escript")).

%% Whether `Module` is referenced from `File` as code rather than as prose.
scan_finds(Module, File) ->
    case file:read_file(File) of
        {ok, Bin} ->
            Code = strip_comment_lines(Bin),
            lists:any(fun(Needle) -> binary:match(Code, Needle) =/= nomatch end, needles(Module));
        {error, _} ->
            false
    end.

%% The two reference shapes, as binaries. The trailing `:` and leading `{,` are
%% what keep `i2p_log` from matching `i2p_log_checklist_tests` and `i2p_log`,
%% which is why neither side needs a word-boundary test of its own.
needles(Name) ->
    Bin = unicode:characters_to_binary(Name),
    [<<Bin/binary, ":">>, <<"{", Bin/binary, ",">>].

%% The newlines are put back rather than dropped. Neither needle can span a line,
%% but a needle that cannot span a line must be unable to *become* one by joining
%% two that should not have met.
strip_comment_lines(Bin) ->
    Lines = [
        Line
     || Line <- binary:split(Bin, <<"\n">>, [global]),
        not starts_with_percent(Line)
    ],
    iolist_to_binary(Lines).

%% A line is a comment when everything before its first `%` is whitespace. A `%`
%% inside a binary or string mid-line is not a comment and is not treated as one,
%% because the line does not *start* with one.
%%
%% **The `\\` is load-bearing.** `<<"[^\s]">>` is `[^ ]` -- the compiler unescapes
%% `\s` to a space on the way in, so PCRE is handed a class matching any
%% character that is not a space, which a tab satisfies. The question is whether
%% anything *but* whitespace precedes the `%`, and that version answers no for an
%% indented comment and reports every indented line in the tree as code.
starts_with_percent(Line) ->
    case binary:match(Line, <<"%">>) of
        nomatch -> false;
        {Pos, _} -> binary:match(binary:part(Line, 0, Pos), <<"[^\\s]">>) =:= nomatch
    end.
