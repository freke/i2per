{ pkgs, lib, config, ... }:

{
  cachix.enable = false;

  languages.erlang.enable = true;
  packages = [ pkgs.just pkgs.jujutsu pkgs.git pkgs.erlfmt pkgs.erlang-language-platform pkgs.gh ];

  # No `enterShell` hook. The `gh` OSC 11 workaround used to live here, as a
  # shell function exported with `export -f`, and it does not survive direnv:
  # `direnv export` drops the function, and zsh has no `export -f` at all, so
  # `type gh` reported the bare binary in every zsh session. `gh auth login` is
  # the only interactive `gh`, and it now pins TERM itself -- see `just
  # gh-login`, which carries the reasoning next to the thing that works.

  # `just smoke-test`, not `rebar3 eunit`.
  #
  # `enterTest` runs when the environment is entered in test mode, so whatever is
  # here is this project's answer to "does this still work". The answer was
  # `rebar3 eunit`, which is a *second* answer: it runs the unit and property
  # layers together, where `just smoke-test` runs the unit layer alone, and it
  # skips `erlfmt` entirely. `scripts/eunit-modules.sh` exists to keep that
  # partition in one place, so a bare `rebar3 eunit` is the one invocation that
  # ignores it.
  #
  # Pointing at the recipe rather than restating the command is what keeps the
  # two from drifting: the recipe is already what CI runs on every push
  # (`.github/workflows/gate.yml`), so this cannot answer a different question
  # from the gate's.
  enterTest = ''
    just smoke-test
  '';
}
