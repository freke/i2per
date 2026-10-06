# Documentation standards

This page is the documentation contract for i2per. It applies to every Erlang
module in the repository and to the release documentation in this directory.

## Generated API documentation

The project uses EEP-48 attributes and ExDoc. The generated site is written to
`doc/` and is ignored by version control.

Every module must have a `-moduledoc` attribute immediately after
`-module/1`:

````erlang
-module(my_module).

-moduledoc """
Describe what the module does and where it fits in the router.

## Usage

```erlang
my_module:do_x().
```
""".
````

Use Markdown in module documentation. Include a `## Usage` section when the
module exposes an API. A module that implements a wire format should identify
the relevant section in the [protocol reference](protocol.md).

## Functions

Every exported function needs a `-doc` attribute and an accurate `-spec`
immediately before its definition. The function documentation must state its
inputs and outputs in prose:

```erlang
-doc """
Process a request.

Input: `Request` is the request to process; `Config` is the server
configuration. Output: `{ok, Result}` on success, or `{error, Reason}` on
failure.
""".
-spec process_request(map(), map()) ->
    {ok, term()} | {error, term()}.
process_request(Request, Config) ->
    {ok, {Request, Config}}.
```

Keep names and specs specific. Do not leave a stale spec, an undocumented
export, or a description that describes an earlier implementation.

Internal functions do not need `-doc`. Keep them below a clear
`%%%%%%% %%% Internal %%%%%%%` separator.

## Types

Public and opaque types that form part of an API need a `-doc` attribute and
must be exported with `-export_type`:

```erlang
-doc "A 16-byte SipHash key.".
-type siphash_key() :: <<_:128>>.

-doc "An opaque connection handle.".
-opaque connection() :: pid().
```

## Cross-references

Use ExDoc reference prefixes inside backticks:

- Modules: `` `m:my_module` ``
- Functions: `` `f:my_function/1` ``
- Types: `` `t:my_type/0` ``

Plain module and function references are also linked by ExDoc. Prefer explicit
prefixes in public documentation because they remain unambiguous when a
function is overloaded.

## Protocol formats

Every wire format implemented by the router must be documented in both places:

1. The encoding or decoding module documents its message type, fields, byte
   layout, validation rules, and limits.
2. [Protocol Reference](protocol.md) gives the wire-format table and a Mermaid
   `packet` or `sequenceDiagram` for the message flow.

The protocol reference describes only the formats implemented in the 0.1.0
release. Unsupported formats and explicit limitations belong in the release
documentation; they must not be presented as implemented behavior.

## Build and review checks

The test tree separates by what is under test: EUnit for a single function,
Common Test for system behaviour, and PropEr for invariants over generated
inputs.

- `just smoke-test` is the push tier — lint, the unit layer, and most of the
  Common Test suites. It runs on every push and is under five minutes on a CI
  runner.
- `just test` runs everything: lint, documentation generation, all EUnit, the
  property layer, and all Common Test suites, plus the merged coverage report.
  It runs on `main`.
- `just proper` runs the property tests alone, for when a counterexample is what
  you are chasing.
- `just doc` generates the ExDoc site and catches malformed documentation
  attributes.
- `just dialyzer` checks the documented types and specifications against the
  implementation. It is also part of `just check`, run before the tests.

The tier boundaries are derived from the tree by `scripts/ct-suites.sh` and
`scripts/eunit-modules.sh`, so a new suite is in the next smoke run by default.
`just check` is an alias for `just test` plus `just dialyzer`.

The `doc/` directory is generated output. Never commit it.
