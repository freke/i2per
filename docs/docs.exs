# ExDoc configuration for the i2per umbrella.
#
# Generates a SINGLE merged documentation site at the repo-root `doc/`
# covering both OTP applications in this umbrella (`i2per` core and the
# standalone `i2per_status` web service). Consumed by `scripts/gen-docs.sh`;
# run via `just doc`.
#
#   ex_doc i2per 0.2.0-rc1 _build/default/lib/i2per/ebin \
#     _build/default/lib/i2per_status/ebin \
#     --proglang erlang --config docs/docs.exs --output doc

[
  main: "readme",
  proglang: :erlang,
  # Source links point at github.com/freke/i2per/blob/<source_ref>/..., so
  # source_ref must name a ref that exists. "main" always does, so it is the
  # default; CI overrides with the tag being built (I2PER_DOCS_SOURCE_REF),
  # which makes the published site's links resolve to the code the site is
  # about.
  source_ref: System.get_env("I2PER_DOCS_SOURCE_REF") || "main",
  source_url: "https://github.com/freke/i2per",

  extras: [
    "README.md",
    {"CHANGELOG.md", title: "Changelog"},
    {"docs/documentation.md", title: "Documentation Standards"},
    {"docs/protocol.md", title: "Protocol Reference"}
  ],

  groups_for_modules: [
    "i2per core": ~w(i2per i2per_app i2per_sup),
    "Status web service": ~w(i2per_status_app i2per_status_json i2per_status_page i2per_status_state i2per_status_sup)
  ],

  # Mermaid diagrams: `docs/protocol.md` (and any extra) may use
  # fenced ```mermaid blocks. We inject mermaid via a CDN script and render
  # each `pre code.mermaid` block into an SVG after ExDoc fires `exdoc:loaded`.
  before_closing_body_tag: %{
    html: """
    <script defer src="https://cdn.jsdelivr.net/npm/mermaid@11.12.2/dist/mermaid.min.js"></script>
    <script>
      let initialized = false;
      window.addEventListener("exdoc:loaded", () => {
        if (!initialized) {
          mermaid.initialize({ startOnLoad: false, theme: document.body.className.includes("dark") ? "dark" : "default" });
          initialized = true;
        }
        let id = 0;
        for (const codeEl of document.querySelectorAll("pre code.mermaid")) {
          const preEl = codeEl.parentElement;
          const graphDefinition = codeEl.textContent;
          const graphEl = document.createElement("div");
          const graphId = "mermaid-graph-" + id++;
          mermaid.render(graphId, graphDefinition).then(({svg, bindFunctions}) => {
            graphEl.innerHTML = svg;
            bindFunctions?.(graphEl);
            preEl.insertAdjacentElement("afterend", graphEl);
            preEl.remove();
          }).catch(error => {
            graphEl.textContent = "Mermaid diagram failed: " + error;
            preEl.insertAdjacentElement("afterend", graphEl);
            preEl.remove();
          });
        }
      });
    </script>
    """
  }
]
