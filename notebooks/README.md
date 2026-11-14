# YARA examples

[01 · Rule matches and string occurrences](01_rule_matches_and_string_occurrences.ipynb)
asks which authored samples satisfy a ruleset and what byte-level evidence supports
the result. It covers all seven named public SQL functions/tables in **v0.4.0**.

[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Query-farm/vgi-yara/blob/main/notebooks/01_rule_matches_and_string_occurrences.ipynb)

The notebook discovers the running worker's modules, uses `hash` in a binary-marker
rule, validates good and broken rule sources, preserves unmatched and missing input,
and distinguishes matching rules from individual pattern occurrences. The two SVG
charts show the full input population and verified byte offsets. The parameter
experiment requires both text markers while keeping the bytes and binary rule fixed.

All input bytes are visible SQL literals: inert `ORBIT`/`LANDER` markers, a four-byte
binary marker, ordinary text, empty bytes and NULL. There are no malware payloads,
captured files or real-system observations. A match is not a malware verdict. The
worker bounds scans to 64 MiB and maps internal scan failures to empty results, so
a no-match report cannot establish that a file is safe or fully scanned.

## Run the example

Open in Colab and choose **Runtime → Run all**. Setup installs the base shared
package and retrieves one verified chart companion. The visible `ATTACH` uses
`github-auto://Query-farm/vgi-yara@v0.4.0`; no compiler, credentials or local worker
checkout is required. Compatible Colab kernel and plotting libraries are preserved.
If an earlier installation replaced them, save your work and choose **Runtime →
Disconnect and delete runtime** before reopening the current example.

For local execution from this directory:

```sh
uv sync --locked
uv run --locked vgi-notebooks
uv run --locked vgi-notebooks --parameters '{"REQUIRE_BOTH_MARKERS":true}' --output-dir artifacts/both-markers
```

The local environment uses the shared package's `[runner]` extra. The notebook
installs its base package only. Branding, setup, runner, SVG publication and the
[standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.2/docs/standard.md)
live in [vgi-example-notebooks](https://github.com/Query-farm/vgi-example-notebooks).
`yara_example.py` contains the two charts and result interpretations; the analytical
worker calls remain in visible SQL. Keep `charts/` with the saved notebook for
GitHub rendering.

## Coverage evidence

`coverage.json` binds the complete runtime catalog, successful execution receipt,
SQL cells, visible results and editorial review. The worker has four scalars,
two table functions, and the `yara_modules` reference table: seven logical objects.
The released worker source and current public-main worker source are identical;
current-interface coverage is compatibility-reviewed while the actual notebook
runtime remains v0.4.0. Tests of Colab-compatible preloaded libraries are local
compatibility checks, not a claim of a manually operated hosted Colab session.
