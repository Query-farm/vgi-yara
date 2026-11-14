# VGI YARA notebooks

[01 · Rule matches and string occurrences answer different questions](01_rule_matches_and_string_occurrences.ipynb)
uses visible Haybarn SQL to validate rules, scan byte columns, retain missing inputs,
and inspect matching rules and individual pattern offsets. Two charts distinguish
rule counts from occurrences. All inputs are authored, harmless synthetic bytes.
The saved notebook contains successful execution outputs.

## Run

Install `uv`, then from this directory:

```sh
uv sync --locked
uv run --locked python execute.py
```

The whole `notebooks/` directory can be copied elsewhere. No worker checkout or Rust
build is required. The runner uses a temporary kernel and this directory as its
working directory, replacing the saved notebook only after success. Internet access
is required initially for Python dependencies, the community VGI extension and the
native release. A matching release asset is required for your platform; macOS Apple
silicon was tested with Haybarn 2.0.0rc11.

For VS Code, select this directory's `.venv/bin/python` as the kernel. Alternatively:

```sh
uv run --locked python -m ipykernel install --user --name vgi-yara-notebooks --display-name 'Python (vgi-yara notebooks)'
```

Run interactively with this directory as the working directory. Parameters,
connection SQL and analytical SQL remain visible; preparation and plotting code are
folded. Restart and run all after changing `REQUIRE_BOTH_MARKERS`.

## Experiment

```sh
uv run --locked python execute.py --parameters '{"REQUIRE_BOTH_MARKERS": true}' --output-dir validation/both
```

Overrides require a separate destination. The runner copies branding, data and
environment companions with the experiment. Requiring both text markers reduces
matched supplied samples from five to three while the binary-only sample remains
matched. The mixed sample retains two matching rules and four pattern occurrences;
its byte-offset chart stays unchanged. Restore `False` for the default.

## Worker and fixture provenance

The literal visible connection is
`github-auto://Query-farm/vgi-yara@v0.4.0`. It downloads a native release, verifies its
hash and caches it. To upgrade, edit the release pin and execute both parameter
settings. Notebook dependencies are isolated in `pyproject.toml` and `uv.lock`.

`fixtures/build.py` deterministically generates seven authored byte files: text
markers, repeated markers with a UTF-8 prefix, binary marker bytes, mixed markers,
unmatched ordinary text and empty bytes. SQL adds an eighth, NULL input record.
`fixtures/manifest.json` records hashes. These are inert examples, not malware or
real-system data. To regenerate the bundled fixtures:

```sh
uv run --locked python fixtures/build.py
```

The selected YARA source is visible in SQL. `yara_check` also checks a deliberately
invalid rule, which is never passed to the scan calls. Scalars take byte and rule
columns. The table functions require constant arguments; folded preparation quotes
the exact validated source and hex-encodes the already inventoried mixed sample for
the visible SQL calls. Analytical transformations remain in the notebook SQL.

## Interpretation and validation

Rule counts are not occurrence counts or severity scores; the first matching rule
is not a priority ranking. String occurrences are emitted only for matching rules.
Offsets count bytes, starting at zero. The chart's end-exclusive spans use the known
fixture patterns, each verified against the original byte slice. Binary matches are
rendered as hex, so rendered-string length is not byte length.

The worker limits each scan to the first 64 MiB and maps internal scan errors to
empty results without exposing a separate status flag. Our fixtures fit within the
bound, but a no-match result still does not prove safety or completeness. NULL input
is unknown; empty supplied bytes return zero under these particular rules. The
parameter experiment tests rule logic, not detection precision, recall or prevalence.

Default and detached experiment runs each pass twelve SQL checks, four independent
byte-slice checks and chart reconciliation. Both charts are inspected in each mode.
Runner guards cover overrides without an output directory, unknown parameters and
invalid-parameter failure preserving saved outputs. All seven fixtures regenerate
identically and match their provenance hashes.

Repository checks pass locked release build, 40 Rust tests, Clippy, formatting,
warning-clean Rust documentation, and 47/51/47 SQL assertions across subprocess,
HTTP and Unix transports (two cases each). Metadata scores 100/100, L2, zero findings
with structural and behavioral checks verified. Source and root dependencies are
unchanged by this notebook publication.

The official Query.Farm Strata Sun wordmark and VGI logo are bundled unchanged.
The wordmark links to Query.Farm at both the top and final bottom of the notebook.
