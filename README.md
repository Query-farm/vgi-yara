<p align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi/main/docs/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# vgi-yara

A [VGI](https://query.farm) worker (Rust, a compiled binary) that brings
**YARA malware scanning** to DuckDB / SQL over Apache Arrow. DuckDB launches the
worker and talks to it over Arrow IPC; the functions appear under the catalog
`yara`, schema `main`. This is a **defensive security tool**: it scans
data/files against [YARA](https://virustotal.github.io/yara/) rules for malware
detection.

Rule compilation and scanning are powered by
[`yara-x`](https://crates.io/crates/yara-x), VirusTotal's official **pure-Rust**
rewrite of YARA — no native `libyara`/C dependency.

```sql
LOAD vgi;
ATTACH 'yara' (TYPE vgi, LOCATION './target/release/yara-worker');
SET search_path = 'yara.main';

-- Per-row predicate over a column of blobs/files.
SELECT path
FROM files
WHERE yara_matches(content, 'rule eicar { strings: $a = "EICAR" condition: $a }');

-- First matching rule / how many rules matched.
SELECT yara_first_rule(content, $rules)  FROM files;   -- VARCHAR (NULL if none)
SELECT yara_match_count(content, $rules) FROM files;   -- INT

-- Validate a ruleset compiles.
SELECT yara_check('rule r { condition: true }');       -- → true

-- Fan one constant blob into its matches (table functions).
SELECT * FROM yara_scan(read_blob('sample.bin'), $rules);
-- rule | namespace | tags
SELECT * FROM yara_string_matches(read_blob('sample.bin'), $rules);
-- rule | identifier | offset | matched
```

## Functions

### Scalar

| Function | Returns | Description |
| --- | --- | --- |
| `yara_matches(data, rules)` | `BOOLEAN` | Does `data` match **any** rule? |
| `yara_first_rule(data, rules)` | `VARCHAR` | Identifier of the first matching rule (`NULL` if none). |
| `yara_match_count(data, rules)` | `INT` | Number of matching rules. |
| `yara_check(rules)` | `BOOLEAN` | Do the rules compile? (validation; never errors). |
| `yara_version()` | `VARCHAR` | Worker version string. |

`data` is a `BLOB` or `VARCHAR` (the bytes/text to scan); `rules` is a YARA rule
source string.

### Table

| Function | Columns | Description |
| --- | --- | --- |
| `yara_scan(data, rules)` | `rule VARCHAR, namespace VARCHAR, tags VARCHAR[]` | One row per matching rule. |
| `yara_string_matches(data, rules)` | `rule VARCHAR, identifier VARCHAR, "offset" BIGINT, matched VARCHAR` | One row per pattern (string) hit. |

> DuckDB table functions take **constant** arguments (no subqueries), so the
> `data` and `rules` passed to `yara_scan` / `yara_string_matches` must be
> constant-foldable expressions (literals, `read_blob('…')`, etc.). `matched` is
> the matched bytes rendered as UTF-8 text when printable, else a lowercase hex
> string.

## Behavior & robustness

The **scanned data is untrusted** — by definition it may be live malware:

* A malformed, truncated, binary, or hostile blob **never** crashes the worker.
  Scanning is total: it yields no matches (`false` / `NULL` / `0` / no rows),
  never an error. A bad blob beside a good one still produces the good one's
  matches.
* Scanned data is **bounded** (64 MiB): an oversized blob is truncated to the cap
  before scanning so it cannot exhaust memory.
* `NULL` input → `NULL` output / no rows.
* An **invalid rule source** (a user mistake) surfaces a clear DuckDB error from
  the scan functions, carrying the compiler diagnostic. `yara_check` instead
  returns `false` for a non-compiling source (it *is* the "does it compile?"
  predicate).

## Building & testing

```sh
cargo build --release                                    # build the worker
cargo test --workspace --all-features                    # unit + integration tests
cargo clippy --all-targets --all-features -- -D warnings # lint
make test-sql                                            # DuckDB SQL end-to-end
```

`make test-sql` builds the release worker, points `VGI_YARA_WORKER` at it, and
runs the [`haybarn-unittest`](https://pypi.org/project/haybarn-unittest/)
sqllogictest suite under `test/sql/`. Install the runner once with
`uv tool install haybarn-unittest`.

## Licensing

* This worker: **MIT** — see [LICENSE](LICENSE).
* [`yara-x`](https://crates.io/crates/yara-x) (the scanning engine): BSD-3-Clause.
* [`vgi`](https://crates.io/crates/vgi) / `vgi-rpc` (the worker SDK) and
  `arrow-*`: Apache-2.0.

---

## Authorship & License

Written by [Query.Farm](https://query.farm) — every VGI worker is designed and built by Query.Farm.

Copyright 2026 Query Farm LLC - https://query.farm

