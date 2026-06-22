# CLAUDE.md — vgi-yara

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion.

## What this is

A [VGI](https://query.farm) worker (Rust, compiled binary) exposing **YARA
malware scanning** to DuckDB/SQL over Arrow IPC. A defensive security tool. Built
on the `vgi` crate (crates.io), modeled on `vgi-image` / `vgi-barcode`. Catalog
name `yara` (single `main` schema). Rule compilation + scanning via
[`yara-x`](https://crates.io/crates/yara-x), VirusTotal's pure-Rust YARA rewrite
(NO native libyara/C dependency).

## Layout

```
Cargo.toml                          workspace; pins vgi = "0.5.0", yara-x = "=1.7.0"
crates/yara-worker/
  src/main.rs                       Worker::new(); registers scalars + tables
  src/scanning.rs                   PURE logic (no Arrow): compile/scan + size bound + unit tests
  src/arrow_io.rs                   BLOB/VARCHAR reads + LIST(VARCHAR) builder + in-process scalar test harness
  src/scalar/{matches,check,version,mod}.rs   thin Arrow scalar adapters
  src/table/{scan,string_matches,mod}.rs      thin Arrow table-producer adapters
  tests/scanning.rs                 integration tests (compile↔scan, hostile input)
test/sql/*.test                     haybarn-unittest sqllogictest — authoritative E2E
Makefile                            test / test-unit / test-sql / lint / fmt / build / clean
```

Pattern: keep computation in `scanning.rs` (pure, unit-tested), keep Arrow
marshalling in `arrow_io.rs` + `scalar/*.rs` + `table/*.rs` (thin, harness-tested).

## Library: yara-x (compile + scan)

Pinned to **`=1.7.0`**. yara-x 1.7.0 declares `rust-version = 1.86` and its
actual transitive deps resolve under our workspace `rust-version = 1.86`; yara-x
**1.8+ bumps MSRV to 1.87+** (and latest 1.18 to 1.91 via wasmtime/cranelift), so
do not bump without raising the workspace MSRV. `default-features` are OFF (they
drag in the heavy `vt`/`dotnet`/`macho`/`lnk`/`cuckoo`/`dex`/`crx` modules and
proto codegen); we enable just the standard malware-rule modules
(`hash`/`pe`/`elf`/`math`/`string`/`time`/`console`) plus
`constant-folding`/`fast-regexp`/`exact-atoms`.

API shape used:

```rust
let mut c = yara_x::Compiler::new();
c.add_source(src)?;              // Result — the ONLY error path (invalid rule)
let rules = c.build();           // Rules (consumes the compiler)
let mut scanner = yara_x::Scanner::new(&rules);
let results = scanner.scan(bytes)?;   // mapped to "no matches" on Err (total)
for r in results.matching_rules() {   // r.identifier(), r.namespace()
    for t in r.tags() { t.identifier(); }
    for p in r.patterns() {           // p.identifier()  e.g. "$a"
        for m in p.matches() {        // m.range() (start/len), m.data()
            ...
        }
    }
}
```

## Sharp edges

1. **`haybarn-unittest` skips `require vgi`** — `.test` files use explicit
   `statement ok` + `LOAD vgi;`. Functions live under the `yara` catalog, so each
   file does `SET search_path = 'yara.main'`, then `USE memory` before
   `DETACH yara`. Determinism via `ORDER BY` / `rowsort`.

2. **Untrusted data is the whole point.** Scanning is *total*: `scan_rules` /
   `scan_strings` map any `scanner.scan` error to an empty result (never a panic,
   never propagated). `bounded()` truncates data to `MAX_DATA_LEN` (64 MiB)
   before scanning so a giant blob can't exhaust memory. The
   `bad_blob_beside_good`/`hostile_blob_beside_good` tests (Rust + SQL) prove a
   hostile blob next to a valid one still yields results and keeps the worker
   alive. The ONLY error path is **rule compilation** — an invalid rule source is
   a user mistake → a clear DuckDB error (`compile_rules` → `YaraError`).

3. **`yara_check` returns a bool, not an error.** It *is* the "does it compile?"
   predicate, so a non-compiling source is `false`, not a DuckDB error. The scan
   scalars (`yara_matches`/…) instead error on an invalid rule.

4. **Scalars take both `data` and `rules` as columns** (positional, ANY-typed).
   `rules` is usually constant across a batch, so `matches.rs` compiles lazily
   with a one-entry `RuleCache` keyed on the source string (compile once per
   batch when `rules` is constant). A compile error from any row propagates.

5. **Table functions take CONSTANTS, not subqueries.** `yara_scan(data, rules)` /
   `yara_string_matches(data, rules)` read both args via `const_bytes(0)` /
   `const_str(1)` (the `data` reader falls back to `const_str` so a VARCHAR data
   literal works too). Args are declared `const_arg(.., "any", ..)` and bound
   positionally (the SDK binds table args positionally — no `name :=`). Rule
   compilation happens in `producer()`; an invalid rule returns `Err` → a clear
   DuckDB error.

6. **`tags VARCHAR[]` output.** `arrow_io::list_varchar_type()` /
   `list_varchar_builder()` produce a `LIST(VARCHAR)` whose child field is named
   `item`; bind publishes exactly that DataType so bind↔process agree. `matched`
   bytes are rendered UTF-8-if-printable else lowercase hex
   (`scanning::render_matched`).

## Testing

```sh
cargo test --workspace --all-features    # pure unit + arrow-boundary harness + integration
cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --all -- --check
make test-sql                            # builds release, sets VGI_YARA_WORKER, haybarn over test/sql/*
make test                                # cargo test + sql
```

CI (`.github/workflows/ci.yml`) runs fmt/clippy/build/test plus a gated
`e2e-sql` job (installs `uv` + `haybarn-unittest`, runs `make test-sql`).

## Function surface

Scalars: `yara_matches` (BOOLEAN), `yara_first_rule` (VARCHAR), `yara_match_count`
(INT), `yara_check` (BOOLEAN), `yara_version` (VARCHAR). Tables: `yara_scan`
(rule/namespace/tags[]), `yara_string_matches` (rule/identifier/offset/matched).
Untrusted/garbage/empty/binary/hostile data → graceful false / NULL / 0 / no
rows; an invalid rule source is a clear error (except `yara_check`, which returns
false).
