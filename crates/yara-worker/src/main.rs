//! The `yara` VGI worker — a defensive malware-scanning tool.
//!
//! A standalone binary that DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'yara' (TYPE vgi, LOCATION '…')`). It brings YARA-X rule compilation
//! and scanning of data/files for malware to SQL under the catalog `yara`,
//! schema `main`:
//!
//! ```sql
//! ATTACH 'yara' (TYPE vgi, LOCATION './target/release/yara-worker');
//! SET search_path = 'yara.main';
//!
//! -- Per-row predicates over a column of blobs/files.
//! SELECT path FROM files
//! WHERE yara_matches(content, (SELECT rules FROM ruleset));   -- BOOLEAN
//! SELECT yara_first_rule(content, $rules) FROM files;          -- VARCHAR
//! SELECT yara_match_count(content, $rules) FROM files;         -- INT
//! SELECT yara_check($rules);                                   -- do rules compile?
//!
//! -- Fan one constant blob into its matches (table functions).
//! SELECT * FROM yara_scan(read_blob('sample.bin'), $rules);    -- rule/namespace/tags
//! SELECT * FROM yara_string_matches(read_blob('sample.bin'), $rules); -- pattern hits
//! ```
//!
//! Pure YARA logic (compile/scan, size bound, total scanning) lives in
//! `scanning.rs`; the `scalar/` and `table/` modules are thin Arrow adapters.
//!
//! The scanned data is UNTRUSTED (by definition possibly live malware): scanning
//! never panics or crashes the worker — a hostile blob yields no matches, never
//! an error. Only an *invalid rule source* surfaces a (clear) DuckDB error.

mod arrow_io;
mod meta;
mod scalar;
mod scanning;
mod table;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Worker version string, surfaced by `yara_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Catalog + schema metadata (description, provenance) surfaced to DuckDB and the
/// `vgi-lint` metadata-quality linter. The function objects themselves are served
/// from the registered scalars/tables; this only adds catalog/schema-level
/// comments and tags.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Defensive YARA-X malware scanning: compile YARA rules and scan blobs/text for \
             matches, all in SQL over Apache Arrow."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "YARA Malware Scanning".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                "yara, yara-x, malware, malware scanning, threat hunting, IOC, indicator of \
                 compromise, signature, rule, detection, security, antivirus, blob scan, \
                 pattern matching, defensive security"
                    .to_string(),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Scan bytes or text for malware/IOC signatures using YARA rules, entirely in SQL. \
                 Per-row scalars test a column of blobs against a YARA ruleset \
                 (`yara_matches` → does it match any rule, `yara_first_rule` → first matching \
                 rule, `yara_match_count` → number of matching rules), validate that a ruleset \
                 compiles (`yara_check`), and report the worker version (`yara_version`). Table \
                 functions fan one constant blob into its hits: `yara_scan` yields one row per \
                 matching rule (rule, namespace, tags), `yara_string_matches` yields one row per \
                 pattern hit (rule, identifier, offset, matched bytes). Use for malware triage, \
                 threat hunting, and IOC matching over data already in DuckDB. Scanning is total \
                 — untrusted/hostile data never crashes the worker; only an invalid rule source \
                 is an error."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# yara\n\nDefensive **YARA-X** malware scanning over Apache Arrow, powered by \
                 VirusTotal's pure-Rust YARA rewrite (no native libyara).\n\n**Scalars:** \
                 `yara_matches` (BOOLEAN), `yara_first_rule` (VARCHAR), `yara_match_count` \
                 (INT), `yara_check` (BOOLEAN), `yara_version` (VARCHAR).\n\n**Tables:** \
                 `yara_scan` (rule, namespace, tags[]), `yara_string_matches` (rule, identifier, \
                 offset, matched).\n\nScanning is total: untrusted/garbage/empty/hostile data \
                 yields no matches rather than crashing; only an invalid rule source raises an \
                 error (except `yara_check`, which returns `false`)."
                    .to_string(),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-yara/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-yara/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-yara".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some("YARA rule compilation and malware-scanning functions.".to_string()),
            tags: vec![
                ("vgi.title".to_string(), "YARA — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    "yara, malware, scan, yara_matches, yara_first_rule, yara_match_count, \
                     yara_check, yara_scan, yara_string_matches, yara_version, rule compilation, \
                     threat hunting, IOC, signature detection"
                        .to_string(),
                ),
                // VGI123 classifying tags (bare keys: domain/category/topic) for faceting.
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "malware-scanning".to_string()),
                ("topic".to_string(), "yara-rule-matching".to_string()),
                (
                    "vgi.source_url".to_string(),
                    "https://github.com/Query-farm/vgi-yara/blob/main/crates/yara-worker/src/main.rs"
                        .to_string(),
                ),
                (
                    "vgi.doc_llm".to_string(),
                    "YARA malware-scanning functions: scan a column of blobs/text against a YARA \
                     ruleset (match predicate, first matching rule, match count), validate that a \
                     ruleset compiles, and fan a constant blob into per-rule or per-pattern hits."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "YARA rule compilation and malware-scanning functions over Apache Arrow."
                        .to_string(),
                ),
                // VGI506 representative example queries for the schema.
                (
                    "vgi.example_queries".to_string(),
                    "SELECT yara.main.yara_version();\n\
                     SELECT yara.main.yara_check('rule demo { strings: $a = \"malware\" condition: $a }');\n\
                     SELECT yara.main.yara_matches('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }');\n\
                     SELECT yara.main.yara_first_rule('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }');\n\
                     SELECT yara.main.yara_match_count('evil worm', 'rule a { strings: $a = \"evil\" condition: $a } rule b { strings: $b = \"worm\" condition: $b }');\n\
                     SELECT * FROM yara.main.yara_scan('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }');\n\
                     SELECT * FROM yara.main.yara_string_matches('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }');"
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    // The catalog name DuckDB sees in `ATTACH 'yara' (TYPE vgi, …)`. Default to
    // `yara`, but honor an explicit override so a test harness can rename it.
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "yara");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "yara".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
