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

/// Analyst tasks (VGI152) that `vgi-lint simulate` uses to measure how well an
/// agent can actually drive this worker. Each task is a natural-language prompt
/// paired with a canonical `reference_sql` answer built only from this worker's
/// published functions. Kept self-contained (inline rule sources, no external
/// tables) so every task is runnable against a freshly-attached `yara` catalog.
///
/// Grading (`_resultsets_equal`) is strict on column NAMES, VALUES and ROW ORDER
/// by default. An analyst reproducing the answer has no way to guess our arbitrary
/// output aliases, so every task sets `"ignore_column_names": true` (compare
/// values, not the alias the agent happens to pick). Multi-row tasks also set
/// `"unordered": true` so a differently-ordered but equal result still passes.
const AGENT_TEST_TASKS: &str = r#"[
  {
    "name": "validate_ruleset_compiles",
    "prompt": "I have this YARA rule source: rule demo { strings: $a = \"malware\" condition: $a }. Before I scan anything with it, tell me whether it compiles into a valid ruleset.",
    "reference_sql": "SELECT yara.main.yara_check('rule demo { strings: $a = \"malware\" condition: $a }') AS compiles",
    "ignore_column_names": true
  },
  {
    "name": "does_text_match_ruleset",
    "prompt": "Does the text 'this file contains malware' match the YARA rule rule demo { strings: $a = \"malware\" condition: $a }? I just need a yes/no.",
    "reference_sql": "SELECT yara.main.yara_matches('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }') AS matched",
    "ignore_column_names": true
  },
  {
    "name": "count_matching_rules",
    "prompt": "Given the two YARA rules rule a { strings: $a = \"evil\" condition: $a } and rule b { strings: $b = \"worm\" condition: $b }, how many of them match the text 'evil worm'?",
    "reference_sql": "SELECT yara.main.yara_match_count('evil worm', 'rule a { strings: $a = \"evil\" condition: $a } rule b { strings: $b = \"worm\" condition: $b }') AS n",
    "ignore_column_names": true
  },
  {
    "name": "name_first_matching_rule",
    "prompt": "For the ruleset rule demo { strings: $a = \"malware\" condition: $a }, what is the name of the first rule that matches the text 'this file contains malware'?",
    "reference_sql": "SELECT yara.main.yara_first_rule('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }') AS first_rule",
    "ignore_column_names": true
  },
  {
    "name": "list_matching_rules",
    "prompt": "Scan the text 'this file contains malware' with the ruleset rule demo { strings: $a = \"malware\" condition: $a } and list the identifier of every rule that matched.",
    "reference_sql": "SELECT rule FROM yara.main.yara_scan('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }') ORDER BY rule",
    "ignore_column_names": true,
    "unordered": true
  },
  {
    "name": "locate_pattern_hits",
    "prompt": "Using the ruleset rule demo { strings: $a = \"malware\" condition: $a }, find where the single pattern hits in the text 'this file contains malware': return the pattern identifier and the byte offset of the match. Remember that `offset` is a reserved keyword and must be double-quoted.",
    "reference_sql": "SELECT identifier, \"offset\" FROM yara.main.yara_string_matches('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }') ORDER BY \"offset\"",
    "ignore_column_names": true,
    "unordered": true
  },
  {
    "name": "report_worker_version",
    "prompt": "What version string does this YARA worker report for itself?",
    "reference_sql": "SELECT yara.main.yara_version() AS version",
    "ignore_column_names": true
  }
]"#;

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
                meta::keywords_json(
                    "yara, yara-x, malware, malware scanning, threat hunting, IOC, indicator of \
                     compromise, signature, rule, detection, security, antivirus, blob scan, \
                     pattern matching, defensive security",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Defensive malware and IOC scanning in SQL, powered by YARA rules. Reach for this \
                 worker whenever you have bytes or text already in DuckDB — file blobs, email \
                 attachments, object-store artifacts, log payloads — and want to know whether they \
                 match a set of YARA signatures, without exporting them to an external scanner. \
                 The core concept is a YARA ruleset (rule source text you supply or load from a \
                 column) matched against untrusted data; results range from a simple boolean \
                 predicate you can filter rows with, through the identity and count of the rules \
                 that fired, to fully expanded per-rule and per-pattern hit details with byte \
                 offsets. Scanning is total by design: garbage, empty, binary, or deliberately \
                 hostile data yields no matches rather than crashing the worker, so it is safe to \
                 point at live malware. The one error path is an invalid rule source, which is a \
                 user mistake and surfaces as a clear error. Use it for malware triage, threat \
                 hunting, and enforcing detection rules over data you already hold. List the schema \
                 to discover the exact scalar and table functions available."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# YARA Malware Scanning in SQL\n\n\
                 ![YARA-X logo](https://raw.githubusercontent.com/VirusTotal/yara-x/main/ls/editors/code/images/icon.png)\n\n\
                 Scan blobs, files, and text columns for malware and indicators of compromise \
                 (IOCs) straight from DuckDB SQL by compiling and matching **YARA rules** — no \
                 external scanner, no native `libyara`, just functions you can call in a query.\n\n\
                 This extension brings defensive YARA rule matching to the database, so security \
                 engineers, threat hunters, and data teams can triage suspicious files, hunt for \
                 signatures, and enforce detection rules over data they already have in DuckDB. \
                 Instead of exporting samples to a standalone tool, you write a YARA ruleset (or \
                 load one from a column) and let SQL fan it across millions of rows: filter a \
                 table of email attachments, label artifacts in an object store, or join scan \
                 verdicts back onto your metadata — all in one place.\n\n\
                 Matching is powered by [YARA-X](https://github.com/VirusTotal/yara-x), \
                 VirusTotal's pure-Rust rewrite of the classic YARA engine, embedded directly in \
                 the worker so there is no C dependency to install or keep patched. Rules are \
                 compiled once per batch and reused, and scanning is *total*: untrusted, garbage, \
                 empty, or deliberately hostile data simply yields no matches rather than crashing \
                 the worker, so you can point it at live malware safely. The full YARA syntax — \
                 string, hex, and regex patterns, conditions, namespaces, tags, and the standard \
                 `pe`/`elf`/`hash`/`math` modules — is supported.\n\n\
                 Two shapes of access are offered. Per-row scalar functions test a whole column of \
                 blobs or text against a ruleset, giving you a filter predicate, a match count, or \
                 the name of the rule that fired — ideal for triaging a table of samples or \
                 labelling artifacts in place. Table functions instead expand a single scan into \
                 detail rows, one per matching rule or per individual pattern hit (with byte \
                 offsets and the matched bytes), for forensics and drill-down. There is also a \
                 validation helper for checking that a ruleset compiles before you scan with it. \
                 Browse the `main` schema to see the exact functions and their signatures.\n\n\
                 For rule-writing syntax and module reference see the official \
                 [YARA-X documentation](https://virustotal.github.io/yara-x/) and the \
                 [yara-x crate docs](https://docs.rs/yara-x)."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                AGENT_TEST_TASKS.to_string(),
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
                // VGI413 category registry: an ordered list the worker uses for
                // navigation/listing sections. Each object declares a matching
                // `vgi.category` naming one of these.
                (
                    "vgi.categories".to_string(),
                    "[\
                     {\"name\":\"Scanning\",\"description\":\"Per-row scalars that test a column of \
                     blobs or text against a YARA ruleset — match predicate, first matching rule, \
                     and matching-rule count.\"},\
                     {\"name\":\"Match Details\",\"description\":\"Table functions that expand a \
                     single scan into detail rows: one per matching rule or per individual pattern \
                     hit with byte offsets.\"},\
                     {\"name\":\"Rule Validation\",\"description\":\"Check that a YARA ruleset \
                     compiles before scanning with it.\"},\
                     {\"name\":\"Diagnostics\",\"description\":\"Report the YARA worker's own \
                     version string.\"}\
                     ]"
                        .to_string(),
                ),
                (
                    "vgi.keywords".to_string(),
                    meta::keywords_json(
                        "yara, malware, scan, yara_matches, yara_first_rule, yara_match_count, \
                         yara_check, yara_scan, yara_string_matches, yara_version, rule \
                         compilation, threat hunting, IOC, signature detection",
                    ),
                ),
                // VGI123 classifying tags (bare keys: domain/category/topic) for faceting.
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "malware-scanning".to_string()),
                ("topic".to_string(), "yara-rule-matching".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "YARA malware-scanning functions: scan a column of blobs/text against a YARA \
                     ruleset (match predicate, first matching rule, match count), validate that a \
                     ruleset compiles, and fan a constant blob into per-rule or per-pattern hits."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "# YARA — `main` schema\n\n\
                     The single schema holding this worker's YARA rule-compilation and \
                     malware-scanning functions over Apache Arrow. The functions fall into a few \
                     groups:\n\n\
                     - **Scanning** — per-row scalars that test a column of blobs or text against a \
                     ruleset (match predicate, matching-rule count, first matching rule).\n\
                     - **Match Details** — table functions that expand a single scan into detail \
                     rows: one per matching rule, or one per individual pattern hit with byte \
                     offsets.\n\
                     - **Rule Validation** — check that a ruleset compiles before you scan with \
                     it.\n\
                     - **Diagnostics** — report the YARA worker's own version string.\n\n\
                     Scanning is *total*: untrusted or hostile data yields no matches rather than \
                     crashing the worker; only an invalid rule source raises an error. List the \
                     schema to see the exact functions and their signatures."
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
