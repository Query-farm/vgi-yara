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
mod scalar;
mod scanning;
mod table;

use vgi::Worker;

/// Worker version string, surfaced by `yara_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    worker.run();
}
