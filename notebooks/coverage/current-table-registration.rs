//! Table functions exposed by the YARA worker, registered under `yara.main`.

pub mod modules;
mod scan;
mod string_matches;

use vgi::Worker;

/// Register the table functions that take arguments. `yara_modules` is
/// parameterless and is instead exposed as a catalog *table* via
/// [`crate::catalog_metadata`] (using `CatTable::with_function`, which
/// auto-registers its scan function), so `SELECT * FROM yara.main.yara_modules`
/// works without knowing any arguments (VGI146/VGI311).
pub fn register(worker: &mut Worker) {
    worker.register_table(scan::YaraScan);
    worker.register_table(string_matches::YaraStringMatches);
}
