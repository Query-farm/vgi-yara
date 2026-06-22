//! Table functions exposed by the YARA worker, registered under `yara.main`.

mod scan;
mod string_matches;

use vgi::Worker;

/// Register every table function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table(scan::YaraScan);
    worker.register_table(string_matches::YaraStringMatches);
}
