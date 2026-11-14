//! Scalar functions exposed by the YARA worker, registered under `yara.main`.

mod check;
mod matches;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(matches::YaraMatches);
    worker.register_scalar(matches::YaraFirstRule);
    worker.register_scalar(matches::YaraMatchCount);
    worker.register_scalar(check::YaraCheck);
}
