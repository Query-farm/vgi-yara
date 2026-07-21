//! `yara_modules() -> (module VARCHAR, description VARCHAR)` — the YARA-X modules
//! compiled into this worker, for discovery.
//!
//! YARA rules can `import "<module>"` to test structured facts about a file (its
//! PE/ELF headers, hashes, arithmetic on byte ranges, and so on). Only the
//! modules built into the running worker are available; this parameterless
//! function lists them so an agent can see what a rule may `import` before
//! writing one. It is also surfaced as a browsable catalog TABLE (see
//! `main.rs::yara_modules_table`), so `SELECT * FROM yara.main.yara_modules`
//! works without knowing any arguments.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

pub struct YaraModules;

/// The YARA-X modules compiled into this worker (name, what a rule uses it for).
/// Keep this list in lockstep with the `yara-x` features enabled in `Cargo.toml`
/// (`hash`/`pe`/`elf`/`math`/`string`/`time`/`console`). Sorted by module name so
/// the table's fixed ordering is deterministic.
pub const MODULES: &[(&str, &str)] = &[
    (
        "console",
        "Emit log messages from a rule's condition while it evaluates, for debugging rule logic.",
    ),
    (
        "elf",
        "Inspect ELF executables: sections, segments, symbols, entry point and machine/type fields.",
    ),
    (
        "hash",
        "Compute MD5, SHA-1, SHA-256, CRC32 and checksums over the file or a byte range for content signatures.",
    ),
    (
        "math",
        "Arithmetic and statistics over byte ranges: entropy, mean, deviation, min/max and serial correlation.",
    ),
    (
        "pe",
        "Inspect Windows PE executables: headers, sections, imports, exports, resources and signatures.",
    ),
    (
        "string",
        "Helpers for working with matched or extracted strings, such as length and byte conversions.",
    ),
    (
        "time",
        "Access the current time so a rule condition can reason about when the scan runs.",
    ),
];

/// Per-column comments carried in the Arrow field metadata (DuckDB surfaces them
/// as the column COMMENT, which the metadata linter reads).
const MODULE_COLUMN_COMMENT: &str =
    "The name of a YARA-X module compiled into this worker — the string a rule may `import`, e.g. \
     `pe`, `elf`, `hash`, `math`.";
const DESCRIPTION_COLUMN_COMMENT: &str =
    "What the module lets a rule inspect or compute (its file-format fields, hashes, or math over \
     byte ranges).";

/// Number of modules `yara_modules` produces — the count of compiled-in modules.
/// Used as the catalog table's fixed cardinality estimate.
pub fn module_count() -> usize {
    MODULES.len()
}

pub fn output_schema() -> SchemaRef {
    let module_comment =
        HashMap::from([("comment".to_string(), MODULE_COLUMN_COMMENT.to_string())]);
    let desc_comment = HashMap::from([(
        "comment".to_string(),
        DESCRIPTION_COLUMN_COMMENT.to_string(),
    )]);
    Arc::new(Schema::new(vec![
        Field::new("module", DataType::Utf8, false).with_metadata(module_comment),
        Field::new("description", DataType::Utf8, false).with_metadata(desc_comment),
    ]))
}

impl TableFunction for YaraModules {
    fn name(&self) -> &str {
        "yara_modules"
    }

    fn metadata(&self) -> FunctionMetadata {
        // No result-schema tag here: `yara_modules` is also surfaced as a
        // browsable catalog TABLE (see `main.rs::yara_modules_table`), whose
        // documented columns already describe the output, so a table-function
        // result schema is neither required (VGI307) nor desirable.
        let tags = crate::meta::object_tags(
            "Supported YARA Modules",
            "List every YARA-X module compiled into this worker, one row per module, with the name \
             a rule may `import` and a short note on what it inspects. Query it to discover which \
             modules (`pe`, `elf`, `hash`, `math`, `string`, `time`, `console`) are available \
             before writing a rule that imports one.",
            "List the YARA-X **modules** built into this worker, one per row. Columns: `module`, \
             `description`.",
            "yara modules, import, available modules, pe, elf, hash, math, module reference, \
             yara_modules, discovery, which modules",
            "Reference",
        );
        FunctionMetadata {
            description: "List the YARA-X modules compiled into this worker".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        Ok(Box::new(ModulesProducer {
            schema: params.output_schema.clone(),
            done: false,
        }))
    }
}

struct ModulesProducer {
    schema: SchemaRef,
    done: bool,
}

impl TableProducer for ModulesProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        let mut module = StringBuilder::new();
        let mut description = StringBuilder::new();
        for (m, d) in MODULES {
            module.append_value(m);
            description.append_value(d);
        }
        let cols: Vec<ArrayRef> = vec![Arc::new(module.finish()), Arc::new(description.finish())];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
