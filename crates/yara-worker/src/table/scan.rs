//! `yara_scan(data, rules) -> (rule VARCHAR, namespace VARCHAR, tags VARCHAR[])`
//! — one row per matching rule.
//!
//! Both arguments are bind-time constants (DuckDB table functions take constant
//! arguments, not row columns): `data` is the BLOB/VARCHAR to scan, `rules` is a
//! YARA rule source string. An *invalid rule source* is a clear DuckDB error; a
//! valid ruleset that matches nothing — or a hostile/garbage/NULL `data` — yields
//! zero rows, never a crash.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io::{list_varchar_builder, list_varchar_type};
use crate::scanning::{self, RuleMatch};

pub struct YaraScan;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("rule", DataType::Utf8, false),
        Field::new("namespace", DataType::Utf8, false),
        Field::new("tags", list_varchar_type(), false),
    ]))
}

impl TableFunction for YaraScan {
    fn name(&self) -> &str {
        "yara_scan"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description:
                "Scan data against YARA rules; one row per matching rule (rule, namespace, tags)"
                    .into(),
            examples: vec![FunctionExample {
                sql: "SELECT * FROM yara.main.yara_scan('this file contains malware', 'rule demo \
                      { meta: severity = \"high\" strings: $a = \"malware\" condition: $a }');"
                    .into(),
                description: "Scan a constant blob against a ruleset, one row per matching rule \
                              (rule, namespace, tags)."
                    .into(),
                expected_output: None,
            }],
            tags: vec![(
                "vgi.columns_md".into(),
                "| column | type | description |\n\
                 |---|---|---|\n\
                 | `rule` | VARCHAR | Identifier of the matching YARA rule. |\n\
                 | `namespace` | VARCHAR | Namespace the rule was compiled under (default \
                 `default`). |\n\
                 | `tags` | VARCHAR[] | Tags declared on the matching rule (empty list if none). |"
                    .into(),
            )],
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::const_arg("data", 0, "any", "Bytes/text to scan (BLOB or VARCHAR)"),
            ArgSpec::const_arg("rules", 1, "any", "YARA rule source (VARCHAR)"),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        // `rules` NULL/absent → no rows; invalid `rules` → clear DuckDB error.
        // `data` NULL/absent → no rows (nothing to scan).
        let rows = match params.arguments.const_str(1) {
            None => Vec::new(),
            Some(src) => {
                let rules = scanning::compile_rules(&src)
                    .map_err(|e| RpcError::value_error(e.to_string()))?;
                match const_data_bytes(params) {
                    None => Vec::new(),
                    // Scanning untrusted data is total — no panic on a bad blob.
                    Some(bytes) => scanning::scan_rules(&rules, &bytes),
                }
            }
        };
        Ok(Box::new(ScanProducer {
            schema: params.output_schema.clone(),
            rows,
            done: false,
        }))
    }
}

/// Read the `data` const argument as bytes — accepting either a BLOB or a
/// VARCHAR constant.
fn const_data_bytes(params: &ProcessParams) -> Option<Vec<u8>> {
    if let Some(b) = params.arguments.const_bytes(0) {
        return Some(b);
    }
    params.arguments.const_str(0).map(|s| s.into_bytes())
}

struct ScanProducer {
    schema: SchemaRef,
    rows: Vec<RuleMatch>,
    done: bool,
}

impl TableProducer for ScanProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;

        let mut rule = StringBuilder::new();
        let mut namespace = StringBuilder::new();
        let mut tags = list_varchar_builder();
        for m in &self.rows {
            rule.append_value(&m.rule);
            namespace.append_value(&m.namespace);
            for t in &m.tags {
                tags.values().append_value(t);
            }
            tags.append(true);
        }
        let cols: Vec<ArrayRef> = vec![
            Arc::new(rule.finish()),
            Arc::new(namespace.finish()),
            Arc::new(tags.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
