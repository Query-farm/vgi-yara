//! `yara_string_matches(data, rules) -> (rule VARCHAR, identifier VARCHAR,
//! "offset" BIGINT, matched VARCHAR)` — one row per pattern hit.
//!
//! Both arguments are bind-time constants. `matched` is the matched bytes
//! rendered as UTF-8 text when printable, else a lowercase hex string. An invalid
//! rule source is a clear DuckDB error; no hits / hostile / NULL `data` → no rows.

use std::sync::Arc;

use arrow_array::builder::{Int64Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::scanning::{self, StringMatch};

pub struct YaraStringMatches;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("rule", DataType::Utf8, false),
        Field::new("identifier", DataType::Utf8, false),
        Field::new("offset", DataType::Int64, false),
        Field::new("matched", DataType::Utf8, true),
    ]))
}

impl TableFunction for YaraStringMatches {
    fn name(&self) -> &str {
        "yara_string_matches"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Scan Data Into Pattern Hits",
            "Scan a constant blob/text against a YARA ruleset and return one row per individual \
             pattern hit: which rule and string identifier matched, the byte offset of the hit, \
             and the matched bytes (rendered as UTF-8 when printable, else lowercase hex). Both \
             arguments are bind-time constants. An invalid rule source is a clear DuckDB error; \
             no hits, or hostile/NULL data, yields zero rows.",
            "Scan a constant blob against a ruleset; one row per pattern hit. Columns: `rule`, \
             `identifier`, `offset`, `matched`.",
            "yara_string_matches, pattern hit, string match, offset, matched bytes, identifier, \
             per-pattern, forensics, where matched, table function",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n\
             |---|---|---|\n\
             | `rule` | VARCHAR | Identifier of the matching YARA rule. |\n\
             | `identifier` | VARCHAR | Pattern/string identifier that hit, e.g. `$a`. |\n\
             | `offset` | BIGINT | Byte offset of the match within the scanned data. |\n\
             | `matched` | VARCHAR | Matched bytes as UTF-8 when printable, else lowercase \
             hex (NULL if unavailable). |"
                .into(),
        ));
        FunctionMetadata {
            description:
                "Scan data against YARA rules; one row per pattern hit (rule, identifier, offset, matched)"
                    .into(),
            examples: vec![FunctionExample {
                sql: "SELECT * FROM yara.main.yara_string_matches('this file contains malware', \
                      'rule demo { strings: $a = \"malware\" condition: $a }');"
                    .into(),
                description: "Scan a constant blob against a ruleset, one row per pattern hit \
                              (which rule/string matched, at what offset, and the matched bytes)."
                    .into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            // `data` accepts either a binary blob or text, so it stays type-generic.
            ArgSpec::const_arg(
                "data",
                0,
                "any",
                "The constant content to scan for malware/IOC signatures",
            ),
            // `rules` is always textual YARA source, so it is typed concretely.
            ArgSpec::const_arg(
                "rules",
                1,
                "varchar",
                "YARA rule source whose rules are compiled and matched against the data",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let rows = match params.arguments.const_str(1) {
            None => Vec::new(),
            Some(src) => {
                let rules = scanning::compile_rules(&src)
                    .map_err(|e| RpcError::value_error(e.to_string()))?;
                match const_data_bytes(params) {
                    None => Vec::new(),
                    Some(bytes) => scanning::scan_strings(&rules, &bytes),
                }
            }
        };
        Ok(Box::new(StringMatchProducer {
            schema: params.output_schema.clone(),
            rows,
            done: false,
        }))
    }
}

/// Read the `data` const argument as bytes — accepting either a BLOB or VARCHAR.
fn const_data_bytes(params: &ProcessParams) -> Option<Vec<u8>> {
    if let Some(b) = params.arguments.const_bytes(0) {
        return Some(b);
    }
    params.arguments.const_str(0).map(|s| s.into_bytes())
}

struct StringMatchProducer {
    schema: SchemaRef,
    rows: Vec<StringMatch>,
    done: bool,
}

impl TableProducer for StringMatchProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;

        let mut rule = StringBuilder::new();
        let mut identifier = StringBuilder::new();
        let mut offset = Int64Builder::new();
        let mut matched = StringBuilder::new();
        for m in &self.rows {
            rule.append_value(&m.rule);
            identifier.append_value(&m.identifier);
            offset.append_value(m.offset as i64);
            matched.append_value(&m.matched);
        }
        let cols: Vec<ArrayRef> = vec![
            Arc::new(rule.finish()),
            Arc::new(identifier.finish()),
            Arc::new(offset.finish()),
            Arc::new(matched.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
