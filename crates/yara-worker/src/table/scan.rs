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

/// Guaranteed-runnable, catalog-qualified examples (VGI509). Each `sql` is
/// self-contained and re-runnable against an attached `yara` worker. We omit
/// `expected_result` deliberately — the linter only needs each query to execute
/// cleanly, and pinning exact output would be brittle.
const EXECUTABLE_EXAMPLES: &str = r#"[
  {
    "description": "Report the YARA worker version.",
    "sql": "SELECT yara.main.yara_version() AS version"
  },
  {
    "description": "Validate that a YARA ruleset compiles before scanning with it.",
    "sql": "SELECT yara.main.yara_check('rule demo { strings: $a = \"malware\" condition: $a }') AS ok"
  },
  {
    "description": "Test whether a blob matches any rule in a ruleset.",
    "sql": "SELECT yara.main.yara_matches('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }') AS hit"
  },
  {
    "description": "Name the first rule that matches the data.",
    "sql": "SELECT yara.main.yara_first_rule('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }') AS rule"
  },
  {
    "description": "Count how many rules match the data.",
    "sql": "SELECT yara.main.yara_match_count('evil worm', 'rule a { strings: $a = \"evil\" condition: $a } rule b { strings: $b = \"worm\" condition: $b }') AS n"
  },
  {
    "description": "Scan a constant blob, one row per matching rule.",
    "sql": "SELECT rule, namespace FROM yara.main.yara_scan('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }')"
  },
  {
    "description": "Scan a constant blob, one row per pattern hit with offsets.",
    "sql": "SELECT rule, identifier, \"offset\", matched FROM yara.main.yara_string_matches('this file contains malware', 'rule demo { strings: $a = \"malware\" condition: $a }')"
  }
]"#;

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
        let mut tags = crate::meta::object_tags(
            "Scan Data Into Matching Rules",
            "Scan a constant blob/text against a YARA ruleset and return one row per matching \
             rule, projecting the rule identifier, the namespace it was compiled under, and the \
             rule's tags as a VARCHAR[]. Both arguments are bind-time constants. An invalid rule \
             source is a clear DuckDB error; a ruleset that matches nothing, or hostile/garbage/\
             NULL data, yields zero rows.",
            "Scan a constant blob against a ruleset; one row per matching rule. Columns: `rule`, \
             `namespace`, `tags`.",
            "yara_scan, scan, matching rules, rule, namespace, tags, per-rule, table function, \
             malware triage, threat hunting",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n\
             |---|---|---|\n\
             | `rule` | VARCHAR | Identifier of the matching YARA rule. |\n\
             | `namespace` | VARCHAR | Namespace the rule was compiled under (default \
             `default`). |\n\
             | `tags` | VARCHAR[] | Tags declared on the matching rule (empty list if none). |"
                .into(),
        ));
        tags.push(("vgi.executable_examples".into(), EXECUTABLE_EXAMPLES.into()));
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
