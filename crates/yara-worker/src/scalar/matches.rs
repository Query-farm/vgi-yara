//! Per-row scan scalars over `(data, rules)`:
//!
//! * `yara_matches(data, rules) -> BOOLEAN` — does data match ANY rule?
//! * `yara_first_rule(data, rules) -> VARCHAR` — identifier of the first match.
//! * `yara_match_count(data, rules) -> INT` — number of matching rules.
//!
//! `data` is BLOB or VARCHAR (bytes to scan); `rules` is a YARA rule source
//! string. Either NULL → NULL. An *invalid rule source* surfaces a clear DuckDB
//! error (it is a user mistake). Scanning the untrusted `data` is total — a
//! hostile blob never crashes the worker (see `scanning.rs`).
//!
//! Rules typically repeat across a batch (often a constant), so we compile lazily
//! and cache the last `(source → Rules)` to avoid recompiling every row.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, Int32Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};
use yara_x::Rules;

use crate::arrow_io::{blob_bytes, text_str};
use crate::scanning;

/// A tiny one-entry cache so a constant `rules` column compiles once per batch.
#[derive(Default)]
struct RuleCache {
    last_src: Option<String>,
    last_rules: Option<Rules>,
}

impl RuleCache {
    /// Compile `src` (or return the cached `Rules` if `src` is unchanged). A
    /// compilation error propagates as a DuckDB value error.
    fn get(&mut self, src: &str) -> Result<&Rules> {
        if self.last_src.as_deref() != Some(src) {
            let rules =
                scanning::compile_rules(src).map_err(|e| RpcError::value_error(e.to_string()))?;
            self.last_src = Some(src.to_string());
            self.last_rules = Some(rules);
        }
        Ok(self.last_rules.as_ref().expect("just set"))
    }
}

/// Which projection of a scan a given scalar produces.
#[derive(Clone, Copy)]
enum Kind {
    Matches,
    FirstRule,
    MatchCount,
}

macro_rules! scan_scalar {
    ($struct:ident, $kind:expr) => {
        pub struct $struct;
        impl $struct {
            const KIND: Kind = $kind;
        }
    };
}

scan_scalar!(YaraMatches, Kind::Matches);
scan_scalar!(YaraFirstRule, Kind::FirstRule);
scan_scalar!(YaraMatchCount, Kind::MatchCount);

/// Shared bind/process for all three: same `(data, rules)` inputs, different
/// output column type and projection.
fn argument_specs() -> Vec<ArgSpec> {
    vec![
        // `data` is genuinely type-generic — it accepts either a binary blob or a
        // text column of bytes to scan — so it stays ANY.
        ArgSpec::any_column("data", 0, "The content to scan for malware/IOC signatures"),
        // `rules` is always textual YARA source, so it is typed concretely.
        ArgSpec::column(
            "rules",
            1,
            "varchar",
            "YARA rule source whose rules are compiled and matched against the data",
        ),
    ]
}

/// One output cell builder, by kind.
enum Out {
    Matches(BooleanBuilder),
    FirstRule(StringBuilder),
    MatchCount(Int32Builder),
}

impl Out {
    fn new(kind: Kind) -> Self {
        match kind {
            Kind::Matches => Out::Matches(BooleanBuilder::new()),
            Kind::FirstRule => Out::FirstRule(StringBuilder::new()),
            Kind::MatchCount => Out::MatchCount(Int32Builder::new()),
        }
    }

    fn append_null(&mut self) {
        match self {
            Out::Matches(b) => b.append_null(),
            Out::FirstRule(b) => b.append_null(),
            Out::MatchCount(b) => b.append_null(),
        }
    }

    fn append(&mut self, rules: &Rules, data: &[u8]) {
        match self {
            Out::Matches(b) => {
                let any = !scanning::scan_rules(rules, data).is_empty();
                b.append_value(any);
            }
            Out::FirstRule(b) => {
                let m = scanning::scan_rules(rules, data);
                match m.first() {
                    Some(first) => b.append_value(&first.rule),
                    None => b.append_null(),
                }
            }
            Out::MatchCount(b) => {
                let n = scanning::scan_rules(rules, data).len() as i32;
                b.append_value(n);
            }
        }
    }

    fn finish(self) -> ArrayRef {
        match self {
            Out::Matches(mut b) => Arc::new(b.finish()),
            Out::FirstRule(mut b) => Arc::new(b.finish()),
            Out::MatchCount(mut b) => Arc::new(b.finish()),
        }
    }
}

fn return_type(kind: Kind) -> DataType {
    match kind {
        Kind::Matches => DataType::Boolean,
        Kind::FirstRule => DataType::Utf8,
        Kind::MatchCount => DataType::Int32,
    }
}

/// The common process loop, parameterized by kind.
fn process_kind(kind: Kind, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
    let data_col = batch.column(0);
    let rules_col = batch.column(1);
    let rows = batch.num_rows();
    let mut out = Out::new(kind);
    let mut cache = RuleCache::default();

    for i in 0..rows {
        let data = blob_bytes(data_col, i)?;
        let src = text_str(rules_col, i)?;
        match (data, src) {
            // Either operand NULL → NULL out.
            (Some(bytes), Some(src)) => {
                let rules = cache.get(src)?;
                out.append(rules, bytes);
            }
            _ => out.append_null(),
        }
    }
    let arr = out.finish();
    RecordBatch::try_new(params.output_schema.clone(), vec![arr])
        .map_err(|e| RpcError::runtime_error(e.to_string()))
}

macro_rules! impl_scalar {
    ($struct:ident, $name:literal, $desc:literal, $ex_sql:literal, $ex_desc:literal,
     $title:literal, $llm:literal, $md:literal, $kw:literal) => {
        impl ScalarFunction for $struct {
            fn name(&self) -> &str {
                $name
            }
            fn metadata(&self) -> FunctionMetadata {
                FunctionMetadata {
                    description: $desc.into(),
                    return_type: Some(return_type(Self::KIND)),
                    examples: vec![FunctionExample {
                        sql: $ex_sql.into(),
                        description: $ex_desc.into(),
                        expected_output: None,
                    }],
                    tags: crate::meta::object_tags($title, $llm, $md, $kw, "Scanning"),
                    ..Default::default()
                }
            }
            fn argument_specs(&self) -> Vec<ArgSpec> {
                argument_specs()
            }
            fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
                Ok(BindResponse::result(return_type(Self::KIND)))
            }
            fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
                process_kind(Self::KIND, params, batch)
            }
        }
    };
}

impl_scalar!(
    YaraMatches,
    "yara_matches",
    "True if the data matches ANY of the YARA rules (BLOB/VARCHAR data, VARCHAR rules)",
    "SELECT yara.main.yara_matches('this file contains malware', 'rule demo { strings: $a = \
     \"malware\" condition: $a }');",
    "Test whether a blob/text matches any rule in a YARA ruleset.",
    "YARA Matches Any Rule",
    "Return true if the data (BLOB or VARCHAR bytes) matches ANY rule in the YARA ruleset, false \
     if none match. Either operand NULL → NULL. A column-friendly predicate for filtering rows \
     whose contents hit a ruleset. An invalid rule source raises a clear error; scanning the \
     untrusted data is total and never crashes the worker.",
    "Return `true` if the data matches any rule in the YARA ruleset, else `false` (either argument \
     NULL → NULL).",
    "yara_matches, match, predicate, scan, does it match, malware detection, filter, contains \
     malware, boolean scan"
);
impl_scalar!(
    YaraFirstRule,
    "yara_first_rule",
    "Identifier of the first matching YARA rule, or NULL if none match",
    "SELECT yara.main.yara_first_rule('this file contains malware', 'rule demo { strings: $a = \
     \"malware\" condition: $a }');",
    "Return the identifier of the first YARA rule that matches the data.",
    "YARA First Matching Rule",
    "Return the identifier of the first YARA rule that matches the data (BLOB or VARCHAR bytes), \
     or NULL if no rule matches. Either operand NULL → NULL. Useful for labelling a row with the \
     signature that triggered. An invalid rule source raises a clear error; scanning untrusted \
     data is total.",
    "Return the identifier of the first YARA rule that matches the data, or `NULL` if none match \
     (either argument NULL → NULL).",
    "yara_first_rule, first match, rule name, label, which rule, signature name, matching rule \
     identifier"
);
impl_scalar!(
    YaraMatchCount,
    "yara_match_count",
    "Number of YARA rules that match the data (INT)",
    "SELECT yara.main.yara_match_count('evil worm', 'rule a { strings: $a = \"evil\" condition: \
     $a } rule b { strings: $b = \"worm\" condition: $b }');",
    "Count how many YARA rules in a ruleset match the data.",
    "YARA Matching Rule Count",
    "Return the number of YARA rules in the ruleset that match the data (BLOB or VARCHAR bytes), \
     as an INT (0 if none match). Either operand NULL → NULL. Useful for ranking rows by how many \
     signatures they trigger. An invalid rule source raises a clear error; scanning untrusted \
     data is total.",
    "Return the number of YARA rules in the ruleset that match the data, as an `INT` (0 if none; \
     either argument NULL → NULL).",
    "yara_match_count, count, number of matches, how many rules, match tally, severity ranking"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::{bound_type, run_data_rules, run_data_rules_rows};
    use arrow_array::cast::AsArray;
    use arrow_array::types::Int32Type;
    use arrow_array::Array;

    const DEMO: &str = r#"rule demo { strings: $a = "malware" condition: $a }"#;
    const MULTI: &str = r#"
        rule alpha { strings: $a = "evil" condition: $a }
        rule beta  { strings: $b = "worm" condition: $b }
    "#;

    #[test]
    fn bind_types() {
        assert_eq!(bound_type(&YaraMatches), DataType::Boolean);
        assert_eq!(bound_type(&YaraFirstRule), DataType::Utf8);
        assert_eq!(bound_type(&YaraMatchCount), DataType::Int32);
    }

    #[test]
    fn matches_true_false() {
        let hit = run_data_rules(&YaraMatches, Some(b"has malware"), Some(DEMO)).unwrap();
        assert!(hit.as_boolean().value(0));
        let miss = run_data_rules(&YaraMatches, Some(b"clean data"), Some(DEMO)).unwrap();
        assert!(!miss.as_boolean().value(0));
    }

    #[test]
    fn first_rule_and_count() {
        let first = run_data_rules(&YaraFirstRule, Some(b"evil worm"), Some(MULTI)).unwrap();
        assert!(!first.is_null(0));
        let count = run_data_rules(&YaraMatchCount, Some(b"evil worm"), Some(MULTI)).unwrap();
        assert_eq!(count.as_primitive::<Int32Type>().value(0), 2);

        let none = run_data_rules(&YaraFirstRule, Some(b"clean"), Some(MULTI)).unwrap();
        assert!(none.is_null(0), "no match → NULL first rule");
        let zero = run_data_rules(&YaraMatchCount, Some(b"clean"), Some(MULTI)).unwrap();
        assert_eq!(zero.as_primitive::<Int32Type>().value(0), 0);
    }

    #[test]
    fn null_inputs_yield_null() {
        assert!(run_data_rules(&YaraMatches, None, Some(DEMO))
            .unwrap()
            .is_null(0));
        assert!(run_data_rules(&YaraMatches, Some(b"x"), None)
            .unwrap()
            .is_null(0));
    }

    #[test]
    fn invalid_rules_error() {
        let err = run_data_rules(&YaraMatches, Some(b"x"), Some("rule broken { condition: }"));
        assert!(err.is_err(), "invalid rule source must surface an error");
    }

    #[test]
    fn hostile_blob_beside_good_one_survives() {
        // A hostile binary blob, a NULL, then a good blob — all in one batch,
        // sharing a constant rules column (compiled once). The good one matches,
        // the worker survives.
        let hostile: Vec<u8> = (0u32..50_000).map(|x| (x % 256) as u8).collect();
        let out = run_data_rules_rows(
            &YaraMatches,
            &[
                (Some(&hostile), Some(DEMO)),
                (None, Some(DEMO)),
                (Some(b"contains malware"), Some(DEMO)),
                (Some(b""), Some(DEMO)),
            ],
        )
        .unwrap();
        let b = out.as_boolean();
        assert!(!b.value(0), "hostile blob: no match, no crash");
        assert!(out.is_null(1), "NULL → NULL");
        assert!(b.value(2), "good blob still matches");
        assert!(!b.value(3), "empty blob: no match");
    }

    #[test]
    fn binary_and_empty_data_do_not_crash() {
        let binary: Vec<u8> = (0u16..400).map(|x| (x & 0xff) as u8).collect();
        assert!(run_data_rules(&YaraMatchCount, Some(&binary), Some(DEMO)).is_ok());
        assert!(run_data_rules(&YaraMatchCount, Some(b""), Some(DEMO)).is_ok());
    }
}
