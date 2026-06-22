//! `yara_check(rules) -> BOOLEAN` — do the rules compile? Pure validation: `true`
//! if the source is a valid ruleset, `false` otherwise. NULL → NULL. Never
//! errors (unlike the scan scalars, a non-compiling source here is `false`, not
//! a DuckDB error — this function *is* the "does it compile?" predicate).

use std::sync::Arc;

use arrow_array::builder::BooleanBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams, ScalarFunction};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::text_str;
use crate::scanning;

pub struct YaraCheck;

impl ScalarFunction for YaraCheck {
    fn name(&self) -> &str {
        "yara_check"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "True if the YARA rule source compiles, false otherwise (validation)"
                .into(),
            return_type: Some(DataType::Boolean),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "rules",
            0,
            "YARA rule source (VARCHAR)",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Boolean))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();
        let mut out = BooleanBuilder::new();
        for i in 0..rows {
            match text_str(col, i)? {
                None => out.append_null(),
                Some(src) => out.append_value(scanning::rules_compile(src)),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::{bound_type, run_rules};
    use arrow_array::cast::AsArray;
    use arrow_array::Array;

    #[test]
    fn binds_boolean() {
        assert_eq!(bound_type(&YaraCheck), DataType::Boolean);
    }

    #[test]
    fn valid_rules_true_invalid_false() {
        let ok = run_rules(
            &YaraCheck,
            Some(r#"rule demo { strings: $a = "x" condition: $a }"#),
        )
        .unwrap();
        assert!(ok.as_boolean().value(0));

        let bad = run_rules(&YaraCheck, Some("rule broken { condition: }")).unwrap();
        assert!(!bad.as_boolean().value(0));

        let garbage = run_rules(&YaraCheck, Some("definitely not yara")).unwrap();
        assert!(!garbage.as_boolean().value(0));
    }

    #[test]
    fn null_in_null_out() {
        let out = run_rules(&YaraCheck, None).unwrap();
        assert!(out.is_null(0));
    }
}
