//! Small Arrow helpers shared across the scalar and table functions: reading
//! BLOB/VARCHAR input cells, building a `LIST(VARCHAR)` column (for the `tags`
//! output of `yara_scan`), and an in-process test harness that drives a
//! `ScalarFunction` end-to-end without the RPC/IPC plumbing.

use std::sync::Arc;

use arrow_array::builder::{ListBuilder, StringBuilder};
use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef};
use arrow_schema::{DataType, Field};
use vgi_rpc::{Result, RpcError};

/// Borrow the raw bytes of a BLOB/VARCHAR cell at `row`, or `None` if the cell is
/// null. Errors if the column isn't a binary/utf8 type.
pub fn blob_bytes(col: &ArrayRef, row: usize) -> Result<Option<&[u8]>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Binary => col.as_binary::<i32>().value(row),
        DataType::LargeBinary => col.as_binary::<i64>().value(row),
        DataType::Utf8 => col.as_string::<i32>().value(row).as_bytes(),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row).as_bytes(),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a BLOB/VARCHAR argument, got {other:?}"
            )))
        }
    }))
}

/// Borrow the UTF-8 text of a VARCHAR cell at `row`, or `None` if null. Errors if
/// the column isn't a string type.
pub fn text_str(col: &ArrayRef, row: usize) -> Result<Option<&str>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Utf8 => col.as_string::<i32>().value(row),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a VARCHAR argument, got {other:?}"
            )))
        }
    }))
}

/// The `LIST(VARCHAR)` Arrow `DataType` our [`list_varchar_builder`] produces, so
/// `on_bind` can publish an output schema matching the array built in `process`.
pub fn list_varchar_type() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

/// A fresh `ListBuilder<StringBuilder>` whose child field is named `item` to
/// match [`list_varchar_type`].
pub fn list_varchar_builder() -> ListBuilder<StringBuilder> {
    ListBuilder::new(StringBuilder::new()).with_field(Arc::new(Field::new(
        "item",
        DataType::Utf8,
        true,
    )))
}

/// Test-only helpers shared by the scalar Arrow-boundary unit tests. They let a
/// `#[cfg(test)]` block drive a `ScalarFunction` end-to-end in-process: build a
/// two-column `(data, rules)` input `RecordBatch`, run `on_bind` + `process`,
/// inspect the result column.
#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;

    use arrow_array::builder::{BinaryBuilder, StringBuilder};
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{Field, Schema, SchemaRef};
    use vgi::arguments::Arguments;
    use vgi::{BindParams, ProcessParams, ScalarFunction};
    use vgi_rpc::Result;

    /// A two-column `(data BLOB, rules VARCHAR)` input batch. `None` → NULL.
    pub fn data_rules_batch(rows: &[(Option<&[u8]>, Option<&str>)]) -> RecordBatch {
        let mut data = BinaryBuilder::new();
        let mut rules = StringBuilder::new();
        for (d, r) in rows {
            match d {
                Some(b) => data.append_value(b),
                None => data.append_null(),
            }
            match r {
                Some(s) => rules.append_value(s),
                None => rules.append_null(),
            }
        }
        let data: ArrayRef = Arc::new(data.finish());
        let rules: ArrayRef = Arc::new(rules.finish());
        let schema = Arc::new(Schema::new(vec![
            Field::new("data", data.data_type().clone(), true),
            Field::new("rules", rules.data_type().clone(), true),
        ]));
        RecordBatch::try_new(schema, vec![data, rules]).unwrap()
    }

    /// A one-column `(rules VARCHAR)` input batch (for `yara_check`).
    pub fn rules_batch(rows: &[Option<&str>]) -> RecordBatch {
        let mut rules = StringBuilder::new();
        for r in rows {
            match r {
                Some(s) => rules.append_value(s),
                None => rules.append_null(),
            }
        }
        let rules: ArrayRef = Arc::new(rules.finish());
        let schema = Arc::new(Schema::new(vec![Field::new(
            "rules",
            rules.data_type().clone(),
            true,
        )]));
        RecordBatch::try_new(schema, vec![rules]).unwrap()
    }

    /// Build a `ProcessParams` carrying the given output schema and arguments.
    pub fn process_params(output_schema: SchemaRef, arguments: Arguments) -> ProcessParams {
        ProcessParams {
            substream_id: None,
            if_none_match: None,
            if_modified_since: None,
            output_schema,
            input_schema: None,
            execution_id: Vec::new(),
            init_opaque_data: Vec::new(),
            arguments,
            settings: Default::default(),
            secrets: Default::default(),
            auth_principal: None,
            projection_ids: None,
            pushdown_filters: None,
            join_keys: Vec::new(),
            storage: None,
            order_by_column: None,
            order_by_direction: None,
            order_by_null_order: None,
            order_by_limit: None,
            tablesample_percentage: None,
            tablesample_seed: None,
            attach_opaque_data: None,
            at_unit: None,
            at_value: None,
            copy_from: None,
        }
    }

    /// Run a scalar over a prebuilt input batch: call `on_bind` for the declared
    /// output schema, then `process`, returning the single result column.
    pub fn run_scalar_on<F: ScalarFunction>(
        f: &F,
        batch: RecordBatch,
        arguments: Arguments,
    ) -> Result<ArrayRef> {
        let bind = BindParams {
            input_schema: Some(batch.schema()),
            arguments: arguments.clone(),
            ..Default::default()
        };
        let bound = f.on_bind(&bind)?;
        let params = process_params(bound.output_schema.clone(), arguments);
        let out = f.process(&params, &batch)?;
        Ok(out.column(0).clone())
    }

    /// Run a `(data, rules)` scalar over a single row.
    pub fn run_data_rules<F: ScalarFunction>(
        f: &F,
        data: Option<&[u8]>,
        rules: Option<&str>,
    ) -> Result<ArrayRef> {
        run_scalar_on(f, data_rules_batch(&[(data, rules)]), Arguments::default())
    }

    /// Run a `(data, rules)` scalar over many rows.
    pub fn run_data_rules_rows<F: ScalarFunction>(
        f: &F,
        rows: &[(Option<&[u8]>, Option<&str>)],
    ) -> Result<ArrayRef> {
        run_scalar_on(f, data_rules_batch(rows), Arguments::default())
    }

    /// Run a single-VARCHAR `(rules)` scalar over one row (for `yara_check`).
    pub fn run_rules<F: ScalarFunction>(f: &F, rules: Option<&str>) -> Result<ArrayRef> {
        run_scalar_on(f, rules_batch(&[rules]), Arguments::default())
    }

    /// The declared output `DataType` from `on_bind` (no bind-time args).
    pub fn bound_type<F: ScalarFunction>(f: &F) -> arrow_schema::DataType {
        let bind = BindParams::default();
        let bound = f.on_bind(&bind).unwrap();
        bound.output_schema.field(0).data_type().clone()
    }
}
