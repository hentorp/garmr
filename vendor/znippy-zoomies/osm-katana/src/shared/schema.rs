use std::sync::Arc;

use arrow::datatypes::{DataType, Field, Schema};

pub fn nodes_schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("geometry", DataType::Binary, true),
        Field::new("tags", DataType::Utf8, true),
        Field::new("version", DataType::Int32, true),
        Field::new("changeset", DataType::Int64, true),
        Field::new("timestamp", DataType::Utf8, true),
    ])
}

pub fn ways_schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("geometry", DataType::Binary, true),
        Field::new("tags", DataType::Utf8, true),
        Field::new(
            "node_refs",
            DataType::List(Arc::new(Field::new("item", DataType::Int64, true))),
            true,
        ),
        Field::new("version", DataType::Int32, true),
    ])
}

pub fn relations_schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("geometry", DataType::Binary, true),
        Field::new("tags", DataType::Utf8, true),
        Field::new("members", DataType::Utf8, true),
        Field::new("version", DataType::Int32, true),
    ])
}
