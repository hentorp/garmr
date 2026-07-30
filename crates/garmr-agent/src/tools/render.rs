// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Rendering tool output to the compact text the model reads: Arrow record
//! batches → a capped text table, and a one-line case summary for the
//! institutional-memory search.

use garmr_core::Case;
use skade::arrow_array::RecordBatch;
use skade::arrow_cast::display::{ArrayFormatter, FormatOptions};

use super::MAX_ROWS;

/// A one-line summary of a past case for the `search_cases` tool.
pub(super) fn summarize_case(c: &Case) -> String {
    let disp = c
        .verdict
        .as_ref()
        .map(|v| format!("{:?}/sev{}", v.disposition, v.severity))
        .unwrap_or_else(|| "untriaged".into());
    format!(
        "- {} [{}] rule={} host={} ip={} events={} verdict={}",
        c.opened_at.format("%Y-%m-%d %H:%M"),
        c.id.get(..8).unwrap_or(&c.id),
        c.trigger.rule_id,
        c.trigger.event.host,
        c.trigger.event.src_ip().unwrap_or("-"),
        c.event_count,
        disp,
    )
}

/// Render Arrow record batches to a compact text table, capped at `MAX_ROWS`.
pub fn format_batches(batches: &[RecordBatch]) -> String {
    let opts = FormatOptions::default();
    let mut out = String::new();
    let mut printed = 0usize;

    for batch in batches {
        if printed == 0 {
            let schema = batch.schema();
            let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
            out.push_str(&names.join(" | "));
            out.push('\n');
        }
        let formatters: Vec<ArrayFormatter> = match batch
            .columns()
            .iter()
            .map(|c| ArrayFormatter::try_new(c.as_ref(), &opts))
            .collect::<std::result::Result<_, _>>()
        {
            Ok(f) => f,
            Err(e) => return format!("(could not format result: {e})"),
        };
        for row in 0..batch.num_rows() {
            if printed >= MAX_ROWS {
                out.push_str(&format!("… (capped at {MAX_ROWS} rows)\n"));
                return out;
            }
            let cells: Vec<String> = formatters
                .iter()
                .map(|f| {
                    let mut v = f.value(row).to_string();
                    // Cell width cap: MAX_ROWS bounds row COUNT, this bounds
                    // row WIDTH — one pathological log line must not blow the
                    // prompt (and the budget's input estimate) alone.
                    if v.len() > 500 {
                        let mut cut = 500;
                        while !v.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        v.truncate(cut);
                        v.push('…');
                    }
                    v
                })
                .collect();
            out.push_str(&cells.join(" | "));
            out.push('\n');
            printed += 1;
        }
    }
    if printed == 0 {
        out.push_str("(no rows)\n");
    }
    out
}
