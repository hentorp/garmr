// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The tool catalog offered to the model — the JSON-schema declarations for
//! every read-only tool, in a stable order (prompt-cache friendly). Pure data;
//! the executor lives in the parent [`super`] module.

use garmr_llm::types::ToolSchema;
use serde_json::json;

/// The tools the agent is offered, in a stable order (prompt-cache friendly).
pub fn tool_schemas() -> Vec<ToolSchema> {
    vec![
        ToolSchema {
            name: "query_events".into(),
            description:
                "Run read-only SQL (SELECT/WITH/EXPLAIN) against the event table `events`. \
                Columns: event_ts, host, service, source, environment, severity, log_type, \
                message, fields (JSON). Use for aggregates, trends and counting events."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": { "sql": { "type": "string", "description": "SQL query (read-only)." } },
                "required": ["sql"]
            }),
        },
        ToolSchema {
            name: "search_events".into(),
            description: "Substring search in raw log lines (message) over the last N hours."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Text to search for." },
                    "hours": { "type": "number", "description": "Time window backwards (default 24)." }
                },
                "required": ["text"]
            }),
        },
        ToolSchema {
            name: "hybrid_search".into(),
            description: "Hybrid event retrieval fusing a STRUCTURED filter (typed, \
                safe — never raw SQL), FULL-TEXT (BM25), and SEMANTIC (meaning) \
                signals, ranked with provenance. Prefer this over query_events for \
                'find events like/about X on host Y in the last N hours'. Give at \
                least one of: a filter dimension, text, or semantic."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "object",
                        "description": "Structured predicates (AND across, OR within a list).",
                        "properties": {
                            "time": {
                                "type": "object",
                                "properties": {
                                    "last_hours": { "type": "number", "description": "Events within the last N hours." },
                                    "from_micros": { "type": "integer" },
                                    "to_micros": { "type": "integer" }
                                }
                            },
                            "host": { "type": "array", "items": { "type": "string" } },
                            "service": { "type": "array", "items": { "type": "string" } },
                            "source": { "type": "array", "items": { "type": "string" } },
                            "environment": { "type": "array", "items": { "type": "string" } },
                            "severity": { "type": "array", "items": { "type": "string" } },
                            "log_type": { "type": "array", "items": { "type": "string" } },
                            "fields": {
                                "type": "array",
                                "description": "Extracted-field predicates, e.g. src_ip=1.2.3.4.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "key": { "type": "string" },
                                        "value": { "type": "string" },
                                        "negate": { "type": "boolean" }
                                    },
                                    "required": ["key", "value"]
                                }
                            }
                        }
                    },
                    "text": {
                        "type": "object",
                        "description": "Full-text (Tantivy) clause.",
                        "properties": { "query": { "type": "string" } }
                    },
                    "semantic": {
                        "type": "object",
                        "description": "Natural-language meaning clause (needs a semantic model).",
                        "properties": { "query": { "type": "string" } }
                    },
                    "fusion": {
                        "type": "object",
                        "properties": { "limit": { "type": "integer", "description": "results (default 20, max 200)" } }
                    }
                }
            }),
        },
        ToolSchema {
            name: "get_host_baseline".into(),
            description: "Normal services/ports/users for a host (last 30 days).".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "host": { "type": "string" } },
                "required": ["host"]
            }),
        },
        ToolSchema {
            name: "pivot_entity".into(),
            description: "Link analysis: show everything (cases, hosts, IPs, users) linked \
                to an entity via shared cases — pivot on an IP/host/user to see \
                the whole picture. kind = host | ip | user | case."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": ["host", "ip", "user", "case"] },
                    "name": { "type": "string" },
                    "depth": { "type": "integer", "description": "number of hops (default 2)" }
                },
                "required": ["kind", "name"]
            }),
        },
        ToolSchema {
            name: "ip_reputation".into(),
            description:
                "Info about an IP: private/public, how often seen in the logs, and any IOC.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "ip": { "type": "string" } },
                "required": ["ip"]
            }),
        },
        ToolSchema {
            name: "domain_reputation".into(),
            description: "Info about a domain name: occurrence in the DNS logs and any hit on \
                structured threat data (STIX/TAXII domain indicator). Also matches parent domain."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": { "domain": { "type": "string" } },
                "required": ["domain"]
            }),
        },
        ToolSchema {
            name: "get_rule".into(),
            description: "The Sigma rule (YAML) that triggered the case.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "rule_id": { "type": "string" } },
                "required": ["rule_id"]
            }),
        },
        ToolSchema {
            name: "search_cases".into(),
            description: "Search past cases by host/IP/rule/rationale — institutional memory."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        },
        ToolSchema {
            name: "propose_action".into(),
            description: "PROPOSE a response action (block IP / isolate host) for THIS case. \
                You can only propose — a human approves and a separate executor carries it out. \
                Call at most once, only on clearly malicious activity."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": ["block_ip", "isolate_host"] },
                    "arg": { "type": "string", "description": "IP to block, or host to isolate." },
                    "rationale": { "type": "string" }
                },
                "required": ["kind", "arg", "rationale"]
            }),
        },
        ToolSchema {
            name: "submit_verdict".into(),
            description: "FINISH the investigation with a verdict. Call exactly once.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "disposition": { "type": "string", "enum": ["benign", "suspicious", "malicious", "needs_human"] },
                    "severity": { "type": "integer", "minimum": 0, "maximum": 10 },
                    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "rationale": { "type": "string" },
                    "proposed_action": { "type": "string" }
                },
                "required": ["disposition", "severity", "confidence", "rationale"]
            }),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_search_tool_is_offered_and_parses_a_valid_ir() {
        let schemas = tool_schemas();
        assert!(
            schemas.iter().any(|s| s.name == "hybrid_search"),
            "the hybrid_search tool must be offered to the agent"
        );
        // A representative agent-composed IR must deserialize into the typed
        // HybridQuery (deny_unknown_fields would reject a schema drift).
        let ir = json!({
            "filter": { "host": ["web01"], "time": { "last_hours": 24 } },
            "text": { "query": "failed password" },
            "fusion": { "limit": 10 }
        });
        let q: garmr_query::HybridQuery = serde_json::from_value(ir).unwrap();
        assert_eq!(q.filter.host, vec!["web01".to_string()]);
        assert_eq!(q.fusion.limit, 10);
    }
}
