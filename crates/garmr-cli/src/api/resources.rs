// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/resources` + `GET /api/resources/:id` — the resource workspace
//! (DoD 5). A first-class, product-shaped view over the resource **catalog** (the
//! same Trusted set the app-audit plane uses to classify traffic — read via
//! `AppAudit::catalog_snapshot`, so it reflects exactly what is enforced, file- or
//! registry-backed) joined with the **lakehouse** (recent access history) and the
//! **policy** set (per-resource coverage).
//!
//! The list summarises each data-bearing catalog entry (table / view / endpoint /
//! document-collection / sensitive-resource) with a bounded recent-access tally;
//! the detail answers "who accessed this resource, from where, under which
//! justification, and which policies govern it". Strictly read-only: registering /
//! classifying / retiring a resource is a governed registry promotion (the generic
//! `/admin/registry` surface on the `catalog` kind), never a console write. The
//! access scan reuses the exact bounded, event-time-pruned read path and typed
//! projection the `/api/policies/simulate` backtest uses.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use garmr_catalog::{object_pattern_matches, CatalogEntry};
use garmr_core::AuditRecord;
use garmr_policy::{context_from_event, Policy};

use super::behavioral::{outcome_failed, outcome_label, top_counts};
use super::*;

/// Default access-history window (7 days), overridable on the detail route via
/// `?hours=`, clamped to `[1, MAX_SCAN_HOURS]`.
const DEFAULT_SCAN_HOURS: i64 = 168;
/// Hard ceiling on the access-history window (90 days) — a scan can't be widened
/// without bound.
const MAX_SCAN_HOURS: i64 = 24 * 90;
/// Row cap on a single access scan — the shared query-API row ceiling.
const SCAN_LIMIT: usize = super::MAX_QUERY_ROWS;
/// Cap on the per-resource access-history list returned in the detail body.
const HISTORY_CAP: usize = 200;
/// How many top users / clients the detail reports.
const TOP_N: usize = 10;

/// One projected access to some object, owned so it outlives the borrowed
/// `AccessContext` it was derived from. `objects` is the SQL-resolved object list
/// (identical to what the policy engine matches on) used to attribute the access
/// to a catalog resource.
struct Access {
    ts: DateTime<Utc>,
    actor: String,
    actor_role: Option<String>,
    /// Where the access came from: client IP, else client host.
    client: Option<String>,
    source_host: String,
    operation: Option<String>,
    outcome: &'static str,
    /// The access did not succeed (denied / failed / errored).
    failed: bool,
    object_name: Option<String>,
    objects: Vec<String>,
    ticket_ref: Option<String>,
    case_ref: Option<String>,
    purpose: Option<String>,
    event_id: Option<String>,
}

/// Does this access touch a resource whose object pattern is `pattern`? Uses the
/// same matcher (`object_pattern_matches`) the catalog and policy engine use, so
/// attribution never disagrees with enforcement.
fn access_matches(a: &Access, pattern: &str) -> bool {
    a.objects.iter().any(|o| object_pattern_matches(pattern, o))
        || a.object_name
            .as_deref()
            .is_some_and(|o| object_pattern_matches(pattern, o))
}

/// The four aggregate numbers a resource shows for a window, computed ONE way so
/// the list and detail surfaces can never disagree. Empty-actor accesses are
/// excluded from the distinct-user count (an unattributable access is not a
/// distinct user).
struct AccessTally {
    count: u64,
    distinct_users: usize,
    failed: u64,
    last: Option<DateTime<Utc>>,
}

/// Tally the accesses attributed to `pattern` — the single source of truth for the
/// per-resource access numbers, used by both handlers.
fn tally(accesses: &[Access], pattern: &str) -> AccessTally {
    let mut count = 0u64;
    let mut failed = 0u64;
    let mut users: BTreeSet<&str> = BTreeSet::new();
    let mut last: Option<DateTime<Utc>> = None;
    for a in accesses {
        if !access_matches(a, pattern) {
            continue;
        }
        count += 1;
        if a.failed {
            failed += 1;
        }
        if !a.actor.is_empty() {
            users.insert(a.actor.as_str());
        }
        last = Some(last.map_or(a.ts, |l| l.max(a.ts)));
    }
    AccessTally {
        count,
        distinct_users: users.len(),
        failed,
        last,
    }
}

/// Run one bounded, event-time-pruned scan of recent audit accesses and project
/// each to an owned [`Access`]. Same read discipline as `/api/policies/simulate`
/// (LIMIT + `event_ts` prune + timeout), and the same catalog-stamped projection
/// the live detector pipeline uses, so history is faithful to enforcement.
async fn scan_accesses(
    st: &ApiState,
    aa: &crate::appaudit::AppAudit,
    hours: i64,
    limit: usize,
) -> Result<Vec<Access>, (StatusCode, String)> {
    let events = super::policies::scan_audit_events(st, hours, limit).await?;
    let mut out = Vec::new();
    for ev in &events {
        if !AuditRecord::is_audit_event(ev) {
            continue;
        }
        let mut rec = AuditRecord::from_event(ev);
        aa.stamp_record(&mut rec);
        let ctx = context_from_event(ev, &rec);
        out.push(Access {
            ts: ev.ts,
            actor: rec.actor.actor_id.clone(),
            actor_role: rec.actor.actor_role.clone(),
            client: rec
                .context
                .client_ip
                .clone()
                .or_else(|| rec.context.client_host.clone()),
            source_host: ev.host.to_string(),
            operation: rec
                .action
                .operation
                .clone()
                .or_else(|| rec.action.action.clone()),
            outcome: outcome_label(&rec.action.outcome),
            failed: outcome_failed(&rec.action.outcome),
            object_name: rec
                .action
                .object_name
                .clone()
                .or_else(|| rec.action.resource_path.clone()),
            objects: ctx.objects.clone(),
            ticket_ref: rec.justification.ticket_ref.clone(),
            case_ref: rec.justification.case_ref.clone(),
            purpose: rec.justification.purpose.clone(),
            event_id: ev.fields.get("event_id").cloned(),
        });
    }
    Ok(out)
}

/// One resource-scope dimension evaluated against a resource attribute.
#[derive(PartialEq, Clone, Copy)]
enum Dim {
    /// The policy does not scope on this dimension (a wildcard — no constraint).
    Empty,
    /// The dimension is scoped and the resource satisfies it.
    Match,
    /// The dimension is scoped and the resource does NOT satisfy it — the policy
    /// cannot govern this resource.
    NoMatch,
}

fn dim_objects(pats: &[String], pattern: Option<&str>) -> Dim {
    if pats.is_empty() {
        return Dim::Empty;
    }
    match pattern {
        // Wildcards can sit on either side (catalog `raw.*` vs policy `raw.persons`,
        // or the reverse), so the object match is bidirectional.
        Some(pat)
            if pats
                .iter()
                .any(|po| object_pattern_matches(po, pat) || object_pattern_matches(pat, po)) =>
        {
            Dim::Match
        }
        _ => Dim::NoMatch,
    }
}

fn dim_str(pats: &[String], val: Option<&str>) -> Dim {
    if pats.is_empty() {
        return Dim::Empty;
    }
    match val {
        Some(v) if pats.iter().any(|p| object_pattern_matches(p, v)) => Dim::Match,
        _ => Dim::NoMatch,
    }
}

fn dim_cls(pats: &[String], cls: Option<&str>) -> Dim {
    if pats.is_empty() {
        return Dim::Empty;
    }
    match cls {
        Some(c) if pats.iter().any(|p| p.eq_ignore_ascii_case(c)) => Dim::Match,
        _ => Dim::NoMatch,
    }
}

/// The policies whose resource scope governs `entry`. Mirrors the enforcement
/// semantics of `garmr_policy::ResourceMatch::matches`: every scoped dimension is
/// **ANDed**, so a policy is reported only when EVERY dimension it declares is
/// satisfiable by the resource (an object/classification/schema the policy scopes
/// to but the resource cannot match excludes it — never an OR of one matching
/// dimension). A fully-unscoped `ResourceMatch` governs every object ("all
/// objects"). Dimensions a catalog entry can't resolve (databases, object types,
/// columns, data-subject categories) don't exclude but are flagged "other scope"
/// so the coverage is never claimed as fully verified when it isn't.
fn policy_coverage(policies: &[Policy], entry: &CatalogEntry) -> Vec<Value> {
    let pattern = entry.object_pattern();
    // The schema is the segment before the first dot of a qualified object pattern
    // (`raw.persons` / `raw.*` → `raw`); an unqualified pattern has no schema.
    let schema = pattern.and_then(|p| p.split_once('.').map(|(s, _)| s));
    let classification = entry.object_summary().and_then(|s| s.classification);
    let cls = classification.as_deref();

    let mut out = Vec::new();
    for pol in policies {
        let rm = &pol.resource;
        let obj = dim_objects(&rm.objects, pattern);
        let sch = dim_str(&rm.schemas, schema);
        let cl = dim_cls(&rm.data_classifications, cls);
        // Scope dimensions a catalog entry can't resolve — don't exclude on them,
        // but note that the policy narrows further than we verified.
        let unverified = !rm.databases.is_empty()
            || !rm.object_types.is_empty()
            || !rm.columns.is_empty()
            || !rm.data_subject_categories.is_empty();

        // AND-semantics: any resolvable dimension the resource fails excludes it.
        if obj == Dim::NoMatch || sch == Dim::NoMatch || cl == Dim::NoMatch {
            continue;
        }

        let mut reasons: Vec<&str> = Vec::new();
        if obj == Dim::Match {
            reasons.push("object");
        }
        if sch == Dim::Match {
            reasons.push("schema");
        }
        if cl == Dim::Match {
            reasons.push("classification");
        }
        let fully_unscoped =
            obj == Dim::Empty && sch == Dim::Empty && cl == Dim::Empty && !unverified;
        if reasons.is_empty() {
            if fully_unscoped {
                reasons.push("all objects");
            } else if unverified {
                // Scoped only by dimensions we couldn't resolve from the catalog —
                // report it rather than silently omit a governing policy.
                reasons.push("other scope");
            } else {
                continue;
            }
        } else if unverified {
            reasons.push("+other scope");
        }

        out.push(json!({
            "id": pol.id,
            "title": pol.title,
            "enabled": pol.enabled,
            "effect": pol.effect,
            "priority": pol.priority,
            "match": reasons,
        }));
    }
    out
}

/// GET /api/resources — the resource inventory: each data-bearing catalog entry
/// with its classification/ownership and a bounded recent-access tally. 404 when
/// the app-audit plane is disabled (the catalog lives there). Paginated.
pub(super) async fn resources(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let Some(aa) = &st.app_audit else {
        return Err((
            StatusCode::NOT_FOUND,
            "the application-audit plane is disabled (set detect.app_audit_enabled = true)"
                .to_string(),
        ));
    };
    let catalog = aa.catalog_snapshot();
    let entries: Vec<&CatalogEntry> = catalog
        .entries
        .iter()
        .filter(|e| e.object_pattern().is_some())
        .collect();

    let hours = DEFAULT_SCAN_HOURS;
    let accesses = scan_accesses(&st, aa, hours, SCAN_LIMIT).await?;

    let mut rows: Vec<Value> = Vec::with_capacity(entries.len());
    for e in &entries {
        let pattern = e.object_pattern().unwrap_or_default();
        let summary = e.object_summary();
        let t = tally(&accesses, pattern);
        rows.push(json!({
            "id": e.id,
            "kind": summary.as_ref().map(|s| s.kind),
            "object": pattern,
            "application": summary.as_ref().and_then(|s| s.application.clone()),
            "owner": summary.as_ref().and_then(|s| s.owner.clone()),
            "classification": summary.as_ref().and_then(|s| s.classification.clone()),
            "sensitive": summary.as_ref().is_some_and(|s| s.sensitive),
            "expected_users": summary.as_ref().map_or(0, |s| s.expected_users),
            "approval": e.approval,
            "trusted": e.is_trusted(),
            "version": e.version,
            "source": e.source,
            "access": {
                "count": t.count,
                "distinct_users": t.distinct_users,
                "failed": t.failed,
                "last_access": t.last,
            },
        }));
    }
    // A useful default order: sensitive resources first, then most-accessed, then
    // by id. Pagination slices this stable order.
    rows.sort_by(|a, b| {
        let (sa, sb) = (
            a["sensitive"].as_bool().unwrap_or(false),
            b["sensitive"].as_bool().unwrap_or(false),
        );
        sb.cmp(&sa)
            .then_with(|| {
                b["access"]["count"]
                    .as_u64()
                    .unwrap_or(0)
                    .cmp(&a["access"]["count"].as_u64().unwrap_or(0))
            })
            .then_with(|| {
                a["id"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["id"].as_str().unwrap_or(""))
            })
    });

    let mut out = Page::from_query(&p).envelope("resources", rows);
    out["window_hours"] = json!(hours);
    out["scanned"] = json!(accesses.len());
    out["catalog_total"] = json!(catalog.entries.len());
    Ok(Json(out))
}

/// GET /api/resources/:id — one resource: its catalog facts, a bounded access
/// history (who / from where / justification), top users + clients, and which
/// policies govern it. `?hours=` overrides the window (clamped). 404 for an
/// unknown id or a disabled plane.
pub(super) async fn resource_by_id(
    State(st): State<ApiState>,
    Path(id): Path<String>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let Some(aa) = &st.app_audit else {
        return Err((
            StatusCode::NOT_FOUND,
            "the application-audit plane is disabled (set detect.app_audit_enabled = true)"
                .to_string(),
        ));
    };
    let catalog = aa.catalog_snapshot();
    let Some(entry) = catalog.entries.iter().find(|e| e.id == id) else {
        return Err((StatusCode::NOT_FOUND, format!("no resource with id {id:?}")));
    };

    let hours = p
        .get("hours")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_SCAN_HOURS)
        .clamp(1, MAX_SCAN_HOURS);

    // Policy coverage is a pure function of the enforced policy set + this entry —
    // computed even for a non-data-bearing entry.
    let policies = aa.policy_snapshot();
    let coverage = policy_coverage(&policies, entry);

    // Common catalog facts. `kind` is emitted top-level (not only inside `summary`)
    // so a non-data-bearing entry — whose `object_summary` is null — still shows it.
    let mut body = json!({
        "id": entry.id,
        "kind": entry.resource.kind_label(),
        "object": entry.object_pattern(),
        "summary": entry.object_summary(),
        "resource": entry.resource,
        "approval": entry.approval,
        "trusted": entry.is_trusted(),
        "version": entry.version,
        "source": entry.source,
        "created_by": entry.created_by,
        "approved_by": entry.approved_by,
        "valid_from": entry.valid_from,
        "valid_until": entry.valid_until,
        "policy_coverage": coverage,
    });

    let Some(pattern) = entry.object_pattern() else {
        // A hierarchy/identity entry (Application, Schema, UserRole, …) has no
        // object to accrue access history against.
        body["data_bearing"] = json!(false);
        body["note"] = json!("not a data-bearing resource — no access history");
        return Ok(Json(body));
    };

    let accesses = scan_accesses(&st, aa, hours, SCAN_LIMIT).await?;
    // Newest-first is preserved from the scan's `ORDER BY event_ts DESC`.
    let hits: Vec<&Access> = accesses
        .iter()
        .filter(|a| access_matches(a, pattern))
        .collect();
    // Summary numbers come from the shared `tally` so they never diverge from the list.
    let t = tally(&accesses, pattern);

    let top_users = top_counts(
        hits.iter()
            .filter(|a| !a.actor.is_empty())
            .map(|a| a.actor.clone()),
        TOP_N,
    );
    let top_clients = top_counts(hits.iter().filter_map(|a| a.client.clone()), TOP_N);

    let history: Vec<Value> = hits
        .iter()
        .take(HISTORY_CAP)
        .map(|a| {
            let justification = (a.ticket_ref.is_some() || a.case_ref.is_some() || a.purpose.is_some())
                .then(|| json!({ "ticket_ref": a.ticket_ref, "case_ref": a.case_ref, "purpose": a.purpose }));
            json!({
                "ts": a.ts,
                "actor": a.actor,
                "actor_role": a.actor_role,
                "client": a.client,
                "source_host": a.source_host,
                "operation": a.operation,
                "outcome": a.outcome,
                "failed": a.failed,
                "object": a.object_name,
                "justification": justification,
                "event_id": a.event_id,
            })
        })
        .collect();

    body["data_bearing"] = json!(true);
    body["window_hours"] = json!(hours);
    body["access_summary"] = json!({
        "total": t.count,
        "distinct_users": t.distinct_users,
        "failed": t.failed,
        "last_access": t.last,
        "scanned": accesses.len(),
        "history_truncated": t.count as usize > HISTORY_CAP,
    });
    body["top_users"] = json!(top_users);
    body["top_clients"] = json!(top_clients);
    body["history"] = json!(history);
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_catalog::{CatalogSource, DataClassification, Resource, Schema, Table};
    use garmr_policy::{ConditionMatch, Effect, ResourceMatch, SubjectMatch};

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    /// A test access, defaulting to a successful `anna` touching `objects`.
    fn access(objects: &[&str], object_name: Option<&str>) -> Access {
        Access {
            ts: ts(0),
            actor: "anna".into(),
            actor_role: None,
            client: None,
            source_host: "db01".into(),
            operation: None,
            outcome: "success",
            failed: false,
            object_name: object_name.map(str::to_string),
            objects: objects.iter().map(|s| s.to_string()).collect(),
            ticket_ref: None,
            case_ref: None,
            purpose: None,
            event_id: None,
        }
    }

    fn access_full(actor: &str, obj: &str, failed: bool, secs: i64) -> Access {
        Access {
            actor: actor.into(),
            failed,
            ts: ts(secs),
            ..access(&[obj], None)
        }
    }

    fn table_entry(
        id: &str,
        name: &str,
        cls: Option<DataClassification>,
        sensitive: bool,
    ) -> CatalogEntry {
        let mut e = CatalogEntry::candidate(
            id,
            Resource::Table(Table {
                name: name.into(),
                classification: cls,
                sensitive,
                ..Default::default()
            }),
            CatalogSource::Manual,
        );
        e.promote("tester");
        e
    }

    fn policy(id: &str, resource: ResourceMatch) -> Policy {
        Policy {
            id: id.into(),
            version: 1,
            title: String::new(),
            description: String::new(),
            priority: 0,
            enabled: true,
            subject: SubjectMatch::default(),
            resource,
            condition: ConditionMatch::default(),
            effect: Effect::Deny,
            created_by: "tester".into(),
            approved_by: Some("tester".into()),
        }
    }

    fn objects(objs: &[&str]) -> ResourceMatch {
        ResourceMatch {
            objects: objs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn cov_ids(cov: &[Value]) -> Vec<String> {
        cov.iter()
            .map(|c| c["id"].as_str().unwrap().to_string())
            .collect()
    }

    fn cov_row<'a>(cov: &'a [Value], id: &str) -> &'a Value {
        cov.iter().find(|c| c["id"] == id).unwrap()
    }

    #[test]
    fn access_attribution_uses_the_shared_object_matcher() {
        assert!(access_matches(&access(&["raw.persons"], None), "raw.*"));
        assert!(access_matches(&access(&[], Some("raw.persons")), "raw.*"));
        assert!(access_matches(
            &access(&["public.persons"], None),
            "persons"
        ));
        assert!(!access_matches(&access(&["curated.orders"], None), "raw.*"));
    }

    #[test]
    fn tally_counts_matches_distinct_nonempty_users_failed_and_latest() {
        let accesses = vec![
            access_full("anna", "raw.persons", false, 100),
            access_full("anna", "raw.persons", true, 300), // later + failed, same user
            access_full("bob", "raw.orders", false, 200),  // matches raw.* too
            access_full("", "raw.persons", false, 50),     // empty actor: counted, not a user
            access_full("carol", "curated.orders", false, 999), // does NOT match raw.*
        ];
        let t = tally(&accesses, "raw.*");
        assert_eq!(t.count, 4, "curated.* access excluded");
        assert_eq!(t.distinct_users, 2, "anna + bob; empty actor excluded");
        assert_eq!(t.failed, 1);
        assert_eq!(t.last, Some(ts(300)), "latest matching ts");
    }

    #[test]
    fn policy_coverage_ands_scoped_dimensions_like_enforcement() {
        let entry = table_entry(
            "table:raw.persons",
            "raw.persons",
            Some(DataClassification::Restricted),
            true,
        );

        // Single-dimension matches.
        let by_object = policy("p-object", objects(&["raw.*"]));
        // Concrete policy object vs the entry — exercises the bidirectional match.
        let by_object_concrete = policy("p-object2", objects(&["raw.persons"]));
        let by_class = policy(
            "p-class",
            ResourceMatch {
                data_classifications: vec!["RESTRICTED".into()], // case-insensitive
                ..Default::default()
            },
        );
        let by_schema = policy(
            "p-schema",
            ResourceMatch {
                schemas: vec!["raw".into()],
                ..Default::default()
            },
        );
        let unscoped = policy("p-all", ResourceMatch::default());

        // BOTH object and classification match → multi-reason.
        let by_both = policy(
            "p-both",
            ResourceMatch {
                objects: vec!["raw.*".into()],
                data_classifications: vec!["restricted".into()],
                ..Default::default()
            },
        );
        // Object present but NOT matching, though classification matches — AND
        // semantics must EXCLUDE it (the over-report bug).
        let mixed_nomatch = policy(
            "p-mixed",
            ResourceMatch {
                objects: vec!["curated.*".into()],
                data_classifications: vec!["restricted".into()],
                ..Default::default()
            },
        );
        // Scoped to a different object entirely.
        let other = policy("p-other", objects(&["curated.*"]));

        let cov = policy_coverage(
            &[
                by_object,
                by_object_concrete,
                by_class,
                by_schema,
                unscoped,
                by_both,
                mixed_nomatch,
                other,
            ],
            &entry,
        );
        let ids = cov_ids(&cov);
        for want in [
            "p-object",
            "p-object2",
            "p-class",
            "p-schema",
            "p-all",
            "p-both",
        ] {
            assert!(ids.contains(&want.to_string()), "missing {want}: {ids:?}");
        }
        assert!(
            !ids.contains(&"p-mixed".to_string()),
            "AND-semantics must exclude object-mismatch"
        );
        assert!(
            !ids.contains(&"p-other".to_string()),
            "unrelated policy wrongly reported"
        );

        assert_eq!(cov_row(&cov, "p-object")["match"][0], "object");
        assert_eq!(cov_row(&cov, "p-schema")["match"][0], "schema");
        assert_eq!(cov_row(&cov, "p-all")["match"][0], "all objects");
        // Multi-reason accumulation, in declaration order.
        let both = &cov_row(&cov, "p-both")["match"];
        assert_eq!(both[0], "object");
        assert_eq!(both[1], "classification");
    }

    #[test]
    fn policy_coverage_reports_schema_only_policy() {
        // The under-report bug: a schema-only policy still governs raw.persons.
        let entry = table_entry("table:raw.persons", "raw.persons", None, false);
        let sch = policy(
            "p-schema",
            ResourceMatch {
                schemas: vec!["raw".into()],
                ..Default::default()
            },
        );
        let cov = policy_coverage(&[sch], &entry);
        assert_eq!(cov_ids(&cov), vec!["p-schema".to_string()]);
    }

    #[test]
    fn policy_coverage_on_non_data_bearing_entry_only_reports_unscoped() {
        // A Schema entry has no object pattern and no classification.
        let mut entry = CatalogEntry::candidate(
            "schema:raw",
            Resource::Schema(Schema::default()),
            CatalogSource::Manual,
        );
        entry.promote("tester");
        assert!(entry.object_pattern().is_none());

        let unscoped = policy("p-all", ResourceMatch::default());
        let by_object = policy("p-object", objects(&["raw.*"]));
        let by_class = policy(
            "p-class",
            ResourceMatch {
                data_classifications: vec!["restricted".into()],
                ..Default::default()
            },
        );
        let cov = policy_coverage(&[unscoped, by_object, by_class], &entry);
        // Only the fully-unscoped policy can govern an objectless, unclassified entry.
        assert_eq!(cov_ids(&cov), vec!["p-all".to_string()]);
        assert_eq!(cov_row(&cov, "p-all")["match"][0], "all objects");
    }
}
