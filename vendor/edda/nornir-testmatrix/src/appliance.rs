//! **The appliance (product × proof) rollup** — ONE place that answers "which
//! products have a PROVEN identity ceremony, and how far up the ladder?".
//!
//! The suite's appliance work (the wg-appliance ceremony, the container robot,
//! the installer KVM proofs, Secure Boot arming) emits ordinary
//! [`functional_status`](crate::functional_status) rows under a NAMING
//! CONVENTION this module owns:
//!
//! ```text
//!   component = "<product>-appliance"            (the host/server form)
//!            or "<product>-appliance/<form>"     (a specific form: container, iso …)
//!   check     = the proof name (identity_ready, ping_through_tunnel, …)
//! ```
//!
//! [`ApplianceRollup::from_rows`] folds any row set into a grid of
//! [`ProofVerdict`]s keyed `(product, proof)`. Three verdicts, and the third is
//! the load-bearing one:
//!
//! * [`ProofVerdict::Green`] — every matching row passed.
//! * [`ProofVerdict::Red`] — ANY matching row failed. Red wins over green
//!   (a proof that passed on one form and failed on another is NOT proven).
//! * [`ProofVerdict::Absent`] — no row at all. A product that never emitted is
//!   a visible HOLE in the grid, never silent green — "no evidence" and
//!   "proven" must be impossible to confuse (the same law as the gated-tests
//!   guard: silence is not success).
//!
//! The canonical rosters ([`APPLIANCE_PRODUCTS`], [`APPLIANCE_PROOFS`]) pin the
//! grid's SHAPE: the rollup always shows all three products against the full
//! proof ladder, so korp's empty row is on the wall next to holger's green one.
//! Extra products/proofs found in the rows are appended after the canonical
//! ones — the roster floors the grid, it does not cap it.

use std::collections::BTreeMap;

use crate::model::{TestResultRow, status};

/// The products the suite ships as appliances. The grid ALWAYS carries all of
/// them — an unproven product is a row of `Absent`, not a missing row.
pub const APPLIANCE_PRODUCTS: [&str; 3] = ["holger", "gunnar", "korp"];

/// The proof ladder, in ceremony order — each name is a `check` some proof
/// emits (or will emit; an emitter that does not exist yet shows `Absent`,
/// which is exactly the honest answer):
///
/// * `identity_ready` — the server binary ran the ceremony (host form).
/// * `identity_minted` / `identity_survives_replacement` /
///   `identity_survives_upgrade` — the container robot's durability arms.
/// * `tunnel_up_traffic_crossed` — handshake seen + ≥1 packet sealed.
/// * `ping_through_tunnel` — ICMP echo through the tunnel, both directions.
/// * `install_ok` — the installer ISO laid the product onto a disk under KVM.
/// * `secure_boot_armed` — enforcing firmware boots the signed installer and
///   refuses the unsigned/foreign-keyed one.
pub const APPLIANCE_PROOFS: [&str; 8] = [
    "identity_ready",
    "identity_minted",
    "identity_survives_replacement",
    "identity_survives_upgrade",
    "tunnel_up_traffic_crossed",
    "ping_through_tunnel",
    "install_ok",
    "secure_boot_armed",
];

/// The `-appliance` component-name marker the convention hangs on.
const COMPONENT_SUFFIX: &str = "-appliance";

/// One cell of the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerdict {
    /// Every matching row passed.
    Green,
    /// At least one matching row failed — red wins over green.
    Red,
    /// No row matched — no evidence, visibly so.
    Absent,
}

impl ProofVerdict {
    /// The single-glyph cell rendering: `✔` / `✘` / `—`.
    pub fn glyph(self) -> &'static str {
        match self {
            ProofVerdict::Green => "✔",
            ProofVerdict::Red => "✘",
            ProofVerdict::Absent => "—",
        }
    }
}

/// Parse a component name against the convention: `holger-appliance` and
/// `holger-appliance/container` both yield `Some("holger")`; anything without
/// the `-appliance` marker (or with an EMPTY product) is `None` — foreign
/// components never leak into the grid.
pub fn appliance_product(component: &str) -> Option<&str> {
    let base = component.split('/').next().unwrap_or(component);
    let product = base.strip_suffix(COMPONENT_SUFFIX)?;
    if product.is_empty() {
        return None;
    }
    Some(product)
}

/// The folded (product × proof) grid.
#[derive(Debug, Clone)]
pub struct ApplianceRollup {
    /// Row order: the canonical products first, then any extras seen in the
    /// rows (sorted). Same floor-not-cap rule for `proofs`.
    pub products: Vec<String>,
    /// Column order: the canonical ladder first, then extras (sorted).
    pub proofs: Vec<String>,
    verdicts: BTreeMap<(String, String), ProofVerdict>,
}

impl ApplianceRollup {
    /// Fold rows into the grid. Rows whose component does not match the
    /// convention are ignored; `pass` folds green, anything else that matched
    /// a proof cell folds RED (a stalled or failed proof is not proven).
    pub fn from_rows<'a, I: IntoIterator<Item = &'a TestResultRow>>(rows: I) -> Self {
        let mut verdicts: BTreeMap<(String, String), ProofVerdict> = BTreeMap::new();
        let mut extra_products: Vec<String> = Vec::new();
        let mut extra_proofs: Vec<String> = Vec::new();
        for row in rows {
            let Some(product) = appliance_product(&row.suite) else {
                continue;
            };
            let proof = row.test_name.as_str();
            let ok = row.status == status::PASS;
            let key = (product.to_string(), proof.to_string());
            let cell = verdicts.entry(key).or_insert(ProofVerdict::Green);
            if !ok {
                *cell = ProofVerdict::Red;
            }
            if !APPLIANCE_PRODUCTS.contains(&product)
                && !extra_products.iter().any(|p| p == product)
            {
                extra_products.push(product.to_string());
            }
            if !APPLIANCE_PROOFS.contains(&proof) && !extra_proofs.iter().any(|p| p == proof) {
                extra_proofs.push(proof.to_string());
            }
        }
        extra_products.sort();
        extra_proofs.sort();
        let products = APPLIANCE_PRODUCTS
            .iter()
            .map(|p| p.to_string())
            .chain(extra_products)
            .collect();
        let proofs = APPLIANCE_PROOFS
            .iter()
            .map(|p| p.to_string())
            .chain(extra_proofs)
            .collect();
        Self {
            products,
            proofs,
            verdicts,
        }
    }

    /// The verdict for one cell (any product/proof string — off-grid asks are
    /// `Absent`, the same answer as an on-grid hole).
    pub fn verdict(&self, product: &str, proof: &str) -> ProofVerdict {
        self.verdicts
            .get(&(product.to_string(), proof.to_string()))
            .copied()
            .unwrap_or(ProofVerdict::Absent)
    }

    /// True when every canonical (product × proof) cell is `Green` — the
    /// suite-wide "all appliances fully proven" gate. Today this is FALSE and
    /// the grid shows exactly which cells keep it false.
    pub fn all_green(&self) -> bool {
        APPLIANCE_PRODUCTS.iter().all(|product| {
            APPLIANCE_PROOFS
                .iter()
                .all(|proof| self.verdict(product, proof) == ProofVerdict::Green)
        })
    }

    /// Render the grid as a fixed-width text table — products as rows, proofs
    /// as columns (numbered, with a legend, so the table stays terminal-width).
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("appliance (product × proof) — ✔ proven · ✘ FAILED · — no evidence\n");
        let width = self
            .products
            .iter()
            .map(|p| p.len())
            .max()
            .unwrap_or(0)
            .max(7);
        out.push_str(&format!("{:width$} ", ""));
        for i in 1..=self.proofs.len() {
            out.push_str(&format!("{i:>3}"));
        }
        out.push('\n');
        for product in &self.products {
            out.push_str(&format!("{product:width$} "));
            for proof in &self.proofs {
                out.push_str(&format!("{:>3}", self.verdict(product, proof).glyph()));
            }
            out.push('\n');
        }
        for (i, proof) in self.proofs.iter().enumerate() {
            out.push_str(&format!("  {:>2} = {proof}\n", i + 1));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functional::functional_row;

    // RED-BEFORE-GREEN: the hole is the load-bearing verdict — a product with
    // no rows is Absent in EVERY cell, and all_green() refuses.
    #[test]
    fn a_product_that_never_emitted_is_a_visible_hole_not_silent_green() {
        let rows = vec![functional_row(
            "holger-appliance",
            "identity_ready",
            true,
            "pubkey=… minted=false",
        )];
        let grid = ApplianceRollup::from_rows(&rows);
        assert_eq!(grid.verdict("korp", "identity_ready"), ProofVerdict::Absent);
        assert_eq!(
            grid.verdict("gunnar", "ping_through_tunnel"),
            ProofVerdict::Absent
        );
        assert!(!grid.all_green(), "holes must hold the gate red");
        let rendered = grid.render();
        assert!(
            rendered.contains("korp"),
            "korp's empty row is ON the wall:\n{rendered}"
        );
        assert!(rendered.contains('—'), "absence renders as —:\n{rendered}");
    }

    #[test]
    fn red_wins_over_green_across_forms() {
        // Same proof, two forms: host passed, container FAILED → the cell is red.
        let rows = vec![
            functional_row("holger-appliance", "identity_ready", true, "host ok"),
            functional_row(
                "holger-appliance/container",
                "identity_ready",
                false,
                "container broke",
            ),
        ];
        let grid = ApplianceRollup::from_rows(&rows);
        assert_eq!(grid.verdict("holger", "identity_ready"), ProofVerdict::Red);
    }

    // The EXACT strings holger's emitters use today — the convention test that
    // keeps this module honest against the real vocabulary (server/cli
    // main.rs: "holger-appliance"/"identity_ready"; the container robot:
    // "holger-appliance/container" with the five durability/tunnel checks).
    #[test]
    fn holgers_real_vocabulary_folds_onto_the_canonical_grid() {
        let rows = vec![
            functional_row("holger-appliance", "identity_ready", true, ""),
            functional_row("holger-appliance/container", "identity_minted", true, ""),
            functional_row(
                "holger-appliance/container",
                "identity_survives_replacement",
                true,
                "",
            ),
            functional_row(
                "holger-appliance/container",
                "identity_survives_upgrade",
                true,
                "",
            ),
            functional_row(
                "holger-appliance/container",
                "tunnel_up_traffic_crossed",
                true,
                "",
            ),
            functional_row(
                "holger-appliance/container",
                "ping_through_tunnel",
                true,
                "",
            ),
            functional_row("holger-appliance/iso", "install_ok", true, ""),
            functional_row("holger-appliance/iso", "secure_boot_armed", true, ""),
        ];
        let grid = ApplianceRollup::from_rows(&rows);
        for proof in APPLIANCE_PROOFS {
            assert_eq!(
                grid.verdict("holger", proof),
                ProofVerdict::Green,
                "holger's {proof} must fold onto the canonical column"
            );
        }
        // No stray columns: everything holger emits IS canonical.
        assert_eq!(grid.proofs.len(), APPLIANCE_PROOFS.len());
    }

    #[test]
    fn foreign_components_never_leak_into_the_grid() {
        let rows = vec![
            functional_row(
                "holger-mvp",
                "build",
                true,
                "a build tier, not an appliance",
            ),
            functional_row("appliance", "identity_ready", true, "no product prefix"),
            functional_row("-appliance", "identity_ready", true, "EMPTY product"),
        ];
        let grid = ApplianceRollup::from_rows(&rows);
        assert_eq!(
            grid.products.len(),
            APPLIANCE_PRODUCTS.len(),
            "only the canonical roster"
        );
        for product in APPLIANCE_PRODUCTS {
            for proof in APPLIANCE_PROOFS {
                assert_eq!(grid.verdict(product, proof), ProofVerdict::Absent);
            }
        }
    }

    #[test]
    fn extra_products_and_proofs_floor_not_cap() {
        let rows = vec![functional_row(
            "skrymt-appliance",
            "quantum_ready",
            false,
            "a fourth product",
        )];
        let grid = ApplianceRollup::from_rows(&rows);
        assert!(
            grid.products.iter().any(|p| p == "skrymt"),
            "extras appended"
        );
        assert!(grid.proofs.iter().any(|p| p == "quantum_ready"));
        assert_eq!(grid.verdict("skrymt", "quantum_ready"), ProofVerdict::Red);
        // …and the canonical three still lead the row order.
        assert_eq!(&grid.products[..3], &["holger", "gunnar", "korp"]);
    }

    #[test]
    fn product_parsing_handles_forms_and_refuses_nonmatches() {
        assert_eq!(appliance_product("holger-appliance"), Some("holger"));
        assert_eq!(
            appliance_product("holger-appliance/container"),
            Some("holger")
        );
        assert_eq!(appliance_product("korp-appliance/iso"), Some("korp"));
        assert_eq!(appliance_product("holger-mvp"), None);
        assert_eq!(appliance_product("-appliance"), None);
        assert_eq!(appliance_product("appliance"), None);
    }
}
