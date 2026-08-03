// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! First-run setup: what resolves each step, and where.
//!
//! The checklist was already honest about *state* — it is computed live by the
//! server and never inferred from an empty event store. What it was not honest
//! about was *action*: several steps offered a button that went somewhere it
//! could not be fixed, and three offered nothing at all. A checklist that tells
//! you what is wrong but sends you to the wrong page is a worse dead end than one
//! that says nothing.
//!
//! So the mapping from step to next action lives here, as a pure function over
//! the step ids the server actually emits (`GET /api/setup/status`), unit-tested
//! so a renamed or added step cannot silently fall back to "no action".

/// Where an incomplete step is resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupAction {
    /// A tab inside System, with the section to look for.
    SystemTab {
        tab: &'static str,
        label: &'static str,
    },
    /// A different console area entirely.
    ConsoleArea {
        area: &'static str,
        label: &'static str,
    },
    /// Only doable on the host: an exact command plus what must be true first.
    /// The console cannot run this, and pretending otherwise is the dead end.
    Host {
        command: &'static str,
        prerequisite: &'static str,
        label: &'static str,
    },
    /// Resolved on a page outside the SPA (the passkey ceremony needs its own
    /// origin-level page).
    Page {
        href: &'static str,
        label: &'static str,
    },
    /// Genuinely informational — nothing to do.
    Informational,
}

impl SetupAction {
    /// True when the operator must leave the console to finish this.
    pub fn is_host_only(&self) -> bool {
        matches!(self, SetupAction::Host { .. })
    }
}

/// The action that resolves `step_id`.
///
/// Every id the server currently emits is handled explicitly; an unknown id
/// returns `Informational` rather than a misleading button.
pub fn action_for(step_id: &str) -> SetupAction {
    match step_id {
        // Storage and deployment mode are configuration.
        "storage" | "deployment_mode" => SetupAction::SystemTab {
            tab: "config",
            label: "Open Configuration",
        },
        // The Admin principal and API credentials live in Access.
        "admin" => SetupAction::SystemTab {
            tab: "access",
            label: "Open Access",
        },
        // Passkeys are REGISTERED on the login page (the WebAuthn ceremony needs
        // navigator.credentials on its own page), and reviewed in Access. Sending
        // the operator to Access alone is the dead end the task calls out: with no
        // passkey enabled there is nothing there to click.
        "passkeys" => SetupAction::Page {
            href: "/login",
            label: "Register a passkey",
        },
        // Break-glass recovery is deliberately host-only: it must work when the
        // console cannot be reached, so it is not exposed over HTTP.
        "recovery" => SetupAction::Host {
            command: "garmr recover issue-admin",
            prerequisite: "run on the host with the garmr service stopped",
            label: "Host command",
        },
        // The provider, model and key are configured in Model provider — NOT in
        // Access, which is where this used to point.
        "llm" => SetupAction::SystemTab {
            tab: "llm",
            label: "Open Model provider",
        },
        // Reachability is proven by the real connection test, which lives on the
        // Model provider tab next to the provider it tests.
        "llm_reachable" => SetupAction::SystemTab {
            tab: "llm",
            label: "Run the connection test",
        },
        // Ingest onboarding is its own area, not a System tab.
        "data_sources" => SetupAction::ConsoleArea {
            area: "data-sources",
            label: "Open Data Sources",
        },
        "detection" => SetupAction::SystemTab {
            tab: "config",
            label: "Open Configuration",
        },
        // Notifications are configuration, not access control.
        "notifications" => SetupAction::SystemTab {
            tab: "config",
            label: "Open Configuration",
        },
        // The self-test is an offline CLI check by design.
        "selftest" => SetupAction::Host {
            command: "garmr selftest",
            prerequisite: "run from the CLI on the host; runs offline",
            label: "Host command",
        },
        _ => SetupAction::Informational,
    }
}

/// Should opening System land on Setup rather than the usual default?
///
/// While setup is incomplete the checklist is the most useful thing in System, so
/// it becomes the default tab. Once setup completes, the normal default applies —
/// the console must not nag forever about a finished job.
pub fn default_system_tab(setup_complete: Option<bool>) -> &'static str {
    match setup_complete {
        Some(false) => "setup",
        // Complete, or not yet known: the ordinary default. Guessing "setup"
        // before the answer arrives would make System flicker on every visit.
        _ => "audit",
    }
}

/// Should the persistent (non-blocking) setup banner be shown?
///
/// Only when setup is known-incomplete AND the viewer can actually act on it.
/// Showing an unauthorized analyst a banner they cannot resolve is noise.
pub fn show_setup_banner(setup_complete: Option<bool>, may_administer: bool) -> bool {
    setup_complete == Some(false) && may_administer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact ids `/api/setup/status` emits, read from the running lab
    /// deployment on 2026-08-03.
    const LIVE_STEP_IDS: &[&str] = &[
        "deployment_mode",
        "storage",
        "admin",
        "passkeys",
        "recovery",
        "llm",
        "llm_reachable",
        "data_sources",
        "detection",
        "notifications",
        "selftest",
    ];

    #[test]
    fn every_live_step_has_a_real_action() {
        for id in LIVE_STEP_IDS {
            let a = action_for(id);
            assert_ne!(
                a,
                SetupAction::Informational,
                "step {id} must offer a next action, not a dead end"
            );
        }
    }

    /// The regression the task names: LLM configuration and reachability used to
    /// point at Access, where neither can be resolved.
    #[test]
    fn llm_steps_point_at_the_model_provider_not_access() {
        for id in ["llm", "llm_reachable"] {
            match action_for(id) {
                SetupAction::SystemTab { tab, .. } => {
                    assert_eq!(tab, "llm", "{id} must route to the Model provider tab")
                }
                other => panic!("{id} routed to {other:?}"),
            }
        }
    }

    #[test]
    fn notifications_are_configuration_not_access() {
        assert_eq!(
            action_for("notifications"),
            SetupAction::SystemTab {
                tab: "config",
                label: "Open Configuration"
            }
        );
    }

    /// Passkey registration must not send the operator to a tab that is empty
    /// precisely because no passkey exists yet.
    #[test]
    fn passkey_step_routes_to_the_registration_page() {
        assert_eq!(
            action_for("passkeys"),
            SetupAction::Page {
                href: "/login",
                label: "Register a passkey"
            }
        );
    }

    #[test]
    fn host_only_steps_carry_a_command_and_a_prerequisite() {
        for id in ["recovery", "selftest"] {
            match action_for(id) {
                SetupAction::Host {
                    command,
                    prerequisite,
                    ..
                } => {
                    assert!(command.starts_with("garmr "), "{id}: {command}");
                    assert!(!prerequisite.is_empty(), "{id} needs a prerequisite");
                }
                other => panic!("{id} should be host-only, got {other:?}"),
            }
        }
    }

    #[test]
    fn host_only_is_distinguishable_from_console_work() {
        assert!(action_for("recovery").is_host_only());
        assert!(action_for("selftest").is_host_only());
        assert!(!action_for("llm").is_host_only());
        assert!(!action_for("passkeys").is_host_only());
        assert!(!action_for("data_sources").is_host_only());
    }

    #[test]
    fn data_sources_step_leaves_system_entirely() {
        assert_eq!(
            action_for("data_sources"),
            SetupAction::ConsoleArea {
                area: "data-sources",
                label: "Open Data Sources"
            }
        );
    }

    #[test]
    fn an_unknown_step_offers_no_misleading_button() {
        assert_eq!(action_for("something_new"), SetupAction::Informational);
    }

    // ---- defaults and the banner -------------------------------------------

    #[test]
    fn system_defaults_to_setup_only_while_incomplete() {
        assert_eq!(default_system_tab(Some(false)), "setup");
        assert_eq!(default_system_tab(Some(true)), "audit");
        // Unknown: do not guess, or System flickers on every visit.
        assert_eq!(default_system_tab(None), "audit");
    }

    #[test]
    fn banner_only_for_someone_who_can_act() {
        assert!(show_setup_banner(Some(false), true));
        assert!(!show_setup_banner(Some(false), false));
        assert!(!show_setup_banner(Some(true), true));
        assert!(!show_setup_banner(None, true));
    }
}
