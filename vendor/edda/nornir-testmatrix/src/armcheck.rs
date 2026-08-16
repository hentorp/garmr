//! **A declared rescue arm must actually rescue something.**
//!
//! [`crate::gatedtests`] catches a `tests/*.rs` that can never run: a crate-level
//! `#![cfg(feature = "X")]` the crate's `default` set does not satisfy compiles to
//! an EMPTY test binary and reports `0 tests ... ok`. A repo silences that finding
//! by DECLARING the re-invocation that rescues the file, in
//! `.nornir/testmatrix-arms.json`.
//!
//! Which makes the declaration the whole guarantee. And until now nothing checked
//! it. [`MatrixArm::command`] renders a *display string* — it is what shows up in
//! the report so a reader can audit the rescue — and that string was the entire
//! extent of the arm's existence. Nothing compiled an arm, let alone ran one.
//!
//! Forty declared arms across eleven repos were "verified" by a human once
//! (korp's arms file still says `Verified 2026-07-22`), and a hand-verification is
//! a claim with a timestamp on it: it does not survive a feature rename, a test
//! target moved to another package, or a `default = [...]` edit three months
//! later. The gated-tests guard would go on reporting green, because the *only*
//! thing it asks is whether an arm with matching features was declared.
//!
//! What the shape of the failure would be: a `tests/robot_ui_app.rs` gated on
//! `gui`, an arm declaring `-p holger-ui --features gui`, and someone renaming the
//! feature to `robot-ui`. The gate stays green (an arm is declared), the arm no
//! longer compiles (nobody runs it), and the tests it named have not executed in
//! months. Silence, wearing the badge that says it is not silence.
//!
//! # What this checks, and why each part is load-bearing
//!
//! For each arm, [`verify_arm`] runs the arm's own `cargo test … --no-run` and
//! then asks three questions that a `--no-run` exit code does NOT answer:
//!
//! 1. **Does it compile?** Exit status of `cargo test --no-run`. Catches renamed
//!    features, moved packages, deleted test targets.
//! 2. **Did it produce a test binary?** An arm can compile and build *nothing* —
//!    e.g. `--test <name>` for a target that no longer exists is an error, but a
//!    package whose test targets all vanished is not. Parsed out of
//!    `--message-format=json` artifacts, not guessed from the exit code.
//! 3. **Does that binary contain any tests?** THE point. A rescue arm exists to
//!    turn an empty binary into a non-empty one; an arm that builds a binary
//!    listing zero tests has rescued nothing and is indistinguishable, from the
//!    gate's side, from one that works. Asked by running the built binary with
//!    `--list`, which enumerates without executing.
//!
//! Compiling is the expensive part, so this is not something to run on every
//! `cargo test`; it is the arms' own guard, run where the arms are declared.
//!
//! ```no_run
//! use nornir_testmatrix::{verify_arms, MatrixArms};
//! let arms = MatrixArms::load(std::path::Path::new(".")).unwrap();
//! let v = verify_arms(std::path::Path::new("."), &arms);
//! assert!(v.all_ok(), "{}", v.summary());
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::gatedtests::{MatrixArm, MatrixArms};

/// What happened when one declared arm was actually invoked.
#[derive(Debug, Clone)]
pub struct ArmCheck {
    /// The `cargo test …` line the arm stands for ([`MatrixArm::command`]).
    pub command: String,
    /// Did `cargo test --no-run` succeed?
    pub compiled: bool,
    /// Test binaries the arm produced (after `--test` filtering).
    pub binaries: Vec<PathBuf>,
    /// Total `#[test]`s the produced binaries enumerate via `--list`.
    pub tests_listed: usize,
    /// `None` when the arm is real. Otherwise what is wrong with it.
    pub problem: Option<String>,
}

impl ArmCheck {
    /// A real arm: it compiles, it builds a test binary, and that binary has tests.
    pub fn is_ok(&self) -> bool {
        self.problem.is_none()
    }
}

/// Every arm's verdict, plus the counts a caller needs to know the run was real.
#[derive(Debug, Clone, Default)]
pub struct ArmVerification {
    /// One entry per declared arm, in declaration order.
    pub checks: Vec<ArmCheck>,
}

impl ArmVerification {
    /// True when every declared arm is real. NOTE: also true for a repo that
    /// declares no arms — use [`ArmVerification::declared`] to tell the two
    /// apart. A guard that reads "no arms" as "all arms fine" is the empty-scan
    /// false green.
    pub fn all_ok(&self) -> bool {
        self.checks.iter().all(ArmCheck::is_ok)
    }

    /// How many arms were examined.
    pub fn declared(&self) -> usize {
        self.checks.len()
    }

    /// A paste-into-a-failure report.
    pub fn summary(&self) -> String {
        let bad: Vec<&ArmCheck> = self.checks.iter().filter(|c| !c.is_ok()).collect();
        if bad.is_empty() {
            let tests: usize = self.checks.iter().map(|c| c.tests_listed).sum();
            return format!(
                "{} declared rescue arm(s) verified: all compile and together rescue {} test(s)",
                self.checks.len(),
                tests
            );
        }
        let mut s = String::from(
            "DECLARED RESCUE ARMS THAT DO NOT RESCUE — the gated-tests guard treats a\n\
             declared arm as proof the silenced tests are run somewhere. These arms are\n\
             that proof, and they do not hold:\n\n",
        );
        for c in bad {
            s.push_str(&format!(
                "  {}\n    {}\n",
                c.command,
                c.problem.as_deref().unwrap_or("(no detail)")
            ));
        }
        s.push_str(&format!(
            "\n({} arm(s) checked, {} ok)\n",
            self.checks.len(),
            self.checks.len() - self.checks.iter().filter(|c| !c.is_ok()).count()
        ));
        s
    }
}

/// The `cargo test` argv an arm stands for, as ARGS (the machine-readable twin of
/// [`MatrixArm::command`], which renders the same thing for humans).
pub fn arm_args(arm: &MatrixArm) -> Vec<String> {
    let mut v = vec!["test".to_string()];
    if let Some(p) = &arm.package {
        v.push("-p".into());
        v.push(p.clone());
    }
    if arm.no_default_features {
        v.push("--no-default-features".into());
    }
    if arm.all_features {
        v.push("--all-features".into());
    } else if !arm.features.is_empty() {
        v.push("--features".into());
        v.push(arm.features.join(","));
    }
    if let Some(t) = &arm.test {
        v.push("--test".into());
        v.push(t.clone());
    }
    v
}

/// Pull `(target_name, executable)` for every TEST artifact out of a
/// `cargo --message-format=json` stream.
///
/// Deliberately tolerant of non-JSON lines (cargo interleaves plain progress on
/// stdout in some versions) and of unknown fields — but NOT of a missing
/// `executable`, which is exactly how a lib/bin artifact differs from a test one.
pub fn test_artifacts(stdout: &str) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        if v.get("profile")
            .and_then(|p| p.get("test"))
            .and_then(|t| t.as_bool())
            != Some(true)
        {
            continue;
        }
        let Some(exe) = v.get("executable").and_then(|e| e.as_str()) else {
            continue;
        };
        let name = v
            .get("target")
            .and_then(|t| t.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        let kinds = v
            .get("target")
            .and_then(|t| t.get("kind"))
            .and_then(|k| k.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).any(|x| x == "test"))
            .unwrap_or(false);
        if !kinds {
            continue;
        }
        out.push((name, PathBuf::from(exe)));
    }
    out
}

/// Count the `#[test]`s a built libtest binary enumerates.
///
/// Parses the OUTPUT of `--list` rather than trusting the exit code: a binary
/// containing zero tests exits 0 and prints nothing but the trailing summary, and
/// that is precisely the case this whole module exists to catch.
pub fn count_listed_tests(list_output: &str) -> usize {
    list_output
        .lines()
        .filter(|l| l.trim_end().ends_with(": test"))
        .count()
}

/// Where an arm's `--no-run` build output goes: a sibling of the caller's own
/// target dir, never the caller's own (see [`verify_arm`] on the build lock).
/// Honours `NORNIR_ARM_TARGET_DIR` so a fleet with a scratch-disk policy can put
/// it somewhere other than the repo.
pub fn arm_target_dir(repo_root: &Path) -> PathBuf {
    if let Ok(explicit) = std::env::var("NORNIR_ARM_TARGET_DIR") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    match std::env::var("CARGO_TARGET_DIR") {
        Ok(t) if !t.is_empty() => PathBuf::from(t).join("armcheck"),
        _ => repo_root.join("target").join("armcheck"),
    }
}

/// Compile and interrogate ONE declared arm. Never runs the tests.
pub fn verify_arm(repo_root: &Path, arm: &MatrixArm) -> ArmCheck {
    let command = arm.command();
    let mut args = arm_args(arm);
    args.push("--no-run".into());
    args.push("--message-format=json".into());

    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(&args)
        .current_dir(repo_root)
        // A DEDICATED target dir, and it is not optional. The caller of this is
        // itself running under `cargo test`, which holds the build lock on its
        // target dir for the whole invocation — INCLUDING while the test binary
        // runs. A child cargo pointed at that same directory does not fail, it
        // BLOCKS, forever, and the guard looks like a hang rather than a result.
        // Deriving it from the parent's keeps the build cached between runs.
        .env("CARGO_TARGET_DIR", arm_target_dir(repo_root))
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .output();

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return ArmCheck {
                command,
                compiled: false,
                binaries: Vec::new(),
                tests_listed: 0,
                problem: Some(format!("could not run cargo: {e}")),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if !out.status.success() {
        let tail: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("error"))
            .take(6)
            .collect();
        let detail = if tail.is_empty() {
            stderr.lines().rev().take(6).collect()
        } else {
            tail
        };
        return ArmCheck {
            command,
            compiled: false,
            binaries: Vec::new(),
            tests_listed: 0,
            problem: Some(format!(
                "declared, but does NOT COMPILE — so nothing it names has run since it \
                 stopped compiling:\n      {}",
                detail.join("\n      ")
            )),
        };
    }

    let mut artifacts = test_artifacts(&stdout);
    if let Some(t) = &arm.test {
        artifacts.retain(|(name, _)| name == t);
        if artifacts.is_empty() {
            return ArmCheck {
                command,
                compiled: true,
                binaries: Vec::new(),
                tests_listed: 0,
                problem: Some(format!(
                    "compiles, but builds no test target named `{t}` — the arm names a \
                     test file that is no longer there"
                )),
            };
        }
    }
    if artifacts.is_empty() {
        return ArmCheck {
            command,
            compiled: true,
            binaries: Vec::new(),
            tests_listed: 0,
            problem: Some(
                "compiles, but produces NO test binary at all — there is nothing here to \
                 rescue"
                    .into(),
            ),
        };
    }

    let mut binaries = Vec::new();
    let mut tests_listed = 0usize;
    let mut empty: Vec<String> = Vec::new();
    for (name, exe) in artifacts {
        match std::fs::metadata(&exe) {
            Ok(m) if m.len() > 0 => {}
            Ok(_) => {
                return ArmCheck {
                    command,
                    compiled: true,
                    binaries: vec![exe.clone()],
                    tests_listed: 0,
                    problem: Some(format!("built a ZERO-BYTE binary for `{name}`")),
                };
            }
            Err(e) => {
                return ArmCheck {
                    command,
                    compiled: true,
                    binaries: Vec::new(),
                    tests_listed: 0,
                    problem: Some(format!(
                        "cargo reported the binary for `{name}` at {} but it is not there: {e}",
                        exe.display()
                    )),
                };
            }
        }
        let listed = Command::new(&exe).arg("--list").output();
        let n = match listed {
            Ok(o) => count_listed_tests(&String::from_utf8_lossy(&o.stdout)),
            Err(e) => {
                return ArmCheck {
                    command,
                    compiled: true,
                    binaries: vec![exe.clone()],
                    tests_listed: 0,
                    problem: Some(format!("could not list tests in {}: {e}", exe.display())),
                };
            }
        };
        if n == 0 {
            empty.push(name);
        }
        tests_listed += n;
        binaries.push(exe);
    }

    let problem = (tests_listed == 0).then(|| {
        format!(
            "compiles and builds {} binary/binaries ({}), and they contain ZERO tests — \
             the arm rescues nothing, which is the exact silence the gated-tests guard \
             believes it disproves",
            binaries.len(),
            empty.join(", ")
        )
    });

    ArmCheck {
        command,
        compiled: true,
        binaries,
        tests_listed,
        problem,
    }
}

/// Verify every declared arm of a repo.
pub fn verify_arms(repo_root: &Path, arms: &MatrixArms) -> ArmVerification {
    ArmVerification {
        checks: arms.arms.iter().map(|a| verify_arm(repo_root, a)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_args_mirror_the_rendered_command() {
        let arm = MatrixArm::features(["tls"])
            .package("nornir-flight")
            .test("tls_roundtrip");
        assert_eq!(
            arm_args(&arm),
            vec![
                "test",
                "-p",
                "nornir-flight",
                "--features",
                "tls",
                "--test",
                "tls_roundtrip"
            ]
        );
        // The display string and the argv must not be able to drift apart.
        assert_eq!(
            arm.command(),
            format!(
                "cargo {}",
                arm_args(&arm).join(" ").replacen("test ", "test ", 1)
            )
        );
    }

    #[test]
    fn all_features_wins_over_a_feature_list_in_both_renderings() {
        let mut arm = MatrixArm::features(["a", "b"]).package("p");
        arm.all_features = true;
        let args = arm_args(&arm);
        assert!(args.contains(&"--all-features".to_string()));
        assert!(!args.contains(&"--features".to_string()));
        assert!(arm.command().contains("--all-features"));
    }

    #[test]
    fn a_workspace_wide_arm_passes_no_package_flag() {
        let arm = MatrixArm::features(["scan", "warehouse"]);
        assert_eq!(arm_args(&arm), vec!["test", "--features", "scan,warehouse"]);
    }

    /// The artifact parser must pick test binaries and ONLY test binaries — a lib
    /// artifact has no `executable`, and a bin artifact has one but is not a test.
    #[test]
    fn only_test_artifacts_with_an_executable_are_collected() {
        let stream = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"nornir_flight","kind":["lib"]},"profile":{"test":false},"executable":null}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"nornir","kind":["bin"]},"profile":{"test":false},"executable":"/t/nornir"}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"tls_roundtrip","kind":["test"]},"profile":{"test":true},"executable":"/t/tls-abc"}"#,
            "\n",
            "   Compiling something v1.0\n",
            r#"{"reason":"build-finished","success":true}"#,
        );
        let got = test_artifacts(stream);
        assert_eq!(got.len(), 1, "got {got:?}");
        assert_eq!(got[0].0, "tls_roundtrip");
        assert_eq!(got[0].1, PathBuf::from("/t/tls-abc"));
    }

    /// An empty test binary — the thing a rescue arm exists to prevent — prints a
    /// summary line and nothing else, and exits 0. Counting the OUTPUT is what
    /// separates it from a real one; the exit code does not.
    #[test]
    fn an_empty_binarys_list_counts_zero_and_a_real_ones_does_not() {
        assert_eq!(count_listed_tests("\n0 tests, 0 benchmarks\n"), 0);
        assert_eq!(
            count_listed_tests(
                "tls::rejects_a_bad_token: test\ntls::accepts_bearer: test\n\n2 tests, 0 benchmarks\n"
            ),
            2
        );
        // Benchmarks are not tests and must not pad the count.
        assert_eq!(
            count_listed_tests("throughput: bench\n\n0 tests, 1 benchmark\n"),
            0
        );
    }

    /// `all_ok()` on a repo that declares nothing is TRUE, and that is the empty
    /// scan. Anyone asserting on it must also assert `declared()`.
    #[test]
    fn an_empty_verification_is_vacuously_ok_and_says_so_via_declared() {
        let v = ArmVerification::default();
        assert!(v.all_ok());
        assert_eq!(v.declared(), 0);
    }

    #[test]
    fn the_summary_names_every_broken_arm() {
        let v = ArmVerification {
            checks: vec![
                ArmCheck {
                    command: "cargo test -p a --features x".into(),
                    compiled: true,
                    binaries: vec![],
                    tests_listed: 3,
                    problem: None,
                },
                ArmCheck {
                    command: "cargo test -p b --features gone".into(),
                    compiled: false,
                    binaries: vec![],
                    tests_listed: 0,
                    problem: Some("does NOT COMPILE".into()),
                },
            ],
        };
        assert!(!v.all_ok());
        let s = v.summary();
        assert!(s.contains("cargo test -p b --features gone"), "{s}");
        assert!(s.contains("does NOT COMPILE"), "{s}");
        assert!(
            !s.contains("cargo test -p a --features x"),
            "the ok arm is not noise: {s}"
        );
    }
}
