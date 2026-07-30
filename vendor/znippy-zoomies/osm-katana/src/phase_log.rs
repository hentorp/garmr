//! Phase-grained structured logging.
//!
//! Every pipeline phase (pass1, sort_and_stree, pass2, and the outer
//! `convert`) opens a [`Phase`] guard via [`PhaseSink::phase`]. On drop the
//! guard emits a `done` JSONL line; while it lives a sampler thread emits
//! `progress` lines every [`PROGRESS_INTERVAL`]. Each line carries:
//!
//!   * `cpu_cores`   — average cores held over the interval, computed as the
//!     process CPU-seconds delta (utime+stime from `/proc/self/stat`, the
//!     shared [`read_self_cpu`] helper) over the wall-seconds delta.
//!   * `n_cores`     — the machine's core count (the `cpu_cores` denominator).
//!   * `busy_pct`    — REAL core occupancy: `cpu_cores / n_cores * 100`, i.e.
//!     the fraction of the whole box this phase held. Because the phase log is
//!     bracketed around each phase's window and the phases run sequentially,
//!     this attributes occupancy PER PHASE (pass1 vs sort_and_stree vs pass2)
//!     from one process-wide CPU counter — no per-thread accounting needed.
//!   * `collector_pct` — diagnostic: fraction of wall the single collector
//!     (sink) thread spent inside its `process()` body. A phase with low
//!     `busy_pct` but high `collector_pct` is collector-bound (workers starve
//!     while the collector stitches); `record_busy_ns` feeds it. 0 where no
//!     collector runs (sort_and_stree, the outer convert).
//!
//! Historically `busy_pct` was the collector fraction and read ~0 throughout
//! (the collector is near-idle in the balanced fast path), which told you
//! nothing about which phase drained the pool. It is now the real per-phase
//! occupancy; the old signal survives as `collector_pct`.
//!
//! All events are written to stderr unconditionally and, if a `--log`
//! path was given, appended as one JSON object per line to that file.
//! No serde dep — we hand-write the JSON to keep the module zero-cost
//! and zero-dep.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Cadence between `progress` events emitted by the sampler thread.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

/// Stop signal for a phase's sampler thread.
///
/// This used to be a bare `AtomicBool` that the sampler polled between 100 ms
/// sleeps. Closing a phase sets the flag and JOINS the sampler, so every phase
/// boundary paid up to a full 100 ms of dead time — with the whole worker pool
/// already idle, waiting for a sleeping logger. Four phases per convert
/// (pass1 → sort_and_stree → pass2 → the outer convert) meant up to 0.4 s of
/// pure stall attributed to the phases themselves, and on a small input that was
/// most of the wall clock (liechtenstein reported 0.5 s for ~0.1 s of work, every
/// phase a suspiciously exact multiple of 100 ms).
///
/// A condvar makes the stop take effect immediately: the sampler waits on the
/// timeout OR the signal, whichever comes first, so teardown is microseconds.
/// Purely a logging-path change — no output byte is touched.
struct StopFlag {
    stopped: Mutex<bool>,
    cv: Condvar,
}

impl StopFlag {
    fn new() -> Self {
        Self {
            stopped: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    /// Signal every waiter. Idempotent.
    fn stop(&self) {
        if let Ok(mut g) = self.stopped.lock() {
            *g = true;
        }
        self.cv.notify_all();
    }

    /// Block until `deadline` or until [`stop`] is called. Returns `true` if the
    /// phase was stopped (the caller should exit), `false` on timeout.
    fn wait_until(&self, deadline: Instant) -> bool {
        let Ok(mut g) = self.stopped.lock() else {
            return true;
        };
        loop {
            if *g {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let Ok((next, timeout)) = self.cv.wait_timeout(g, deadline - now) else {
                return true;
            };
            g = next;
            if timeout.timed_out() && !*g {
                return false;
            }
        }
    }
}

/// One per process. Cheap to clone (just an `Arc`).
#[derive(Clone)]
pub struct PhaseSink {
    inner: Arc<Inner>,
}

struct Inner {
    file: Option<Mutex<std::fs::File>>,
}

impl PhaseSink {
    /// `log_path = None` ⇒ stderr only. Otherwise events are also appended
    /// to that file as JSONL.
    pub fn new(log_path: Option<&Path>) -> std::io::Result<Self> {
        let file = match log_path {
            None => None,
            Some(p) => Some(Mutex::new(
                OpenOptions::new().create(true).append(true).open(p)?,
            )),
        };
        Ok(Self {
            inner: Arc::new(Inner { file }),
        })
    }

    /// Start a phase. Drop the returned guard (or call `done`) to emit
    /// the `done` event. Stash counters via [`Phase::counter`] and busy
    /// time via [`Phase::record_busy_ns`] before drop.
    pub fn phase(&self, name: &'static str, meta_kv: &[(&str, &str)]) -> Phase {
        Phase::start(self.clone(), name, meta_kv)
    }

    fn emit(&self, line: &str) {
        // stderr unconditionally
        eprintln!("{line}");
        if let Some(f) = &self.inner.file {
            if let Ok(mut f) = f.lock() {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }
    }
}

/// RAII phase guard. On drop emits the `done` event.
pub struct Phase {
    sink: PhaseSink,
    name: &'static str,
    start: Instant,
    cpu_start: (u64, u64),
    pub busy_ns: Arc<AtomicU64>,
    finished: bool,
    /// Signalled by `done`/Drop so the sampler wakes and exits at once.
    stop: Arc<StopFlag>,
    sampler: Option<std::thread::JoinHandle<()>>,
}

impl Phase {
    fn start(sink: PhaseSink, name: &'static str, meta_kv: &[(&str, &str)]) -> Self {
        let cpu_start = read_self_cpu();
        let mut line = String::with_capacity(256);
        line.push('{');
        write_iso_ts(&mut line);
        line.push_str(",\"phase\":\"");
        line.push_str(name);
        line.push_str("\",\"ev\":\"start\"");
        for &(k, v) in meta_kv {
            line.push_str(",\"");
            line.push_str(k);
            line.push_str("\":");
            write_jsval(&mut line, v);
        }
        line.push('}');
        sink.emit(&line);
        let busy_ns = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(StopFlag::new());
        let sampler = spawn_sampler(
            name,
            sink.clone(),
            cpu_start,
            Instant::now(),
            Arc::clone(&busy_ns),
            Arc::clone(&stop),
        );
        Self {
            sink,
            name,
            start: Instant::now(),
            cpu_start,
            busy_ns,
            finished: false,
            stop,
            sampler: Some(sampler),
        }
    }

    fn stop_sampler(&mut self) {
        self.stop.stop();
        if let Some(h) = self.sampler.take() {
            let _ = h.join();
        }
    }

    /// Add `delta` nanoseconds to the busy timer (time the sink thread
    /// spent inside its `process()` body).
    #[inline]
    pub fn record_busy_ns(&self, delta: u64) {
        self.busy_ns.fetch_add(delta, Ordering::Relaxed);
    }

    /// Emit `done`, marking the phase as cleanly closed. `extra_kv` is
    /// appended to the JSON object.
    pub fn done(mut self, extra_kv: &[(&str, String)]) {
        self.stop_sampler();
        self.finished = true;
        let line = self.build_done_line(extra_kv, /*abnormal=*/ false);
        self.sink.emit(&line);
    }

    fn build_done_line(&self, extra_kv: &[(&str, String)], abnormal: bool) -> String {
        let wall_s = self.start.elapsed().as_secs_f64();
        let cpu_end = read_self_cpu();
        let ticks = (cpu_end.0 + cpu_end.1).saturating_sub(self.cpu_start.0 + self.cpu_start.1);
        let cpu_secs = ticks as f64 / clk_tck();
        let cpu_cores = if wall_s > 0.0 { cpu_secs / wall_s } else { 0.0 };
        let ncores = n_cores();
        // REAL per-phase occupancy: process CPU-seconds/wall-seconds over this
        // phase's window, divided by core count. Attributes core occupancy to
        // THIS phase because the phases run sequentially over one process-wide
        // CPU counter.
        let busy_pct = occupancy_pct(cpu_cores, ncores);
        // Diagnostic: fraction of wall the collector thread spent in process().
        let busy_s = self.busy_ns.load(Ordering::Relaxed) as f64 / 1e9;
        let collector_pct = if wall_s > 0.0 {
            busy_s / wall_s * 100.0
        } else {
            0.0
        };

        let mut line = String::with_capacity(256);
        line.push('{');
        write_iso_ts(&mut line);
        line.push_str(",\"phase\":\"");
        line.push_str(self.name);
        line.push_str("\",\"ev\":\"done\"");
        write_kv_f(&mut line, "wall_s", wall_s, 3);
        write_kv_f(&mut line, "cpu_cores", cpu_cores, 2);
        write_kv_f(&mut line, "n_cores", ncores, 0);
        write_kv_f(&mut line, "busy_pct", busy_pct, 1);
        write_kv_f(&mut line, "collector_pct", collector_pct, 1);
        if abnormal {
            line.push_str(",\"abnormal\":true");
        }
        for (k, v) in extra_kv {
            line.push_str(",\"");
            line.push_str(k);
            line.push_str("\":");
            write_jsval(&mut line, v);
        }
        line.push('}');
        line
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        self.stop_sampler();
        if !self.finished {
            let line = self.build_done_line(&[], /*abnormal=*/ true);
            self.sink.emit(&line);
        }
    }
}

fn spawn_sampler(
    name: &'static str,
    sink: PhaseSink,
    cpu_start: (u64, u64),
    start: Instant,
    busy_ns: Arc<AtomicU64>,
    stop: Arc<StopFlag>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("phase-{name}"))
        .spawn(move || {
            // Per-interval delta: track cpu ticks and busy ns at the previous tick.
            let mut prev_ticks = cpu_start.0 + cpu_start.1;
            let mut prev_busy = busy_ns.load(Ordering::Relaxed);
            let mut prev_wall = start;
            // First sample at +PROGRESS_INTERVAL, never before — short phases
            // (e.g. stree build) finish before we emit anything, which is fine.
            let mut next = prev_wall + PROGRESS_INTERVAL;
            loop {
                // Wait for the next sample tick OR the stop signal, whichever
                // comes first. The condvar means closing the phase does not have
                // to wait out a sleep — the whole worker pool is idle at a phase
                // boundary, so a polled sleep there was pure dead core time.
                if stop.wait_until(next) {
                    return;
                }
                let cur_ticks = {
                    let (u, s) = read_self_cpu();
                    u + s
                };
                let cur_busy = busy_ns.load(Ordering::Relaxed);
                let cur_wall = Instant::now();
                let dwall = cur_wall.duration_since(prev_wall).as_secs_f64();
                let dticks = cur_ticks.saturating_sub(prev_ticks);
                let cpu_secs = dticks as f64 / clk_tck();
                let cpu_cores = if dwall > 0.0 { cpu_secs / dwall } else { 0.0 };
                let ncores = n_cores();
                // REAL interval occupancy (this phase, this 5 s window).
                let busy_pct = occupancy_pct(cpu_cores, ncores);
                let dbusy_s = (cur_busy.saturating_sub(prev_busy)) as f64 / 1e9;
                let collector_pct = if dwall > 0.0 {
                    dbusy_s / dwall * 100.0
                } else {
                    0.0
                };
                let wall_total = cur_wall.duration_since(start).as_secs_f64();

                let mut line = String::with_capacity(192);
                line.push('{');
                write_iso_ts(&mut line);
                line.push_str(",\"phase\":\"");
                line.push_str(name);
                line.push_str("\",\"ev\":\"progress\"");
                write_kv_f(&mut line, "wall_s", wall_total, 3);
                write_kv_f(&mut line, "cpu_cores", cpu_cores, 2);
                write_kv_f(&mut line, "n_cores", ncores, 0);
                write_kv_f(&mut line, "busy_pct", busy_pct, 1);
                write_kv_f(&mut line, "collector_pct", collector_pct, 1);
                line.push('}');
                sink.emit(&line);

                prev_ticks = cur_ticks;
                prev_busy = cur_busy;
                prev_wall = cur_wall;
                next += PROGRESS_INTERVAL;
            }
        })
        .expect("failed to spawn phase sampler thread")
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn read_self_cpu() -> (u64, u64) {
    // /proc/self/stat: field 14 = utime, field 15 = stime in clock ticks.
    // The comm field (2) is enclosed in `(...)` and may contain spaces — split
    // after the LAST `)` to be safe.
    let Ok(s) = std::fs::read_to_string("/proc/self/stat") else {
        return (0, 0);
    };
    let Some(close) = s.rfind(')') else {
        return (0, 0);
    };
    let rest = &s[close + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After the closing ')', proc(5) starts at field 3 (state) = index 0.
    // utime is field 14 = index 11, stime is field 15 = index 12.
    let utime = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (utime, stime)
}

#[inline]
fn clk_tck() -> f64 {
    // sysconf(_SC_CLK_TCK) — on every supported Linux this is 100. Hard-code
    // to avoid the libc dep and one extra syscall per `done` event.
    100.0
}

/// The machine's logical core count — the denominator for `busy_pct`. Queried
/// once and cached (the value can't change under us) so per-event work stays a
/// cheap atomic load, never a syscall.
fn n_cores() -> f64 {
    static N: OnceLock<f64> = OnceLock::new();
    *N.get_or_init(|| {
        std::thread::available_parallelism()
            .map(|n| n.get() as f64)
            .unwrap_or(1.0)
    })
}

/// REAL core occupancy as a percentage: average cores held over the interval,
/// normalised to the machine's core count. `cpu_cores` is process CPU-seconds
/// over wall-seconds; dividing by `n_cores` yields "fraction of the whole box"
/// so the number reads as a saturation % independent of how many cores exist.
/// Pure and total (guards a zero/absent core count) so it is unit-testable.
#[inline]
fn occupancy_pct(cpu_cores: f64, n_cores: f64) -> f64 {
    if n_cores > 0.0 {
        cpu_cores / n_cores * 100.0
    } else {
        0.0
    }
}

fn write_iso_ts(out: &mut String) {
    let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        out.push_str("\"ts\":0");
        return;
    };
    // Seconds-since-epoch with millisecond precision. Avoids chrono dep;
    // log consumers can convert if they want wall-clock.
    out.push_str("\"ts\":");
    let secs = d.as_secs();
    let ms = d.subsec_millis();
    out.push_str(&secs.to_string());
    out.push('.');
    if ms < 100 {
        out.push('0');
    }
    if ms < 10 {
        out.push('0');
    }
    out.push_str(&ms.to_string());
}

fn write_kv_f(out: &mut String, k: &str, v: f64, decimals: usize) {
    out.push_str(",\"");
    out.push_str(k);
    out.push_str("\":");
    out.push_str(&format!("{v:.decimals$}"));
}

/// Best-effort JSON value: integers and decimals are emitted bare; everything
/// else is JSON-stringified (with `"` and `\` escaped).
fn write_jsval(out: &mut String, v: &str) {
    if v.parse::<i64>().is_ok() || v.parse::<f64>().is_ok() {
        out.push_str(v);
        return;
    }
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ── busy_pct instrumentation tests ──────────────────────────────────────────────
#[cfg(test)]
mod busy_tests {
    use super::*;

    /// Pull a numeric field's value out of a JSONL line (e.g. `"busy_pct":4.2`).
    fn field(line: &str, key: &str) -> f64 {
        let pat = format!("\"{key}\":");
        let i = line
            .find(&pat)
            .unwrap_or_else(|| panic!("no {key} in {line}"))
            + pat.len();
        let rest = &line[i..];
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        rest[..end]
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("bad {key} in {line}"))
    }

    /// Pure occupancy formula: cpu_cores normalised to the core count, guarded.
    #[test]
    fn occupancy_pct_is_cpu_cores_over_ncores() {
        assert!(
            (occupancy_pct(8.0, 16.0) - 50.0).abs() < 1e-9,
            "8/16 cores = 50%"
        );
        assert!(
            (occupancy_pct(16.0, 16.0) - 100.0).abs() < 1e-9,
            "fully pegged = 100%"
        );
        assert_eq!(
            occupancy_pct(4.0, 0.0),
            0.0,
            "unknown core count ⇒ 0, never NaN/inf"
        );
        assert_eq!(occupancy_pct(0.0, 32.0), 0.0, "idle ⇒ 0");
    }

    /// L4 RED-when-broken: closing a phase must be IMMEDIATE, not "within one
    /// sampler poll". The sampler used to sleep in 100 ms slices and only then
    /// notice the stop flag, so `done()` — which joins it before reading the
    /// clock — charged every phase boundary up to 100 ms of dead time while the
    /// whole worker pool sat idle. Four phases per convert made that up to 0.4 s.
    ///
    /// Ten back-to-back trivial phases must therefore cost far less than ten poll
    /// intervals; reverting to the polled `AtomicBool` turns this red instantly
    /// (it would take ~1 s). The wall_s the phase REPORTS must be tiny too, since
    /// the stall used to land inside the measurement it published.
    /// A stop that arrives while the sampler is parked must take effect AT ONCE,
    /// however far away the next sample tick is. This is the whole fix: the
    /// polled `AtomicBool` could only notice the flag after its current
    /// `sleep(100 ms)` returned, and `done()` joins the sampler *before* reading
    /// the clock — so the stall landed inside the phase's own published wall_s
    /// and inside the convert's critical path, four times per run, with every
    /// worker already idle. RED-when-broken structurally: reverting to a polled
    /// flag deletes `StopFlag` and this test stops compiling.
    ///
    /// Deterministic (no thread, no load sensitivity): a deadline an hour out
    /// must still return immediately once the flag is set.
    #[test]
    fn stop_flag_short_circuits_however_far_the_deadline() {
        let f = StopFlag::new();
        f.stop();
        let t0 = Instant::now();
        let stopped = f.wait_until(Instant::now() + Duration::from_secs(3600));
        let el = t0.elapsed();
        assert!(stopped, "wait_until must report the stop");
        assert!(
            el < Duration::from_millis(50),
            "a stopped flag must not wait for its deadline, took {el:?}"
        );
        // Idempotent: a second stop and a second wait behave the same.
        f.stop();
        assert!(f.wait_until(Instant::now() + Duration::from_secs(3600)));
    }

    /// The other half of the contract: with no stop, `wait_until` must actually
    /// wait for the deadline and report a timeout — otherwise the sampler would
    /// spin and the `progress` cadence would be meaningless.
    #[test]
    fn stop_flag_times_out_when_not_stopped() {
        let f = StopFlag::new();
        let t0 = Instant::now();
        let stopped = f.wait_until(Instant::now() + Duration::from_millis(30));
        let el = t0.elapsed();
        assert!(
            !stopped,
            "an un-stopped flag must report a timeout, not a stop"
        );
        assert!(
            el >= Duration::from_millis(25),
            "must have actually waited, took {el:?}"
        );
    }

    /// End-to-end: a phase that is opened, held briefly and closed must REPORT a
    /// wall close to what it was held for. With the polled sampler this read
    /// ~100 ms regardless (on liechtenstein every phase reported a suspiciously
    /// exact multiple of 100 ms, and `convert` read 0.5 s for ~0.2 s of work).
    /// The ceiling is loose on purpose — the suite runs 50 tests across the box —
    /// but a reinstated 100 ms-granularity stall still trips it.
    #[test]
    fn a_short_phase_reports_a_short_wall() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("phase.jsonl");
        let sink = PhaseSink::new(Some(&log)).unwrap();
        for _ in 0..3 {
            let ph = sink.phase("t_teardown", &[]);
            std::thread::sleep(Duration::from_millis(5));
            ph.done(&[]);
        }
        let text = std::fs::read_to_string(&log).unwrap();
        let walls: Vec<f64> = text
            .lines()
            .filter(|l| l.contains("\"ev\":\"done\""))
            .map(|l| field(l, "wall_s"))
            .collect();
        assert_eq!(walls.len(), 3, "every phase must emit a done line");
        let best = walls.iter().cloned().fold(f64::INFINITY, f64::min);
        assert!(
            best < 0.09,
            "a 5 ms phase must be able to report ~5 ms; best of 3 was {best}s — the sampler \
             teardown is being charged to the phase"
        );
    }

    /// L4 RED-when-broken: a phase that burns REAL single-threaded CPU must emit
    /// a `done` line whose `busy_pct` is > 0 and plausible (≤ 100). This fails if
    /// `busy_pct` regresses to the old collector-`busy_ns` formula — no collector
    /// runs in this test, so that path emits 0. `cpu_cores` must likewise be
    /// non-zero (≈ 1 core held), while `collector_pct` stays 0 (no sink thread).
    #[test]
    fn busy_pct_reflects_real_cpu_occupancy() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("phase.jsonl");
        let sink = PhaseSink::new(Some(&log)).unwrap();

        let ph = sink.phase("t_cpu_burn", &[]);
        // Burn ~300 ms of single-threaded CPU so /proc/self/stat accrues ticks.
        let t0 = Instant::now();
        let mut acc: u64 = 0;
        while t0.elapsed() < Duration::from_millis(300) {
            for _ in 0..4096 {
                acc = acc.wrapping_mul(6364136223846793005).wrapping_add(1);
            }
        }
        std::hint::black_box(acc);
        ph.done(&[]);

        let text = std::fs::read_to_string(&log).unwrap();
        let done = text
            .lines()
            .find(|l| l.contains("\"ev\":\"done\""))
            .unwrap_or_else(|| panic!("no done line in:\n{text}"));

        let busy = field(done, "busy_pct");
        let cores = field(done, "cpu_cores");
        let ncores = field(done, "n_cores");
        // Magnitude is environment-dependent (scheduler contention on a shared
        // box can hold this well under one core); only require it registered.
        assert!(
            cores > 0.0,
            "burning CPU must register non-zero cpu_cores, got {cores}: {done}"
        );
        assert!(
            ncores >= 1.0,
            "n_cores must be populated, got {ncores}: {done}"
        );
        // THE gate: busy_pct is now real proc-CPU occupancy, not the collector
        // fraction (which is 0 here — no sink thread). Regressing the formula
        // turns this RED.
        assert!(
            busy > 0.0,
            "busy_pct must be > 0 after real CPU work, got {busy}: {done}"
        );
        assert!(
            busy <= 105.0,
            "busy_pct must be a plausible %, got {busy}: {done}"
        );
        // busy_pct is exactly cpu_cores normalised to the core count.
        let expected = occupancy_pct(cores, ncores);
        assert!(
            (busy - expected).abs() < 0.15,
            "busy_pct {busy} ≠ cpu_cores/n_cores {expected}"
        );
    }
}
