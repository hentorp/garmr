//! Pure-Rust torrent fetch of the OSM planet `.osm.bz2` fixture (dev-only).
//!
//! Gated behind the `planet-fixture` feature (alias `dev`) so the default and
//! published builds pull neither [`librqbit`] nor `tokio`. The download is
//! strictly opt-in: nothing here runs unless someone calls [`ensure_planet_osm`]
//! (or runs the `planet_bench` binary) in a build that enabled the feature.
//!
//! The fixture LAW of this repo: bench inputs live under `~/.cache` or `/home`,
//! NEVER on the (near-full) T9 drive. [`planet_cache_path`] enforces that.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;

/// Official OSM planet torrent (fetched over HTTPS by librqbit if no local
/// `.torrent`/magnet source is found).
const PLANET_TORRENT_URL: &str =
    "https://planet.openstreetmap.org/planet/planet-latest.osm.bz2.torrent";

/// A pre-fetched `.torrent` the user already keeps in their downloads dir.
/// Used automatically when present so no network round-trip to OSM is needed.
const LOCAL_TORRENT_REL: &str = "Hämtningar/planet-260427.osm.bz2.torrent";

/// Minimum plausible size of a fully-downloaded planet bz2. The real file is
/// ~80 GiB; anything above 1 GiB at the cache path is treated as "already have
/// it" so we never re-download (and the unit test can fake it with a sparse
/// file via `set_len`).
const MIN_PLANET_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Resolve the home directory without pulling an extra crate.
fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .context("HOME is not set; cannot locate the fixture cache directory")
}

/// Path of the cached planet `.osm.bz2`.
///
/// `~/.cache/osm-katana/planet-latest.osm.bz2` by default; override the whole
/// path with the `OSM_KATANA_PLANET` env var. The result is guaranteed to live
/// under `~/.cache` / `/home` and never on T9 — see the unit test.
pub fn planet_cache_path() -> PathBuf {
    if let Some(p) = std::env::var_os("OSM_KATANA_PLANET") {
        return PathBuf::from(p);
    }
    // Best-effort: if HOME is somehow unset, fall back to a relative .cache so
    // the path is still off T9 (callers that actually download go through
    // ensure_planet_osm, which surfaces a real error on a missing HOME).
    let base = home_dir().unwrap_or_else(|_| PathBuf::from("."));
    base.join(".cache")
        .join("osm-katana")
        .join("planet-latest.osm.bz2")
}

/// How the torrent should be added, resolved by priority (see
/// [`ensure_planet_osm`]).
enum TorrentSource {
    /// A local `.torrent` file whose bytes we read and add from buffer.
    LocalFile(PathBuf),
    /// A magnet link or remote `.torrent` URL librqbit fetches itself.
    Url(String),
}

/// Resolve the torrent source by priority:
/// 1. `OSM_KATANA_PLANET_TORRENT` — a local `.torrent` path or a magnet string;
/// 2. `~/Hämtningar/planet-260427.osm.bz2.torrent` if it exists (user already
///    has it);
/// 3. the official OSM planet torrent URL.
fn resolve_torrent_source() -> TorrentSource {
    if let Some(v) = std::env::var_os("OSM_KATANA_PLANET_TORRENT") {
        let s = v.to_string_lossy().into_owned();
        if s.starts_with("magnet:") {
            return TorrentSource::Url(s);
        }
        let p = PathBuf::from(&s);
        if p.exists() {
            return TorrentSource::LocalFile(p);
        }
        // A path that doesn't exist or some other URL form: hand it to librqbit
        // as a URL and let it produce a clear error.
        return TorrentSource::Url(s);
    }
    if let Ok(home) = home_dir() {
        let local = home.join(LOCAL_TORRENT_REL);
        if local.exists() {
            return TorrentSource::LocalFile(local);
        }
    }
    TorrentSource::Url(PLANET_TORRENT_URL.to_string())
}

/// Ensure the planet `.osm.bz2` fixture is present locally, torrent-downloading
/// it (pure Rust, via [`librqbit`]) if needed, and return its path.
///
/// * If [`planet_cache_path`] already holds a file larger than 1 GiB, it is
///   returned immediately with **no network access**.
/// * Otherwise the torrent is downloaded into the cache directory, this call
///   **blocks until the download completes**, and the finished file is returned.
///
/// A tokio runtime is built internally so callers (e.g. the bencher) can invoke
/// this synchronously.
pub fn ensure_planet_osm() -> anyhow::Result<PathBuf> {
    let cache_path = planet_cache_path();

    if let Ok(meta) = std::fs::metadata(&cache_path) {
        if meta.is_file() && meta.len() >= MIN_PLANET_BYTES {
            eprintln!(
                "osm-katana fixture: using cached planet at {} ({:.1} GiB), no download",
                cache_path.display(),
                meta.len() as f64 / (1024.0 * 1024.0 * 1024.0)
            );
            return Ok(cache_path);
        }
    }

    let cache_dir = cache_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating fixture cache dir {}", cache_dir.display()))?;

    let source = resolve_torrent_source();
    let rt = tokio::runtime::Runtime::new().context("building tokio runtime for torrent fetch")?;
    let downloaded = rt
        .block_on(download_planet(&cache_dir, source))
        .context("torrent download of OSM planet failed")?;

    if downloaded != cache_path {
        std::fs::rename(&downloaded, &cache_path).with_context(|| {
            format!(
                "moving downloaded planet {} -> {}",
                downloaded.display(),
                cache_path.display()
            )
        })?;
    }
    Ok(cache_path)
}

/// Async core: add the torrent to a librqbit session pointed at `cache_dir`,
/// wait until complete while reporting progress, and return the absolute path
/// of the downloaded `.osm.bz2` file inside `cache_dir`.
async fn download_planet(cache_dir: &Path, source: TorrentSource) -> anyhow::Result<PathBuf> {
    use librqbit::{AddTorrent, AddTorrentOptions, Session};

    // Session downloads land directly under cache_dir (its default output dir).
    let session = Session::new(cache_dir.to_path_buf())
        .await
        .context("creating librqbit session")?;

    let add = match &source {
        TorrentSource::LocalFile(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading local .torrent file {}", path.display()))?;
            eprintln!("osm-katana fixture: adding torrent from {}", path.display());
            AddTorrent::from_bytes(bytes)
        }
        TorrentSource::Url(url) => {
            eprintln!("osm-katana fixture: adding torrent from {url}");
            AddTorrent::from_url(url.as_str())
        }
    };

    let opts = AddTorrentOptions {
        // Allow resuming on top of a partially-downloaded file in the cache dir.
        overwrite: true,
        ..Default::default()
    };

    let handle = session
        .add_torrent(add, Some(opts))
        .await
        .context("adding torrent to session")?
        .into_handle()
        .context("torrent was list-only; no download handle")?;

    // Resolve metadata so we know the on-disk filename, then drive a progress
    // bar until completion.
    handle
        .wait_until_initialized()
        .await
        .context("waiting for torrent metadata")?;

    let rel_name: PathBuf = handle
        .with_metadata(|m| m.file_infos.first().map(|fi| fi.relative_filename.clone()))
        .context("reading torrent metadata")?
        .context("torrent has no files")?;

    let bar = {
        let total = handle.stats().total_bytes;
        let b = indicatif::ProgressBar::new(total);
        b.set_style(
            indicatif::ProgressStyle::with_template(
                "{spinner} planet {bytes}/{total_bytes} ({percent}%) {binary_bytes_per_sec} eta {eta} {msg}",
            )
            .unwrap_or_else(|_| indicatif::ProgressStyle::default_bar()),
        );
        b
    };

    let completed = handle.wait_until_completed();
    tokio::pin!(completed);
    loop {
        tokio::select! {
            res = &mut completed => {
                res.context("torrent download did not complete")?;
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                let stats = handle.stats();
                bar.set_length(stats.total_bytes);
                bar.set_position(stats.progress_bytes);
                if let Some(live) = stats.live.as_ref() {
                    bar.set_message(format!("{}", live.download_speed));
                }
                if let Some(err) = stats.error.as_ref() {
                    anyhow::bail!("torrent error: {err}");
                }
            }
        }
    }
    bar.finish_and_clear();

    let downloaded = cache_dir.join(&rel_name);
    anyhow::ensure!(
        downloaded.exists(),
        "torrent reported complete but {} is missing",
        downloaded.display()
    );
    Ok(downloaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cache path LAW: under `.cache` / home, and NEVER on T9.
    #[test]
    fn cache_path_is_off_t9() {
        let p = planet_cache_path();
        let s = p.to_string_lossy();
        assert!(
            !s.contains("/T9"),
            "fixture cache path must never be on T9, got {s}"
        );
        assert!(
            s.contains(".cache") || s.contains("/home"),
            "fixture cache path must be under .cache or /home, got {s}"
        );
    }

    /// A >1 GiB file already at the cache path short-circuits with no download.
    #[test]
    fn ensure_returns_cached_without_download() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("planet-latest.osm.bz2");
        // Fake a >1 GiB file cheaply via a sparse allocation.
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MIN_PLANET_BYTES + 1).unwrap();
        drop(f);

        // Point the resolver at our dummy via the documented override.
        // SAFETY: single-threaded test; we restore/remove the var right after.
        unsafe {
            std::env::set_var("OSM_KATANA_PLANET", &path);
        }
        let got = ensure_planet_osm();
        unsafe {
            std::env::remove_var("OSM_KATANA_PLANET");
        }

        let got = got.expect("cached path should be returned without downloading");
        assert_eq!(got, path);
        // dir (and the sparse file) are cleaned up when `dir` drops.
    }
}
