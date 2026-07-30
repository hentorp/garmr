//! Integration tests: extract 20 real Maven JARs (which are ZIP files) and verify
//! output against the `zip` crate reference implementation.
//!
//! JARs are cached in `$LZIP_TEST_ZIPS` (default: `~/work/test-zips/`).
//! If missing, tests download from Maven Central on first run.
//!
//! Run:  cargo test --test maven_artifacts -- --nocapture
//! Skip: set `LZIP_SKIP_MAVEN_TESTS=1` to skip when offline.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Where to cache downloaded test ZIPs.
fn zip_cache_dir() -> PathBuf {
    if let Ok(d) = std::env::var("LZIP_TEST_ZIPS") {
        return PathBuf::from(d);
    }
    dirs_or_home().join("work/test-zips")
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Maven Central base URL.
const MAVEN_BASE: &str = "https://repo1.maven.org/maven2";

struct TestJar {
    filename: &'static str,
    maven_path: &'static str,
    group: &'static str,
}

const TEST_JARS: &[TestJar] = &[
    // Group 1: Many Small Files
    TestJar {
        filename: "commons-lang3-3.14.0.jar",
        maven_path: "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
        group: "many-small",
    },
    TestJar {
        filename: "guava-33.2.1-jre.jar",
        maven_path: "com/google/guava/guava/33.2.1-jre/guava-33.2.1-jre.jar",
        group: "many-small",
    },
    TestJar {
        filename: "commons-collections4-4.4.jar",
        maven_path: "org/apache/commons/commons-collections4/4.4/commons-collections4-4.4.jar",
        group: "many-small",
    },
    TestJar {
        filename: "slf4j-api-2.0.13.jar",
        maven_path: "org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar",
        group: "many-small",
    },
    TestJar {
        filename: "validation-api-2.0.1.Final.jar",
        maven_path: "javax/validation/validation-api/2.0.1.Final/validation-api-2.0.1.Final.jar",
        group: "many-small",
    },
    TestJar {
        filename: "commons-text-1.12.0.jar",
        maven_path: "org/apache/commons/commons-text/1.12.0/commons-text-1.12.0.jar",
        group: "many-small",
    },
    TestJar {
        filename: "jackson-databind-2.17.1.jar",
        maven_path: "com/fasterxml/jackson/core/jackson-databind/2.17.1/jackson-databind-2.17.1.jar",
        group: "many-small",
    },
    // Group 2: Few Files
    TestJar {
        filename: "json-20240303.jar",
        maven_path: "org/json/json/20240303/json-20240303.jar",
        group: "few-files",
    },
    TestJar {
        filename: "commons-io-2.16.1.jar",
        maven_path: "commons-io/commons-io/2.16.1/commons-io-2.16.1.jar",
        group: "few-files",
    },
    TestJar {
        filename: "gson-2.11.0.jar",
        maven_path: "com/google/code/gson/gson/2.11.0/gson-2.11.0.jar",
        group: "few-files",
    },
    TestJar {
        filename: "joda-time-2.12.7.jar",
        maven_path: "joda-time/joda-time/2.12.7/joda-time-2.12.7.jar",
        group: "few-files",
    },
    TestJar {
        filename: "snakeyaml-2.2.jar",
        maven_path: "org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar",
        group: "few-files",
    },
    TestJar {
        filename: "commons-codec-1.17.0.jar",
        maven_path: "commons-codec/commons-codec/1.17.0/commons-codec-1.17.0.jar",
        group: "few-files",
    },
    TestJar {
        filename: "httpclient-4.5.14.jar",
        maven_path: "org/apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.jar",
        group: "few-files",
    },
    // Group 3: Large JARs
    TestJar {
        filename: "poi-ooxml-5.2.5.jar",
        maven_path: "org/apache/poi/poi-ooxml/5.2.5/poi-ooxml-5.2.5.jar",
        group: "large",
    },
    TestJar {
        filename: "android-4.1.1.4.jar",
        maven_path: "com/google/android/android/4.1.1.4/android-4.1.1.4.jar",
        group: "large",
    },
    TestJar {
        filename: "spark-core_2.13-3.5.1.jar",
        maven_path: "org/apache/spark/spark-core_2.13/3.5.1/spark-core_2.13-3.5.1.jar",
        group: "large",
    },
    TestJar {
        filename: "lwjgl-3.3.3.jar",
        maven_path: "org/lwjgl/lwjgl/3.3.3/lwjgl-3.3.3.jar",
        group: "large",
    },
    TestJar {
        filename: "ecj-3.37.0.jar",
        maven_path: "org/eclipse/jdt/ecj/3.37.0/ecj-3.37.0.jar",
        group: "large",
    },
    TestJar {
        filename: "netty-all-4.1.110.Final.jar",
        maven_path: "io/netty/netty-all/4.1.110.Final/netty-all-4.1.110.Final.jar",
        group: "large",
    },
    // Group 4: Extra-Large JARs (stress parallel decompression)
    TestJar {
        filename: "scala-library-2.13.14.jar",
        maven_path: "org/scala-lang/scala-library/2.13.14/scala-library-2.13.14.jar",
        group: "xlarge",
    },
    TestJar {
        filename: "kotlin-stdlib-2.0.0.jar",
        maven_path: "org/jetbrains/kotlin/kotlin-stdlib/2.0.0/kotlin-stdlib-2.0.0.jar",
        group: "xlarge",
    },
    TestJar {
        filename: "groovy-4.0.22.jar",
        maven_path: "org/apache/groovy/groovy/4.0.22/groovy-4.0.22.jar",
        group: "xlarge",
    },
    TestJar {
        filename: "spring-core-6.1.10.jar",
        maven_path: "org/springframework/spring-core/6.1.10/spring-core-6.1.10.jar",
        group: "xlarge",
    },
    TestJar {
        filename: "icu4j-75.1.jar",
        maven_path: "com/ibm/icu/icu4j/75.1/icu4j-75.1.jar",
        group: "xlarge",
    },
    TestJar {
        filename: "xalan-2.7.3.jar",
        maven_path: "xalan/xalan/2.7.3/xalan-2.7.3.jar",
        group: "xlarge",
    },
];

/// Ensure a JAR is cached locally; download from Maven Central if missing.
fn ensure_jar(jar: &TestJar) -> PathBuf {
    let dir = zip_cache_dir();
    fs::create_dir_all(&dir).expect("create cache dir");
    let path = dir.join(jar.filename);
    if path.exists() {
        return path;
    }
    let url = format!("{}/{}", MAVEN_BASE, jar.maven_path);
    eprintln!("  downloading {} ...", jar.filename);
    let output = std::process::Command::new("curl")
        .args(["-sSfL", "-o"])
        .arg(&path)
        .arg(&url)
        .output()
        .expect("curl must be available");
    assert!(
        output.status.success(),
        "failed to download {}: {}",
        jar.filename,
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

/// Build a reference map { entry_name → decompressed_bytes } using the `zip` crate.
fn reference_entries(path: &Path) -> HashMap<String, Vec<u8>> {
    let file = fs::File::open(path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut map = HashMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        map.insert(name, data);
    }
    map
}

/// Extract with lzip and build the same map.
fn lzip_entries(path: &Path) -> HashMap<String, Vec<u8>> {
    let file = fs::File::open(path).unwrap();
    let entries = lzip_parallel::decompress_zip_stream(file).unwrap();
    entries.into_iter().map(|e| (e.name, e.data)).collect()
}

/// Core verification: compare lzip output against zip crate reference.
/// Returns (entry_count, elapsed_secs) for timing.
fn verify_jar(jar: &TestJar) -> (usize, f64) {
    if std::env::var("LZIP_SKIP_MAVEN_TESTS").is_ok() {
        eprintln!("  SKIPPED (LZIP_SKIP_MAVEN_TESTS set)");
        return (0, 0.0);
    }
    let path = ensure_jar(jar);
    let file_size = fs::metadata(&path).unwrap().len();

    let reference = reference_entries(&path);

    let t0 = std::time::Instant::now();
    let result = lzip_entries(&path);
    let elapsed = t0.elapsed().as_secs_f64();

    assert_eq!(
        reference.len(),
        result.len(),
        "{}: entry count mismatch (zip={}, lzip={})",
        jar.filename,
        reference.len(),
        result.len()
    );

    let mut total_bytes: usize = 0;
    for (name, expected) in &reference {
        let got = result
            .get(name)
            .unwrap_or_else(|| panic!("{}: missing entry '{}'", jar.filename, name));
        assert_eq!(
            got.len(),
            expected.len(),
            "{}: size mismatch for '{}' (expected {}, got {})",
            jar.filename,
            name,
            expected.len(),
            got.len()
        );
        assert_eq!(
            got, expected,
            "{}: content mismatch for '{}'",
            jar.filename, name
        );
        total_bytes += got.len();
    }
    let mb_out = total_bytes as f64 / (1024.0 * 1024.0);
    let throughput = if elapsed > 0.0 { mb_out / elapsed } else { 0.0 };
    eprintln!(
        "  ✓ {} — {} entries, {:.1} KB jar, {:.1} MB decompressed, {:.1} ms, {:.0} MB/s",
        jar.filename,
        reference.len(),
        file_size as f64 / 1024.0,
        mb_out,
        elapsed * 1000.0,
        throughput,
    );
    (reference.len(), elapsed)
}

// ── Group 1: Many Small Files ───────────────────────────────────────────────

#[test]
fn maven_commons_lang3() {
    verify_jar(&TEST_JARS[0]);
}
#[test]
fn maven_guava() {
    verify_jar(&TEST_JARS[1]);
}
#[test]
fn maven_commons_collections4() {
    verify_jar(&TEST_JARS[2]);
}
#[test]
fn maven_slf4j_api() {
    verify_jar(&TEST_JARS[3]);
}
#[test]
fn maven_validation_api() {
    verify_jar(&TEST_JARS[4]);
}
#[test]
fn maven_commons_text() {
    verify_jar(&TEST_JARS[5]);
}
#[test]
fn maven_jackson_databind() {
    verify_jar(&TEST_JARS[6]);
}

// ── Group 2: Few Files ──────────────────────────────────────────────────────

#[test]
fn maven_json() {
    verify_jar(&TEST_JARS[7]);
}
#[test]
fn maven_commons_io() {
    verify_jar(&TEST_JARS[8]);
}
#[test]
fn maven_gson() {
    verify_jar(&TEST_JARS[9]);
}
#[test]
fn maven_joda_time() {
    verify_jar(&TEST_JARS[10]);
}
#[test]
fn maven_snakeyaml() {
    verify_jar(&TEST_JARS[11]);
}
#[test]
fn maven_commons_codec() {
    verify_jar(&TEST_JARS[12]);
}
#[test]
fn maven_httpclient() {
    verify_jar(&TEST_JARS[13]);
}

// ── Group 3: Large JARs ─────────────────────────────────────────────────────

#[test]
fn maven_poi_ooxml() {
    verify_jar(&TEST_JARS[14]);
}
#[test]
fn maven_android() {
    verify_jar(&TEST_JARS[15]);
}
#[test]
fn maven_spark_core() {
    verify_jar(&TEST_JARS[16]);
}
#[test]
fn maven_lwjgl() {
    verify_jar(&TEST_JARS[17]);
}
#[test]
fn maven_ecj() {
    verify_jar(&TEST_JARS[18]);
}
#[test]
fn maven_netty_all() {
    verify_jar(&TEST_JARS[19]);
}

// ── Group 4: Extra-Large JARs ───────────────────────────────────────────────

#[test]
fn maven_scala_library() {
    verify_jar(&TEST_JARS[20]);
}
#[test]
fn maven_kotlin_stdlib() {
    verify_jar(&TEST_JARS[21]);
}
#[test]
fn maven_groovy() {
    verify_jar(&TEST_JARS[22]);
}
#[test]
fn maven_spring_core() {
    verify_jar(&TEST_JARS[23]);
}
#[test]
fn maven_icu4j() {
    verify_jar(&TEST_JARS[24]);
}
#[test]
fn maven_xalan() {
    verify_jar(&TEST_JARS[25]);
}

// ── CLI binary test ─────────────────────────────────────────────────────────

/// Test the lzip binary end-to-end on a representative JAR.
#[test]
fn maven_cli_extract_guava() {
    if std::env::var("LZIP_SKIP_MAVEN_TESTS").is_ok() {
        return;
    }
    let jar_path = ensure_jar(&TEST_JARS[1]); // guava
    let out_dir = tempfile::tempdir().expect("create tempdir");

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_lzip"))
        .arg(&jar_path)
        .arg(out_dir.path())
        .status()
        .expect("run lzip binary");
    assert!(status.success(), "lzip binary failed");

    // Verify a sample of files against the zip crate.
    let reference = reference_entries(&jar_path);
    let mut checked = 0;
    for (name, expected) in &reference {
        let file_path = out_dir.path().join(name);
        assert!(file_path.exists(), "missing extracted file: {name}");
        let got = fs::read(&file_path).unwrap();
        assert_eq!(got, *expected, "cli extract content mismatch for '{name}'");
        checked += 1;
    }
    eprintln!("  ✓ CLI extract guava — {checked} entries verified");
}

// ── Timing summary ──────────────────────────────────────────────────────────

/// Runs all JARs and prints a timing summary table with unzip comparison.
/// Run with:  cargo test --test maven_artifacts maven_timing_summary -- --nocapture --ignored
#[test]
fn maven_timing_summary() {
    if std::env::var("LZIP_SKIP_MAVEN_TESTS").is_ok() {
        eprintln!("SKIPPED (LZIP_SKIP_MAVEN_TESTS set)");
        return;
    }

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let physical = physical_cores_linux().unwrap_or(cores);

    eprintln!();
    eprintln!(
        "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════"
    );
    eprintln!(
        "  lzip Maven artifact timing — {} logical cores, {} physical cores",
        cores, physical
    );
    eprintln!(
        "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════"
    );
    eprintln!(
        "  {:40} {:>6} {:>8} {:>10} {:>9} {:>9} {:>9} {:>7}",
        "JAR", "Group", "Entries", "JAR size", "lzip", "unzip", "MB/s", "speedup"
    );
    eprintln!("  {}", "─".repeat(104));

    let mut total_entries = 0usize;
    let mut total_lzip_time = 0.0f64;
    let mut total_unzip_time = 0.0f64;
    let mut total_decompressed = 0u64;

    let mut failures: Vec<String> = Vec::new();

    for jar in TEST_JARS {
        let path = ensure_jar(jar);
        let file_size = fs::metadata(&path).unwrap().len();
        let reference = reference_entries(&path);

        // Benchmark lzip
        let t0 = std::time::Instant::now();
        let result = lzip_entries(&path);
        let lzip_elapsed = t0.elapsed().as_secs_f64();

        let mut decomp_bytes = 0u64;
        let mut mismatches = 0usize;
        if reference.len() != result.len() {
            failures.push(format!(
                "{}: entry count mismatch (zip={}, lzip={})",
                jar.filename,
                reference.len(),
                result.len()
            ));
        }
        for (name, expected) in &reference {
            if let Some(got) = result.get(name) {
                if got != expected {
                    mismatches += 1;
                }
                decomp_bytes += got.len() as u64;
            } else {
                mismatches += 1;
                decomp_bytes += expected.len() as u64;
            }
        }
        if mismatches > 0 {
            failures.push(format!(
                "{}: {} entries with content mismatch",
                jar.filename, mismatches
            ));
        }

        // Benchmark unzip (extract to /dev/null via tmpdir)
        let unzip_elapsed = bench_unzip(&path);

        let mb_out = decomp_bytes as f64 / (1024.0 * 1024.0);
        let throughput = if lzip_elapsed > 0.0 {
            mb_out / lzip_elapsed
        } else {
            0.0
        };
        let speedup = if lzip_elapsed > 0.0 {
            unzip_elapsed / lzip_elapsed
        } else {
            0.0
        };

        let marker = if mismatches > 0 { " ✗" } else { "" };
        eprintln!(
            "  {:40} {:>6} {:>8} {:>10} {:>8.1}ms {:>8.1}ms {:>8.0} {:>6.2}x{}",
            jar.filename,
            jar.group,
            reference.len(),
            format_size(file_size),
            lzip_elapsed * 1000.0,
            unzip_elapsed * 1000.0,
            throughput,
            speedup,
            marker,
        );

        total_entries += reference.len();
        total_lzip_time += lzip_elapsed;
        total_unzip_time += unzip_elapsed;
        total_decompressed += decomp_bytes;
    }

    let total_mb = total_decompressed as f64 / (1024.0 * 1024.0);
    let total_speedup = if total_lzip_time > 0.0 {
        total_unzip_time / total_lzip_time
    } else {
        0.0
    };
    eprintln!("  {}", "─".repeat(104));
    eprintln!(
        "  {:40} {:>6} {:>8} {:>10} {:>8.1}ms {:>8.1}ms {:>8.0} {:>6.2}x",
        "TOTAL",
        "",
        total_entries,
        format_size(total_decompressed),
        total_lzip_time * 1000.0,
        total_unzip_time * 1000.0,
        if total_lzip_time > 0.0 {
            total_mb / total_lzip_time
        } else {
            0.0
        },
        total_speedup,
    );
    eprintln!(
        "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════"
    );

    if !failures.is_empty() {
        eprintln!();
        eprintln!("  ⚠ CORRECTNESS FAILURES ({}):", failures.len());
        for f in &failures {
            eprintln!("    • {}", f);
        }
        eprintln!();
        panic!("{} correctness failures detected", failures.len());
    }
}

/// Benchmark `unzip` by extracting to a tmpdir and measuring wall-clock time.
fn bench_unzip(jar_path: &Path) -> f64 {
    let tmp = tempfile::tempdir().expect("create tmpdir for unzip bench");
    let t0 = std::time::Instant::now();
    let status = std::process::Command::new("unzip")
        .args(["-q", "-o"])
        .arg(jar_path.as_os_str())
        .arg("-d")
        .arg(tmp.path().as_os_str())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("unzip must be available");
    let elapsed = t0.elapsed().as_secs_f64();
    assert!(status.success(), "unzip failed for {:?}", jar_path);
    elapsed
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Detect physical cores on Linux via sysfs.
fn physical_cores_linux() -> Option<usize> {
    use std::collections::HashSet;
    let mut ids = HashSet::new();
    for entry in fs::read_dir("/sys/devices/system/cpu").ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name = name.to_str()?;
        if !name.starts_with("cpu") || !name[3..].chars().next()?.is_ascii_digit() {
            continue;
        }
        let base = entry.path().join("topology");
        let pkg = fs::read_to_string(base.join("physical_package_id"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
        if let Ok(s) = fs::read_to_string(base.join("core_id")) {
            if let Ok(core) = s.trim().parse::<u32>() {
                ids.insert((pkg, core));
            }
        }
    }
    Some(ids.len()).filter(|&n| n > 0)
}

// ── Additional JARs for batch benchmark (fills 200MB buffer) ────────────────

const BATCH_EXTRA_JARS: &[TestJar] = &[
    // Popular libraries — diverse sizes and compression characteristics
    TestJar {
        filename: "log4j-core-2.23.1.jar",
        maven_path: "org/apache/logging/log4j/log4j-core/2.23.1/log4j-core-2.23.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-context-6.1.10.jar",
        maven_path: "org/springframework/spring-context/6.1.10/spring-context-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-beans-6.1.10.jar",
        maven_path: "org/springframework/spring-beans/6.1.10/spring-beans-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-web-6.1.10.jar",
        maven_path: "org/springframework/spring-web/6.1.10/spring-web-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-webmvc-6.1.10.jar",
        maven_path: "org/springframework/spring-webmvc/6.1.10/spring-webmvc-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "netty-buffer-4.1.110.Final.jar",
        maven_path: "io/netty/netty-buffer/4.1.110.Final/netty-buffer-4.1.110.Final.jar",
        group: "batch",
    },
    TestJar {
        filename: "netty-codec-4.1.110.Final.jar",
        maven_path: "io/netty/netty-codec/4.1.110.Final/netty-codec-4.1.110.Final.jar",
        group: "batch",
    },
    TestJar {
        filename: "netty-transport-4.1.110.Final.jar",
        maven_path: "io/netty/netty-transport/4.1.110.Final/netty-transport-4.1.110.Final.jar",
        group: "batch",
    },
    TestJar {
        filename: "netty-handler-4.1.110.Final.jar",
        maven_path: "io/netty/netty-handler/4.1.110.Final/netty-handler-4.1.110.Final.jar",
        group: "batch",
    },
    TestJar {
        filename: "jackson-core-2.17.1.jar",
        maven_path: "com/fasterxml/jackson/core/jackson-core/2.17.1/jackson-core-2.17.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "jackson-annotations-2.17.1.jar",
        maven_path: "com/fasterxml/jackson/core/jackson-annotations/2.17.1/jackson-annotations-2.17.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "hibernate-core-6.5.2.Final.jar",
        maven_path: "org/hibernate/orm/hibernate-core/6.5.2.Final/hibernate-core-6.5.2.Final.jar",
        group: "batch",
    },
    TestJar {
        filename: "mockito-core-5.12.0.jar",
        maven_path: "org/mockito/mockito-core/5.12.0/mockito-core-5.12.0.jar",
        group: "batch",
    },
    TestJar {
        filename: "junit-jupiter-api-5.10.3.jar",
        maven_path: "org/junit/jupiter/junit-jupiter-api/5.10.3/junit-jupiter-api-5.10.3.jar",
        group: "batch",
    },
    TestJar {
        filename: "lombok-1.18.32.jar",
        maven_path: "org/projectlombok/lombok/1.18.32/lombok-1.18.32.jar",
        group: "batch",
    },
    TestJar {
        filename: "logback-classic-1.5.6.jar",
        maven_path: "ch/qos/logback/logback-classic/1.5.6/logback-classic-1.5.6.jar",
        group: "batch",
    },
    TestJar {
        filename: "logback-core-1.5.6.jar",
        maven_path: "ch/qos/logback/logback-core/1.5.6/logback-core-1.5.6.jar",
        group: "batch",
    },
    TestJar {
        filename: "commons-math3-3.6.1.jar",
        maven_path: "org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "guice-7.0.0.jar",
        maven_path: "com/google/inject/guice/7.0.0/guice-7.0.0.jar",
        group: "batch",
    },
    TestJar {
        filename: "byte-buddy-1.14.17.jar",
        maven_path: "net/bytebuddy/byte-buddy/1.14.17/byte-buddy-1.14.17.jar",
        group: "batch",
    },
    TestJar {
        filename: "protobuf-java-4.27.2.jar",
        maven_path: "com/google/protobuf/protobuf-java/4.27.2/protobuf-java-4.27.2.jar",
        group: "batch",
    },
    TestJar {
        filename: "caffeine-3.1.8.jar",
        maven_path: "com/github/ben-manes/caffeine/caffeine/3.1.8/caffeine-3.1.8.jar",
        group: "batch",
    },
    TestJar {
        filename: "micrometer-core-1.13.1.jar",
        maven_path: "io/micrometer/micrometer-core/1.13.1/micrometer-core-1.13.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "reactor-core-3.6.7.jar",
        maven_path: "io/projectreactor/reactor-core/3.6.7/reactor-core-3.6.7.jar",
        group: "batch",
    },
    TestJar {
        filename: "tomcat-embed-core-10.1.25.jar",
        maven_path: "org/apache/tomcat/embed/tomcat-embed-core/10.1.25/tomcat-embed-core-10.1.25.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-boot-3.3.1.jar",
        maven_path: "org/springframework/boot/spring-boot/3.3.1/spring-boot-3.3.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-data-jpa-3.3.1.jar",
        maven_path: "org/springframework/data/spring-data-jpa/3.3.1/spring-data-jpa-3.3.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-security-core-6.3.1.jar",
        maven_path: "org/springframework/security/spring-security-core/6.3.1/spring-security-core-6.3.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "commons-compress-1.26.2.jar",
        maven_path: "org/apache/commons/commons-compress/1.26.2/commons-compress-1.26.2.jar",
        group: "batch",
    },
    TestJar {
        filename: "antlr4-runtime-4.13.1.jar",
        maven_path: "org/antlr/antlr4-runtime/4.13.1/antlr4-runtime-4.13.1.jar",
        group: "batch",
    },
    // More JARs to push past 200MB (exercise multi-batch pipeline)
    TestJar {
        filename: "h2-2.2.224.jar",
        maven_path: "com/h2database/h2/2.2.224/h2-2.2.224.jar",
        group: "batch",
    },
    TestJar {
        filename: "lucene-core-9.11.1.jar",
        maven_path: "org/apache/lucene/lucene-core/9.11.1/lucene-core-9.11.1.jar",
        group: "batch",
    },
    TestJar {
        filename: "neo4j-kernel-5.20.0.jar",
        maven_path: "org/neo4j/neo4j-kernel/5.20.0/neo4j-kernel-5.20.0.jar",
        group: "batch",
    },
    TestJar {
        filename: "jetty-server-12.0.10.jar",
        maven_path: "org/eclipse/jetty/jetty-server/12.0.10/jetty-server-12.0.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-jdbc-6.1.10.jar",
        maven_path: "org/springframework/spring-jdbc/6.1.10/spring-jdbc-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-tx-6.1.10.jar",
        maven_path: "org/springframework/spring-tx/6.1.10/spring-tx-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-aop-6.1.10.jar",
        maven_path: "org/springframework/spring-aop/6.1.10/spring-aop-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-orm-6.1.10.jar",
        maven_path: "org/springframework/spring-orm/6.1.10/spring-orm-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "spring-expression-6.1.10.jar",
        maven_path: "org/springframework/spring-expression/6.1.10/spring-expression-6.1.10.jar",
        group: "batch",
    },
    TestJar {
        filename: "vertx-core-4.5.8.jar",
        maven_path: "io/vertx/vertx-core/4.5.8/vertx-core-4.5.8.jar",
        group: "batch",
    },
    TestJar {
        filename: "okhttp-4.12.0.jar",
        maven_path: "com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar",
        group: "batch",
    },
    TestJar {
        filename: "grpc-core-1.65.0.jar",
        maven_path: "io/grpc/grpc-core/1.65.0/grpc-core-1.65.0.jar",
        group: "batch",
    },
    TestJar {
        filename: "poi-5.2.5.jar",
        maven_path: "org/apache/poi/poi/5.2.5/poi-5.2.5.jar",
        group: "batch",
    },
    TestJar {
        filename: "checker-qual-3.45.0.jar",
        maven_path: "org/checkerframework/checker-qual/3.45.0/checker-qual-3.45.0.jar",
        group: "batch",
    },
    TestJar {
        filename: "error_prone_annotations-2.28.0.jar",
        maven_path: "com/google/errorprone/error_prone_annotations/2.28.0/error_prone_annotations-2.28.0.jar",
        group: "batch",
    },
    TestJar {
        filename: "auto-value-annotations-1.11.0.jar",
        maven_path: "com/google/auto/value/auto-value-annotations/1.11.0/auto-value-annotations-1.11.0.jar",
        group: "batch",
    },
    TestJar {
        filename: "rxjava-3.1.8.jar",
        maven_path: "io/reactivex/rxjava3/rxjava/3.1.8/rxjava-3.1.8.jar",
        group: "batch",
    },
    TestJar {
        filename: "flyway-core-10.15.2.jar",
        maven_path: "org/flywaydb/flyway-core/10.15.2/flyway-core-10.15.2.jar",
        group: "batch",
    },
    TestJar {
        filename: "jaxb-runtime-4.0.5.jar",
        maven_path: "org/glassfish/jaxb/jaxb-runtime/4.0.5/jaxb-runtime-4.0.5.jar",
        group: "batch",
    },
    TestJar {
        filename: "aspectjweaver-1.9.22.1.jar",
        maven_path: "org/aspectj/aspectjweaver/1.9.22.1/aspectjweaver-1.9.22.1.jar",
        group: "batch",
    },
    // Spark ecosystem (large dependency tree)
    TestJar {
        filename: "spark-sql_2.13-3.5.1.jar",
        maven_path: "org/apache/spark/spark-sql_2.13/3.5.1/spark-sql_2.13-3.5.1.jar",
        group: "spark",
    },
    TestJar {
        filename: "spark-catalyst_2.13-3.5.1.jar",
        maven_path: "org/apache/spark/spark-catalyst_2.13/3.5.1/spark-catalyst_2.13-3.5.1.jar",
        group: "spark",
    },
    TestJar {
        filename: "spark-mllib_2.13-3.5.1.jar",
        maven_path: "org/apache/spark/spark-mllib_2.13/3.5.1/spark-mllib_2.13-3.5.1.jar",
        group: "spark",
    },
    TestJar {
        filename: "spark-streaming_2.13-3.5.1.jar",
        maven_path: "org/apache/spark/spark-streaming_2.13/3.5.1/spark-streaming_2.13-3.5.1.jar",
        group: "spark",
    },
    TestJar {
        filename: "spark-network-common_2.13-3.5.1.jar",
        maven_path: "org/apache/spark/spark-network-common_2.13/3.5.1/spark-network-common_2.13-3.5.1.jar",
        group: "spark",
    },
    TestJar {
        filename: "scala-reflect-2.13.14.jar",
        maven_path: "org/scala-lang/scala-reflect/2.13.14/scala-reflect-2.13.14.jar",
        group: "spark",
    },
    TestJar {
        filename: "scala-compiler-2.13.14.jar",
        maven_path: "org/scala-lang/scala-compiler/2.13.14/scala-compiler-2.13.14.jar",
        group: "spark",
    },
    TestJar {
        filename: "hadoop-client-api-3.3.6.jar",
        maven_path: "org/apache/hadoop/hadoop-client-api/3.3.6/hadoop-client-api-3.3.6.jar",
        group: "spark",
    },
    TestJar {
        filename: "parquet-hadoop-1.13.1.jar",
        maven_path: "org/apache/parquet/parquet-hadoop/1.13.1/parquet-hadoop-1.13.1.jar",
        group: "spark",
    },
    TestJar {
        filename: "arrow-vector-15.0.2.jar",
        maven_path: "org/apache/arrow/arrow-vector/15.0.2/arrow-vector-15.0.2.jar",
        group: "spark",
    },
    TestJar {
        filename: "arrow-memory-core-15.0.2.jar",
        maven_path: "org/apache/arrow/arrow-memory-core/15.0.2/arrow-memory-core-15.0.2.jar",
        group: "spark",
    },
    TestJar {
        filename: "hive-exec-2.3.9.jar",
        maven_path: "org/apache/hive/hive-exec/2.3.9/hive-exec-2.3.9.jar",
        group: "spark",
    },
    // Spring Boot full stack
    TestJar {
        filename: "spring-boot-autoconfigure-3.3.1.jar",
        maven_path: "org/springframework/boot/spring-boot-autoconfigure/3.3.1/spring-boot-autoconfigure-3.3.1.jar",
        group: "spring",
    },
    TestJar {
        filename: "spring-data-commons-3.3.1.jar",
        maven_path: "org/springframework/data/spring-data-commons/3.3.1/spring-data-commons-3.3.1.jar",
        group: "spring",
    },
    TestJar {
        filename: "spring-security-web-6.3.1.jar",
        maven_path: "org/springframework/security/spring-security-web/6.3.1/spring-security-web-6.3.1.jar",
        group: "spring",
    },
    TestJar {
        filename: "spring-security-config-6.3.1.jar",
        maven_path: "org/springframework/security/spring-security-config/6.3.1/spring-security-config-6.3.1.jar",
        group: "spring",
    },
    TestJar {
        filename: "spring-webflux-6.1.10.jar",
        maven_path: "org/springframework/spring-webflux/6.1.10/spring-webflux-6.1.10.jar",
        group: "spring",
    },
    TestJar {
        filename: "spring-messaging-6.1.10.jar",
        maven_path: "org/springframework/spring-messaging/6.1.10/spring-messaging-6.1.10.jar",
        group: "spring",
    },
    TestJar {
        filename: "spring-batch-core-5.1.2.jar",
        maven_path: "org/springframework/batch/spring-batch-core/5.1.2/spring-batch-core-5.1.2.jar",
        group: "spring",
    },
    TestJar {
        filename: "spring-kafka-3.2.1.jar",
        maven_path: "org/springframework/kafka/spring-kafka/3.2.1/spring-kafka-3.2.1.jar",
        group: "spring",
    },
    TestJar {
        filename: "jackson-datatype-jsr310-2.17.1.jar",
        maven_path: "com/fasterxml/jackson/datatype/jackson-datatype-jsr310/2.17.1/jackson-datatype-jsr310-2.17.1.jar",
        group: "spring",
    },
    TestJar {
        filename: "jakarta.persistence-api-3.1.0.jar",
        maven_path: "jakarta/persistence/jakarta.persistence-api/3.1.0/jakarta.persistence-api-3.1.0.jar",
        group: "spring",
    },
    TestJar {
        filename: "jakarta.servlet-api-6.0.0.jar",
        maven_path: "jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar",
        group: "spring",
    },
    TestJar {
        filename: "thymeleaf-3.1.2.RELEASE.jar",
        maven_path: "org/thymeleaf/thymeleaf/3.1.2.RELEASE/thymeleaf-3.1.2.RELEASE.jar",
        group: "spring",
    },
];

/// Batch benchmark: extract all JARs (original + extra) using the batch pipeline.
/// Compares against sequential `unzip` of each JAR.
///
/// Run:  cargo test --test maven_artifacts batch_timing -- --nocapture --ignored
#[test]
fn batch_timing() {
    if std::env::var("LZIP_SKIP_MAVEN_TESTS").is_ok() {
        eprintln!("SKIPPED (LZIP_SKIP_MAVEN_TESTS set)");
        return;
    }

    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let physical = physical_cores_linux().unwrap_or(cores);

    // Collect all JAR paths.
    let mut jar_paths: Vec<PathBuf> = Vec::new();
    let mut total_jar_size = 0u64;

    eprintln!();
    eprintln!("  Downloading JARs...");
    for jar in TEST_JARS.iter().chain(BATCH_EXTRA_JARS.iter()) {
        let path = ensure_jar(jar);
        total_jar_size += fs::metadata(&path).unwrap().len();
        jar_paths.push(path);
    }
    let total_mb_in = total_jar_size as f64 / (1024.0 * 1024.0);
    eprintln!(
        "  {} JARs, {:.1} MB total compressed",
        jar_paths.len(),
        total_mb_in
    );

    eprintln!();
    eprintln!(
        "═══════════════════════════════════════════════════════════════════════════════════════════"
    );
    eprintln!(
        "  Batch benchmark — {} JARs, {:.1} MB compressed",
        jar_paths.len(),
        total_mb_in
    );
    eprintln!("  {} logical cores, {} physical cores", cores, physical);
    eprintln!(
        "═══════════════════════════════════════════════════════════════════════════════════════════"
    );

    // ── lzip batch (in-memory, no disk I/O) ──────────────────────────────────
    let (_, batch_stats) = lzip_parallel::batch::decompress_zips(&jar_paths).unwrap();
    let lzip_mb = batch_stats.decompressed_bytes_written as f64 / (1024.0 * 1024.0);

    eprintln!();
    eprintln!("  lzip batch (in-memory decompress):");
    eprintln!(
        "    {:.1} MB decompressed in {:.1} ms",
        lzip_mb,
        batch_stats.elapsed_secs * 1000.0
    );
    eprintln!(
        "    Throughput: {:.0} MB/s",
        batch_stats.throughput_mb_per_sec()
    );

    // ── lzip batch (extract to disk) ─────────────────────────────────────────
    let out_dir = tempfile::tempdir().expect("create output dir");
    let t0 = std::time::Instant::now();
    let disk_stats = lzip_parallel::batch::extract_zips(&jar_paths, out_dir.path(), false).unwrap();
    let lzip_disk_elapsed = t0.elapsed().as_secs_f64();
    let lzip_disk_mb = disk_stats.decompressed_bytes_written as f64 / (1024.0 * 1024.0);

    eprintln!();
    eprintln!("  lzip batch (extract to disk):");
    eprintln!(
        "    {:.1} MB written in {:.1} ms",
        lzip_disk_mb,
        lzip_disk_elapsed * 1000.0
    );
    eprintln!(
        "    Throughput: {:.0} MB/s",
        if lzip_disk_elapsed > 0.0 {
            lzip_disk_mb / lzip_disk_elapsed
        } else {
            0.0
        }
    );

    // ── unzip sequential (extract to disk) ───────────────────────────────────
    let unzip_dir = tempfile::tempdir().expect("create unzip dir");
    let t0 = std::time::Instant::now();
    for jar_path in &jar_paths {
        let stem = jar_path.file_stem().unwrap().to_string_lossy();
        let sub = unzip_dir.path().join(stem.as_ref());
        fs::create_dir_all(&sub).unwrap();
        let status = std::process::Command::new("unzip")
            .args(["-q", "-o"])
            .arg(jar_path.as_os_str())
            .arg("-d")
            .arg(sub.as_os_str())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("unzip");
        assert!(status.success());
    }
    let unzip_elapsed = t0.elapsed().as_secs_f64();

    eprintln!();
    eprintln!("  unzip sequential (extract to disk):");
    eprintln!(
        "    {:.1} MB extracted in {:.1} ms",
        lzip_disk_mb,
        unzip_elapsed * 1000.0
    );
    eprintln!(
        "    Throughput: {:.0} MB/s",
        if unzip_elapsed > 0.0 {
            lzip_disk_mb / unzip_elapsed
        } else {
            0.0
        }
    );

    // ── Summary ──────────────────────────────────────────────────────────────
    let speedup_mem = if batch_stats.elapsed_secs > 0.0 {
        unzip_elapsed / batch_stats.elapsed_secs
    } else {
        0.0
    };
    let speedup_disk = if lzip_disk_elapsed > 0.0 {
        unzip_elapsed / lzip_disk_elapsed
    } else {
        0.0
    };

    eprintln!();
    eprintln!("  ┌──────────────────────────────────────────────────────────┐");
    eprintln!(
        "  │  Speedup vs unzip (in-memory): {:>6.2}x                   │",
        speedup_mem
    );
    eprintln!(
        "  │  Speedup vs unzip (to disk):   {:>6.2}x                   │",
        speedup_disk
    );
    eprintln!("  └──────────────────────────────────────────────────────────┘");
    eprintln!();
    eprintln!(
        "═══════════════════════════════════════════════════════════════════════════════════════════"
    );
}
