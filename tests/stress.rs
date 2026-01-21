use std::process::Command;
use std::time::{Duration, Instant};

use db_keystore::{DbKeyStore, DbKeyStoreConfig};
use keyring_core::api::CredentialStoreApi;

// Stress test environment variables:
//  - STRESS_DB_DIR: optional directory for the SQLite file (prefers tmpfs).
//  - STRESS_DB: internal child-only database path.
//  - STRESS_ID: child identifier string used in generated secrets.
//  - STRESS_CHILD: set in child processes to select child-only tests.
//  - STRESS_MODE: selects which child test to run (e.g. "random_rw").
//  - STRESS_ENTRIES: number of entries to create (default 250).
//  - STRESS_SECONDS: runtime duration in seconds (default 30).
//
// Disk selection:
// 1. use environment STRESS_DB_DIR to set the directory
// 2. use /dev/shm when available (save wear on SSD)
// 3. fall back to tempfile::tempdir()
//    (note: on macos, tempdir is usually disk-backed)

const DEFAULT_STRESS_ENTRIES: usize = 250;
const DEFAULT_STRESS_SECONDS: u64 = 5;

#[test]
#[ignore]
fn stress_two_processes() {
    if std::env::var("STRESS_CHILD").is_ok() {
        return;
    }
    let tempdir = create_temp_db_dir();
    let db_path = tempdir.path().join("store.db");
    let db_path = db_path.to_str().expect("db path").to_string();
    println!("stress_two_processes db_path={db_path}");
    let exe = std::env::current_exe().expect("current_exe");

    let mut child1 = Command::new(&exe)
        .arg("--exact")
        .arg("stress_child")
        .arg("--nocapture")
        .env("STRESS_CHILD", "1")
        .env("STRESS_DB", &db_path)
        .env("STRESS_ID", "1")
        .spawn()
        .expect("spawn child1");
    let mut child2 = Command::new(&exe)
        .arg("--exact")
        .arg("stress_child")
        .arg("--nocapture")
        .env("STRESS_CHILD", "1")
        .env("STRESS_DB", &db_path)
        .env("STRESS_ID", "2")
        .spawn()
        .expect("spawn child2");

    let status1 = child1.wait().expect("child1 wait");
    let status2 = child2.wait().expect("child2 wait");
    assert!(status1.success(), "child1 failed: {status1}");
    assert!(status2.success(), "child2 failed: {status2}");
}

#[test]
fn stress_child() {
    if std::env::var("STRESS_CHILD").is_err() {
        return;
    }
    if std::env::var("STRESS_MODE").ok().as_deref() == Some("random_rw") {
        return;
    }
    let db_path = std::env::var("STRESS_DB").expect("STRESS_DB");
    let id = std::env::var("STRESS_ID").unwrap_or_else(|_| "0".to_string());
    let config = DbKeyStoreConfig {
        path: db_path.into(),
        ..Default::default()
    };
    let store = retry_locking(|| DbKeyStore::new(&config)).expect("store");
    let entry = store
        .build("stress-service", "stress-user", None)
        .expect("build entry");

    for i in 0..200 {
        let secret = format!("secret-{id}-{i}");
        retry_locking(|| entry.set_secret(secret.as_bytes())).expect("set_secret");
        let _ = retry_locking(|| entry.get_secret()).expect("get_secret");
    }
}

#[test]
#[ignore]
fn stress_random_rw_two_processes() {
    if std::env::var("STRESS_CHILD").is_ok() {
        return;
    }
    let tempdir = create_temp_db_dir();
    let db_path = tempdir.path().join("store.db");
    let db_path = db_path.to_str().expect("db path").to_string();
    let exe = std::env::current_exe().expect("current_exe");
    println!(
        "stress_random_rw_two_processes db_path={db_path} entries={} seconds={}",
        DEFAULT_STRESS_ENTRIES, DEFAULT_STRESS_SECONDS
    );

    let mut child1 = Command::new(&exe)
        .arg("--exact")
        .arg("stress_random_rw_child")
        .arg("--nocapture")
        .env("STRESS_CHILD", "1")
        .env("STRESS_MODE", "random_rw")
        .env("STRESS_DB", &db_path)
        .env("STRESS_ID", "1")
        .env("STRESS_ENTRIES", DEFAULT_STRESS_ENTRIES.to_string())
        .env("STRESS_SECONDS", DEFAULT_STRESS_SECONDS.to_string())
        .spawn()
        .expect("spawn child1");
    let mut child2 = Command::new(&exe)
        .arg("--exact")
        .arg("stress_random_rw_child")
        .arg("--nocapture")
        .env("STRESS_CHILD", "1")
        .env("STRESS_MODE", "random_rw")
        .env("STRESS_DB", &db_path)
        .env("STRESS_ID", "2")
        .env("STRESS_ENTRIES", DEFAULT_STRESS_ENTRIES.to_string())
        .env("STRESS_SECONDS", DEFAULT_STRESS_SECONDS.to_string())
        .spawn()
        .expect("spawn child2");

    let status1 = child1.wait().expect("child1 wait");
    let status2 = child2.wait().expect("child2 wait");
    assert!(status1.success(), "child1 failed: {status1}");
    assert!(status2.success(), "child2 failed: {status2}");
}

#[test]
fn stress_random_rw_child() {
    if std::env::var("STRESS_CHILD").is_err() {
        return;
    }
    if std::env::var("STRESS_MODE").ok().as_deref() != Some("random_rw") {
        return;
    }
    let db_path = std::env::var("STRESS_DB").expect("STRESS_DB");
    let id = std::env::var("STRESS_ID").unwrap_or_else(|_| "0".to_string());
    let entries: usize = std::env::var("STRESS_ENTRIES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_STRESS_ENTRIES);
    let seconds: u64 = std::env::var("STRESS_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_STRESS_SECONDS);
    let config = DbKeyStoreConfig {
        path: db_path.into(),
        ..Default::default()
    };
    let store = retry_locking(|| DbKeyStore::new(&config)).expect("store");
    let mut creds = Vec::with_capacity(entries);
    for i in 0..entries {
        let user = format!("user-{i}");
        let entry = store
            .build("stress-service", user.as_str(), None)
            .expect("build entry");
        retry_locking(|| entry.set_secret(b"init")).expect("seed secret");
        creds.push(entry);
        std::thread::sleep(Duration::from_millis(20)); // allow the other process to squeeze in periodically
    }

    let mut rng = Lcg::new(id.parse::<u64>().unwrap_or(0) ^ 0x5e11_u64);
    let start = Instant::now();
    let deadline = Duration::from_secs(seconds);
    let mut counter = 0u64;
    while start.elapsed() < deadline {
        let idx = (rng.next_u32() as usize) % creds.len();
        let entry = &creds[idx];
        if rng.next_u32() % 2 == 0 {
            let _ = retry_locking(|| entry.get_secret()).expect("get_secret");
        } else {
            let secret = format!("secret-{id}-{idx}-{counter}");
            counter = counter.wrapping_add(1);
            retry_locking(|| entry.set_secret(secret.as_bytes())).expect("set_secret");
        }
    }
}

#[test]
fn file_size_by_entry_count() {
    let counts = [5usize, 20, 100];
    for count in counts {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("size.db");
        let config = DbKeyStoreConfig {
            path: path.clone(),
            ..Default::default()
        };
        let store = DbKeyStore::new(&config).expect("store");
        for i in 0..count {
            let user = format!("user-{i}");
            let entry = store
                .build("size-service", user.as_str(), None)
                .expect("build entry");
            entry
                .set_secret(format!("secret-{i}").as_bytes())
                .expect("set_secret");
        }
        let total = file_set_size(&path);
        println!("file_size entries={count} bytes={total}");
    }
}

#[test]
#[ignore]
fn perf_index_always_lookup() {
    if std::env::var("PERF_INDEX").is_err() {
        return;
    }
    let counts = [10usize, 100, 250, 500, 1000];
    for count in counts {
        for index_always in [false, true] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("perf.db");
            let config = DbKeyStoreConfig {
                path: path.clone(),
                allow_ambiguity: true,
                index_always,
                ..Default::default()
            };
            let store = DbKeyStore::new(&config).expect("store");
            for i in 0..count {
                let user = format!("user-{i}");
                let entry = store
                    .build("perf-service", user.as_str(), None)
                    .expect("build entry");
                entry
                    .set_secret(format!("secret-{i}").as_bytes())
                    .expect("set_secret");
            }

            let lookups = std::cmp::max(100, std::cmp::min(5000, count * 10));
            let start = Instant::now();
            for i in 0..lookups {
                let idx = i % count;
                let user = format!("user-{idx}");
                let entry = store
                    .build("perf-service", user.as_str(), None)
                    .expect("build entry");
                let _ = entry.get_secret().expect("get_secret");
            }
            let elapsed = start.elapsed();
            println!(
                "perf_index_lookup entries={count} index_always={index_always} lookups={lookups} elapsed_ms={}",
                elapsed.as_millis()
            );
        }
    }
}

fn retry_locking<T>(
    mut op: impl FnMut() -> Result<T, keyring_core::Error>,
) -> Result<T, keyring_core::Error> {
    let mut retries = 600;
    let mut backoff_ms = 20u64;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                if retries == 0 || !is_locking_error(&err) {
                    return Err(err);
                }
                retries -= 1;
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos();
                let jitter = (nanos % 20) as u64;
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms + jitter));
                backoff_ms = (backoff_ms * 2).min(250);
            }
        }
    }
}

fn is_locking_error(err: &keyring_core::Error) -> bool {
    let text = err.to_string().to_lowercase();
    text.contains("locking error")
        || text.contains("file is locked")
        || text.contains("database is locked")
        || text.contains("database is busy")
        || text.contains("sqlite_busy")
        || text.contains("sqlite_locked")
}

fn create_temp_db_dir() -> tempfile::TempDir {
    if let Ok(dir) = std::env::var("STRESS_DB_DIR") {
        return tempfile::Builder::new()
            .prefix("sqlite-keystore-")
            .tempdir_in(dir)
            .expect("tempdir");
    }
    let shm = std::path::Path::new("/dev/shm");
    if shm.is_dir() {
        return tempfile::Builder::new()
            .prefix("sqlite-keystore-")
            .tempdir_in(shm)
            .expect("tempdir");
    }
    tempfile::tempdir().expect("tempdir")
}

fn file_set_size(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut maybe_add = |p: &std::path::Path| {
        if let Ok(meta) = std::fs::metadata(p) {
            total = total.saturating_add(meta.len());
        }
    };
    maybe_add(path);
    if let Some(base) = path.file_name().and_then(|name| name.to_str()) {
        let wal = path.with_file_name(format!("{base}-wal"));
        let shm = path.with_file_name(format!("{base}-shm"));
        maybe_add(&wal);
        maybe_add(&shm);
    }
    total
}

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }
}
