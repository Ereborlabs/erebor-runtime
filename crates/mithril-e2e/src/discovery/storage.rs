use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use rusqlite::{
    hooks::{AuthAction, AuthContext, Authorization},
    limits::Limit,
    Connection,
};
use serde_json::json;

use crate::platform::TestResult;

struct SqliteExperiment {
    db: Connection,
}

impl SqliteExperiment {
    fn open(path: &Path) -> TestResult<Self> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            PRAGMA cache_size=-32768; PRAGMA wal_autocheckpoint=256;
            PRAGMA temp_store=FILE; PRAGMA trusted_schema=OFF;
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, atom INTEGER NOT NULL,
                revision INTEGER NOT NULL, decision INTEGER NOT NULL, tenant INTEGER NOT NULL,
                payload BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS event_atom ON events(atom,tenant,id);
            CREATE TABLE IF NOT EXISTS atoms(atom INTEGER,tenant INTEGER,n INTEGER NOT NULL,
                PRIMARY KEY(atom,tenant));
            CREATE TABLE IF NOT EXISTS head(id INTEGER PRIMARY KEY CHECK(id=1),cursor INTEGER NOT NULL);
            INSERT OR IGNORE INTO head VALUES(1,0);")?;
        Ok(Self { db })
    }

    fn apply(&mut self, first: u64, last: u64, groups: u64, payload: &[u8]) -> TestResult<()> {
        assert!(last >= first && last - first <= 4096);
        assert!((last - first) * (40 + u64::try_from(payload.len())?) <= 8 * 1024 * 1024);
        let transaction = self.db.transaction()?;
        {
            let mut insert = transaction.prepare(
                "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6)
                ON CONFLICT(id) DO NOTHING",
            )?;
            let mut existing = transaction
                .prepare("SELECT atom,revision,decision,tenant,payload FROM events WHERE id=?1")?;
            let mut aggregate = transaction.prepare(
                "INSERT INTO atoms VALUES(?1,?2,1)
                ON CONFLICT(atom,tenant) DO UPDATE SET n=n+1",
            )?;
            for id in first..last {
                let atom = id % groups;
                let revision = id / 100_000;
                let decision = u64::from(id % 997 == 0);
                let tenant = id % 2;
                if insert.execute(rusqlite::params![
                    id, atom, revision, decision, tenant, payload
                ])? == 1
                {
                    aggregate.execute([atom, tenant])?;
                } else {
                    let row = existing.query_row([id], |row| {
                        Ok((
                            row.get::<_, u64>(0)?,
                            row.get::<_, u64>(1)?,
                            row.get::<_, u64>(2)?,
                            row.get::<_, u64>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                        ))
                    })?;
                    if row != (atom, revision, decision, tenant, payload.to_vec()) {
                        return Err("CONFLICTING_RECORD".into());
                    }
                }
            }
        }
        transaction.execute("UPDATE head SET cursor=max(cursor,?1)", [last])?;
        transaction.commit()?;
        Ok(())
    }

    fn authorize(db: &Connection) -> TestResult<()> {
        db.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 16 * 1024)?;
        db.set_limit(Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024)?;
        db.set_limit(Limit::SQLITE_LIMIT_COLUMN, 64)?;
        db.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 64)?;
        db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
        db.set_limit(Limit::SQLITE_LIMIT_VDBE_OP, 100_000)?;
        db.authorizer(Some(|context: AuthContext<'_>| match context.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read {
                table_name: "events",
                column_name: "id" | "atom",
            } if context.database_name == Some("main") => Authorization::Allow,
            AuthAction::Read {
                table_name: "events",
                column_name: "",
            } if context.database_name.is_none_or(|name| name == "main") => Authorization::Allow,
            AuthAction::Function {
                function_name: "count" | "sum" | "min" | "max" | "avg",
            } => Authorization::Allow,
            _ => Authorization::Deny,
        }))?;
        Ok(())
    }

    fn query(db: &Connection, sql: &str) -> TestResult<Vec<Vec<serde_json::Value>>> {
        if sql.len() > 16 * 1024 {
            return Err("QUERY_SIZE".into());
        }
        let started = Instant::now();
        db.progress_handler(
            1000,
            Some(move || started.elapsed() >= Duration::from_secs(1)),
        )?;
        let mut statement = db.prepare(sql)?;
        if !statement.readonly() || statement.parameter_count() != 0 {
            return Err("QUERY_SHAPE".into());
        }
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        let mut output = Vec::new();
        let mut bytes = 2;
        while let Some(row) = rows.next()? {
            if output.len() == 200 {
                return Err("OUTPUT_ROWS".into());
            }
            let mut values = Vec::with_capacity(columns);
            for column in 0..columns {
                let value = match row.get_ref(column)? {
                    rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                    rusqlite::types::ValueRef::Integer(value) => json!(value),
                    rusqlite::types::ValueRef::Real(value) => json!(value),
                    rusqlite::types::ValueRef::Text(value) => json!(std::str::from_utf8(value)?),
                    rusqlite::types::ValueRef::Blob(_) => return Err("QUERY_BLOB".into()),
                };
                values.push(value);
            }
            bytes += serde_json::to_vec(&values)?.len() + 1;
            if bytes > 1024 * 1024 {
                return Err("OUTPUT_BYTES".into());
            }
            output.push(values);
        }
        Ok(output)
    }

    fn counts(&self) -> TestResult<(u64, u64, u64)> {
        Ok(self.db.query_row(
            "SELECT (SELECT count(*) FROM events),
            (SELECT coalesce(sum(n),0) FROM atoms),(SELECT cursor FROM head)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?)
    }

    fn measure(
        root: &Path,
        count: u64,
        groups: u64,
        payload: &[u8],
    ) -> TestResult<serde_json::Value> {
        fs::create_dir(root)?;
        let path = root.join("index.db");
        let mut owner = Self::open(&path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..2 {
            let stop = stop.clone();
            let path = path.clone();
            readers.push(std::thread::spawn(move || -> Result<Vec<f64>, String> {
                let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(|error|error.to_string())?;
                db.execute_batch("PRAGMA cache_size=-8192").map_err(|error|error.to_string())?;
                let mut samples = Vec::new();
                while !stop.load(Ordering::Acquire) {
                    let started = Instant::now();
                    let mut statement = db.prepare("SELECT atom,n FROM atoms WHERE tenant=0 AND atom>100 ORDER BY atom LIMIT 200")
                        .map_err(|error|error.to_string())?;
                    let mut rows = statement.query([]).map_err(|error|error.to_string())?;
                    while rows.next().map_err(|error|error.to_string())?.is_some() {}
                    samples.push(started.elapsed().as_secs_f64()*1000.0);
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(samples)
            }));
        }
        let mut batches = Vec::new();
        let mut wal_peak = 0;
        let started = Instant::now();
        let ingestion = (|| -> TestResult<()> {
            let batch = 4096.min(8 * 1024 * 1024 / (40 + payload.len()));
            for first in (0..count).step_by(batch) {
                let tick = Instant::now();
                owner.apply(
                    first,
                    count.min(first + u64::try_from(batch)?),
                    groups,
                    payload,
                )?;
                batches.push(tick.elapsed().as_secs_f64() * 1000.0);
                wal_peak = wal_peak.max(fs::metadata(root.join("index.db-wal"))?.len());
            }
            Ok(())
        })();
        stop.store(true, Ordering::Release);
        let mut reads = Vec::new();
        for reader in readers {
            reads.extend(reader.join().map_err(|_| "reader panicked")??);
        }
        ingestion?;
        let ingestion_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(owner.counts()?, (count, count, count));
        owner.apply(
            0,
            count
                .min(8 * 1024 * 1024 / (40 + u64::try_from(payload.len())?))
                .min(4096),
            groups,
            payload,
        )?;
        assert_eq!(owner.counts()?, (count, count, count));
        assert!(owner.apply(0, 1, groups, b"conflict").is_err());
        assert_eq!(owner.counts()?, (count, count, count));
        let canonical: Vec<(u64, u64, u64)> = owner
            .db
            .prepare("SELECT atom,tenant,n FROM atoms ORDER BY atom,tenant")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?;
        assert_eq!(canonical.len(), usize::try_from(count.min(groups))?);
        let digest = crate::DigestV1::of(&serde_json::to_vec(&canonical)?);
        owner.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        drop(owner);
        let tick = Instant::now();
        let owner = Self::open(&path)?;
        assert_eq!(owner.counts()?, (count, count, count));
        let restart_ms = tick.elapsed().as_secs_f64() * 1000.0;
        let tick = Instant::now();
        owner.db.execute_batch("CREATE TABLE rebuilt AS SELECT atom,tenant,count(*) AS n FROM events GROUP BY atom,tenant")?;
        let differences: u64 = owner.db.query_row(
            "SELECT count(*) FROM
            (SELECT * FROM rebuilt EXCEPT SELECT * FROM atoms)",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(differences, 0);
        let rebuild_ms = tick.elapsed().as_secs_f64() * 1000.0;
        let disk = fs::read_dir(root)?.try_fold(0_u64, |sum, entry| -> std::io::Result<u64> {
            Ok(sum + entry?.metadata()?.len())
        })?;
        assert!(disk < 2 * 1024 * 1024 * 1024);
        assert!(wal_peak < 64 * 1024 * 1024);
        batches.sort_by(f64::total_cmp);
        reads.sort_by(f64::total_cmp);
        assert!(!reads.is_empty());
        assert!(batches[batches.len() - 1] < 1000.0);
        assert!(reads[reads.len() - 1] < 1000.0);
        Ok(
            json!({"records":count,"atoms":groups,"payload_bytes":payload.len(),
            "decoded_bytes":count*(40+u64::try_from(payload.len())?),"canonical_digest":digest,
            "ingestion_ms":ingestion_ms,"batch_p95_ms":batches[batches.len()*95/100],
            "batch_max_ms":batches[batches.len()-1],"concurrent_read_count":reads.len(),
            "read_p95_ms":reads[reads.len()*95/100],"read_max_ms":reads[reads.len()-1],
            "restart_ms":restart_ms,"rebuild_ms":rebuild_ms,"wal_peak_bytes":wal_peak,
            "disk_bytes":disk}),
        )
    }
}

#[test]
fn discovery_native_query_binder_and_limits() -> TestResult<()> {
    let db = Connection::open_in_memory()?;
    db.execute_batch(
        "CREATE TABLE events(id INTEGER,atom INTEGER,secret TEXT);
        INSERT INTO events VALUES(1,2,'SYNTHETIC-SECRET');",
    )?;
    SqliteExperiment::authorize(&db)?;
    assert_eq!(
        SqliteExperiment::query(&db, "SELECT id,atom FROM events")?,
        vec![vec![json!(1), json!(2)]]
    );
    for sql in [
        "SELECT secret FROM events",
        "SELECT id FROM events WHERE secret='x'",
        "SELECT id FROM events ORDER BY secret",
        "SELECT count(secret) FROM events",
        "SELECT * FROM events",
        "SELECT name FROM sqlite_master",
        "SELECT sqlite_version()",
        "ATTACH '/etc/passwd' AS stolen",
        "PRAGMA database_list",
        "SELECT load_extension('x')",
        "SELECT readfile('/etc/passwd')",
        "SELECT writefile('/tmp/x','x')",
        "DELETE FROM events",
        "SELECT id FROM events; SELECT atom FROM events",
        "SELECT ?1 FROM events",
        "WITH RECURSIVE x(n) AS(SELECT 1 UNION ALL SELECT n+1 FROM x) SELECT n FROM x",
        "SELECT id FROM events WHERE EXISTS(SELECT secret FROM events)",
    ] {
        assert!(
            SqliteExperiment::query(&db, sql).is_err(),
            "accepted: {sql}"
        );
    }
    Ok(())
}

#[test]
fn discovery_native_transactions_and_readers() -> TestResult<()> {
    let directory = tempfile::tempdir()?;
    SqliteExperiment::measure(&directory.path().join("small"), 10_000, 10_000, b"fixture")?;
    Ok(())
}

#[test]
fn discovery_native_output_and_cancellation() -> TestResult<()> {
    let db = Connection::open_in_memory()?;
    db.execute_batch(
        "CREATE TABLE events(id INTEGER,atom INTEGER);
        WITH RECURSIVE ids(n) AS(SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<201)
        INSERT INTO events SELECT n,n FROM ids;",
    )?;
    SqliteExperiment::authorize(&db)?;
    assert_eq!(
        SqliteExperiment::query(&db, "SELECT id FROM events LIMIT 200")?.len(),
        200
    );
    assert!(SqliteExperiment::query(&db, "SELECT id FROM events").is_err());
    let wide = format!("SELECT '{}' FROM events LIMIT 200", "x".repeat(6000));
    assert!(SqliteExperiment::query(&db, &wide).is_err());
    let started = Instant::now();
    assert!(SqliteExperiment::query(&db,"SELECT count(*) FROM events a CROSS JOIN events b CROSS JOIN events c CROSS JOIN events d CROSS JOIN events e").is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        SqliteExperiment::query(&db, "SELECT count(*) FROM events")?,
        vec![vec![json!(201)]]
    );
    Ok(())
}

#[test]
fn discovery_native_crash_boundaries() -> TestResult<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("index.db");
    let mut owner = SqliteExperiment::open(&path)?;
    owner.apply(0, 1, 2, b"fixture")?;
    drop(owner);
    for (stage, expected) in [("before", 1), ("after", 2)] {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "discovery::storage::discovery_native_crash_worker",
                "--exact",
                "--ignored",
            ])
            .env("MITHRIL_DISCOVERY_CRASH_DB", &path)
            .env("MITHRIL_DISCOVERY_CRASH_STAGE", stage)
            .status()?;
        assert_eq!(status.code(), Some(73));
        let owner = SqliteExperiment::open(&path)?;
        assert_eq!(owner.counts()?, (expected, expected, expected));
        let integrity: String = owner
            .db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        assert_eq!(integrity, "ok");
    }
    Ok(())
}

#[test]
#[ignore = "subprocess helper; requires the parent's temporary database"]
fn discovery_native_crash_worker() -> TestResult<()> {
    let path = PathBuf::from(std::env::var("MITHRIL_DISCOVERY_CRASH_DB")?);
    let mut owner = SqliteExperiment::open(&path)?;
    let transaction = owner.db.transaction()?;
    transaction.execute_batch(
        "INSERT INTO events VALUES(1,1,0,0,1,X'');
        INSERT INTO atoms VALUES(1,1,1); UPDATE head SET cursor=2;",
    )?;
    if std::env::var("MITHRIL_DISCOVERY_CRASH_STAGE")? == "after" {
        transaction.commit()?;
    }
    std::process::exit(73)
}

#[test]
#[ignore = "requires a disposable size-limited filesystem at MITHRIL_DISCOVERY_FULL_ROOT"]
fn discovery_native_filesystem_full() -> TestResult<()> {
    let root = PathBuf::from(std::env::var("MITHRIL_DISCOVERY_FULL_ROOT")?);
    let path = root.join("index.db");
    assert!(!path.exists());
    let mut owner = SqliteExperiment::open(&path)?;
    owner.apply(0, 1, 2, b"before-full")?;
    owner.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    let transaction = owner.db.transaction()?;
    let mut full = false;
    for id in 1..128 {
        match transaction.execute(
            "INSERT INTO events VALUES(?1,1,0,0,1,zeroblob(1048576))",
            [id],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DiskFull =>
            {
                full = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(full, "filesystem did not reject the bounded fill");
    drop(transaction);
    assert_eq!(owner.counts()?, (1, 1, 1));
    drop(owner);
    let owner = SqliteExperiment::open(&path)?;
    assert_eq!(owner.counts()?, (1, 1, 1));
    Ok(())
}

#[test]
#[ignore = "isolated subprocess helper; accepts only an authorized binary projection on stdin"]
fn discovery_native_query_worker() -> TestResult<()> {
    let sql = std::env::var("MITHRIL_DISCOVERY_QUERY_SQL")?;
    let mut db = Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE events(id INTEGER,atom INTEGER)")?;
    let transaction = db.transaction()?;
    let mut input = std::io::stdin().lock();
    let mut total = 0;
    {
        let mut insert = transaction.prepare("INSERT INTO events VALUES(?1,?2)")?;
        loop {
            let mut row = [0; 16];
            if input.read(&mut row[..1])? == 0 {
                break;
            }
            total += row.len();
            if total > 64 * 1024 * 1024 {
                return Err("PROJECTION_LIMIT".into());
            }
            input.read_exact(&mut row[1..])?;
            let id = i64::from_le_bytes(row[..8].try_into()?);
            let atom = i64::from_le_bytes(row[8..].try_into()?);
            insert.execute([id, atom])?;
        }
    }
    transaction.commit()?;
    SqliteExperiment::authorize(&db)?;
    let result = SqliteExperiment::query(&db, &sql)?;
    println!("ARAPHOR_QUERY_RESULT={}", serde_json::to_string(&result)?);
    Ok(())
}

#[test]
#[ignore = "requires an isolated qualification host and MITHRIL_DISCOVERY_STORAGE_OUTPUT"]
fn discovery_native_storage_qualification() -> TestResult<()> {
    let root = PathBuf::from(std::env::var("MITHRIL_DISCOVERY_STORAGE_OUTPUT")?);
    fs::create_dir(&root)?;
    let input = mithril_control::DiscoveryInputManifestV1::from_json(include_bytes!(
        "../../fixtures/discovery/manifest.json"
    ))?;
    let payload = serde_json::to_vec(&(&input.records[0], &input.contexts[0]))?;
    let count = 256 * 1024 * 1024 / (40 + u64::try_from(payload.len())?);
    assert!(count >= 50_000);
    let compact = SqliteExperiment::measure(&root.join("million"), 1_000_000, 50_000, b"")?;
    let complete =
        SqliteExperiment::measure(&root.join("full-envelopes"), count, 50_000, &payload)?;
    let status = fs::read_to_string("/proc/self/status")?;
    let peak = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or("missing RSS")?
        .split_whitespace()
        .nth(1)
        .ok_or("missing RSS value")?
        .parse::<u64>()?;
    assert!(peak < 256 * 1024, "RSS {peak} KiB exceeded the budget");
    super::write_json(
        &root.join("result.json"),
        &json!({"binding":"rusqlite-0.40.2",
        "sqlite":rusqlite::version(),"compact":compact,"full":complete,"rss_kib":peak,
        "result":"PASS","production_selection":"PENDING_OTHER_GATES"}),
    )?;
    Ok(())
}
