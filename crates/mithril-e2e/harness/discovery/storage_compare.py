"""Measure storage and isolated SQL. This experiment grants no authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import statistics
import struct
import subprocess
import sys
import time
import traceback

MIB = 1024 * 1024


def connect(engine, path):
    if engine == "sqlite":
        import apsw
        db = apsw.Connection(str(path))
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA cache_size=-65536")
        db.execute("PRAGMA wal_autocheckpoint=256")
        return db, apsw.sqlitelibversion()
    import duckdb
    db = duckdb.connect(str(path), config={"threads": 1, "memory_limit": "64MiB",
        "preserve_insertion_order": "false",
        "enable_external_access": "false", "autoinstall_known_extensions": "false",
        "autoload_known_extensions": "false"})
    return db, duckdb.__version__


def rows(db, sql):
    return list(db.execute(sql).fetchall())


def apply_batch(db, engine, first, last, atoms, crash=None):
    db.execute("BEGIN TRANSACTION")
    try:
        db.execute("DELETE FROM pending")
        source = (f"SELECT range AS i FROM range({first}, {last})" if engine == "duckdb" else
            f"WITH RECURSIVE numbers(i) AS (SELECT {first} UNION ALL SELECT i+1 FROM numbers WHERE i+1<{last}) SELECT i FROM numbers")
        db.execute(f"INSERT INTO pending SELECT i, i%{atoms}, (i-(i%100000))/100000, CASE WHEN i%997=0 THEN 1 ELSE 0 END, i%2 FROM ({source})")
        mismatch = rows(db, "SELECT count(*) FROM pending p JOIN events e ON p.id=e.id WHERE p.atom<>e.atom OR p.revision<>e.revision OR p.decision<>e.decision OR p.tenant<>e.tenant")[0][0]
        if mismatch:
            raise ValueError("CONFLICTING_RECORD")
        db.execute("INSERT INTO atoms SELECT p.atom, p.tenant, count(*) FROM pending p WHERE NOT EXISTS (SELECT 1 FROM events e WHERE e.id=p.id) GROUP BY p.atom,p.tenant ON CONFLICT(atom,tenant) DO UPDATE SET n=atoms.n+excluded.n")
        db.execute("INSERT INTO events SELECT * FROM pending WHERE true ON CONFLICT(id) DO NOTHING")
        db.execute(f"UPDATE head SET cursor=CASE WHEN cursor<{last} THEN {last} ELSE cursor END")
        if crash == "before-commit":
            os._exit(73)
        db.execute("COMMIT")
        if crash == "after-commit":
            os._exit(73)
    except Exception:
        db.execute("ROLLBACK")
        raise


def percentile(samples, fraction):
    return sorted(samples)[min(len(samples)-1, int(len(samples)*fraction))]


def admit(sql, engine):
    import sqlglot
    if len(sql.encode()) > 16384:
        raise ValueError("QUERY_SIZE")
    expressions = sqlglot.parse(sql, read="sqlite" if engine == "sqlite" else "duckdb")
    if len(expressions) != 1 or not isinstance(expressions[0], sqlglot.exp.Select):
        raise ValueError("QUERY_SHAPE")
    allowed = {"Select", "From", "Table", "Identifier", "Column", "Where", "EQ", "GT",
        "GTE", "LT", "LTE", "And", "Or", "Not", "Literal", "Count", "Sum", "Max", "Min",
        "Avg", "Alias", "Group", "Order", "Ordered", "Limit", "Join", "TableAlias",
        "Paren", "Distinct", "Star"}
    for node in expressions[0].walk():
        if type(node).__name__ not in allowed:
            raise ValueError("QUERY_NODE:" + type(node).__name__)
        if isinstance(node, sqlglot.exp.Table) and (node.name != "events" or node.db or node.catalog):
            raise ValueError("QUERY_VIEW")
        if isinstance(node, sqlglot.exp.Column) and node.name not in {"id", "atom"}:
            raise ValueError("QUERY_FIELD")
    return expressions[0].sql(dialect="sqlite" if engine == "sqlite" else "duckdb")


def query_worker(engine, sql):
    resource.setrlimit(resource.RLIMIT_AS, (256*MIB, 256*MIB))
    resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MIB, MIB))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    body = sys.stdin.buffer.read(64*MIB+1)
    if len(body) > 64*MIB:
        raise ValueError("PROJECTION_LIMIT")
    projection = json.loads(body)
    db, version = connect(engine, ":memory:")
    db.execute("CREATE TABLE events(id BIGINT, atom BIGINT)")
    db.executemany("INSERT INTO events VALUES (?,?)", projection)
    signal.setitimer(signal.ITIMER_REAL, 1)
    cursor = db.execute(sql)
    result = []
    for _ in range(201):
        row = cursor.fetchone()
        if row is None:
            break
        result.append(row)
    if len(result) > 200:
        raise ValueError("OUTPUT_ROWS")
    encoded = json.dumps({"rows": result, "version": version, "rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
    if len(encoded.encode()) > MIB:
        raise ValueError("OUTPUT_BYTES")
    signal.setitimer(signal.ITIMER_REAL, 0)
    print(encoded)


def isolated_query(engine, sql, projection):
    sql = admit(sql, engine)
    packages = str(Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages")
    command = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--ro-bind", packages, "/packages",
        "--ro-bind", str(Path(__file__).resolve()), "/worker.py",
        "--clearenv", "--setenv", "PYTHONPATH", "/packages",
        "--setenv", "OPENBLAS_NUM_THREADS", "1", "--setenv", "OMP_NUM_THREADS", "1",
        "--", "/usr/bin/python3", "/worker.py", "--query-worker", engine, sql]
    started = time.perf_counter()
    result = subprocess.run(command, input=json.dumps(projection), text=True,
        capture_output=True, timeout=2, close_fds=True, env={"PATH": "/usr/bin:/bin"})
    return {"elapsed_ms": (time.perf_counter()-started)*1000,
        "returncode": result.returncode, "stdout": result.stdout[:4096], "stderr": result.stderr[:4096]}


def measure(engine, manifest, directory, count, atom_count):
    db, version = connect(engine, directory / (engine + ".db"))
    db.execute("CREATE TABLE events(id BIGINT PRIMARY KEY, atom BIGINT, revision BIGINT, decision BIGINT, tenant BIGINT)")
    db.execute("CREATE TABLE pending(id BIGINT PRIMARY KEY, atom BIGINT, revision BIGINT, decision BIGINT, tenant BIGINT)")
    db.execute("CREATE TABLE atoms(atom BIGINT, tenant BIGINT, n BIGINT, PRIMARY KEY(atom,tenant))")
    db.execute("CREATE TABLE head(cursor BIGINT)")
    db.execute("INSERT INTO head VALUES (0)")
    if engine == "sqlite":
        db.execute("CREATE INDEX event_atom ON events(atom,tenant,id)")
    digest = hashlib.sha256()
    timings, wal_peak = [], 0
    started = time.perf_counter()
    for first in range(0, count, 4096):
        last = min(count, first+4096)
        for i in range(first, last):
            digest.update(struct.pack("<QQQQQ", i, i % atom_count, i // 100000, int(i % 997 == 0), i % 2))
        tick = time.perf_counter()
        apply_batch(db, engine, first, last, atom_count)
        timings.append((time.perf_counter()-tick)*1000)
        wal_peak = max(wal_peak, sum(p.stat().st_size for p in directory.iterdir() if "wal" in p.name))
    ingestion_seconds = time.perf_counter()-started
    expected_atoms = min(count, atom_count)
    assert rows(db, "SELECT count(*) FROM events")[0][0] == count
    assert rows(db, "SELECT count(*),sum(n) FROM atoms")[0] == (expected_atoms, count)
    apply_batch(db, engine, 0, min(count,4096), atom_count)
    assert rows(db, "SELECT sum(n) FROM atoms")[0][0] == count
    db.execute("UPDATE events SET decision=99 WHERE id=0")
    try:
        apply_batch(db, engine, 0, min(count,4096), atom_count)
        raise AssertionError("conflicting replay was accepted")
    except ValueError as error:
        assert str(error) == "CONFLICTING_RECORD"
    db.execute("UPDATE events SET decision=1 WHERE id=0")
    statements = {
        "page": "SELECT atom,n FROM atoms WHERE tenant=0 AND atom>100 ORDER BY atom LIMIT 200",
        "context_join": "SELECT e.id,a.n FROM events e JOIN atoms a ON e.atom=a.atom AND e.tenant=a.tenant WHERE e.id<200 ORDER BY e.id",
        "evidence_pivot": f"SELECT id,decision FROM events WHERE atom={atom_count//2} ORDER BY id LIMIT 200",
        "revision_diff": "SELECT revision,decision,count(*) FROM events GROUP BY revision,decision ORDER BY revision,decision",
    }
    queries = {}
    for name, sql in statements.items():
        samples = []
        result_digest = None
        for _ in range(21):
            tick = time.perf_counter()
            result = rows(db, sql)
            samples.append((time.perf_counter()-tick)*1000)
            current = hashlib.sha256(json.dumps(result).encode()).hexdigest()
            assert result_digest is None or current == result_digest
            result_digest = current
        queries[name] = {"first_ms": samples[0], "warm_p50_ms": statistics.median(samples[1:]),
            "warm_p95_ms": percentile(samples[1:], .95), "result_digest": result_digest,
            "plan": rows(db, ("EXPLAIN QUERY PLAN " if engine == "sqlite" else "EXPLAIN ")+sql)}
    canonical = hashlib.sha256(json.dumps(rows(db, "SELECT * FROM atoms ORDER BY atom,tenant")).encode()).hexdigest()
    projection = rows(db, "SELECT id,atom FROM events WHERE tenant=0 AND id<400 ORDER BY id")
    tick = time.perf_counter()
    db.close()
    db, _ = connect(engine, directory / (engine + ".db"))
    assert rows(db, "SELECT cursor FROM head")[0][0] == count
    assert rows(db, "SELECT sum(n) FROM atoms")[0][0] == count
    restart_ms = (time.perf_counter()-tick)*1000
    db.close()
    recovery = []
    for stage in ("before-commit", "after-commit"):
        tick = time.perf_counter()
        child = subprocess.run([sys.executable, __file__, "--crash-worker", engine,
            str(directory / (engine + ".db")), str(count), str(atom_count), stage], timeout=10)
        assert child.returncode == 73
        db, _ = connect(engine, directory / (engine + ".db"))
        expected = count + int(stage == "after-commit")
        assert rows(db, "SELECT count(*) FROM events")[0][0] == expected
        assert rows(db, "SELECT sum(n) FROM atoms")[0][0] == expected
        assert rows(db, "SELECT cursor FROM head")[0][0] == expected
        recovery.append({"stage": stage, "records": expected, "recovery_ms": (time.perf_counter()-tick)*1000})
        db.close()
    db, _ = connect(engine, directory / (engine + ".db"))
    tick = time.perf_counter()
    db.execute("CREATE TABLE rebuilt AS SELECT atom,tenant,count(*) AS n FROM events GROUP BY atom,tenant")
    assert rows(db, "SELECT * FROM rebuilt ORDER BY atom,tenant") == rows(db, "SELECT * FROM atoms ORDER BY atom,tenant")
    rebuild_ms = (time.perf_counter()-tick)*1000
    disk_full = "Not run"
    if engine == "sqlite":
        import apsw
        page_limit = rows(db, "PRAGMA page_count")[0][0] + 1
        db.execute(f"PRAGMA max_page_count={page_limit}")
        db.execute("CREATE TABLE disk_full_probe(value BLOB)")
        try:
            db.execute("INSERT INTO disk_full_probe VALUES (zeroblob(8388608))")
            raise AssertionError("disk-full probe did not reach the page limit")
        except apsw.FullError:
            assert rows(db, "SELECT count(*) FROM disk_full_probe")[0][0] == 0
            assert rows(db, "SELECT cursor FROM head")[0][0] == count+1
            disk_full = "Page-limit rejection preserved the committed head"
    db.close()
    rejected = 0
    for sql in ["ATTACH '/tmp/secret' AS secret", "SELECT * FROM read_csv('/etc/passwd')",
        "SELECT load_extension('x')", "SELECT decision FROM events", "SELECT count(*) FROM events WHERE tenant=1",
        "SELECT * FROM sqlite_master", "SELECT * FROM information_schema.tables",
        "SELECT 1; SELECT 2", "WITH RECURSIVE x AS (SELECT 1) SELECT * FROM x"]:
        try:
            admit(sql, engine)
            raise AssertionError("unsafe query admitted: " + sql)
        except ValueError:
            rejected += 1
    try:
        isolation = isolated_query(engine, "SELECT count(*) FROM events", projection)
        if isolation["returncode"] == 0:
            assert json.loads(isolation["stdout"])["rows"] == [[len(projection)]]
    except (subprocess.TimeoutExpired, OSError) as error:
        isolation = {"error": str(error)}
    hostile_sql = "SELECT count(*) FROM events a JOIN events b ON a.id>b.id JOIN events c ON b.id>c.id JOIN events d ON c.id>d.id JOIN events e ON d.id>e.id"
    try:
        cancellation = isolated_query(engine, hostile_sql, projection)
    except (subprocess.TimeoutExpired, OSError) as error:
        cancellation = {"error": str(error)}
    return {"engine": engine, "version": version, "manifest_digest": hashlib.sha256(manifest).hexdigest(),
        "input_digest": digest.hexdigest(), "records": count, "atoms": atom_count,
        "ingestion_seconds": ingestion_seconds, "batch_p95_ms": percentile(timings,.95),
        "batch_max_ms": max(timings), "wal_peak_bytes": wal_peak,
        "disk_bytes": sum(p.stat().st_size for p in directory.iterdir()),
        "rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "canonical_digest": canonical, "queries": queries, "clean_restart_ms": restart_ms,
        "rejected_sql": rejected, "isolation": isolation,
        "adversarial_join": cancellation,
        "crash_recovery": recovery, "rebuild_ms": rebuild_ms, "disk_full": disk_full,
        "selection": "Reject", "reason": "qualification incomplete: native Rust binding, full projection limits, concurrent owner latency, and qualified-host repeat runs remain"}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--query-worker":
        query_worker(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) > 1 and sys.argv[1] == "--crash-worker":
        db, _ = connect(sys.argv[2], sys.argv[3])
        count = int(sys.argv[4])
        apply_batch(db, sys.argv[2], count, count+1, int(sys.argv[5]), sys.argv[6])
        raise AssertionError("the crash worker returned")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--engines", default="sqlite,duckdb")
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--records", type=int, default=1_000_000)
    parser.add_argument("--atoms", type=int, default=50_000)
    parser.add_argument("--engine-child", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.records <= 1_000_000 or not 1 <= args.atoms <= 50_000 or args.atoms % 2:
        parser.error("input bounds: 1..1000000 records; 2..50000 even atoms")
    engines = args.engines.split(",")
    if not engines or any(engine not in {"sqlite", "duckdb"} for engine in engines):
        parser.error("engines must be sqlite,duckdb")
    manifest = args.manifest.read_bytes()
    if len(manifest) > 256*MIB or json.loads(manifest)["schema_version"] != 1:
        parser.error("invalid input manifest")
    args.output_directory.mkdir(exist_ok=False)
    cpus = sorted(os.sched_getaffinity(0))[:4]
    os.sched_setaffinity(0, cpus)
    if args.engine_child:
        try:
            result = measure(engines[0], manifest, args.output_directory, args.records, args.atoms)
        except Exception as error:
            result = {"engine": engines[0], "selection": "Reject", "error_type": type(error).__name__,
                "error": str(error), "traceback": traceback.format_exc(),
                "rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    else:
        results = []
        for engine in engines:
            subprocess.run([sys.executable, __file__, "--manifest", str(args.manifest), "--engines", engine,
                "--output-directory", str(args.output_directory / engine), "--records", str(args.records),
                "--atoms", str(args.atoms), "--engine-child"], check=True, timeout=600)
            results.append(json.loads((args.output_directory / engine / "result.json").read_text()))
        completed = [result for result in results if "input_digest" in result]
        assert len({result["input_digest"] for result in completed}) <= 1
        assert len({result["canonical_digest"] for result in completed}) <= 1
        assert len({result["queries"]["revision_diff"]["result_digest"] for result in completed}) <= 1
        result = {"host": platform.uname()._asdict(), "cpu_affinity": cpus,
            "python": sys.version, "decoded_row_bytes": args.records*40,
            "selection": "Reject", "engines": results}
    with (args.output_directory / "result.json").open("x") as output:
        json.dump(result, output, indent=2)
    print(json.dumps({"result": str(args.output_directory / "result.json"), "selection": result["selection"]}))


if __name__ == "__main__":
    main()
