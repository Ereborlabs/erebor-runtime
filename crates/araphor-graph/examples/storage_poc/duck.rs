use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use araphor_graph::{GraphStore, LayerRequest, Read, WriterCut};
use arrow_array::RecordBatch;
use duckdb::{Connection, OptionalExt, params};

use super::fixture::{Fixture, Step};
use super::{Change, Readout, Result, Timing};

pub struct Duck {
    connection: Connection,
    graph: GraphStore,
}

impl Duck {
    pub fn open(path: &Path, fixture: &Fixture) -> Result<Self> {
        let mut connection = Connection::open(path.join("graph.duckdb"))?;
        connection.execute_batch("SET threads=2; SET memory_limit='-1'")?;
        let exists: bool = connection.query_row(
            "SELECT count(*)>0 FROM information_schema.tables
            WHERE table_name='graph_layers'",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            connection.execute_batch(GraphStore::SCHEMA)?;
            connection.execute_batch("CREATE TABLE poc_state(writer UBIGINT,revision UBIGINT,
                kind UTINYINT,body BLOB,PRIMARY KEY(writer,revision,kind));
                CREATE TABLE poc_changes(revision UBIGINT,slot UBIGINT,body BLOB,
                    PRIMARY KEY(revision,slot));
                CREATE TABLE poc_commits(revision UBIGINT PRIMARY KEY,parent UBIGINT,captured UBIGINT);
                CREATE TABLE poc_head(revision UBIGINT); INSERT INTO poc_head VALUES(1)")?;
        }
        let graph = GraphStore::install(&connection)?;
        if !exists {
            let tx = connection.transaction()?;
            tx.execute_batch("INSERT INTO graph_writers VALUES(1,1),(2,1)")?;
            for (relation, shape) in &fixture.shapes {
                graph.create_relation(
                    &tx,
                    1,
                    *relation,
                    shape,
                    (*relation == 3).then_some((2, 2)),
                )?;
            }
            tx.commit()?;
        }
        Ok(Self { connection, graph })
    }

    pub fn apply(&mut self, fixture: &Fixture, step: &Step, commit: bool) -> Result<Timing> {
        let started = Instant::now();
        let journals = fixture.journals(step)?;
        let view = self.graph.read_view(
            &self.connection,
            1,
            step.captured,
            &[1, 2, 3],
            || Ok(()),
            |_| Ok(()),
        )?;
        let parent = |writer| (step.previous != 1).then_some(step.previous * 2 + writer);
        let cuts = [1, 2].map(|writer| WriterCut {
            writer,
            parent: parent(writer),
            revision: step.captured,
        });
        let views = BTreeMap::from([(1, &view), (2, &view)]);
        let journals = journals.values().collect::<Vec<_>>();
        let prepared =
            GraphStore::prepare_layers(&views, &cuts, &journals, &fixture.shapes, |_, _, _| {
                Ok(None)
            })?;
        let prepared_at = Instant::now();
        let tx = self.connection.transaction()?;
        let head: u64 = tx.query_row("SELECT revision FROM poc_head", [], |r| r.get(0))?;
        assert_eq!(head, step.previous);
        let requests = [1, 2].map(|writer| LayerRequest {
            writer,
            layer: step.revision * 2 + writer,
            parent: parent(writer),
        });
        let (counts, layer) = self
            .graph
            .begin_layers(&tx, step.revision, &requests)?
            .apply_prepared(prepared, |_, _, _| Ok(None))?;
        let (added, closed) = counts
            .values()
            .fold((0, 0), |(a, c), (x, y)| (a + *x as usize, c + *y as usize));
        assert_eq!(added, step.added());
        assert_eq!(closed, step.closed);
        {
            let mut appender = tx.appender("poc_state")?;
            for writer in [1, 2] {
                appender.append_row(params![writer, step.revision, 0, step.state(writer)])?;
                appender.append_row(params![
                    writer,
                    step.revision,
                    1,
                    step.captured.to_be_bytes().as_slice()
                ])?;
            }
            appender.flush()?;
        }
        let mut changes = Vec::new();
        layer.visit_changes(|member| {
            changes.push(Change {
                writer: member.writer,
                relation: member.relation,
                owner: member.owner_key.to_vec(),
                key: member.key.to_vec(),
                opened: member.revision,
                added: member.revision == step.revision,
            });
            Ok(())
        })?;
        changes.sort();
        {
            let mut appender = tx.appender("poc_changes")?;
            for (slot, change) in changes.iter().enumerate() {
                appender.append_row(params![
                    step.revision,
                    slot as u64,
                    rmp_serde::to_vec(change)?
                ])?;
            }
            appender.flush()?;
        }
        tx.execute(
            "INSERT INTO poc_commits VALUES(?,?,?)",
            params![step.revision, step.previous, step.captured],
        )?;
        tx.execute("UPDATE poc_head SET revision=?", params![step.revision])?;
        let work_s = prepared_at.elapsed().as_secs_f64();
        let synced = Instant::now();
        if commit {
            tx.commit()?;
            layer.commit();
        } else {
            drop(layer);
            tx.rollback()?;
        }
        Ok(Timing {
            revision: step.revision,
            prepare_s: prepared_at.duration_since(started).as_secs_f64(),
            work_s,
            commit_s: synced.elapsed().as_secs_f64(),
            total_s: started.elapsed().as_secs_f64(),
            added,
            closed,
            ..Default::default()
        })
    }

    pub fn verify_metadata(&self, fixture: &Fixture, revision: u64, current: u64) -> Result<()> {
        let head: u64 = self
            .connection
            .query_row("SELECT revision FROM poc_head", [], |r| r.get(0))?;
        assert_eq!(head, current);
        let last = fixture
            .steps
            .iter()
            .filter(|s| s.revision <= revision)
            .next_back();
        for writer in [1, 2] {
            let actual: Option<u64> = self.connection.query_row(
                "SELECT max(revision) FROM graph_layers WHERE writer_id=? AND revision<=?",
                params![writer, revision],
                |r| r.get(0),
            )?;
            assert_eq!(actual, last.map(|s| s.revision));
        }
        let actual = self
            .connection
            .query_row(
                "SELECT parent,captured FROM poc_commits WHERE revision=?",
                params![revision],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)),
            )
            .optional()?;
        let expected = fixture
            .steps
            .iter()
            .find(|s| s.revision == revision)
            .map(|s| (s.previous, s.captured));
        assert_eq!(actual, expected);
        Ok(())
    }

    pub fn inspect(&self, fixture: &Fixture, revision: u64, all: bool) -> Result<Readout> {
        let started = Instant::now();
        let view = self.graph.read_view(
            &self.connection,
            1,
            revision,
            &[1, 2, 3],
            || Ok(()),
            |_| Ok(()),
        )?;
        let mut states = Vec::new();
        for writer in [1, 2] {
            for kind in [0, 1] {
                states.push(
                    self.connection
                        .query_row(
                            "SELECT body FROM poc_state WHERE writer=? AND kind=?
                AND revision<=? ORDER BY revision DESC LIMIT 1",
                            params![writer, kind, revision],
                            |r| r.get(0),
                        )
                        .optional()?,
                );
            }
        }
        let capture_s = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let mut rows = Vec::new();
        let mut batches = Vec::new();
        if all {
            for relation in [1, 2, 3] {
                view.read(
                    relation,
                    &fixture.shapes[&relation],
                    Read::Owned(if relation == 1 { 2 } else { 1 }),
                    &RecordBatch::new_empty(Arc::new(arrow_schema::Schema::empty())),
                    || Ok(()),
                    |_| Ok(()),
                    |batch, origins| {
                        batches.push((relation, batch, origins));
                        Ok(())
                    },
                )?;
            }
        } else {
            let keys = fixture.keys()?;
            for (relation, operation) in
                [(2, Read::Nodes), (3, Read::Outgoing), (1, Read::Owned(2))]
            {
                let empty = RecordBatch::new_empty(Arc::new(arrow_schema::Schema::empty()));
                let keys = if relation == 1 { &empty } else { &keys };
                view.read(
                    relation,
                    &fixture.shapes[&relation],
                    operation,
                    keys,
                    || Ok(()),
                    |_| Ok(()),
                    |batch, origins| {
                        batches.push((relation, batch, origins));
                        Ok(())
                    },
                )?;
            }
        }
        for (relation, batch, origins) in batches {
            rows.extend(super::rows_from_batch(
                relation,
                batch,
                &origins.iter().map(|o| o.revision).collect::<Vec<_>>(),
            )?);
        }
        let read_s = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let mut query = self
            .connection
            .prepare("SELECT body FROM poc_changes WHERE revision=? ORDER BY slot")?;
        let values = query
            .query_map(params![revision], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<duckdb::Result<Vec<_>>>()?;
        let mut changes = values
            .iter()
            .map(|v| rmp_serde::from_slice::<Change>(v).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        changes.sort();
        Ok(Readout {
            rows,
            states,
            changes,
            capture_s,
            read_s,
            cdc_s: started.elapsed().as_secs_f64(),
        })
    }
}
