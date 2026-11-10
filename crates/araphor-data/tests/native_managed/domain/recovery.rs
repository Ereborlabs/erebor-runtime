use super::*;

#[test]
fn recovery_rejects_damaged_projection_identity_and_indexes() -> TestResult {
    for fault in [
        "member",
        "owner_id",
        "group",
        "live",
        "owned",
        "group-index",
        "canonical",
        "candidate",
        "finding",
        "import",
        "import-revision",
        "extra-import",
        "proof-cpu",
        "graph-proof-report",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let (_, model, _, observation) = fixture(&store)?;
        commit(&store, &model, &observation, 0)?;
        if fault == "proof-cpu" || fault == "graph-proof-report" {
            let snapshot = store.view()?;
            let mut tx = store.write()?;
            let mut changed = 0;
            for entry in snapshot.snapshot().prefix(b"\0data/X") {
                let (key, bytes) = entry?;
                if key.len() != 15 {
                    continue;
                }
                let mut value: serde_value::Value = rmp_serde::from_slice(&bytes[1..])?;
                let body = super::super::attempts::field(&mut value, &["body"])?;
                let serde_value::Value::Map(variants) = body else {
                    return Err("result body".into());
                };
                let record = variants.first_entry().ok_or("result kind")?.into_mut();
                if fault == "proof-cpu" {
                    let serde_value::Value::Seq(proofs) =
                        super::super::attempts::field(record, &["proofs"])?
                    else {
                        return Err("proofs".into());
                    };
                    let serde_value::Value::Seq(proof) = proofs.first_mut().ok_or("proof")? else {
                        return Err("proof pair".into());
                    };
                    *super::super::attempts::field(&mut proof[0], &["cpu_id"])? =
                        serde_value::Value::U32(99);
                } else {
                    let Ok(proof) = super::super::attempts::field(record, &["graph_proof"]) else {
                        continue;
                    };
                    let serde_value::Value::Seq(sources) =
                        super::super::attempts::field(proof, &["sources"])?
                    else {
                        return Err("Graph proof sources".into());
                    };
                    *super::super::attempts::field(
                        sources.first_mut().ok_or("proof source")?,
                        &["report"],
                    )? = serde_value::Value::U64(1);
                }
                tx.native()
                    .insert(key, [vec![0], rmp_serde::to_vec(&value)?].concat());
                changed += 1;
            }
            assert_eq!(changed, if fault == "proof-cpu" { 3 } else { 2 });
            tx.commit([])?;
            drop(snapshot);
            drop(store);
            assert!(NativeStore::open(&root).is_err(), "accepted {fault}");
            continue;
        }
        let (key, mut value) = row(
            &store,
            match fault {
                "member" | "owner_id" | "group" => b"\0data/graph/property/",
                "live" => b"\0data/graph/live/",
                "owned" => b"\0data/graph/owned/",
                "group-index" => b"\0data/graph/group/",
                "canonical" => b"\0data/graph/canonical/",
                "candidate" => b"\0data/graph/candidate/",
                "import" | "import-revision" | "extra-import" => b"\0data/ref/import/",
                _ => b"\0data/graph/finding/",
            },
        )?;
        let mut tx = store.write()?;
        match fault {
            "member" | "owner_id" | "group" => {
                let serde_value::Value::Map(mut decoded) =
                    rmp_serde::from_slice::<serde_value::Value>(&value[1..])?
                else {
                    return Err("property map".into());
                };
                let field = decoded
                    .get_mut(&serde_value::Value::String(fault.into()))
                    .ok_or("property field")?;
                *field = serde_value::Value::U64(u64::MAX);
                value = [vec![0], rmp_serde::to_vec(&decoded)?].concat();
                tx.native().insert(key, value);
            }
            "canonical" => {
                tx.native().insert(key, u64::MAX.to_be_bytes());
            }
            "import-revision" => {
                tx.native().insert(key, u64::MAX.to_be_bytes());
            }
            "extra-import" => {
                let mut extra = key;
                let length = extra.len();
                extra[length - 8..].copy_from_slice(&u64::MAX.to_be_bytes());
                tx.native().insert(extra, value);
            }
            _ => {
                tx.native().remove(key);
            }
        }
        tx.commit([])?;
        drop(store);
        assert!(NativeStore::open(&root).is_err(), "accepted {fault}");
    }
    Ok(())
}
