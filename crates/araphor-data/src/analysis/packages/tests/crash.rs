use super::*;

#[test]
fn packages_commit_crashes() -> TestResult {
    if let Some(root) = std::env::var_os("ARAPHOR_CRASH_ROOT") {
        let store = AnalysisStore::open(std::path::PathBuf::from(root))?;
        let current = store
            .package_activation(&activation("first", "v1").key)?
            .ok_or("activation absent")?;
        let upgrade = std::env::var("ARAPHOR_PACKAGE_UPGRADE")? == "true";
        if upgrade {
            let mut next = current.clone();
            next.revision = "v2".into();
            let input = commit(next.clone(), "after");
            store.activate_package(&next, Some(current.generation), Some(&input), || Ok(()))?;
        } else {
            store.commit_package(&commit(current, "after"), || Ok(()))?;
        }
        return Err("the requested package crash did not occur".into());
    }
    for upgrade in [false, true] {
        for point in ["package.before", "package.after"] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("store");
            let store = AnalysisStore::open(&root)?;
            let active = start(&store, "first")?;
            if upgrade {
                store.commit_package(&commit(active.clone(), "before"), || Ok(()))?;
                store.install_package(&[package("first", "v2")?], || Ok(()))?;
            }
            let prior = store
                .package_activation(&active.key)?
                .ok_or("activation absent")?;
            drop(store);
            let status = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "analysis::packages::tests::crash::packages_commit_crashes",
                ])
                .env("ARAPHOR_CRASH_ROOT", &root)
                .env("ARAPHOR_CRASH_POINT", point)
                .env("ARAPHOR_PACKAGE_UPGRADE", upgrade.to_string())
                .status()?;
            assert_eq!(status.code(), Some(73), "{point}, upgrade={upgrade}");
            let store = AnalysisStore::open(&root)?;
            let current = store
                .package_activation(&active.key)?
                .ok_or("activation absent")?;
            let result = store.package_result([1; 16], "after")?;
            if point == "package.before" {
                assert_eq!(current, prior);
                assert!(result.is_none());
            } else {
                let result = result.ok_or("committed result absent")?;
                assert_eq!(current.result_id.as_deref(), Some("after"));
                assert_eq!(current.checkpoint_revision, result.commit_revision);
                assert_eq!(current.revision, if upgrade { "v2" } else { "v1" });
                assert_eq!(result.checkpoint, b"state");
                assert_eq!(result.datasets, b"rows");
            }
        }
    }
    Ok(())
}
