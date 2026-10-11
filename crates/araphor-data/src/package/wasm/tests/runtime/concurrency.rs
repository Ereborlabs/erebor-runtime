use std::sync::{mpsc, Arc};
use std::time::Duration;

use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_analysis_sdk as sdk;

use crate::package::wasm::execution::GuestEntry;
use crate::{AnalysisReadControl, InstalledAnalysis, PackageErrorCodeV1 as Code};

use super::TestResult;

fn input(tenant: u8, counts: [u64; 2]) -> sdk::Result<sdk::Evaluation> {
    let limits = sdk::Limits {
        max_batches: 4,
        max_rows: 16,
        max_bytes: 1024 * 1024,
        max_checkpoint_bytes: 1024 * 1024,
    };
    let atoms: Vec<_> = counts
        .into_iter()
        .enumerate()
        .map(|(index, count)| builtin::GroupAtom {
            group: format!("tenant-{tenant}"),
            source: format!("source-{tenant}"),
            cpu: u32::from(tenant),
            interval: [tenant; 16],
            atom: builtin::Atom {
                key: format!("atom-{index}"),
                count,
                first: index as u64 + 1,
                last: index as u64 + 1,
                samples: vec![builtin::Identity {
                    order: index as u64,
                    value: format!("tenant-{tenant}/sample-{index}"),
                }],
                prevented: false,
            },
        })
        .collect();
    let datasets = vec![
        Rows::encode(
            &builtin::Discovery::port::<builtin::GroupAtom>("atoms"),
            &atoms,
            limits,
        )?,
        Rows::encode::<builtin::Coverage>(
            &builtin::Discovery::port::<builtin::Coverage>("coverage"),
            &[],
            limits,
        )?,
    ];
    Ok(sdk::Evaluation {
        export: "groups".into(),
        inputs: datasets
            .into_iter()
            .map(|data| sdk::Input {
                data,
                revision: sdk::Revision {
                    owner: "concurrency-fixture".into(),
                    id: format!("tenant-{tenant}"),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            })
            .collect(),
        checkpoint: None,
        parameters: None,
        context: sdk::EvaluationContext {
            id: format!("tenant-{tenant}"),
            time_utc_ns: 123,
            seed: None,
            limits,
        },
    })
}

fn assert_group(result: &crate::InstalledEvaluation, tenant: u8, count: u64) -> TestResult {
    assert_eq!(result.evaluation.context.id, format!("tenant-{tenant}"));
    assert_eq!(result.output.datasets.len(), 1);
    let groups: Vec<builtin::Group> = Rows::decode(
        &builtin::Discovery::port::<builtin::Group>("groups"),
        &result.output.datasets[0],
        result.evaluation.context.limits,
    )?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].key, format!("tenant-{tenant}"));
    assert_eq!(groups[0].count, count);
    assert_eq!(groups[0].members, [0, 1]);
    assert_eq!(
        groups[0].samples,
        [
            builtin::Identity {
                order: 0,
                value: format!("tenant-{tenant}/sample-0"),
            },
            builtin::Identity {
                order: 1,
                value: format!("tenant-{tenant}/sample-1"),
            },
        ]
    );
    assert!(groups[0].coverage.is_empty());
    assert!(result.output.checkpoint.is_none());
    assert!(result.output.evidence.is_empty());
    assert!(result.output.reasons.is_empty());
    Ok(())
}

#[test]
fn installed_guests_overlap() -> TestResult {
    let execution = InstalledAnalysis::testing_tenants(None, &[[1; 16], [2; 16]])?;
    let owner = execution.testing_owner();
    let first = execution.snapshot([1; 16])?;
    let second = execution.snapshot([2; 16])?;
    assert!(Arc::ptr_eq(&owner, &first.testing_owner()));
    assert!(Arc::ptr_eq(&owner, &second.testing_owner()));
    let first_input = input(1, [2, 3])?;
    let second_input = input(2, [7, 11])?;
    let first_control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let second_control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    std::thread::scope(|scope| -> TestResult {
        let (entered, first_ready) = mpsc::channel();
        let (first_release, release) = mpsc::channel();
        *owner
            .wasm
            .entered
            .lock()
            .map_err(|_| Code::Incomplete.error("component test gate"))? = Some(GuestEntry {
            entered,
            release: Some(release),
        });
        let first =
            scope.spawn(|| first.evaluate([1; 16], "discovery", &first_input, &first_control));
        first_ready.recv_timeout(Duration::from_secs(5))?;

        let (entered, second_ready) = mpsc::channel();
        let (second_release, release) = mpsc::channel();
        *owner
            .wasm
            .entered
            .lock()
            .map_err(|_| Code::Incomplete.error("component test gate"))? = Some(GuestEntry {
            entered,
            release: Some(release),
        });
        let second =
            scope.spawn(|| second.evaluate([2; 16], "discovery", &second_input, &second_control));
        second_ready.recv_timeout(Duration::from_secs(5))?;

        first_release.send(())?;
        second_release.send(())?;
        let first = first
            .join()
            .map_err(|_| Code::Incomplete.error("component concurrency worker"))??;
        let second = second
            .join()
            .map_err(|_| Code::Incomplete.error("component concurrency worker"))??;
        assert_group(&first, 1, 5)?;
        assert_group(&second, 2, 18)?;
        Ok(())
    })
}
