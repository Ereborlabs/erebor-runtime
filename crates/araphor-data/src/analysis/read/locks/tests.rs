use std::sync::mpsc;
use std::time::Duration;

use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn locks_wake_without_runtime() -> TestResult {
    for outcome in ["unlock", "cancel", "deadline"] {
        let lock = Mutex::new(0_u64);
        let control = if outcome == "deadline" {
            AnalysisReadControl::with_timeout(Duration::from_millis(100))?
        } else {
            AnalysisReadControl::default()
        };
        let (entered, observed) = mpsc::channel();
        *control.wait_signal.lock().map_err(|_| "wait signal")? = Some(entered);
        let mut held = lock.lock().map_err(|_| "held mutex")?;
        std::thread::scope(|scope| -> TestResult {
            let waiting = scope.spawn(|| lock.until(&control).map(|value| *value));
            observed.recv_timeout(Duration::from_secs(2))?;
            if outcome == "cancel" {
                control.cancel()?;
            }
            *held = 7;
            let mut held = Some(held);
            if outcome == "unlock" {
                drop(held.take());
            }
            let result = waiting.join().map_err(|_| "waiting thread")?;
            match outcome {
                "unlock" => assert_eq!(result?, 7),
                "cancel" => assert!(matches!(
                    result,
                    Err(crate::Error::AnalysisReadCancelled { .. })
                )),
                "deadline" => assert!(matches!(
                    result,
                    Err(crate::Error::AnalysisReadDeadline { .. })
                )),
                _ => unreachable!(),
            }
            if outcome != "unlock" {
                assert!(matches!(lock.try_lock(), Err(TryLockError::WouldBlock)));
            }
            drop(held);
            Ok(())
        })?;
        assert_eq!(*lock.lock().map_err(|_| "released mutex")?, 7);
    }
    Ok(())
}

#[test]
fn registration_keeps_unlock() -> TestResult {
    for cancel in [false, true] {
        let lock = Mutex::new(7_u64);
        let control = AnalysisReadControl::default();
        let held = lock.lock().map_err(|_| "held mutex")?;
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        std::thread::scope(|scope| -> TestResult {
            let selected = &lock;
            let stage = &control;
            let waiting = scope.spawn(move || {
                let mut first = true;
                stage
                    .lock(&selected.available, || {
                        let result = selected.try_lock();
                        if first && matches!(result, Err(TryLockError::WouldBlock)) {
                            first = false;
                            assert!(entered.send(()).is_ok());
                            assert!(released.recv_timeout(Duration::from_secs(2)).is_ok());
                        }
                        result
                    })
                    .map(|value| *value)
            });
            observed.recv_timeout(Duration::from_secs(2))?;
            if cancel {
                control.cancel()?;
            }
            drop(held);
            release.send(())?;
            let result = waiting.join().map_err(|_| "registered waiter")?;
            if cancel {
                assert!(matches!(
                    result,
                    Err(crate::Error::AnalysisReadCancelled { .. })
                ));
            } else {
                assert_eq!(result?, 7);
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
#[allow(clippy::panic, reason = "The test must poison the held mutex.")]
fn poison_wakes_waiters() -> TestResult {
    let lock = Mutex::new(());
    let control = AnalysisReadControl::default();
    let (locked, holding) = mpsc::channel();
    let (poison, poisoning) = mpsc::channel();
    let (entered, observed) = mpsc::channel();
    *control.wait_signal.lock().map_err(|_| "wait signal")? = Some(entered);
    std::thread::scope(|scope| -> TestResult {
        let selected = &lock;
        let owner = scope.spawn(move || {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> TestResult {
                    let _held = selected.lock().map_err(|_| "held mutex")?;
                    locked.send(())?;
                    poisoning.recv_timeout(Duration::from_secs(2))?;
                    panic!("poison the held mutex");
                }));
            assert!(result.is_err());
        });
        holding.recv_timeout(Duration::from_secs(2))?;
        let waiter = scope.spawn(|| lock.until(&control).map(|_| ()));
        observed.recv_timeout(Duration::from_secs(2))?;
        poison.send(())?;
        owner.join().map_err(|_| "poison owner")?;
        let error = waiter
            .join()
            .map_err(|_| "poison waiter")?
            .err()
            .ok_or("poison accepted")?;
        assert!(matches!(error, crate::Error::AnalysisState { .. }));
        assert!(lock.lock().is_err());
        Ok(())
    })?;
    Ok(())
}

#[test]
fn readers_wake_together() -> TestResult {
    let lock = RwLock::new(7_u64);
    let held = lock.write().map_err(|_| "held writer")?;
    let controls = [
        AnalysisReadControl::default(),
        AnalysisReadControl::default(),
    ];
    let (entered, observed) = mpsc::channel();
    for control in &controls {
        *control.wait_signal.lock().map_err(|_| "wait signal")? = Some(entered.clone());
    }
    std::thread::scope(|scope| -> TestResult {
        let first = scope.spawn(|| lock.read_until(&controls[0]).map(|value| *value));
        let second = scope.spawn(|| lock.read_until(&controls[1]).map(|value| *value));
        observed.recv_timeout(Duration::from_secs(2))?;
        observed.recv_timeout(Duration::from_secs(2))?;
        drop(held);
        assert_eq!(first.join().map_err(|_| "first reader")??, 7);
        assert_eq!(second.join().map_err(|_| "second reader")??, 7);
        Ok(())
    })?;
    Ok(())
}
