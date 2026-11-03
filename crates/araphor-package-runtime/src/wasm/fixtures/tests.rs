use std::collections::BTreeSet;
use std::io::Write as _;

use super::*;

#[test]
fn fixture_code_retains_charges(
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let runtime = WasmExecution::new(WasmLimits::default())?;
    assert_eq!(runtime.limits.cache_bytes, None);
    assert_eq!(runtime.limits.cache_entries, None);
    let sources = WasmExecution::fixture_sources();
    let mut output = std::io::stdout();
    let mut components = BTreeSet::new();
    let mut required = 0usize;
    let mut total = 0usize;
    for (name, source) in sources {
        assert!(components.insert(source), "duplicate component: {name}");
        let prepared = runtime.compiled(
            source,
            &AnalysisReadControl::with_timeout(Duration::from_secs(45))?,
        )?;
        let image = prepared.instance_pre().component().image_range();
        let image_bytes = (image.end as usize)
            .checked_sub(image.start as usize)
            .ok_or("compiled image address range")?;
        assert!(image_bytes > 0);
        let charge = runtime
            .cache
            .lock()
            .map_err(|_| "component cache lock")?
            .charge(source)
            .ok_or("component cache charge")?;
        assert_eq!(
            charge,
            source.len() + image_bytes + std::mem::size_of::<super::super::cache::CacheEntry>(),
            "component: {name}"
        );
        total = total.checked_add(charge).ok_or("component cache total")?;
        if name != "runtime" {
            required = required
                .checked_add(charge)
                .ok_or("required component total")?;
        }
        writeln!(
            output,
            "component cache charge: name={name} source_bytes={} image_bytes={image_bytes} charge_bytes={charge}",
            source.len(),
        )?;
    }
    writeln!(
        output,
        "component cache totals: required_bytes={required} all_bytes={total} entries={}",
        components.len(),
    )?;
    assert_eq!(components.len(), sources.len());
    for (name, source) in sources {
        assert!(
            runtime.cached(source)?.is_some(),
            "component evicted: {name}",
        );
    }
    Ok(())
}

#[test]
fn fixture_options_stay_separate(
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let shared = WasmExecution::fixture_code(WasmLimits::default())?;
    for limits in [
        WasmLimits {
            cache_bytes: Some(1),
            ..Default::default()
        },
        WasmLimits {
            cache_entries: Some(1),
            ..Default::default()
        },
        WasmLimits {
            image_bytes: Some(1),
            ..Default::default()
        },
    ] {
        let configured = WasmExecution::fixture_code(limits)?;
        assert_eq!(configured.limits, limits);
        assert!(!wasmtime::Engine::same(&shared.engine, &configured.engine));
        for (_, source) in WasmExecution::fixture_sources() {
            assert!(configured.cached(source)?.is_none());
        }
    }
    let limits = WasmLimits {
        compiler_bytes: Some(1),
        ..Default::default()
    };
    for result in [
        WasmExecution::new(limits),
        WasmExecution::fixture_code(limits),
    ] {
        assert!(matches!(
            result,
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Unsupported,
                    field: "in-process compiler memory limit",
                    ..
                }
            })
        ));
    }
    Ok(())
}
