use std::collections::BTreeSet;
use std::io::Write as _;

use super::super::cache::{MAX_CACHE_BYTES, MAX_CACHE_ENTRIES, MAX_IMAGE_BYTES};
use super::*;

#[test]
fn fixture_cache_charges_fit() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let runtime = WasmExecution::new(WasmLimits::default())?;
    let sources = WasmExecution::fixture_sources();
    let mut output = std::io::stdout();
    let mut digests = BTreeSet::new();
    let mut required = 0usize;
    let mut total = 0usize;
    assert!(sources.len() <= MAX_CACHE_ENTRIES);
    for (name, source) in sources {
        let digest = Sha256::digest(source);
        let key: [u8; 32] = digest.into();
        assert!(digests.insert(key), "duplicate component: {name}");
        let prepared = runtime.compiled(
            source,
            &AnalysisReadControl::with_timeout(Duration::from_secs(45))?,
        )?;
        let image = prepared.instance_pre().component().image_range();
        let image_bytes = (image.end as usize)
            .checked_sub(image.start as usize)
            .ok_or("compiled image address range")?;
        assert!(image_bytes > 0 && image_bytes <= MAX_IMAGE_BYTES);
        let charge = runtime
            .cache
            .lock()
            .map_err(|_| "component cache lock")?
            .charge(&key)
            .ok_or("component cache charge")?;
        assert_eq!(charge, source.len() + image_bytes, "component: {name}");
        total = total.checked_add(charge).ok_or("component cache total")?;
        if name != "runtime" {
            required = required
                .checked_add(charge)
                .ok_or("required component total")?;
        }
        writeln!(
            output,
            "component cache charge: name={name} sha256={digest:x} source_bytes={} image_bytes={image_bytes} charge_bytes={charge}",
            source.len(),
        )?;
    }
    writeln!(
        output,
        "component cache totals: required_bytes={required} all_bytes={total} entries={} byte_limit={MAX_CACHE_BYTES} entry_limit={MAX_CACHE_ENTRIES}",
        digests.len(),
    )?;
    assert_eq!(digests.len(), sources.len());
    assert!(total <= MAX_CACHE_BYTES, "component cache total: {total}");
    for (name, source) in sources {
        assert!(
            runtime.cached(&Sha256::digest(source).into())?.is_some(),
            "component evicted: {name}",
        );
    }
    Ok(())
}
