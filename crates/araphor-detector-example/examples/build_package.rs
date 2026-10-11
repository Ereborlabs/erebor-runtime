use std::path::PathBuf;

use araphor_component_build::ComponentBuilder;
use araphor_detector_example::BurstDetector;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let core = PathBuf::from(arguments.next().ok_or("expected core Wasm path")?);
    let directory = PathBuf::from(arguments.next().ok_or("expected package directory")?);
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    ComponentBuilder::package(&BurstDetector::package(), &core, &directory)?;
    println!("{}", directory.join("package.json").display());
    Ok(())
}
