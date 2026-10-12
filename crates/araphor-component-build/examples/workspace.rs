use std::path::PathBuf;

use araphor_component_build::ComponentBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let root = PathBuf::from(arguments.next().ok_or("expected workspace root")?);
    let target = PathBuf::from(arguments.next().ok_or("expected guest target directory")?);
    let output = PathBuf::from(arguments.next().ok_or("expected component directory")?);
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    ComponentBuilder::workspace(&root, &target, &output)?;
    println!("{}", output.display());
    Ok(())
}
