use std::path::PathBuf;

use araphor_component_build::ComponentBuilder;
use clap::Parser;

#[derive(Parser)]
#[command(about = "Build an analysis component from a Rust core Wasm module")]
struct Arguments {
    core: PathBuf,
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    ComponentBuilder::build(&arguments.core, &arguments.output)?;
    println!("{}", arguments.output.display());
    Ok(())
}
