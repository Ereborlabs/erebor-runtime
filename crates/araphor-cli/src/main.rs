fn main() -> Result<(), Box<dyn std::error::Error>> {
    if araphor_analysis::AnalysisPackageOwner::run_worker_if_requested()? {
        return Ok(());
    }
    araphor_cli::run();
    Ok(())
}
