fn main() -> araphor_data::Result<()> {
    if araphor_data::AnalysisPackageOwner::run_worker_if_requested()? {
        return Ok(());
    }
    araphor_cli::run();
    Ok(())
}
