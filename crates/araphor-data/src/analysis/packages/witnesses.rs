use crate::{AnalysisContextRefV1, AnalysisWitnessV1};

type PackageEvidence = (Vec<AnalysisWitnessV1>, Vec<AnalysisContextRefV1>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_provenance_reads() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        assert!(store.package_contexts([1; 16], &[])?.is_empty());
        assert!(store.package_result_refs([1; 16], &[])?.is_empty());
        assert_eq!(
            store.package_evidence([1; 16], &[])?,
            (Vec::new(), Vec::new())
        );
        Ok(())
    }
}
