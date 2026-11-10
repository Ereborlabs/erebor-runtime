

use crate :: { AnalysisContextRefV1 , AnalysisWitnessV1 } ;


type PackageEvidence = (Vec<AnalysisWitnessV1>, Vec<AnalysisContextRefV1>);



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_provenance_reads() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            Default::default(),
            crate::StorageLimitsV1 {
                reader_admissions: Some(16),
                ..Default::default()
            },
        )?;
        let mut held = Vec::new();
        while let Ok(permit) = store.reserve_reader() {
            held.push(permit);
        }
        assert!(!held.is_empty());
        assert!(store.package_contexts([1; 16], &[])?.is_empty());
        assert!(store.package_result_refs([1; 16], &[])?.is_empty());
        assert_eq!(
            store.package_evidence([1; 16], &[])?,
            (Vec::new(), Vec::new())
        );
        Ok(())
    }
}
