use std::path::PathBuf;

use clap::{CommandFactory as _, Parser, ValueEnum};

#[derive(Clone, PartialEq, ValueEnum)]
enum Case {
    OfflineExact,
    StorageContract,
    EvidenceRestart,
    ContextRoundtrip,
    DataStoreRecovery,
    DataStoreStartup,
    DataStoreLoad,
    DataStoreTenants,
    DataStoreQuota,
    DataStoreRollout,
    DataStoreInspect,
    QueryFollow,
}

#[derive(Parser)]
#[command(about = "Verify Araphor discovery with bounded qualification cases")]
struct Cli {
    #[arg(long, value_enum)]
    case: Case,
    #[arg(long)]
    output_directory: PathBuf,
    #[arg(long, value_parser = clap::value_parser!(u8).range(2..=10))]
    tenants: Option<u8>,
    #[arg(
        long,
        required_if_eq("case", "data-store-inspect"),
        requires = "tenant_id"
    )]
    data_directory: Option<PathBuf>,
    #[arg(
        long,
        required_if_eq("case", "data-store-inspect"),
        requires = "data_directory"
    )]
    tenant_id: Option<uuid::Uuid>,
    #[arg(long, requires_all = ["data_directory", "tenant_id"])]
    baseline: Option<PathBuf>,
}

impl Cli {
    fn validate(&self) -> Result<(), clap::Error> {
        if self.case != Case::DataStoreTenants && self.tenants.is_some() {
            return Err(Self::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--tenants requires --case data-store-tenants",
            ));
        }
        if self.case != Case::DataStoreInspect && self.data_directory.is_some() {
            return Err(Self::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "inspection inputs require --case data-store-inspect",
            ));
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = cli.validate() {
        error.exit();
    }
    let result = match cli.case {
        Case::OfflineExact => mithril_e2e::run_discovery_offline(&cli.output_directory)
            .map_err(Box::<dyn std::error::Error>::from),
        Case::QueryFollow => {
            mithril_e2e::QueryFollowQualification::new(cli.output_directory)
                .run()
                .await
        }
        Case::StorageContract => mithril_e2e::run_discovery_storage_contract(&cli.output_directory),
        Case::DataStoreRecovery => {
            mithril_e2e::DataStoreQualification::new(cli.output_directory)
                .recovery()
                .await
        }
        Case::DataStoreStartup => {
            mithril_e2e::DataStoreQualification::new(cli.output_directory)
                .startup()
                .await
        }
        Case::DataStoreLoad => {
            mithril_e2e::DataStoreQualification::new(cli.output_directory)
                .load()
                .await
        }
        Case::DataStoreTenants => {
            mithril_e2e::DataStoreQualification::new(cli.output_directory)
                .tenant_load(usize::from(cli.tenants.unwrap_or(2)))
                .await
        }
        Case::DataStoreQuota => {
            mithril_e2e::DataStoreQualification::new(cli.output_directory)
                .quota()
                .await
        }
        Case::DataStoreRollout => {
            mithril_e2e::DataStoreQualification::new(cli.output_directory)
                .rollout_load()
                .await
        }
        Case::DataStoreInspect => match (cli.data_directory, cli.tenant_id) {
            (Some(root), Some(tenant)) => mithril_e2e::DataStoreQualification::new(
                cli.output_directory,
            )
            .inspect(&root, *tenant.as_bytes(), cli.baseline.as_deref()),
            _ => Err("inspection requires a data directory and tenant".into()),
        },
        Case::EvidenceRestart => {
            mithril_e2e::DiscoveryQualificationRunner::new(cli.output_directory)
                .evidence_restart()
                .await
        }
        Case::ContextRoundtrip => {
            mithril_e2e::DiscoveryQualificationRunner::new(cli.output_directory)
                .context_roundtrip()
                .await
        }
    };
    match result {
        Ok(()) => {
            println!("Araphor discovery check passed; see result.json for its proof boundary")
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_follow_arguments_are_scoped() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from([
            "qualification",
            "--case",
            "query-follow",
            "--output-directory",
            "/tmp/query-follow",
        ])?;
        cli.validate()?;
        assert!(cli.case == Case::QueryFollow);
        let wrong = Cli::try_parse_from([
            "qualification",
            "--case",
            "query-follow",
            "--output-directory",
            "/tmp/query-follow",
            "--tenants",
            "2",
        ])?;
        assert!(wrong.validate().is_err());
        Ok(())
    }

    #[test]
    fn tenant_arguments_are_scoped() -> Result<(), clap::Error> {
        let base = [
            "qualification",
            "--case",
            "data-store-tenants",
            "--output-directory",
            "/tmp/result",
        ];
        let default = Cli::try_parse_from(base)?;
        default.validate()?;
        assert_eq!(default.tenants, None);
        for count in ["2", "10"] {
            let parsed = Cli::try_parse_from(base.into_iter().chain(["--tenants", count]))?;
            parsed.validate()?;
            assert_eq!(
                parsed.tenants.map(|value| value.to_string()).as_deref(),
                Some(count)
            );
        }
        for count in ["0", "1", "11", "256"] {
            assert!(Cli::try_parse_from(base.into_iter().chain(["--tenants", count])).is_err());
        }
        let wrong = Cli::try_parse_from([
            "qualification",
            "--case",
            "data-store-load",
            "--output-directory",
            "/tmp/result",
            "--tenants",
            "10",
        ])?;
        assert!(wrong.validate().is_err());
        Ok(())
    }

    #[test]
    fn inspection_arguments_are_scoped() -> Result<(), clap::Error> {
        let tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let base = [
            "qualification",
            "--case",
            "data-store-inspect",
            "--output-directory",
            "/tmp/result",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--data-directory", "/tmp/data"])).is_err()
        );
        assert!(Cli::try_parse_from(base.into_iter().chain(["--tenant-id", tenant])).is_err());
        let complete =
            base.into_iter()
                .chain(["--data-directory", "/tmp/data", "--tenant-id", tenant]);
        Cli::try_parse_from(complete.clone())?.validate()?;
        Cli::try_parse_from(complete.chain(["--baseline", "/tmp/baseline.json"]))?.validate()?;
        let wrong = Cli::try_parse_from([
            "qualification",
            "--case",
            "data-store-startup",
            "--output-directory",
            "/tmp/result",
            "--data-directory",
            "/tmp/data",
            "--tenant-id",
            tenant,
        ])?;
        assert!(wrong.validate().is_err());
        Ok(())
    }
}
