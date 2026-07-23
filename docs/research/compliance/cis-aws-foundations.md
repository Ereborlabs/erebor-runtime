# CIS AWS Foundations

## What It Is For

CIS AWS Foundations is a secure configuration benchmark for AWS accounts. It is
useful for Erebor when agents perform AWS administration, but the benchmark
itself still requires actual AWS configuration evidence from AWS-native tools or
equivalent scanners.

## Evidence Companies Need

- AWS configuration scans
- Security Hub/CSPM findings
- IAM, root, MFA, and access-key evidence
- CloudTrail, Config, and logging evidence
- network exposure evidence
- encryption settings
- remediation records
- exceptions and periodic benchmark reports

## What Erebor Can Do

Erebor can govern AI agents making AWS changes through CLI, console browser
sessions, SDKs, or SaaS automation. It can require approvals for IAM, S3,
security group, CloudTrail, KMS, RDS, and logging changes, then correlate agent
activity with AWS evidence when those actions are routed through
Erebor-controlled execution paths.

## Artifacts Erebor Could Generate

- AWS AI-agent action report mapped to CIS control areas
- pre-change approval and post-change verification bundle
- Security Hub finding-to-agent-action correlation report
- privileged AWS action exception log
- CloudTrail/Erebor transcript reconciliation report
- periodic AWS AI-operation posture summary

## Do Not Claim

Erebor is not a CIS-certified scanner, AWS Security Hub replacement, AWS Config
replacement, CloudTrail replacement, CSPM, or proof of AWS configuration state
without actual AWS evidence.

## Sources

- https://www.cisecurity.org/benchmark/amazon_web_services
- https://www.cisecurity.org/cis-benchmarks
- https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html
