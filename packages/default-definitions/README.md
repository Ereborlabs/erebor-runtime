# Default package Definitions

Each YAML file is a normal Araphor Definition. Its SQL selects the package
exports to call. Package code owns analysis and Graph changes.

The Control build uses `Definition::read` to capture these files. The binary
contains the captured Definitions and needs no source-tree path. Set
`package_definitions` in the Control configuration to read an operator folder
instead. That folder uses the same Definition reader. Files must have unique
Definition names. A folder does not grant trust to an OCI image.

Control admits each Definition through the normal managed instance API. Its
name is the stored instance ID within the tenant. Existing stopped and removed
instances remain stopped and removed. Changed image or Definition pins require
an explicit managed update.

The focused causal test passes its full 16,402-record workload in 72.96 s.
This result does not meet the millisecond or 100-fold latency target.
