# Session OS Backends

Session runners can attach OS-specific enforcement helpers when a surface needs
kernel-level observation.

Current layout:

- `linux/`: Linux process-tree guard used by the Docker/OCI session runner.

Future host runtimes should add their implementation under a matching OS
directory instead of putting platform-specific enforcement in the generic
session runner.
