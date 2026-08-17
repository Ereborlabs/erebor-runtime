#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$directory/enforcement-runtime.sh"
host_shared_directory=
container_shared_directory=
case $# in
  0)
    enforcement_prepare_k3s \
      docker.io/library/python@sha256:78098ea6a3a9c6a7727a5d4674e4a44e57e01fac878ee9cb4d24a86bd93916ff
    secret_path=$identity_k3s_secret_path
    host_shared_directory=$identity_k3s_shared_directory
    container_shared_directory=$identity_k3s_container_shared_directory
    ;;
  3)
    observation_prepare_docker "$1" "$2" "$3"
    secret_path=$3
    ;;
  5)
    enforcement_prepare_cri_shared "$1" "$2" "$3" "$4" "$5"
    secret_path=$3
    host_shared_directory=$4
    container_shared_directory=$5
    ;;
  *)
  echo "usage: sudo $0 <node.json> <container> <absolute-secret-path>" >&2
  echo "   or: sudo $0 <node.json> <container-id> <absolute-secret-path> <host-shared-directory> <container-shared-directory>" >&2
  echo "   or: sudo $0" >&2
  exit 2
    ;;
esac
enforcement_bind_alias=/tmp/mithril-local-enforcement-bind-alias-$$
enforcement_second_bind_alias=/tmp/mithril-local-enforcement-second-bind-alias-$$
exec {enforcement_mount_namespace_fd}<"/proc/$identity_init_pid/ns/mnt"
exec {enforcement_root_fd}<"/proc/$identity_init_pid/root"
touch -- \
  "/proc/$identity_init_pid/root$enforcement_bind_alias" \
  "/proc/$identity_init_pid/root$enforcement_second_bind_alias"
nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
  --root="/proc/self/fd/$enforcement_root_fd" -- \
  mount --bind -- "$secret_path" "$enforcement_bind_alias"
nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
  --root="/proc/self/fd/$enforcement_root_fd" -- \
  mount --bind -- "$secret_path" "$enforcement_second_bind_alias"
# Re-resolve the exact file after both aliases change the retained mount view.
observation_configure_secret "$secret_path"
if [[ $identity_mode == cri ]]; then
  observation_configure_cri_shared_directory \
    "$host_shared_directory" "$container_shared_directory"
fi
enforcement_cleanup_bind_alias() {
  nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
    --root="/proc/self/fd/$enforcement_root_fd" -- \
    umount -- "$enforcement_bind_alias" 2>/dev/null || true
  nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
    --root="/proc/self/fd/$enforcement_root_fd" -- \
    umount -- "$enforcement_second_bind_alias" 2>/dev/null || true
  nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
    --root="/proc/self/fd/$enforcement_root_fd" -- \
    rm -f -- "$enforcement_bind_alias"
  nsenter --mount="/proc/self/fd/$enforcement_mount_namespace_fd" \
    --root="/proc/self/fd/$enforcement_root_fd" -- \
    rm -f -- "$enforcement_second_bind_alias"
  exec {enforcement_mount_namespace_fd}<&-
  exec {enforcement_root_fd}<&-
}
identity_cleanup_functions+=(enforcement_cleanup_bind_alias)
observation_preload_nsenter_probe python3 -c '
import errno, os, sys
ready, *paths = sys.argv[1:]
release = os.environ["MITHRIL_MANUAL_RELEASE"]
os.mkfifo(release, 0o600)
release_fd = os.open(release, os.O_RDWR)
with open(ready, "w", encoding="ascii") as output:
    output.write(str(os.getpid()))
os.read(release_fd, 1)
os.close(release_fd)
for path in paths:
    try:
        os.open(path, os.O_RDONLY)
    except PermissionError as error:
        if error.errno in (errno.EACCES, errno.EPERM):
            continue
    raise SystemExit("bind alias returned a protected fd")
' "$observation_probe_ready" "$enforcement_bind_alias" "$enforcement_second_bind_alias"
if ! observation_release_probe; then
  "$identity_inspect" effects --socket-path "$observation_socket" \
    --cgroup-scope "$observation_scope" >&2 || true
  exit 1
fi
enforcement_expect_exact_denial
[[ $(grep -c 'reason=EXACT_POLICY_DENY.*exact_object_key_id=7' "$identity_work/effects.txt") -ge 2 ]]
identity_pass "PASS: two pre-existing bind aliases canonicalized to the same exact denial."
