#!/usr/bin/env bash

set -euo pipefail

if (($# < 3)) || [[ $(id -u) != 0 ]]; then
  echo "usage: sudo bash $0 DATA_DIRECTORY CHECK_DIRECTORY ARGUMENT..." >&2
  exit 2
fi
data_path=$1
check_root=$2
shift 2
[[ -d $data_path && -d $check_root/data && ! -L $check_root/data &&
   -x $check_root/check && -d $check_root/results ]] || {
  echo "inspection requires the data and checker directories" >&2
  exit 2
}

exec unshare --mount --propagation private -- /bin/sh -ec '
  data_path=$1
  check_root=$2
  shift 2
  mount --bind "$data_path" "$check_root/data"
  exec setpriv --reuid=65532 --regid=65532 --clear-groups -- \
    "$check_root/check" "$@"
' inspect-data "$data_path" "$check_root" "$@"
