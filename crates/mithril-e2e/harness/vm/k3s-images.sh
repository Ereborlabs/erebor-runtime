#!/usr/bin/env bash

set -euo pipefail

if (($# < 4)); then
  echo "usage: $0 K3S CACHE_NAME ARCHIVE IMAGE [IMAGE...]" >&2
  exit 2
fi

k3s=$1
cache=$2
archive=$3
shift 3

[[ $(id -u) -eq 0 && -x $k3s ]] || {
  echo "K3s image setup requires root and K3s" >&2
  exit 2
}
[[ $cache =~ ^[a-z0-9-]+$ ]] || {
  echo "invalid K3s image cache name: $cache" >&2
  exit 2
}
systemctl is-active --quiet k3s || {
  echo "K3s is not active" >&2
  exit 1
}

missing=false
for image in "$@"; do
  "$k3s" crictl inspecti "$image" >/dev/null || missing=true
done
[[ $missing == true ]] || exit 0
[[ -r $archive ]] || {
  echo "K3s image setup needs a readable archive for a missing image" >&2
  exit 2
}

image_dir=/var/lib/rancher/k3s/agent/images
target=$image_dir/mithril-e2e-$cache.tar
install -d -m 0700 "$image_dir"
"$k3s" ctr images import "$archive" >/dev/null
for image in "$@"; do
  "$k3s" crictl inspecti "$image" >/dev/null || {
    echo "K3s archive does not provide image: $image" >&2
    exit 1
  }
done
install -m 0600 "$archive" "$target.new"
mv -f -- "$target.new" "$target"
