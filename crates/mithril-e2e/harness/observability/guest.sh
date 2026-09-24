#!/usr/bin/env bash
set -euo pipefail

if (($# != 2)); then
  echo "usage: guest.sh QUALIFICATION_BINARY OUTPUT_DIRECTORY" >&2
  exit 2
fi
binary=$1
output=$2
[[ $binary == /* && -x $binary && $output == /tmp/araphor-observability-* && ! -e $output ]] || exit 2
mkdir -m 0700 -- "$output"
uname -a >"$output/kernel.txt"
bpftrace --version >"$output/bpftrace-version.txt" 2>&1
dpkg-query -W bpftrace libbpf1 libbpfcc libclang1-18 libllvm18 >"$output/packages.txt"
sha256sum /usr/bin/bpftrace /sys/kernel/btf/vmlinux "$binary" >"$output/binaries.sha256"
ldd /usr/bin/bpftrace >"$output/libraries.txt"
mapfile -t libraries < <(awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' "$output/libraries.txt" | sort -u)
((${#libraries[@]} > 0)) || exit 2
sha256sum "${libraries[@]}" >"$output/libraries.sha256"
cp /usr/share/doc/bpftrace/copyright "$output/bpftrace-copyright"
digest=$(sha256sum /usr/bin/bpftrace)
digest=${digest%% *}
timeout --kill-after=10s 300s "$binary" --executable /usr/bin/bpftrace \
  --sha256 "$digest" --output-directory "$output/cases"
