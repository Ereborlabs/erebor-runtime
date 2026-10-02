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
sha256sum /usr/bin/bpftrace /sys/kernel/btf/vmlinux "$binary" >"$output/binaries.sha256"
ldd /usr/bin/bpftrace >"$output/libraries.txt"
mapfile -t libraries < <(awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' "$output/libraries.txt" | sort -u)
((${#libraries[@]} > 0)) || exit 2
sha256sum "${libraries[@]}" >"$output/libraries.sha256"
for artifact in /usr/bin/bpftrace "${libraries[@]}"; do
  package=$(dpkg-query -S "$(readlink -f -- "$artifact")" 2>/dev/null || dpkg-query -S "$artifact")
  package=${package%%: /*}
  printf '%s\t%s\n' "$artifact" "$package" >>"$output/library-packages.txt"
done
mapfile -t packages < <(cut -f2 "$output/library-packages.txt" | sort -u)
dpkg-query -W -f='${binary:Package}\t${Version}\n' "${packages[@]}" >"$output/packages.txt"
mkdir -- "$output/copyright" "$output/common-licenses"
for package in "${packages[@]}"; do
  cp -L -- "/usr/share/doc/${package%%:*}/copyright" "$output/copyright/$package"
done
mapfile -t licenses < <(grep -hEo '/usr/share/common-licenses/[[:alnum:]][[:alnum:].+_-]*[[:alnum:]]' \
  "$output/copyright/"* | sort -u)
for license in "${licenses[@]}"; do
  cp -L -- "$license" "$output/common-licenses/"
done
cp /usr/share/doc/bpftrace/copyright "$output/bpftrace-copyright"
(
  cd -- "$output"
  shopt -s nullglob
  sha256sum kernel.txt bpftrace-version.txt binaries.sha256 libraries.txt \
    libraries.sha256 library-packages.txt packages.txt bpftrace-copyright \
    copyright/* common-licenses/* >provenance.sha256
  sha256sum provenance.sha256 >provenance-id.sha256
)
digest=$(sha256sum /usr/bin/bpftrace)
digest=${digest%% *}
timeout --kill-after=10s 300s "$binary" --executable /usr/bin/bpftrace \
  --sha256 "$digest" --output-directory "$output/cases"
