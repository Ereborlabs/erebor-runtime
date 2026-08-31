#!/usr/bin/env bash

set -euo pipefail

# Implements the provider contract documented by the VM e2e harness.

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
harness_directory=$(cd -- "$directory/.." && pwd)
cloud_init_template=$harness_directory/cloud-init-v1.yaml

connection=${MITHRIL_LIBVIRT_URI:-qemu:///system}
ssh_user=${MITHRIL_VM_SSH_USER:-ubuntu}
ssh_private_key=${MITHRIL_VM_SSH_PRIVATE_KEY:-$HOME/.ssh/id_rsa}
known_hosts=${MITHRIL_VM_KNOWN_HOSTS:-/tmp/mithril-vm-test-known-hosts}
base_image_url=${MITHRIL_VM_BASE_IMAGE_URL:-https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img}
image_cache=${MITHRIL_VM_IMAGE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/mithril-vm-test}
owner_file_name=libvirt-domain-owner
source_mount=${MITHRIL_VM_SOURCE_MOUNT:-}
source_mount_tag=mithril-source
source_mountpoint=/mnt/mithril-source

require_command() {
  command -v "$1" >/dev/null || {
    echo "required command is not installed: $1" >&2
    exit 2
  }
}

valid_work_directory() {
  local work_directory=$1
  local configured_root=${MITHRIL_VM_WORK_ROOT:-}
  [[ $work_directory == /tmp/mithril-vm-test.* && -d $work_directory ]] ||
    [[ -n $configured_root && $configured_root == /* && $configured_root != / &&
       $work_directory == "$configured_root"/mithril-vm-test.* && -d $work_directory ]]
}

address() {
  virsh -c "$connection" domifaddr "$1" --source lease 2>/dev/null \
    | awk '$3 == "ipv4" && !found {sub(/\/.*/, "", $4); print $4; found = 1} END {exit !found}'
}

ssh_options() {
  printf '%s\n' -o StrictHostKeyChecking=no -o UserKnownHostsFile="$known_hosts" \
    -o ConnectTimeout=5 -i "$ssh_private_key"
}

case ${1:-} in
  address)
    (($# == 2)) || { echo "usage: $0 address NAME" >&2; exit 2; }
    require_command virsh
    address "$2"
    ;;
  create)
    (($# == 4)) || { echo "usage: $0 create NAME WORK_DIRECTORY PUBLIC_KEY" >&2; exit 2; }
    name=$2
    work_directory=$3
    public_key_path=$4
    require_command curl
    require_command qemu-img
    require_command sha256sum
    require_command virsh
    require_command virt-install
    valid_work_directory "$work_directory" || {
      echo "unexpected VM work directory: $work_directory" >&2
      exit 2
    }
    virsh -c "$connection" dominfo "$name" >/dev/null 2>&1 && {
      echo "libvirt domain already exists: $name" >&2
      exit 2
    }
    virsh -c "$connection" net-info default 2>/dev/null \
      | awk '$1 == "Active:" && $2 == "yes" { active = 1 } END { exit !active }' || {
        echo "libvirt default network is not active" >&2
        exit 2
      }
    if [[ -n $source_mount ]]; then
      [[ $source_mount == /* && -d $source_mount ]] || {
        echo "MITHRIL_VM_SOURCE_MOUNT must be an existing absolute directory: $source_mount" >&2
        exit 2
      }
      source_mount=$(cd -- "$source_mount" && pwd -P)
    fi
    chmod 755 "$work_directory"
    mkdir -p -- "$image_cache"
    image_name=${base_image_url##*/}
    base_image=$image_cache/$image_name
    checksum_file=$work_directory/SHA256SUMS
    curl --fail --location --silent --show-error \
      --output "$checksum_file" "${base_image_url%/*}/SHA256SUMS"
    image_checksum=$work_directory/image.sha256
    awk -v image_name="$image_name" \
      '$2 == image_name || $2 == "*" image_name { print; found = 1 } END { exit !found }' \
      "$checksum_file" >"$image_checksum" || {
      echo "published checksums do not contain $image_name" >&2
      exit 1
    }
    if [[ -f $base_image ]] &&
        ! (cd -- "$image_cache" && sha256sum --check "$image_checksum"); then
      rm -f -- "$base_image"
    fi
    if [[ ! -f $base_image ]]; then
      download=$work_directory/$image_name
      curl --fail --location --progress-bar \
        --output "$download" "$base_image_url"
      (cd -- "$work_directory" && sha256sum --check "$image_checksum")
      mv -- "$download" "$base_image"
    fi

    overlay=$work_directory/root.qcow2
    qemu-img convert -f qcow2 -O qcow2 "$base_image" "$overlay"
    qemu-img resize "$overlay" 20G
    public_key=$(<"$public_key_path")
    [[ -r $cloud_init_template ]] || {
      echo "checked cloud-init template is not readable: $cloud_init_template" >&2
      exit 2
    }
    user_data=$work_directory/cloud-init.yaml
    escaped_public_key=${public_key//&/\\&}
    escaped_public_key=${escaped_public_key//|/\\|}
    sed "s|__MITHRIL_SSH_PUBLIC_KEY__|$escaped_public_key|" \
      "$cloud_init_template" >"$user_data"
    domain_uuid=$(< /proc/sys/kernel/random/uuid)
    owner_file=$work_directory/$owner_file_name
    printf '%s\n%s\n' "$name" "$domain_uuid" >"$owner_file"
    cleanup_partial_create() {
      local status=$?
      local live_uuid=
      trap - EXIT
      if ((status != 0)); then
        live_uuid=$(virsh -c "$connection" domuuid "$name" 2>/dev/null || true)
        if [[ $live_uuid == "$domain_uuid" ]]; then
          virsh -c "$connection" destroy "$name" >/dev/null 2>&1 || true
          virsh -c "$connection" undefine "$name" --nvram >/dev/null 2>&1 \
            || virsh -c "$connection" undefine "$name" >/dev/null 2>&1 \
            || true
        fi
      fi
      exit "$status"
    }
    trap cleanup_partial_create EXIT
    filesystem=()
    if [[ -n $source_mount ]]; then
      filesystem=(--filesystem "$source_mount,$source_mount_tag,accessmode=mapped,readonly=on")
    fi
    virt-install --connect "$connection" --name "$name" \
      --uuid "$domain_uuid" \
      --memory 4096 --vcpus 2 --cpu host-passthrough \
      --disk "path=$overlay,format=qcow2,bus=virtio" \
      --os-variant ubuntu24.04 --network network=default,model=virtio \
      --graphics none --noautoconsole --import \
      "${filesystem[@]}" \
      --cloud-init "user-data=$user_data,disable=on"
    ;;
  wait)
    (($# == 2)) || { echo "usage: $0 wait NAME" >&2; exit 2; }
    name=$2
    require_command ssh
    require_command timeout
    require_command virsh
    [[ -r $ssh_private_key ]] || {
      echo "SSH private key is not readable: $ssh_private_key" >&2
      exit 2
    }
    for _attempt in $(seq 1 180); do
      if [[ $(virsh -c "$connection" domstate "$name" 2>/dev/null) == "shut off" ]]; then
        virsh -c "$connection" start "$name" >/dev/null
      fi
      ip=$(address "$name" || true)
      if [[ -n $ip ]]; then
        mapfile -t options < <(ssh_options)
        if timeout --kill-after=2s 10s ssh "${options[@]}" "$ssh_user@$ip" \
          'test -r /sys/kernel/btf/vmlinux && test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs && test "$(stat -fc %T /sys/fs/bpf)" = bpf_fs && grep -qw bpf /sys/kernel/security/lsm' \
          >/dev/null 2>&1; then
          if [[ -n $source_mount ]] && ! ssh "${options[@]}" "$ssh_user@$ip" \
            "sudo install -d -m 0755 -- $source_mountpoint && if [ \"\$(findmnt -rn -o FSTYPE --target $source_mountpoint)\" != 9p ]; then mountpoint -q $source_mountpoint && exit 1; sudo mount -t 9p -o trans=virtio,version=9p2000.L,ro $source_mount_tag $source_mountpoint; fi && test \"\$(findmnt -rn -o FSTYPE --target $source_mountpoint)\" = 9p && test -r $source_mountpoint" \
            >/dev/null 2>&1; then
            sleep 1
            continue
          fi
          exit 0
        fi
      fi
      sleep 1
    done
    echo "VM did not become ready with BTF, cgroup v2, bpffs, and BPF LSM: $name" >&2
    exit 1
    ;;
  put)
    (($# == 4)) || { echo "usage: $0 put NAME LOCAL REMOTE" >&2; exit 2; }
    ip=$(address "$2")
    mapfile -t options < <(ssh_options)
    scp "${options[@]}" "$3" "$ssh_user@$ip:$4"
    ;;
  get)
    (($# == 4)) || { echo "usage: $0 get NAME REMOTE LOCAL" >&2; exit 2; }
    ip=$(address "$2")
    mapfile -t options < <(ssh_options)
    scp "${options[@]}" "$ssh_user@$ip:$3" "$4"
    ;;
  run)
    (($# >= 3)) || { echo "usage: $0 run NAME COMMAND..." >&2; exit 2; }
    name=$2
    shift 2
    ip=$(address "$name")
    mapfile -t options < <(ssh_options)
    ssh "${options[@]}" "$ssh_user@$ip" "$@"
    ;;
  ssh)
    (($# == 2)) || { echo "usage: $0 ssh NAME" >&2; exit 2; }
    name=$2
    require_command ssh
    require_command virsh
    [[ -r $ssh_private_key ]] || {
      echo "SSH private key is not readable: $ssh_private_key" >&2
      exit 2
    }
    ip=$(address "$name")
    [[ -n $ip ]] || {
      echo "VM has no DHCP lease address: $name" >&2
      exit 1
    }
    mapfile -t options < <(ssh_options)
    ssh "${options[@]}" "$ssh_user@$ip"
    ;;
  destroy)
    (($# == 3)) || { echo "usage: $0 destroy NAME WORK_DIRECTORY" >&2; exit 2; }
    name=$2
    work_directory=$3
    case $name in
      mithril-runtime-qualification-[0-9]*) ;;
      *) echo "refusing to destroy an unexpected domain: $name" >&2; exit 2 ;;
    esac
    valid_work_directory "$work_directory" || {
      echo "refusing cleanup without the VM work directory: $work_directory" >&2
      exit 2
    }
    owner_file=$work_directory/$owner_file_name
    [[ -r $owner_file ]] || {
      echo "refusing cleanup without a domain ownership record: $owner_file" >&2
      exit 2
    }
    mapfile -t ownership <"$owner_file"
    [[ ${#ownership[@]} -eq 2 && ${ownership[0]} == "$name" &&
       ${ownership[1]} =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || {
      echo "refusing cleanup with an invalid domain ownership record" >&2
      exit 2
    }
    if virsh -c "$connection" dominfo "$name" >/dev/null 2>&1; then
      live_uuid=$(virsh -c "$connection" domuuid "$name")
      [[ $live_uuid == "${ownership[1]}" ]] || {
        echo "refusing cleanup of a domain with a different UUID: $name" >&2
        exit 2
      }
      virsh -c "$connection" destroy "$name" >/dev/null 2>&1 || true
      virsh -c "$connection" undefine "$name" --nvram >/dev/null 2>&1 \
        || virsh -c "$connection" undefine "$name" >/dev/null
    fi
    rm -f -- "$owner_file"
    ;;
  *)
    echo "usage: $0 {address|create|wait|put|get|run|ssh|destroy} ..." >&2
    exit 2
    ;;
esac
