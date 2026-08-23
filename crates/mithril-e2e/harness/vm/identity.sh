#!/usr/bin/env bash

# This file is sourced by the VM harness lifecycle owners.

mithril_vm_branch_name() {
  local repo_root=$1
  local branch

  if branch=$(git -C "$repo_root" symbolic-ref --quiet --short HEAD); then
    printf '%s\n' "$branch"
  else
    printf 'detached-%s\n' "$(git -C "$repo_root" rev-parse --short=12 HEAD)"
  fi
}

mithril_vm_branch_key() {
  local branch=$1
  local digest slug

  slug=$(printf '%s' "$branch" | LC_ALL=C tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')
  slug=${slug:0:24}
  slug=${slug%-}
  [[ -n $slug ]] || slug=branch
  digest=$(printf '%s' "$branch" | sha256sum | awk '{print substr($1, 1, 12)}')
  printf '%s-%s\n' "$slug" "$digest"
}

mithril_vm_name() {
  local branch_key=$1
  local lane=$2
  local process_id=$3
  local node=${4:-}
  local name

  [[ $branch_key =~ ^[a-z0-9]+(-[a-z0-9]+)*-[0-9a-f]{12}$ \
    && $process_id =~ ^[1-9][0-9]*$ ]] || return 2
  case "$lane:$node" in
    s:|r:|n:a|n:b|c:a|c:b) ;;
    *) return 2 ;;
  esac
  name=mithril-vm-$branch_key-$lane-$process_id
  [[ -z $node ]] || name=$name-$node
  [[ ${#name} -le 63 ]] || return 2
  printf '%s\n' "$name"
}
