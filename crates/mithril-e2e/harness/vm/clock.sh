#!/usr/bin/env bash

clock_skew_seconds() {
  local first=$1
  local second=$2

  if ((first >= second)); then
    printf '%s\n' "$((first - second))"
  else
    printf '%s\n' "$((second - first))"
  fi
}

clock_is_within_tolerance() {
  local first=$1
  local second=$2
  local tolerance=$3

  (( $(clock_skew_seconds "$first" "$second") <= tolerance ))
}
