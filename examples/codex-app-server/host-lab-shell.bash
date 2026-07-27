# This file is sourced only by run-host-lab.sh's unprivileged interactive shell.
# It receives all values through an explicit, process-local environment.

if [[ -z "${EREBOR_BIN:-}" || -z "${EREBOR_SOCKET:-}" || -z "${EREBOR_WORKSPACE:-}" ]]; then
  printf '%s\n' 'host-lab shell is missing its explicit Erebor environment' >&2
  return 1
fi

erebor() {
  "$EREBOR_BIN" --socket "$EREBOR_SOCKET" "$@"
}

cd -- "$EREBOR_WORKSPACE"
PS1='[erebor host lab] \u@\h:\w$ '

printf '%s\n' "The erebor function selects $EREBOR_SOCKET for this shell only."
printf '%s\n' 'Run: erebor agent load "$EREBOR_CODEX_PACKAGE_NAME" --from "$EREBOR_CODEX_FIXTURE" --adapter codex-v1 --name fixture-codex'
printf '%s\n' 'Then: erebor run --policy fixture --workspace "$PWD" fixture-codex'
printf '%s\n' 'Type exit to stop the foreground daemon. The lab directory is retained.'
