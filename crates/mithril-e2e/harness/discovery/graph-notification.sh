#!/usr/bin/env bash
set -euo pipefail

if (($# != 2)); then
  echo "usage: $0 LIGHTWEIGHT_RESULT_JSON NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
expected=$1
output=$2
if [[ $expected != /* || ! -r $expected || $output != /* || -e $output ||
      ! -x ${MITHRIL_TEST_BIN:-} ]]; then
  echo "the incident needs a readable absolute result, new absolute output, and MITHRIL_TEST_BIN" >&2
  exit 2
fi
export MITHRIL_GRAPH_NOTIFICATION_EXPECTED=$expected
export MITHRIL_GRAPH_NOTIFICATION_OUTPUT=$output
exec "$MITHRIL_TEST_BIN" \
  discovery::graph_notification::physical::graph_notification_incident \
  --exact --ignored --nocapture --test-threads=1
