#!/usr/bin/env bash
# Proof harness for slow-subscriber isolation.
#
# Runs the ignored 100k-message pub/sub stress test that creates one slow
# subscriber (never drains) and one fast subscriber (drains everything).
# The pub/sub layer should drop the slow subscriber once its 10k channel
# fills while the publisher and fast subscriber continue unharmed.

set -euo pipefail

PROOF_DIR="${PROOF_DIR:-proofs/slow-consumer-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$PROOF_DIR"
RESULT_JSON="$PROOF_DIR/result.json"
LOG="$PROOF_DIR/test.log"
SUMMARY="$PROOF_DIR/summary.md"

printf '[%s] slow-consumer proof → %s\n' "$(date -u +%H:%M:%S)" "$PROOF_DIR" | tee "$LOG"

X0X_SLOW_CONSUMER_PROOF="$RESULT_JSON" \
  cargo test --lib test_slow_subscriber_isolated_at_100k_messages -- --ignored --nocapture \
  2>&1 | tee -a "$LOG"

python3 - "$RESULT_JSON" <<'PY' > "$SUMMARY"
import json, sys
path = sys.argv[1]
d = json.load(open(path))
print('# Slow consumer proof')
print()
print('- messages:', d['messages'])
print('- publish_total:', d['publish_total'])
print('- delivered_to_subscriber:', d['delivered_to_subscriber'])
print('- subscriber_channel_closed:', d['subscriber_channel_closed'])
print('- decode_to_delivery_drops:', d['decode_to_delivery_drops'])
print('- fast_received:', d['fast_received'])
print()
print('## Assertions')
print()
print(f"- publisher reached 100000: {'yes' if d['publish_total'] == 100000 else 'no'}")
print(f"- slow subscriber dropped after filling: {'yes' if d['subscriber_channel_closed'] >= 1 else 'no'}")
print(f"- fast subscriber received 100000: {'yes' if d['fast_received'] == 100000 else 'no'}")
PY

printf '[%s] wrote %s and %s\n' "$(date -u +%H:%M:%S)" "$RESULT_JSON" "$SUMMARY" | tee -a "$LOG"
