#!/usr/bin/env bash
# Test platform: scan -> remediate -> rescan -> idempotency check.
#
#   1. Build a deliberately non-compliant Ubuntu container.
#   2. Scan it with the generated InSpec profile  -> must FAIL (exit 100).
#   3. Fix it with the generated Chef cookbook.
#   4. Scan again                                 -> must PASS (exit 0).
#   5. Run Chef again                             -> must change nothing.
#
# Needs: docker, and cinc-auditor (or inspec: SCANNER=inspec).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="$ROOT/build/profiles/linux-baseline"
COOKBOOKS="$ROOT/build/cookbooks"
RECIPE="linux_baseline_remediation"
IMAGE="compliance-target:test"
NAME="compliance-target"
REPORTS="$ROOT/reports"
SCANNER="${SCANNER:-cinc-auditor}"

mkdir -p "$REPORTS"

echo "==> Building non-compliant target image"
docker build -t "$IMAGE" "$ROOT/test-platform"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

scan() {
  "$SCANNER" exec "$PROFILE" -t "docker://$NAME" --no-color \
    --reporter cli "json:$REPORTS/$1.json"
}

converge() {
  docker exec -w /tmp "$NAME" cinc-client --local-mode --no-color \
    --config-option cookbook_path=/tmp/cookbooks \
    -o "recipe[$RECIPE]"
}

echo "==> [1/4] Baseline scan (expect failures)"
rc=0; scan before || rc=$?
if [ "$rc" -ne 100 ]; then
  echo "FAIL: expected exit 100 (control failures) on the insecure image, got $rc"
  exit 1
fi

echo "==> [2/4] Remediating with Chef (cinc-client, local mode)"
docker cp "$COOKBOOKS" "$NAME:/tmp/cookbooks"
converge | tee "$REPORTS/remediate.log"

echo "==> [3/4] Rescan (expect every control to pass)"
rc=0; scan after || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "FAIL: rescan after remediation exited $rc"
  exit 1
fi

echo "==> [4/4] Idempotency: a second Chef run must change nothing"
converge | tee "$REPORTS/idempotency.log"
if ! grep -Eq ' 0/[0-9]+ resources updated' "$REPORTS/idempotency.log"; then
  echo "FAIL: second Chef run updated resources - remediation is not idempotent"
  exit 1
fi

echo "==> PASS: non-compliant -> remediated -> compliant, and idempotent"
