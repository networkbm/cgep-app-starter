#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
SHA="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
OUT_DIR="${1:-evidence}"
PLAN_JSON="${2:-terraform/plan.json}"

mkdir -p "$OUT_DIR"

BUNDLE_DIR="$OUT_DIR/bundle-${RUN_ID}-${RUN_ATTEMPT}"
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"

cp "$PLAN_JSON" "$BUNDLE_DIR/plan.json"
terraform -chdir=terraform show -json > "$BUNDLE_DIR/state.json"
terraform -chdir=terraform output -json > "$BUNDLE_DIR/outputs.json"
git rev-parse HEAD > "$BUNDLE_DIR/commit.txt"

cat > "$BUNDLE_DIR/manifest.json" <<JSON
{
  "project": "acme-health-intake",
  "primary_framework": "HIPAA Security Rule",
  "commit": "$SHA",
  "github_run_id": "$RUN_ID",
  "github_run_attempt": "$RUN_ATTEMPT"
}
JSON

tar -czf "$OUT_DIR/evidence-${RUN_ID}-${RUN_ATTEMPT}.tar.gz" -C "$OUT_DIR" "bundle-${RUN_ID}-${RUN_ATTEMPT}"
shasum -a 256 "$OUT_DIR/evidence-${RUN_ID}-${RUN_ATTEMPT}.tar.gz" > "$OUT_DIR/evidence-${RUN_ID}-${RUN_ATTEMPT}.tar.gz.sha256"

echo "$OUT_DIR/evidence-${RUN_ID}-${RUN_ATTEMPT}.tar.gz"
