#!/usr/bin/env bash
set -euo pipefail

PLAN_JSON="${1:-terraform/plan.json}"
POLICY_DIR="${2:-policies}"

if [[ ! -f "$PLAN_JSON" ]]; then
  echo "Terraform plan JSON not found: $PLAN_JSON" >&2
  exit 1
fi

opa test "$POLICY_DIR"
conftest test "$PLAN_JSON" --policy "$POLICY_DIR"
