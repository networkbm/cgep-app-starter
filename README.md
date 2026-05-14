# Acme Health CGE-P Capstone

This repo is a governed fork of `GRCEngClub/cgep-app-starter`. The primary framework is the **HIPAA Security Rule** because the Patient Intake API handles PHI.

## What Is Included

- Terraform baseline for KMS, S3 Object Lock evidence vault, CloudTrail, VPC placement, API logging, and starter resource hardening.
- HIPAA-mapped OPA/Rego policy suite under `policies/`.
- GitHub Actions evidence pipeline in `.github/workflows/grc-gate.yml`.
- OSCAL component definition under `oscal/components/` plus Trestle-validation copies under `component-definitions/` and `profiles/`.
- Design rationale in `WRITEUP.md`.

## Local Verification

```bash
make test AWS_PROFILE=sandbox
terraform -chdir=terraform validate
opa test ./policies
eval "$(aws configure export-credentials --profile sandbox --format env)"
terraform -chdir=terraform plan -out=tfplan
terraform -chdir=terraform show -json tfplan > terraform/plan.json
scripts/policy-gate.sh terraform/plan.json policies
trestle validate -t component-definition -n acme-health-intake-component
trestle validate -t profile -n hipaa-security-rule-profile
rm -f terraform/tfplan terraform/plan.json
```

## GitHub Secret

Set this repository secret before running the workflow on GitHub:

```text
AWS_ROLE_TO_ASSUME=arn:aws:iam::771469181384:role/acme-health-intake-github-actions-788484bb
```

## Key Outputs

```text
API URL: https://hy7lfpmvgc.execute-api.us-east-1.amazonaws.com/intake
Evidence bucket: acme-health-intake-evidence-788484bb
CloudTrail bucket: acme-health-intake-cloudtrail-788484bb
KMS key: arn:aws:kms:us-east-1:771469181384:key/16799b9c-2e43-4fa9-acde-5f70aa4f9c9f
```
