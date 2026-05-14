# Acme Health Capstone Write-Up

The primary framework I chose for this capstone is the **HIPAA Security Rule**. I picked HIPAA because this app handles patient intake data, which is PHI. For this project, the main goal is to make the system more defensible for PHI: encrypt it, restrict access to it, log activity, and keep evidence that proves those controls are in place.

## Design Decisions

I kept the starter app mostly the same. I did not try to rebuild the workload or add a bunch of extra services. The point of this capstone is to govern the system that already exists.

I used `us-east-1` as the AWS region. I also used one AWS account for both the workload and the evidence vault. A separate evidence account would be better in a real company, but for this capstone a single sandbox account is enough.

For the evidence bucket, I used S3 Object Lock in `GOVERNANCE` mode for 30 days. I chose governance mode instead of compliance mode because this is a student sandbox and I wanted strong retention without making mistakes impossible to clean up.

The pipeline is meant to apply on merge to `main`. Pull requests run the Terraform plan and policy check. When code lands on `main`, the workflow applies Terraform, creates an evidence bundle, signs it with Cosign, and uploads it to the evidence vault.

## Control Coverage

| Gap | HIPAA control | What I did |
|---|---|---|
| GAP-01 S3 encryption | 164.312(a)(2)(iv) | Added SSE-KMS encryption to the uploads bucket using a customer-managed KMS key. |
| GAP-02 DynamoDB encryption | 164.312(a)(2)(iv) | Enabled DynamoDB encryption with the same customer-managed KMS key. |
| GAP-03 S3 TLS | 164.312(e)(1) | Added a bucket policy that denies non-TLS requests. |
| GAP-04 S3 recovery | 164.308(a)(7) | Enabled versioning on the uploads bucket. |
| GAP-05 Lambda networking | 164.312(e)(1) | Moved the Lambda into the starter VPC private subnets. |
| GAP-06 Lambda monitoring/resilience | 164.312(b) | Added reserved concurrency, a DLQ, and X-Ray tracing. |
| GAP-07 IAM least privilege | 164.312(a)(1) | Replaced broad `dynamodb:*` and `s3:*` permissions with narrower actions. |
| GAP-08 API audit logging | 164.312(b) | Added API Gateway access logging and throttling. |

The Rego policies in `policies/` check these controls against the Terraform plan. Each policy includes a HIPAA control ID in the deny message so a developer can see why the policy failed.

## Evidence Pipeline

The GitHub Actions workflow has the five required steps:

1. Plan
2. Policy check
3. Apply
4. Sign
5. Upload

The evidence bundle includes the Terraform plan, Terraform state, Terraform outputs, commit SHA, and a small manifest. The workflow signs the bundle with Cosign and uploads the bundle, hash, signature, and Sigstore bundle to the evidence bucket.

The evidence bucket is:

```text
acme-health-intake-evidence-788484bb
```

It has versioning, KMS encryption, public access blocking, and Object Lock enabled.

## Trade-Offs

The biggest trade-off is that I used one AWS account instead of separating the workload account from the evidence account. That is not the cleanest production design, but it is reasonable for a 30-day capstone.

Another trade-off is the GitHub Actions AWS role. I used `AdministratorAccess` for the deploy role, but limited who can assume it through GitHub OIDC conditions. In a production setup, I would replace that with a tighter IAM policy.

I also focused the policies on the Terraform plan. That catches problems before merge. A more mature setup would also add AWS Config or another runtime check to catch drift after deploy.

## What I Would Do With Another Sprint

With more time, I would:

- Move the evidence vault into a separate AWS account.
- Add AWS Config rules.
- Add WAF in front of API Gateway.
- Replace the GitHub deploy role with least-privilege permissions.
- Add a script that verifies the signed evidence bundle for the grader.

## What I Did Not Get To

I did not build a separate evidence account. I did not add WAF. I also did not model every possible HIPAA safeguard in OSCAL. The OSCAL file only describes the controls this repo actually implements.

I also still need to run the final GitHub workflow after pushing the repo so the real signed evidence object exists in S3.
