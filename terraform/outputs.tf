output "api_url" {
  value       = "${aws_apigatewayv2_api.intake.api_endpoint}/intake"
  description = "POST /intake endpoint."
}

output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "kms_key_arn" {
  value       = aws_kms_key.grc.arn
  description = "Customer-managed KMS key used for PHI and evidence encryption."
}

output "evidence_bucket" {
  value       = aws_s3_bucket.evidence.id
  description = "Object Lock evidence vault bucket."
}

output "cloudtrail_bucket" {
  value       = aws_s3_bucket.cloudtrail.id
  description = "CloudTrail management event log bucket."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.management.name
  description = "Multi-region CloudTrail trail with log-file validation."
}

output "github_actions_role_arn" {
  value       = aws_iam_role.github_actions.arn
  description = "Role ARN to store in the GitHub AWS_ROLE_TO_ASSUME secret."
}
