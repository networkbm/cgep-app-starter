variable "aws_region" {
  type        = string
  description = "AWS region for the capstone workload."
  default     = "us-east-1"
}

variable "github_repository" {
  type        = string
  description = "GitHub owner/repo allowed to assume the deployment role via OIDC."
  default     = "networkbm/cgep-app-starter"
}
