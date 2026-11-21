terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# FINDING 1 (CRITICAL): Over-privileged IAM Policy with wildcard Action:* and Resource:*
resource "aws_iam_role_policy" "app_role_policy" {
  name = "app-automation-policy"
  role = "app-automation-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullAdminWildcard"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# FINDING 2 (CRITICAL): Publicly readable S3 bucket without PublicAccessBlock or SSE
resource "aws_s3_bucket" "customer_exports" {
  bucket = "acme-customer-pii-exports-prod"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "customer_exports_pab" {
  bucket                  = aws_s3_bucket.customer_exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# FINDING 3 (HIGH): Unencrypted EBS volume storing database snapshots
resource "aws_ebs_volume" "db_data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# FINDING 4 (HIGH): Security Group exposing SSH (22) and RDP (3389) to 0.0.0.0/0
resource "aws_security_group" "mgmt_sg" {
  name        = "prod-mgmt-sg"
  description = "Management access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FINDING 5 (HIGH): Multi-Region CloudTrail disabled / log file validation off
resource "aws_cloudtrail" "audit_trail" {
  name                          = "acme-org-trail"
  s3_bucket_name                = aws_s3_bucket.customer_exports.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
}
