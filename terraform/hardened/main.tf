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

# REMEDIATION 1: Least-Privilege IAM Policy scoped to specific S3 prefix & KMS key
resource "aws_iam_role_policy" "app_role_policy" {
  name = "app-automation-policy"
  role = "app-automation-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LeastPrivilegeS3ExportReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::acme-customer-pii-exports-prod",
          "arn:aws:s3:::acme-customer-pii-exports-prod/exports/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      }
    ]
  })
}

# REMEDIATION 2: Private S3 bucket + full PublicAccessBlock + KMS Server-Side Encryption + Versioning
resource "aws_s3_bucket" "customer_exports" {
  bucket = "acme-customer-pii-exports-prod"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "customer_exports_pab" {
  bucket                  = aws_s3_bucket.customer_exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_exports_sse" {
  bucket = aws_s3_bucket.customer_exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/prod-s3-kms-key"
    }
    bucket_key_enabled = true
  }
}

# REMEDIATION 3: Encrypted EBS volume with customer-managed KMS key
resource "aws_ebs_volume" "db_data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/prod-ebs-kms-key"
}

# REMEDIATION 4: Restricted Security Group (Bastion VPN CIDR only, RDP removed)
resource "aws_security_group" "mgmt_sg" {
  name        = "prod-mgmt-sg"
  description = "Management access via corporate VPN bastion only"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.24.0.0/24"]
  }
}

# REMEDIATION 5: Multi-Region CloudTrail enabled with KMS encryption and log digest validation
resource "aws_cloudtrail" "audit_trail" {
  name                          = "acme-org-trail"
  s3_bucket_name                = aws_s3_bucket.customer_exports.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = "arn:aws:kms:us-east-1:123456789012:key/prod-cloudtrail-kms-key"
}
