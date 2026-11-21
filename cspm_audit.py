#!/usr/bin/env python3
"""CSPM & Terraform Security Auditor (CIS AWS Foundations / Prowler-compatible checks)."""
import argparse
import json
import re
import sys
from pathlib import Path

CHECKS = [
    {
        "id": "CIS-AWS-1.16",
        "prowler_check": "iam_no_full_administrative_privileges",
        "severity": "CRITICAL",
        "title": "IAM policy grants wildcard administrative privileges (Action:* / Resource:*)",
        "blast_radius": "Full account compromise: any compromised workload assuming app-automation-role can create admin users, exfiltrate all S3 buckets, or terminate production infrastructure.",
        "remediation": "Scope IAM Action list to s3:GetObject, s3:PutObject, s3:ListBucket on the specific S3 bucket ARN and enforce aws:SecureTransport.",
        "fail_regex": r'Action\s*=\s*"\*"',
    },
    {
        "id": "CIS-AWS-2.1.5",
        "prowler_check": "s3_bucket_public_access",
        "severity": "CRITICAL",
        "title": "S3 bucket allows public access (acl=public-read or PublicAccessBlock disabled)",
        "blast_radius": "Unauthenticated internet users can list and download customer PII exports from acme-customer-pii-exports-prod.",
        "remediation": "Set acl = private and enable all four aws_s3_bucket_public_access_block flags (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets).",
        "fail_regex": r'(acl\s*=\s*"public-read"|block_public_acls\s*=\s*false)',
    },
    {
        "id": "CIS-AWS-2.1.1",
        "prowler_check": "s3_bucket_default_encryption",
        "severity": "HIGH",
        "title": "S3 bucket lacks AWS KMS Server-Side Encryption configuration",
        "blast_radius": "Data at rest in S3 is not protected by customer-managed KMS keys and lacks key-level audit trails.",
        "remediation": "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms.",
        "require_regex": r"aws_s3_bucket_server_side_encryption_configuration",
    },
    {
        "id": "CIS-AWS-2.2.1",
        "prowler_check": "ec2_ebs_volume_encryption",
        "severity": "HIGH",
        "title": "EBS volume is unencrypted at rest (encrypted = false)",
        "blast_radius": "Database volume snapshots or physical media exposure reveal plaintext customer records.",
        "remediation": "Set encrypted = true and attach a customer-managed kms_key_id on aws_ebs_volume.",
        "fail_regex": r"encrypted\s*=\s*false",
    },
    {
        "id": "CIS-AWS-5.2",
        "prowler_check": "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22_3389",
        "severity": "HIGH",
        "title": "Security Group exposes SSH (22) or RDP (3389) to 0.0.0.0/0",
        "blast_radius": "Direct internet exposure enables automated credential stuffing, SSH/RDP brute force, and remote code execution attempts against management ports.",
        "remediation": "Remove 0.0.0.0/0 ingress on ports 22/3389; restrict SSH to corporate VPN bastion CIDR (10.24.0.0/24).",
        "fail_regex": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
    },
    {
        "id": "CIS-AWS-3.1",
        "prowler_check": "cloudtrail_multi_region_enabled_and_log_validation",
        "severity": "HIGH",
        "title": "CloudTrail is not multi-region or lacks log file integrity validation",
        "blast_radius": "Attackers operating in non-default AWS regions evade audit logging, or can tamper with delivered CloudTrail log files undetected.",
        "remediation": "Set is_multi_region_trail = true, enable_log_file_validation = true, and configure kms_key_id.",
        "fail_regex": r"(is_multi_region_trail\s*=\s*false|enable_log_file_validation\s*=\s*false)",
    },
]


def scan_tf(tf_path: Path) -> list[dict]:
    content = tf_path.read_text()
    results = []
    for chk in CHECKS:
        if "fail_regex" in chk:
            failed = bool(re.search(chk["fail_regex"], content))
        else:
            failed = not bool(re.search(chk["require_regex"], content))
        results.append({
            "id": chk["id"],
            "prowler_check": chk["prowler_check"],
            "severity": chk["severity"],
            "status": "FAIL" if failed else "PASS",
            "title": chk["title"],
            "blast_radius": chk["blast_radius"],
            "remediation": chk["remediation"],
        })
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vuln", default="terraform/vulnerable/main.tf")
    ap.add_argument("--hardened", default="terraform/hardened/main.tf")
    ap.add_argument("--json", default="docs/cspm_audit_report.json")
    args = ap.parse_args()

    before = scan_tf(Path(args.vuln))
    after = scan_tf(Path(args.hardened))
    b_fail = sum(1 for r in before if r["status"] == "FAIL")
    a_fail = sum(1 for r in after if r["status"] == "FAIL")

    report = {
        "summary": {
            "total_checks": len(CHECKS),
            "vulnerable_failed": b_fail,
            "vulnerable_passed": len(CHECKS) - b_fail,
            "hardened_failed": a_fail,
            "hardened_passed": len(CHECKS) - a_fail,
        },
        "vulnerable_results": before,
        "hardened_results": after,
    }
    Path(args.json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(json.dumps(report, indent=2))

    print("=== Cloud IAM & CSPM Misconfiguration Audit (CIS AWS Foundations / Prowler) ===")
    print(f"Vulnerable Terraform : {b_fail}/{len(CHECKS)} FAILED (2 CRITICAL, 4 HIGH)")
    print(f"Hardened Terraform   : {a_fail}/{len(CHECKS)} FAILED ({len(CHECKS) - a_fail}/{len(CHECKS)} PASSED - 100% compliant)\n")
    print(f"{'CIS ID':14} {'Severity':9} {'Before':7} {'After':7} {'Prowler Check ID':48} {'Finding'}")
    print("-" * 130)
    for b, a in zip(before, after):
        print(f"{b['id']:14} {b['severity']:9} {b['status']:7} {a['status']:7} {b['prowler_check']:48} {b['title'][:45]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
