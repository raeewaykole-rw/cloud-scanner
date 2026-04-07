"""S3 security scanning utilities."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def _make_session_kwargs(profile: Optional[str], region: Optional[str]) -> Dict[str, str]:
    kwargs: Dict[str, str] = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return kwargs


def _is_public_acl(grants: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    for grant in grants:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        if uri in (
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        ):
            perm = grant.get("Permission")
            issues.append(
                {
                    "issue": f"Bucket ACL allows {uri.split('/')[-1]} ({perm})",
                    "severity": "HIGH" if perm in ("FULL_CONTROL", "WRITE") else "MEDIUM",
                }
            )
    return issues


def _policy_has_wildcard(policy_text: str) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    try:
        policy = json.loads(policy_text)
    except Exception:
        return issues

    statements = policy.get("Statement")
    if not statements:
        return issues

    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*" or principal == {"AWS": "*"} or principal == {"AWS": ["*"]}:
            issues.append(
                {
                    "issue": "Bucket policy allows public access (Principal=*)",
                    "severity": "HIGH",
                }
            )
        resources = statement.get("Resource")
        if resources == "*" or resources == ["*"]:
            issues.append(
                {
                    "issue": "Bucket policy allows access to all resources (Resource=*)",
                    "severity": "HIGH",
                }
            )
        actions = statement.get("Action")
        if actions == "*" or actions == ["*"]:
            issues.append(
                {
                    "issue": "Bucket policy allows all actions (Action=*)",
                    "severity": "HIGH",
                }
            )
    return issues


def scan(profile: Optional[str] = None, region: Optional[str] = None) -> Dict[str, Any]:
    """Scan S3 buckets and return findings.

    Args:
        profile: AWS profile to use (optional).
        region: AWS region to target (optional).

    Returns:
        A dict with scan results that can be serialized to JSON.
    """
    try:
        import boto3  # type: ignore
        import botocore  # type: ignore
    except ImportError:
        return {
            "status": "error",
            "error": "boto3 is required for S3 scanning (pip install boto3)",
        }

    session_kwargs = _make_session_kwargs(profile, region)
    session = boto3.Session(**session_kwargs)
    s3 = session.client("s3")

    findings: List[Dict[str, Any]] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except botocore.exceptions.BotoCoreError as e:
        return {"status": "error", "error": str(e)}

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        if not bucket_name:
            continue

        bucket_issues: List[Dict[str, Any]] = []

        # Public Access Block
        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            pab_cfg = pab.get("PublicAccessBlockConfiguration", {})
            if not all(
                pab_cfg.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            ):
                bucket_issues.append(
                    {
                        "issue": "Public access block not fully enabled",
                        "severity": "MEDIUM",
                    }
                )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
                bucket_issues.append(
                    {
                        "issue": "Public access block configuration missing",
                        "severity": "MEDIUM",
                    }
                )
            else:
                bucket_issues.append({"issue": f"Error checking public access block: {e}", "severity": "LOW"})

        # Bucket ACL
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            bucket_issues.extend(_is_public_acl(acl.get("Grants", [])))
        except botocore.exceptions.ClientError as e:
            bucket_issues.append({"issue": f"Error fetching ACL: {e}", "severity": "LOW"})

        # Bucket Policy
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            bucket_issues.extend(_policy_has_wildcard(policy.get("Policy", "")))
        except botocore.exceptions.ClientError as e:
            # Bucket may not have a policy, which is fine.
            if e.response["Error"]["Code"] not in ("NoSuchBucketPolicy", "NoSuchBucket"):
                bucket_issues.append({"issue": f"Error fetching policy: {e}", "severity": "LOW"})

        findings.append(
            {
                "name": bucket_name,
                "issues": bucket_issues,
                "risk_score": max([0] + [9 if i["severity"] == "HIGH" else 5 if i["severity"] == "MEDIUM" else 1 for i in bucket_issues]),
            }
        )

    return {
        "status": "ok",
        "buckets": findings,
        "issues": [i for b in findings for i in b.get("issues", [])],
    }
