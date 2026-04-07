"""IAM security scanning utilities."""

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


def _check_policy_document(policy_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    statements = policy_doc.get("Statement")
    if not statements:
        return issues

    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action")
        resources = statement.get("Resource")

        if actions == "*" or actions == ["*"] or (isinstance(actions, list) and "*" in actions):
            issues.append(
                {"issue": "Policy allows all actions (*)", "severity": "HIGH"}
            )

        if resources == "*" or resources == ["*"] or (isinstance(resources, list) and "*" in resources):
            issues.append(
                {"issue": "Policy allows access to all resources (*)", "severity": "HIGH"}
            )

    return issues


def scan(profile: Optional[str] = None, region: Optional[str] = None) -> Dict[str, Any]:
    """Scan IAM policies for over-permissive rules."""
    try:
        import boto3  # type: ignore
        import botocore  # type: ignore
    except ImportError:
        return {
            "status": "error",
            "error": "boto3 is required for IAM scanning (pip install boto3)",
        }

    session_kwargs = _make_session_kwargs(profile, region)
    session = boto3.Session(**session_kwargs)
    iam = session.client("iam")

    findings: List[Dict[str, Any]] = []

    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policy_arn = policy.get("Arn")
                policy_name = policy.get("PolicyName")
                if not policy_arn:
                    continue

                versions = iam.list_policy_versions(PolicyArn=policy_arn).get("Versions", [])
                default_version = next((v for v in versions if v.get("IsDefaultVersion")), None)
                if not default_version:
                    continue

                version_id = default_version.get("VersionId")
                doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id).get("PolicyVersion", {}).get(
                    "Document",
                    {},
                )
                issues = _check_policy_document(doc)
                findings.append(
                    {
                        "name": policy_name,
                        "arn": policy_arn,
                        "issues": issues,
                        "risk_score": max([0] + [9 if i["severity"] == "HIGH" else 5 for i in issues]),
                    }
                )
    except botocore.exceptions.BotoCoreError as e:
        return {"status": "error", "error": str(e)}

    return {"status": "ok", "policies": findings, "issues": [i for p in findings for i in p.get("issues", [])]}
