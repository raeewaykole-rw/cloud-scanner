"""EC2 security scanning utilities."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _make_session_kwargs(profile: Optional[str], region: Optional[str]) -> Dict[str, str]:
    kwargs: Dict[str, str] = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return kwargs


def _find_open_ingress(permissions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    for perm in permissions:
        ip_ranges = perm.get("IpRanges", [])
        ipv6_ranges = perm.get("Ipv6Ranges", [])
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        ports = (
            f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
            if from_port is not None and to_port is not None
            else "any"
        )

        for ip_range in ip_ranges:
            cidr = ip_range.get("CidrIp")
            if cidr == "0.0.0.0/0":
                severity = "HIGH" if from_port in (22, 3389) else "MEDIUM"
                issues.append(
                    {
                        "issue": f"Ingress {ports} opened to 0.0.0.0/0",
                        "severity": severity,
                    }
                )

        for ip_range in ipv6_ranges:
            cidr = ip_range.get("CidrIpv6")
            if cidr == "::/0":
                severity = "HIGH" if from_port in (22, 3389) else "MEDIUM"
                issues.append(
                    {
                        "issue": f"Ingress {ports} opened to ::/0",
                        "severity": severity,
                    }
                )

    return issues


def scan(profile: Optional[str] = None, region: Optional[str] = None) -> Dict[str, Any]:
    """Scan EC2 security groups for risky ingress rules."""
    try:
        import boto3  # type: ignore
        import botocore  # type: ignore
    except ImportError:
        return {
            "status": "error",
            "error": "boto3 is required for EC2 scanning (pip install boto3)",
        }

    session_kwargs = _make_session_kwargs(profile, region)
    session = boto3.Session(**session_kwargs)
    ec2 = session.client("ec2")

    findings: List[Dict[str, Any]] = []

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")
                issues = _find_open_ingress(sg.get("IpPermissions", []))
                findings.append(
                    {
                        "id": sg_id,
                        "name": sg_name,
                        "issues": issues,
                        "risk_score": max([0] + [9 if i["severity"] == "HIGH" else 5 for i in issues]),
                    }
                )
    except botocore.exceptions.BotoCoreError as e:
        return {"status": "error", "error": str(e)}

    return {"status": "ok", "security_groups": findings, "issues": [i for g in findings for i in g.get("issues", [])]}
