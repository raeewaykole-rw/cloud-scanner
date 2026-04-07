"""Helpers for formatting scan reports."""

from typing import Any, Dict
import json


def format_report(report: Dict[str, Any], style: str = "json") -> str:
    """Format the scan report for display.

    Args:
        report: Scan results to format.
        style: One of "json", "plain".
    """

    if style == "plain":
        # A minimal plain text rendering for CLI output.
        lines = []
        for service, data in report.items():
            lines.append(f"[{service.upper()}]")
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == "issues" and isinstance(v, list):
                        lines.append("  Issues:")
                        for issue in v:
                            title = issue.get("issue") or issue.get("title") or "(unknown)"
                            severity = issue.get("severity")
                            lines.append(f"    - {title} (severity={severity})")
                    else:
                        lines.append(f"  {k}: {v}")
            else:
                lines.append(str(data))
            lines.append("")
        return "\n".join(lines)

    # Default to JSON
    return json.dumps(report, indent=2, sort_keys=True)
