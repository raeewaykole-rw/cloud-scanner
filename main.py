"""cloud-scanner

Entrypoint for the cloud scanning tool.
"""

import argparse
import json
import os
from typing import Any, Dict, Optional

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # pragma: no cover
    class _NoColor:  # type: ignore
        RESET_ALL = ""
        RED = ""

    Fore = _NoColor()
    Style = _NoColor()

    def colorama_init(*args: Any, **kwargs: Any) -> None:  # type: ignore
        return None

from scanner import s3_scanner, ec2_scanner, iam_scanner
from utils.logger import setup_logger
from utils.formatter import format_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cloud security misconfiguration scanner")
    parser.add_argument(
        "--scan",
        choices=["all", "s3", "ec2", "iam"],
        default="all",
        help="Which service(s) to scan",
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name (uses AWS SDK default if omitted)",
    )
    parser.add_argument(
        "--region",
        help="AWS region to target (default uses SDK defaults)",
    )
    parser.add_argument(
        "--output",
        help="Path to write a JSON report. If omitted, output is printed to stdout.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser.parse_args()


def write_report(report: Dict[str, Any], output_path: str) -> None:
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)


def main() -> None:
    args = parse_args()
    logger = setup_logger(level=(20 if not args.verbose else 10))

    colorama_init(autoreset=True)

    logger.info("Starting cloud-scanner")

    # If no region is provided and AWS doesn't have a default, use a sensible default.
    # This prevents botocore.exceptions.NoRegionError when running the scan.
    region = args.region or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

    scan_kwargs: Dict[str, Optional[str]] = {
        "profile": args.profile,
        "region": region,
    }

    report: Dict[str, Any] = {}
    if args.scan in ("all", "s3"):
        report["s3"] = s3_scanner.scan(**scan_kwargs)
    if args.scan in ("all", "ec2"):
        report["ec2"] = ec2_scanner.scan(**scan_kwargs)
    if args.scan in ("all", "iam"):
        report["iam"] = iam_scanner.scan(**scan_kwargs)

    if args.output:
        write_report(report, args.output)
        logger.info("Wrote report to %s", args.output)
    else:
        # Print a human-friendly summary
        formatted = format_report(report, style="plain")
        if any(r.get("status") == "error" for r in report.values() if isinstance(r, dict)):
            print(Fore.RED + formatted + Style.RESET_ALL)
        else:
            print(formatted)

    logger.info("Finished cloud-scanner")


if __name__ == "__main__":
    main()
