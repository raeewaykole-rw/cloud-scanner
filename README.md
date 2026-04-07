# Cloud Scanner

A simple Python tool to scan AWS infrastructure (S3, EC2, IAM) for common misconfiguration issues.

## Quick Start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Configure AWS credentials using the AWS CLI or environment variables:

```bash
aws configure
```

Or set credentials via environment variables:

```bash
setx AWS_ACCESS_KEY_ID "[insert your own]"
setx AWS_SECRET_ACCESS_KEY "[insert your own]"
setx AWS_DEFAULT_REGION "us-east-1"
```

Run a full scan:

```bash
python main.py --scan all
```

Write a report to disk:

```bash
python main.py --scan all --output reports/report.json
```

## GitHub Recommendations

Include these important files:

- `main.py`
- `requirements.txt`
- `README.md`
- `scanner/__init__.py`
- `scanner/s3_scanner.py`
- `scanner/ec2_scanner.py`
- `scanner/iam_scanner.py`
- `utils/__init__.py`
- `utils/formatter.py`
- `utils/logger.py`
- `.gitignore`

Do not commit local environment files such as `.venv`, AWS credential files, or generated report files.
