# SecureCode Scanner X

A lightweight, Flask-based static application security testing (SAST) tool for Python, JavaScript, PHP, and HTML.

## Features

- Multi-language scanning (`.py`, `.js`, `.php`, `.html/.htm`)
- Basic detection of:
  - SQL injection patterns
  - Hardcoded passwords and API keys
  - Dangerous functions (`eval`, weak hashes)
  - Potential XSS vectors
- Security score and risk level
- Scan history with delete
- PDF security reports

## Requirements

- Python 3.10+  
- pip

## Installation

```bash
cd securecode_scanner_x
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

## Running the App

```bash
python app.py
```

Open in browser:

- http://127.0.0.1:5000

## Usage

1. Go to **New Scan**.
2. Upload a source file (`.py`, `.js`, `.php`, `.html`).
3. View results, security score, and download PDF report.
4. Check **History** for past scans.

## Notes

- This is a prototype / educational tool, not a replacement for mature SAST products.
- Do not use on sensitive production code without additional hardening and review.

## License

MIT