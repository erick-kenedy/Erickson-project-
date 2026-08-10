# 🛡️ NetGuard Security Scanner

NetGuard is a defensive security assessment application for identifying
common network exposure and data-security weaknesses.

## Features

- TCP network service assessment
- Risk classification
- Security recommendations
- Detection of potentially exposed secrets
- File-permission assessment on Unix/Linux
- Security dashboard
- CSV report generation
- Text report generation

## Installation

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

### Linux / macOS

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run streamlit_app.py
```

## Quick start

Run the Streamlit UI (after activating your venv):

```bash
streamlit run streamlit_app.py
```

Run the CLI scanner (example):

```bash
python -c "from scanner.scan import scan_directory; print(scan_directory('.', max_files=100))"
```

## Safety and usage

Only run network scans on hosts you own or have explicit authorization to assess. The secret-detection patterns can produce false positives — review findings before taking action.
