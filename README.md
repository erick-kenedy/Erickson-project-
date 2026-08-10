NetGuard Security Scanner
Defensive network and data security assessment package.

# NetGuard

NetGuard is a small defensive network and data security assessment toolkit. It provides:

- A TCP port scanner for quick assessment of open services (scanner.network.scan_host).
- A file system scanner that checks for world-readable/writable files and common secret patterns (scanner.scan.scan_directory).
- A risk scoring utility (scanner.risk.score) and report generation helpers (scanner.report.generate_csv, scanner.report.report_header).

## Quick start

1. Create a virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. Run the Streamlit UI:

```bash
streamlit run streamlit_app.py
```

3. Run the CLI scanner (example):

```bash
python -c "from scanner.scan import scan_directory; print(scan_directory('.', max_files=100))"
```

## Safety and usage

Only run network scans on hosts you own or have explicit authorization to assess. The secret-detection patterns can produce false positives — review findings before taking action.
