# AI Index for NetGuard

name: NetGuard Security Scanner
description: Defensive network and data security assessment package.
license: MIT
languages:
  - Python
entrypoints:
  - app.py
  - streamlit_app.py
modules:
  - scanner.scan
  - scanner.network
  - scanner.risk
  - scanner.report
notes: |
  This repository contains a TCP port scanner and a file scanner that checks
  filesystem permissions and secret patterns. Use only on systems you own or
  have explicit authorization to test.
