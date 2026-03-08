#!/bin/bash
# Example: RealTest validation
python3 slipscan_cli_2n.py realtest \
  --domain your.domain.com \
  --file results/scan_ok.txt \
  --result-dir results \
  --slipstream-path ./slipstream-client \
  --ready-timeout-ms 20000 \
  --timeout-s 25.0 \
  --auth username:password
