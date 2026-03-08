#!/bin/bash
# Example: Fast IP scan
python3 slipscan_cli_2n.py scan \
  --domain your.domain.com \
  --targets 8.8.8.8 \
  --threads 64 \
  --result-dir results
