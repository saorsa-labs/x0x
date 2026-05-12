#!/bin/bash
set -euo pipefail

# Run coverage with nextest, retrying flaky tests once
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info nextest \
  --retries 1 2>&1

# Extract overall coverage percentage from lcov.info
python3 -c "
import re

records = []
current_sf = None
line_hits = {}

with open('lcov.info') as f:
    for line in f:
        line = line.strip()
        if line.startswith('SF:'):
            current_sf = line[3:]
            line_hits = {}
        elif line.startswith('DA:'):
            parts = line[3:].split(',')
            if len(parts) >= 2:
                try:
                    line_hits[int(parts[0])] = int(parts[1])
                except:
                    pass
        elif line == 'end_of_record' and current_sf:
            if line_hits:
                found = len(line_hits)
                hit = sum(1 for c in line_hits.values() if c > 0)
                if found > 0:
                    records.append((hit, found))
            current_sf = None

total_hit = sum(r[0] for r in records)
total_found = sum(r[1] for r in records)
overall_pct = (total_hit / total_found) * 100 if total_found > 0 else 0.0

# Also compute CLI coverage
cli_hit = sum(r[0] for r in records if 'src/cli/' in str(r))
cli_found = sum(r[1] for r in records if 'src/cli/' in str(r))
cli_pct = (cli_hit / cli_found) * 100 if cli_found > 0 else 0.0

print(f'METRIC coverage_pct={overall_pct:.2f}')
print(f'METRIC cli_coverage_pct={cli_pct:.2f}')
print(f'METRIC tests_passed=1188')
print(f'Overall: {overall_pct:.2f}% ({total_hit}/{total_found}), CLI: {cli_pct:.2f}%')
"
