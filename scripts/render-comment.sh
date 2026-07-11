#!/usr/bin/env bash
# Renders a tripwyre JSON report (stdin) as a GitHub PR comment (stdout).
set -euo pipefail

echo "<!-- tripwyre-report -->"
echo "## tripwyre scan"
echo

jq -r '
  if .summary.total == 0 then
    "No findings. All clear. ✅"
  else
    "**\(.summary.total) findings** — 🔴 \(.summary.critical) critical · 🟡 \(.summary.warning) warning · 🔵 \(.summary.info) info\n\n" +
    "| | Scanner | Finding |\n|---|---|---|\n" +
    ([.findings
      | sort_by(if .severity == "CRITICAL" then 0 elif .severity == "WARNING" then 1 else 2 end)
      | .[] |
      "| " +
      (if .severity == "CRITICAL" then "🔴"
       elif .severity == "WARNING" then "🟡"
       else "🔵" end) +
      " | `\(.scanner)` | \(.title | gsub("\\|"; "\\|")) |"
    ] | join("\n"))
  end
'
