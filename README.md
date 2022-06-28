# increase-detector
Based in a csv baseline file with previous number of issues, this script resolves if there are more findings after a sast tool analysis, useful for ci-pipelines

Usage:./compare_findings basefile new_report linter_name

Supported combinations of linters-format
any linter --> sarif
semgrep --> json, xml
bandit --> json
pip-audit --> json
