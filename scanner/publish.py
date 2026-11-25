#!/usr/bin/env python3
"""Add one scan report to the dashboard site folder (the gh-pages checkout).

Usage: publish.py <report.json> <site_dir> <dashboard_src_dir>
"""
import json
import shutil
import sys
from pathlib import Path

report_path, site, dashboard = (Path(p) for p in sys.argv[1:4])
report = json.loads(report_path.read_text(encoding="utf-8"))

shutil.copytree(dashboard, site, dirs_exist_ok=True)  # keep the UI in sync with the source branch
(site / ".nojekyll").touch()
reports = site / "data" / "reports"
reports.mkdir(parents=True, exist_ok=True)
(reports / f"{report['id']}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

index_path = site / "data" / "index.json"
index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
keys = ("id", "sha", "short_sha", "actor", "branch", "event", "pr", "timestamp", "gate", "counts", "total", "run_url")
entry = {k: report[k] for k in keys}
index = [entry] + [e for e in index if e["id"] != report["id"]]
index_path.write_text(json.dumps(index[:500], indent=1), encoding="utf-8")
print(f"Published {report['id']} ({report['gate']}); {len(index[:500])} report(s) in index")
