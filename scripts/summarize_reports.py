"""Turn before/after InSpec JSON reports into a Markdown table.

Usage: python scripts/summarize_reports.py reports/before.json reports/after.json
CI appends the output to $GITHUB_STEP_SUMMARY so the run page shows the table.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

LABEL = {"passed": "✅ pass", "failed": "❌ fail", "skipped": "⏭ skip", None: "—"}


def control_status(control: dict) -> str | None:
    statuses = [r.get("status") for r in control.get("results", [])]
    if not statuses:
        return None
    if "failed" in statuses:
        return "failed"
    if all(s == "skipped" for s in statuses):
        return "skipped"
    return "passed"


def load(path: str) -> dict[str, tuple[str, float, str | None]]:
    p = Path(path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    out = {}
    for profile in data.get("profiles", []):
        for c in profile.get("controls", []):
            out[c["id"]] = (c.get("title") or "", c.get("impact", 0), control_status(c))
    return out


def main(before_path: str, after_path: str) -> str:
    before, after = load(before_path), load(after_path)
    ids = sorted(before.keys() | after.keys())
    lines = [
        "## Compliance: scan → remediate → rescan",
        "",
        "| Control | Title | Impact | Before | After |",
        "|---|---|---|---|---|",
    ]
    for cid in ids:
        title, impact, b = before.get(cid, ("", 0, None))
        a_title, a_impact, a = after.get(cid, (title, impact, None))
        lines.append(
            f"| `{cid}` | {title or a_title} | {impact or a_impact} | {LABEL[b]} | {LABEL[a]} |"
        )
    passed = sum(1 for cid in ids if after.get(cid, (0, 0, None))[2] == "passed")
    lines += ["", f"**{passed}/{len(ids)} controls passing after remediation.**"]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    print(main(sys.argv[1], sys.argv[2]))
