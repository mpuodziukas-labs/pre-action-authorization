import json
import os
import pathlib
import sys
import tempfile

import gate

ORDER = ["unknown-tier", "case-variant", "unknown-host", "host-trick", "userinfo", "port", "scheme",
         "homoglyph", "outside-workspace", "traversal", "symlink", "secret-glob", "env-or-tilde",
         "destructive", "shell-expansion", "interpreter", "network-tool", "git-force", "path-arg", "chaining", "malformed", "fail-closed"]


def rows():
    p = pathlib.Path(__file__).with_name("cases.jsonl")
    return [json.loads(l) for l in p.read_text().splitlines() if l]


def build_world(root):
    """A throwaway workspace with a sibling outside directory, an escaping symlink and a secret file."""
    root = pathlib.Path(root)
    ws, outside = root / "workspace", root / "outside"
    (ws / "src").mkdir(parents=True)
    outside.mkdir()
    (ws / "src" / "main.py").write_text("print('ok')\n")
    (outside / "data.txt").write_text("outside\n")
    (ws / ".env").write_text("TOKEN=example\n")
    os.symlink(outside, ws / "link-out")
    os.symlink(ws / ".env", ws / "link-env")
    policy = {"models": ["small-model-v1", "large-model-v1"], "hosts": ["api.example.com", "kb.example.com"], "workspace": str(ws)}
    return str(ws), policy


def run():
    with tempfile.TemporaryDirectory() as tmp:
        ws, policy = build_world(tmp)
        data = rows()
        out = {}
        failed = []
        for r in data:
            verdict, _ = gate.authorize({"class": r["class"], "value": r["value"].replace("{ws}", ws)}, policy)
            out.setdefault(r["bypass"], []).append(verdict == r["expect"])
            if verdict != r["expect"]:
                failed.append(r["id"])
    lines = ["| bypass class | denied as expected |", "|---|---|"]
    for cls in ORDER:
        res = out.get(cls, [])
        lines.append(f"| {cls} | {sum(res)}/{len(res)} |")
    res = out.get("control", [])
    lines.append(f"| control (allowed) | {sum(res)}/{len(res)} |")
    return "\n".join(lines), failed


def results():
    return run()[0]


if __name__ == "__main__":
    table, failed = run()
    print(table)
    if failed:
        print("FAILED rows: " + ", ".join(failed), file=sys.stderr)
        sys.exit(1)
