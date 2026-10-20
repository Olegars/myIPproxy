import json
from pathlib import Path

root = Path(r"C:\Qt\myIPproxy\resources")
google = (root / "google-ipv4.txt").read_text(encoding="ascii").strip()
meta = (root / "meta-ipv4.txt").read_text(encoding="ascii").strip()
path = Path(r"C:\ProgramData\stopRKN\config.json")
cfg = json.loads(path.read_text(encoding="utf-8"))

def append(rule, nets, marker):
    target = rule.get("target") or ""
    if marker in target:
        return "already"
    rule["target"] = target + ("," if target else "") + nets
    return "added"

done = []
for rule in cfg["rules"]:
    name = rule.get("comment") or ""
    if name == "YouTube":
        done.append(("YouTube", append(rule, google, "142.250.0.0/15"), len(rule["target"])))
    elif name == "Instagram":
        done.append(("Instagram", append(rule, meta, "157.240.0.0/17"), len(rule["target"])))

path.write_text(json.dumps(cfg, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")
for name, status, length in done:
    print(name, status, length)
