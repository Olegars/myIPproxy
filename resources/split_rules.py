import json
import uuid
from pathlib import Path

path = Path(r"C:\ProgramData\stopRKN\config.json")
cfg = json.loads(path.read_text(encoding="utf-8"))
rules = cfg["rules"]
cidr_rules = []
split = []
for rule in rules:
    tokens = [part.strip() for part in (rule.get("target") or "").split(",") if part.strip()]
    names = [part for part in tokens if "/" not in part]
    cidrs = [part for part in tokens if "/" in part]
    if not names or not cidrs:
        continue
    rule["target"] = ",".join(names)
    extra = dict(rule)
    extra["id"] = str(uuid.uuid4())
    extra["target"] = ",".join(cidrs)
    comment = (rule.get("comment") or "").strip()
    extra["comment"] = (comment + " — сети").strip()
    cidr_rules.append(extra)
    split.append((comment, len(names), len(cidrs)))

last_named = max((i for i, rule in enumerate(rules) if (rule.get("target") or "").strip()), default=-1)
insert_at = last_named + 1
rules[insert_at:insert_at] = cidr_rules
path.write_text(json.dumps(cfg, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")
for comment, names, cidrs in split:
    print(comment, "names", names, "nets", cidrs, "insert", insert_at)
print("rules", len(rules))
