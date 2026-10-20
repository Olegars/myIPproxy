from pathlib import Path

root = Path(r"C:\Qt\myIPproxy")
google = (root / "resources" / "google-ipv4.txt").read_text(encoding="ascii").strip()
meta = (root / "resources" / "meta-ipv4.txt").read_text(encoding="ascii").strip()
header = (
    "#pragma once\n"
    "#include <QString>\n"
    "namespace qpr {\n"
    "inline QString googleIpv4Nets() { return QString::fromLatin1(\"" + google + "\"); }\n"
    "inline QString metaIpv4Nets() { return QString::fromLatin1(\"" + meta + "\"); }\n"
    "}\n"
)
(root / "src" / "core" / "netranges.h").write_text(header, encoding="utf-8")
print("header", len(header), "google", google.count(",") + 1, "meta", meta.count(",") + 1)
