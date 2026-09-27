"""Inline vendor/vis-network.min.js into frontend/src.html -> frontend/index.html (fully offline)."""
import re
src = open("frontend/src.html", encoding="utf-8").read()
lib = open("vendor/vis-network.min.js", encoding="utf-8").read()
assert "</scr" + "ipt" not in lib, "lib contains closing script tag"
assert "__VIS_LIB_INLINE__" in src
out = src.replace("/*__VIS_LIB_INLINE__*/", "\n" + lib + "\n")
open("frontend/index.html", "w", encoding="utf-8").write(out)
print("wrote frontend/index.html", len(out), "bytes")
ext = sorted(set(re.findall(r'https?://[^\s"\'<>]+', out)))
print("external URLs:", ext if ext else "NONE")
