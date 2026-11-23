"""Compare BR November findings with a fresh Semgrep + Horusec scan of the current revision.

Usage: python3 -I compare.py <br-tools dir> <rescan dir> <out json>
"""
import collections
import glob
import json
import os
import re
import sys

BR, RS, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
old = json.load(open(os.path.join(BR, "findings.json")))

SCOPE_DIRS = ("server/", "packages/", "ui/", "cli/")  # BR Horusec scope (no tests)
TEST_RE = re.compile(r"(^|/)(__tests__|tests?|e2e|fixtures?|__mocks__|stories)(/|$)|\.(test|spec|stories)\.[cm]?[jt]sx?$")


def hs_rule(title):
    return re.sub(r"^\(\d+/\d+\) \* Possible vulnerability detected: ", "", title.split("\n")[0], flags=re.I).strip()


def norm(code):
    return re.sub(r"\s+", "", code or "")[:120]


new = []
# Semgrep
_p = os.path.join(RS, "semgrep-br.json")
sg = json.load(open(_p)) if os.path.exists(_p) else {}
for r in sg.get("results", []):
    path = r["path"].removeprefix("/src/")
    new.append(dict(tool="Semgrep", rule=r["check_id"].split(".")[-1], check_id=r["check_id"],
                    severity="High" if r["extra"]["severity"] == "ERROR" else r["extra"]["severity"],
                    file=path, line=r["start"]["line"], code=r["extra"].get("lines", "").strip()[:200],
                    cwe=",".join(r["extra"].get("metadata", {}).get("cwe", []) if isinstance(r["extra"].get("metadata", {}).get("cwe"), list) else [str(r["extra"].get("metadata", {}).get("cwe", ""))])))
sg_errors = len(sg.get("errors", []))
sg_skipped = len(sg.get("paths", {}).get("skipped", []) or [])
# Horusec (per-directory runs)
for fn in glob.glob(os.path.join(RS, "hs", "*.json")):
    prefix = os.path.basename(fn)[:-5].replace("_", "/") + "/"
    d = json.load(open(fn))
    for x in d.get("analysisVulnerabilities") or []:
        v = x["vulnerabilities"]
        sev = v["severity"].capitalize()
        new.append(dict(tool="Horusec", rule=hs_rule(v["details"]), rule_id=v.get("rule_id", ""),
                        severity=sev, file=prefix + v["file"], line=int(v["line"] or 0),
                        code=(v.get("code") or "").strip()[:200], language=v.get("language", "")))


def in_br_profile(x):
    """Same reporting profile as the BR export."""
    if x["tool"] == "Semgrep":
        return x["severity"] == "High"
    if x["language"] == "Leaks" or x["severity"] in ("Low", "Info"):
        return False
    return x["file"].startswith(SCOPE_DIRS) and not TEST_RE.search(x["file"])


def old_rule(o):
    if o["tool"] == "Semgrep":
        return o["title"].split(".")[-1]
    return re.sub(r"^\(\d+/\d+\) \* Possible Vulnerability Detected: ", "", o["title"], flags=re.I).strip()


# Match old -> new
pool = collections.defaultdict(list)
for i, x in enumerate(new):
    pool[(x["tool"], x["rule"].lower(), x["file"])].append(i)
used = set()
matches = {}
olds = [o for o in old if o["tool"] != "DependencyTrack"]
for exact in (True, False):
    for o in olds:
        if o["id"] in matches:
            continue
        cands = [i for i in pool.get((o["tool"], old_rule(o).lower(), o["file"]), []) if i not in used]
        if exact:
            cands = [i for i in cands if norm(new[i]["code"]) and norm(new[i]["code"]) == norm(o["code"])]
        if not cands:
            continue
        best = min(cands, key=lambda i: abs(new[i]["line"] - int(o.get("cur_line") or o["line"] or 0)))
        used.add(best)
        matches[o["id"]] = best

for i, x in enumerate(new):
    x["br_id"] = next((k for k, v in matches.items() if v == i), "")
    x["in_profile"] = in_br_profile(x)

result = dict(new=new, matches=matches, sg_errors=sg_errors, sg_skipped=sg_skipped,
              old_unmatched=[o["id"] for o in old if o["tool"] != "DependencyTrack" and o["id"] not in matches])
json.dump(result, open(OUT, "w"), ensure_ascii=False, indent=1)

prof = [x for x in new if x["in_profile"]]
print("new total", len(new), "in BR profile", len(prof))
print("old matched", len(matches), "old unmatched", result["old_unmatched"])
print("new in profile without BR id", sum(1 for x in prof if not x["br_id"]))
c = collections.Counter((x["tool"], x["severity"], x["rule"][:70], bool(x["br_id"])) for x in prof)
for k, v in sorted(c.items(), key=lambda kv: (-kv[1])):
    print(v, k)
