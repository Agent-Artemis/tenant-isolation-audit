#!/bin/bash
# Every verdict the SQL can emit must be documented in the README.
#
# This exists because the shipped version emitted six verdicts and documented
# four, and nobody noticed until a teammate read both files side by side. The
# first search for it missed the gap too, because it looked for quoted strings
# and the verdicts are built inside a CASE with their explanation appended.
#
# So this does not grep for a pattern. It extracts the literals the CASE can
# actually produce, and checks each one against the README.
set -euo pipefail
cd "$(dirname "$0")"
fail=0
verdicts=$(python3 - <<'PY'
import re
s=open('tenant_isolation_audit.sql').read()
m=re.search(r"\n  case\n(.*?)\n  end as verdict", s, re.S)
if not m: raise SystemExit("could not find the verdict CASE")
body=m.group(1)
out=[]
for lit in re.findall(r"then '([^']+)'", body) + re.findall(r"else '([^']+)'", body):
    t=re.split(r'\s*(?:—|:)', lit)[0].strip()
    if t and t not in out: out.append(t)
print("\n".join(out))
PY
)
for v in $verdicts; do
  if grep -q "\`$v\`" README.md; then
    echo "  ok        $v is documented"
  else
    echo "  UNDOCUMENTED  $v is emitted by the SQL and absent from the README"
    fail=1
  fi
done
documented=$(grep -oE '^\| `[A-Za-z]+`' README.md | tr -d '|` ' || true)
for d in $documented; do
  if ! echo "$verdicts" | grep -qx "$d"; then
    echo "  STALE     $d is documented and the SQL no longer emits it"
    fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "  PASS: the SQL and the README agree" || { echo "  FAIL"; exit 1; }
