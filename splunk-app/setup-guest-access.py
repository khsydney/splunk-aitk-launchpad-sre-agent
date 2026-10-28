"""One-off (27 Oct 2026): let the read-only workshop role tuktuk_guest read index=tuktukpay_agent_audit, so attendees
can open the TukTukPay SRE Agent app (splunk/sre-app). Adds the index to srchIndexesAllowed and to the role's search
filter, limited to the event types the app reads (the owner asked 27 Oct); capabilities are left as they are (checked before and after). Role `user` needs nothing: it already has
srchIndexesAllowed = *. The app itself is readable by every role (metadata/default.meta: read : [ * ]).
Idempotent. Run: python3 -I setup-guest-access.py
"""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lib"))
from stack import S  # noqa: E402

ROLE, IDX = "tuktuk_guest", "tuktukpay_agent_audit"
PATH = f"/services/authorization/roles/{ROLE}"


def role():
    return json.loads(S.get(PATH)[1])["entry"][0]["content"]


c = role()
caps_before = sorted(c.get("capabilities") or [])
allowed = list(c.get("srchIndexesAllowed") or [])
filt = c.get("srchFilter") or ""
if IDX not in allowed:
    allowed.append(IDX)
# only the event types the app reads, not the whole audit trail (tool results stay in sre.mcp.call / sre.rca.evidence)
CLAUSE = f'(index={IDX} event IN ("sre.case.*", "sre.tree.*", "sre.rca.tool", "sre.rca.step", "sre.llm.call"))'
if f"index={IDX}" not in filt:
    filt = f"{filt} OR {CLAUSE}" if filt else CLAUSE
st, b = S.post(PATH, {"srchIndexesAllowed": allowed, "srchFilter": filt})
print("update ->", st)
if st not in (200, 201):
    sys.exit(b[:400])
c = role()
print("srchIndexesAllowed:", c.get("srchIndexesAllowed"))
print("srchFilter:", c.get("srchFilter"))
caps_after = sorted(c.get("capabilities") or [])
print("capabilities unchanged:", caps_before == caps_after, caps_after)
for r in ("user",):
    print(r, "srchIndexesAllowed:", json.loads(S.get(f"/services/authorization/roles/{r}")[1])["entry"][0]["content"].get("srchIndexesAllowed"))
