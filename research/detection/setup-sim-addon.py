"""Configure the Splunk Infrastructure Monitoring Add-on (splunk_ta_sim 1.3.1) on the EC2 Splunk (27 Oct 2026). Idempotent.

The add-on reads its account from KV store collection `sim_api_config` (record: org_id, org_name, realm, default,
enable) and the token from storage/passwords (realm `splunk_ta_sim`, username = org_id) - see its bin/sim_common.py.
The token comes from $SPLUNK_O11Y_TOKEN and travels only in the request body. Then one `| sim flow` test.
Run: SPLUNK_O11Y_TOKEN=... python3 -I setup-sim-addon.py
"""
import json, os, pathlib, sys, urllib.parse, urllib.request
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "lib"))
from stack import S, BASE  # noqa: E402

ORG_ID, ORG_NAME, REALM = "YOUR_ORG_ID", "your Observability Cloud org", "us1"
NS = BASE + "/en-US/splunkd/__raw/servicesNS/nobody/splunk_ta_sim"
TOKEN = os.environ["SPLUNK_O11Y_TOKEN"]


def req(method, url, data=None, ctype="application/x-www-form-urlencoded"):
    r = urllib.request.Request(url, data=data, method=method, headers={**S.h, "Content-Type": ctype})
    try:
        with S.op.open(r, timeout=60) as x:
            return x.status, x.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# 1. account record (replace any existing record for this org)
st, b = req("GET", NS + "/storage/collections/data/sim_api_config?output_mode=json")
for rec in json.loads(b) if st == 200 else []:
    if rec.get("org_id") == ORG_ID:
        req("DELETE", NS + "/storage/collections/data/sim_api_config/" + rec["_key"])
rec = {"org_id": ORG_ID, "org_name": ORG_NAME, "realm": REALM, "default": True, "enable": True}
st, b = req("POST", NS + "/storage/collections/data/sim_api_config", json.dumps(rec).encode(), "application/json")
print("account record ->", st)

# 2. token in storage/passwords (realm splunk_ta_sim, user = org id); update if present
name = urllib.parse.quote(f"splunk_ta_sim:{ORG_ID}:", safe="")
st, _ = req("POST", NS + f"/storage/passwords/{name}", urllib.parse.urlencode({"password": TOKEN}).encode())
if st == 404:
    st, _ = req("POST", NS + "/storage/passwords",
                urllib.parse.urlencode({"name": ORG_ID, "realm": "splunk_ta_sim", "password": TOKEN}).encode())
print("token stored ->", st)

# 3. test: payment-router APM request and error counts, last 15 min
q = ("| sim flow query=\"A = data('service.request.count', filter=filter('sf_environment','tuktukpay-demo') "
     "and filter('sf_service','payment-router'), rollup='sum').sum(by=['sf_error']).publish()\" resolution=60000")
r = S.search(q, earliest="-15m", app="splunk_ta_sim", wait=180)
rows = r.get("results") or []
print("sim flow rows:", len(rows), "| messages:", [m.get("text", "")[:200] for m in (r.get("messages") or [])], r.get("error", ""))
for x in rows[:4]:
    print("  ", {k: v for k, v in x.items() if not k.startswith("_") or k == "_time"})
