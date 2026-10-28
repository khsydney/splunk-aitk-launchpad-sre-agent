"""Session helper for a Splunk Enterprise / Splunk Cloud search head through Splunk Web: form login, then the
web-proxied REST API at /en-US/splunkd/__raw/services/... Nothing is printed.

Environment:
  SPLUNK_WEB_URL      e.g. https://splunk.example.com:8000
  SPLUNK_CREDS_FILE   file with line 1 = user, line 2 = password (keep it outside the repo, mode 600)
  SPLUNK_VERIFY_TLS   "false" for a self-signed certificate (default true)
Usage: from stack import S, BASE; S.get(path), S.post(path, dict), S.search(spl)."""
import http.cookiejar, json, os, pathlib, ssl, time, urllib.parse, urllib.request

BASE = os.environ.get("SPLUNK_WEB_URL", "https://splunk.example.com:8000").rstrip("/")
CREDS = pathlib.Path(os.path.expanduser(os.environ.get("SPLUNK_CREDS_FILE", "~/.splunk_creds")))
VERIFY = os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() != "false"


class Stack:
    def __init__(self):
        user, password = CREDS.read_text().splitlines()[:2]
        self.jar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if not VERIFY:
            handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        self.op = urllib.request.build_opener(*handlers)
        self._req(BASE + "/en-US/account/login")
        cval = next((c.value for c in self.jar if c.name == "cval"), "")
        self._req(BASE + "/en-US/account/login", urllib.parse.urlencode({"username": user, "password": password, "cval": cval}).encode(),
                  {"X-Requested-With": "XMLHttpRequest", "X-Splunk-Form-Key": cval})
        key = next((c.name for c in self.jar if c.name.startswith("splunkweb_csrf_token_")), None)
        self.h = {"X-Splunk-Form-Key": next((c.value for c in self.jar if c.name == key), ""), "X-Requested-With": "XMLHttpRequest"}
        self.ok = any(c.name.startswith("splunkd_") for c in self.jar)

    def _req(self, url, data=None, headers=None, timeout=60):
        r = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            with self.op.open(r, timeout=timeout) as resp:
                return resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except Exception as e:  # noqa: BLE001
            return 0, f"{type(e).__name__}: {e}"

    def get(self, path, **params):
        params.setdefault("output_mode", "json")
        return self._req(f"{BASE}/en-US/splunkd/__raw{path}?{urllib.parse.urlencode(params)}", headers=self.h)

    def post(self, path, form):
        form = dict(form); form.setdefault("output_mode", "json")
        return self._req(f"{BASE}/en-US/splunkd/__raw{path}", urllib.parse.urlencode(form, doseq=True).encode(), self.h)

    def search(self, spl, earliest="-24h", app="search", wait=120):
        if not spl.lstrip().startswith("|"):
            spl = "search " + spl
        st, body = self.post(f"/servicesNS/nobody/{app}/search/jobs", {"search": spl, "earliest_time": earliest, "latest_time": "now"})
        if st not in (200, 201):
            return {"error": f"http {st}: {body[:300]}"}
        sid = json.loads(body)["sid"]
        t0 = time.time()
        while time.time() - t0 < wait:
            st, body = self.get(f"/services/search/jobs/{sid}")
            if json.loads(body)["entry"][0]["content"].get("isDone"):
                break
            time.sleep(2)
        st, body = self.get(f"/services/search/jobs/{sid}/results", count=0)
        d = json.loads(body) if st == 200 else {}
        return {"results": d.get("results", []), "messages": d.get("messages", [])}


S = Stack()
