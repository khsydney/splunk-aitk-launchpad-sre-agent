# TukTukPay SRE agent inside the AI Toolkit's container framework (27 Oct 2026).
# Base: Splunk's CPU image (the toolkit's container API on :5000, Python 3.9). The agent needs the current Anthropic
# SDK (Python >= 3.10), so it gets its own Python 3.11 venv; the toolkit module (3.9) runs it as a subprocess.
# No credentials in the image: they come from --env-file and a read-only /creds mount at run time.
FROM splunk/mltk-container-golden-cpu:5.2.1
USER root
RUN dnf install -y -q python3.11 python3.11-pip && dnf clean all \
 && python3.11 -m venv /dltk/sre-venv \
 && /dltk/sre-venv/bin/pip install --no-cache-dir -q "anthropic>=1.15" "httpx>=0.27"
COPY sre_agent /dltk/sre-agent/sre_agent
COPY aitk-container/aitk_runner.py /dltk/sre-agent/aitk_runner.py
COPY aitk-container/tuktuk_sre.py /dltk/app/model/tuktuk_sre.py
