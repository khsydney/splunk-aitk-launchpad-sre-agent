# TukTukPay anomaly detection modules for the AI Toolkit's container framework (28 Oct 2026).
# Base: Splunk's CPU image (container API on :5000; PyOD, scikit-learn, SciPy, statsmodels, Prophet included).
# Adds five modules the toolkit calls through `| fit|apply AITKContainer algo=<module>`; models persist under
# /srv/app/model/data (mount a volume). No credentials in the image.
FROM splunk/mltk-container-golden-cpu:5.2.1
COPY model/tuktuk_common.py model/tuktuk_ecod.py model/tuktuk_iforest.py model/tuktuk_drift.py model/tuktuk_seasonal.py model/tuktuk_rules.py /dltk/app/model/
