"""Streamlit replay dashboard for passive flow detection."""

from __future__ import annotations

import io
import json
import time

import pandas as pd
import streamlit as st

from passivewatch.detector import StreamDetector
from passivewatch.replay import read_stream, synthetic_records

st.set_page_config(page_title="PassiveWatch", layout="wide")
st.title("PassiveWatch: Threat Detection")
st.write("Replay passive flow metadata to detect and review potential threats. Traffic is not probed, blocked, or decrypted.")

upload = st.file_uploader("Upload flow export (CSV, JSONL, or NDJSON)", type=["csv", "jsonl", "ndjson"])
source_name = upload.name if upload else "Built-in scenario"
control_col, button_col = st.columns([2, 1])
with control_col:
    pause_ms = st.slider("Replay delay per flow (ms)", 0, 100, 0, 5)
with button_col:
    st.write("")
    st.write("")
    start = st.button("Replay stream", type="primary", use_container_width=True)
st.caption("Expected fields: timestamp, src_ip, dst_ip, ports, protocol, bytes_out/in, packets, duration; optional DNS, TLS fingerprint, QUIC, flags, and packet_sizes.")

if start:
    if upload:
        source = read_stream(io.StringIO(upload.getvalue().decode("utf-8-sig")), upload.name)
    else:
        source = iter(synthetic_records())
    detector = StreamDetector()
    alerts = []
    flow_count = 0
    progress = st.empty()
    alert_area = st.empty()
    status = st.empty()
    for index, record in enumerate(source, start=1):
        flow_count += 1
        alerts.extend(detector.process(record))
        if index % 5 == 0:
            progress.caption(f"Reading {source_name} · processed {index:,} flows")
            if alerts:
                alert_area.dataframe(pd.DataFrame(alerts).sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
            status.caption(f"{flow_count:,} flows observed · {len(alerts):,} alerts · {source_name}")
        if pause_ms:
            time.sleep(pause_ms / 1000)

    if alerts:
        alert_area.dataframe(pd.DataFrame(alerts).sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
    progress.caption(f"Replay complete · processed {flow_count:,} flows")

    if not alerts:
        st.info("Replay complete. No alerts matched the current prototype thresholds.")
    else:
        classes = pd.Series([alert["threat_class"] for alert in alerts]).value_counts().rename_axis("threat_class").to_frame("alerts")
        left, right = st.columns([1, 2])
        with left:
            st.subheader("Threat classes")
            st.bar_chart(classes)
        with right:
            st.subheader("Replay summary")
            critical = sum(alert["severity"] == "critical" for alert in alerts)
            high = sum(alert["severity"] == "high" for alert in alerts)
            one, two, three = st.columns(3)
            one.metric("Flows", f"{flow_count:,}")
            two.metric("Alerts", f"{len(alerts):,}")
            three.metric("High / critical", f"{high + critical:,}")
        st.download_button("Download alert JSONL", "\n".join(json.dumps(item) for item in alerts) + "\n", file_name="passivewatch-alerts.jsonl", mime="application/x-ndjson")
else:
    st.info("Choose a passive flow export or replay the included synthetic traffic scenario.")

st.markdown("---")
st.caption("Confidence values are prototype scores, not calibrated probabilities. Validate thresholds and models against representative, locally labelled traffic before operational use.")