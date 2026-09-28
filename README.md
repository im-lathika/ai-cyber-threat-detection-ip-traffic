# PassiveWatch

PassiveWatch is a working prototype for one-way cyber threat intelligence from flow-export and protocol metadata. It reads records incrementally, keeps only local rolling detector state, and emits labelled JSON Lines alerts. It has no network client, active probe, inline block, or return-path integration. TLS/QUIC payloads are never decrypted.

## Run

```powershell
python -m pip install -r requirements.txt
python -m streamlit run dashboard.py
```

In VS Code, select the workspace `.venv` interpreter. In PowerShell, you can also invoke it explicitly as `\.venv\Scripts\python.exe` for all commands below.

Use the built-in synthetic scenario or upload CSV / JSONL / NDJSON flow metadata. For terminal replay, run `python -m passivewatch.cli` or add `--input path\to\flows.csv`; alerts are written as JSON Lines to stdout. Run tests with `python -m unittest discover -s tests`.

CSV requires `timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes_out,bytes_in,packets,duration`. Optional columns are `flags,dns_query,dns_type,tls_ja3,tls_ja4,quic,packet_sizes`. Input must be a passive flow/exporter record; the prototype does not capture packets itself. `bytes_out` and `bytes_in` refer to exporter directional byte counters.

## Detection approach

The rules are explainable, stateful heuristics over a ten-second rolling flow window. SYN floods use SYN-only flow counts per destination; UDP amplification uses directional byte asymmetry; spoofed-source floods use source-IP count and entropy; reconnaissance uses per-source destination fan-out; DNS DGA/tunnelling uses query length and label entropy; beaconing uses inter-arrival coefficient of variation to a repeated endpoint; and exfiltration uses outbound volume and directional byte ratios. Cooldown suppression limits repeated alerts per source and class.

Encrypted-session anomalies use a seeded scikit-learn Isolation Forest over synthetic benign flow feature vectors (byte/packet volume, duration, directional ratios, packet-size summary, service port, transport, and TLS/QUIC presence). It scores only metadata; a high score on a TLS/QUIC flow produces `malware_encrypted_session`. This baseline is for demonstrating the inference path, not a production malware model. Domain feature helpers also compute digit, vowel, bigram, and label-count features for experimentation; current alert thresholds use length and Shannon entropy.

Confidence and severity are rule/model output scores, not calibrated probabilities. The included benign baseline is synthetic and no claim of field accuracy is made. For validation, replace it with representative labelled enclave data, use time-separated train/validation/test sets, tune thresholds to the operator's false-positive budget, and measure per-class precision/recall and detection latency. Fingerprint reputation feeds and threat-intel enrichment are intentionally not required by the offline prototype.

## Alert schema

Each alert contains `timestamp` (Unix seconds), `flow_identifier`, `threat_class`, `confidence` in `[0,1]`, `severity` (`medium`, `high`, `critical`), and `evidence` with the measurements that triggered the alert. Encrypted-session evidence explicitly records `payload_decrypted: false`.

## Throughput

The measured target was 10,000 flow records replayed through the same detector in the project's Python 3.13 virtual environment on Windows: 258.8 flows/second, completing in 38.635 seconds. Reproduce with `python -m passivewatch.cli --benchmark 10000`; the command reports its own elapsed time and rate. This is an in-process synthetic-flow measurement, not a Mbps wire-rate or end-to-end capture guarantee. Throughput depends on host, dependencies, and the fraction of TLS/QUIC records, which invoke model inference.

## Limitations

This is a prototype, not an inline defense or a safety-certified monitoring product. Flow exporter semantics, clock quality, NAT aggregation, sampling, missing metadata, encrypted protocol evolution, and local baselines materially affect the detections. The engine, CLI, and dashboard process parsed records incrementally; Streamlit itself holds an uploaded file in memory. Validate access controls, retention, alert handling, and performance in an isolated test environment before operational use.