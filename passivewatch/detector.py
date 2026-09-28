"""Stateful streaming detections over one-way flow metadata."""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from .alerts import make_alert
from .features import domain_features, flow_features, normalized_row


class StreamDetector:
    """Incrementally score flow records; this class has no network I/O."""

    def __init__(self, window_seconds: float = 10.0, alert_cooldown: float = 10.0, random_state: int = 17):
        self.window_seconds = window_seconds
        self.alert_cooldown = alert_cooldown
        self.events: deque[dict[str, Any]] = deque()
        self.beacons: dict[tuple[str, str, int], deque[float]] = defaultdict(lambda: deque(maxlen=8))
        self.last_alert: dict[tuple[str, str], float] = {}
        self.model = self._train_baseline(random_state)

    @staticmethod
    def _train_baseline(random_state: int) -> IsolationForest:
        rng = np.random.default_rng(random_state)
        baseline = np.column_stack((
            rng.normal(7.0, 1.5, 1200), rng.normal(6.0, 1.5, 1200), rng.normal(2.5, 0.8, 1200),
            rng.exponential(4.0, 1200), rng.lognormal(-1.0, 0.8, 1200), rng.lognormal(-1.0, 0.8, 1200),
            rng.normal(650, 220, 1200), rng.normal(200, 100, 1200), rng.integers(20, 50000, 1200),
            rng.binomial(1, 0.7, 1200), rng.binomial(1, 0.2, 1200), rng.binomial(1, 0.35, 1200),
            rng.binomial(1, 0.45, 1200),
        ))
        model = IsolationForest(n_estimators=24, contamination=0.015, random_state=random_state, n_jobs=1)
        model.fit(baseline)
        return model

    def process(self, source_row: dict[str, Any]) -> list[dict[str, Any]]:
        row = normalized_row(source_row)
        now = row["timestamp"]
        self.events.append(row)
        while self.events and now - self.events[0]["timestamp"] > self.window_seconds:
            self.events.popleft()

        current = list(self.events)
        alerts: list[dict[str, Any]] = []
        src_events = [event for event in current if event["src_ip"] == row["src_ip"]]
        dst_events = [event for event in current if event["dst_ip"] == row["dst_ip"]]

        if row["protocol"] == "TCP" and "SYN" in row["flags"] and "ACK" not in row["flags"]:
            syn_count = sum(event["protocol"] == "TCP" and "SYN" in event["flags"] and "ACK" not in event["flags"] for event in dst_events)
            if syn_count >= 20:
                alerts.append(self._alert(row, "syn_flood", 0.78 + min(0.2, syn_count / 500), {"syn_flows_10s": syn_count, "target": row["dst_ip"]}))

        if row["protocol"] == "UDP" and row["bytes_in"] >= 100_000 and row["bytes_in"] / max(1.0, row["bytes_out"]) >= 10:
            alerts.append(self._alert(row, "udp_reflection_amplification", 0.88, {"bytes_in": row["bytes_in"], "bytes_out": row["bytes_out"], "in_out_ratio": round(row["bytes_in"] / max(1.0, row["bytes_out"]), 2)}))

        src_entropy, unique_sources = self._source_entropy(dst_events)
        if len(dst_events) >= 40 and unique_sources >= 20 and src_entropy >= 3.0:
            alerts.append(self._alert(row, "spoofed_source_flood", 0.82, {"flows_10s": len(dst_events), "unique_sources": unique_sources, "source_ip_entropy": round(src_entropy, 3)}))

        unique_ports = len({event["dst_port"] for event in src_events})
        unique_hosts = len({event["dst_ip"] for event in src_events})
        if unique_ports >= 12 or unique_hosts >= 12:
            alerts.append(self._alert(row, "reconnaissance_port_scan", 0.8, {"unique_destination_ports_10s": unique_ports, "unique_destination_hosts_10s": unique_hosts}))

        if row["dns_query"]:
            name = row["dns_query"].split(".")[0]
            entropy = self._entropy(name)
            domain_stats = domain_features(row["dns_query"])
            dns_count = sum(bool(event["dns_query"]) for event in src_events)
            dga_like = entropy >= 3.5 or (entropy >= 3.1 and domain_stats["dns_uncommon_bigram_ratio"] >= 0.72)
            if len(name) >= 20 and dga_like:
                alerts.append(self._alert(row, "dga_domain", 0.82, {"query": row["dns_query"], "query_length": len(name), "label_entropy": round(entropy, 3), "uncommon_bigram_ratio": round(domain_stats["dns_uncommon_bigram_ratio"], 3), "dns_type": row["dns_type"]}))
            if len(row["dns_query"]) >= 50 or dns_count >= 30:
                alerts.append(self._alert(row, "dns_tunneling", 0.84, {"query_length": len(row["dns_query"]), "dns_queries_10s": dns_count, "dns_type": row["dns_type"]}))

        beacon_key = (row["src_ip"], row["dst_ip"], row["dst_port"])
        if row["protocol"] in {"TCP", "UDP"} and (row["tls_ja3"] or row["tls_ja4"] or row["quic"]):
            times = self.beacons[beacon_key]
            times.append(now)
            intervals = np.diff(list(times))
            if len(intervals) >= 3 and np.mean(intervals) > 0:
                cv = float(np.std(intervals) / np.mean(intervals))
                if cv <= 0.08:
                    alerts.append(self._alert(row, "botnet_c2_beaconing", 0.8 + max(0, 0.08 - cv), {"interval_seconds": round(float(np.mean(intervals)), 3), "interval_cv": round(cv, 4), "repeated_flows": len(times), "destination": row["dst_ip"]}))

        ratio = row["bytes_out"] / max(1.0, row["bytes_in"])
        if (row["bytes_out"] >= 1_000_000 and ratio >= 5) or (row["bytes_out"] >= 250_000 and ratio >= 20):
            alerts.append(self._alert(row, "data_exfiltration", 0.86, {"bytes_out": row["bytes_out"], "bytes_in": row["bytes_in"], "out_in_ratio": round(ratio, 2)}))

        if row["tls_ja3"] or row["tls_ja4"] or row["quic"]:
            features = flow_features(row)
            vector = np.array([[features[key] for key in features]], dtype=float)
            anomaly_score = float(-self.model.score_samples(vector)[0])
            if anomaly_score >= 0.68:
                alerts.append(self._alert(row, "malware_encrypted_session", min(0.95, 0.76 + (anomaly_score - 0.68) * 0.35), {"metadata_anomaly_score": round(anomaly_score, 4), "tls_fingerprint_present": bool(row["tls_ja3"] or row["tls_ja4"]), "quic": row["quic"], "packet_size_mean": round(features["packet_size_mean"], 2), "payload_decrypted": False}))

        return self._deduplicate(alerts)

    def _alert(self, row: dict[str, Any], threat_class: str, confidence: float, evidence: dict[str, Any]) -> dict[str, Any]:
        return make_alert(row, threat_class, confidence, evidence)

    def _deduplicate(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        emitted = []
        for alert in alerts:
            key = (alert["threat_class"], alert["flow_identifier"].split("->", 1)[0])
            timestamp = alert["timestamp"]
            if timestamp - self.last_alert.get(key, -math.inf) >= self.alert_cooldown:
                emitted.append(alert)
                self.last_alert[key] = timestamp
        return emitted

    @staticmethod
    def _entropy(value: str) -> float:
        counts = Counter(value)
        return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values()) if value else 0.0

    @classmethod
    def _source_entropy(cls, events: list[dict[str, Any]]) -> tuple[float, int]:
        counts = Counter(event["src_ip"] for event in events)
        entropy = -sum((count / len(events)) * math.log2(count / len(events)) for count in counts.values()) if events else 0.0
        return entropy, len(counts)