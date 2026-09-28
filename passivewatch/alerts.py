"""Alert record construction and JSON Lines output."""

from __future__ import annotations

import json
from typing import Any, TextIO


def flow_identifier(row: dict[str, Any]) -> str:
    return f"{row['src_ip']}:{row['src_port']}->{row['dst_ip']}:{row['dst_port']}/{row['protocol']}"


def make_alert(row: dict[str, Any], threat_class: str, confidence: float, evidence: dict[str, Any]) -> dict[str, Any]:
    confidence = max(0.0, min(1.0, float(confidence)))
    severity = "critical" if confidence >= 0.9 else "high" if confidence >= 0.78 else "medium"
    return {
        "timestamp": float(row["timestamp"]),
        "flow_identifier": flow_identifier(row),
        "threat_class": threat_class,
        "confidence": round(confidence, 4),
        "severity": severity,
        "evidence": evidence,
    }


def write_jsonl(alert: dict[str, Any], output: TextIO) -> None:
    output.write(json.dumps(alert, sort_keys=True) + "\n")