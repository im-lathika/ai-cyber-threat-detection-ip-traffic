"""Feature extraction from flow and protocol metadata only."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any


def _number(row: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(row.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def normalized_row(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize exporter fields without retaining or decoding payloads."""
    result = dict(row)
    result["timestamp"] = _number(row, "timestamp", _number(row, "ts"))
    result["src_ip"] = str(row.get("src_ip", "unknown"))
    result["dst_ip"] = str(row.get("dst_ip", "unknown"))
    result["src_port"] = int(_number(row, "src_port"))
    result["dst_port"] = int(_number(row, "dst_port"))
    result["protocol"] = str(row.get("protocol", "OTHER")).upper()
    for key in ("bytes_out", "bytes_in", "packets", "duration"):
        result[key] = max(0.0, _number(row, key))
    result["flags"] = str(row.get("flags", "")).upper()
    result["dns_query"] = str(row.get("dns_query", "")).strip(".").lower()
    result["dns_type"] = str(row.get("dns_type", "")).upper()
    result["tls_ja3"] = str(row.get("tls_ja3", ""))
    result["tls_ja4"] = str(row.get("tls_ja4", ""))
    result["quic"] = str(row.get("quic", "false")).lower() in {"1", "true", "yes"}
    return result


def domain_features(domain: str) -> dict[str, float]:
    labels = [part for part in domain.split(".") if part]
    name = labels[0] if labels else ""
    counts = Counter(name)
    length = len(name)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values()) if length else 0.0
    vowels = sum(char in "aeiou" for char in name)
    alphabetic = sum(char.isalpha() for char in name)
    bigrams = Counter(name[index:index + 2] for index in range(max(0, length - 1)))
    common_bigrams = {"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar"}
    uncommon_ratio = sum(count for gram, count in bigrams.items() if gram not in common_bigrams) / max(1, length - 1)
    return {
        "dns_name_length": float(length),
        "dns_entropy": entropy,
        "dns_digit_ratio": sum(char.isdigit() for char in name) / max(1, length),
        "dns_vowel_ratio": vowels / max(1, alphabetic),
        "dns_uncommon_bigram_ratio": uncommon_ratio,
        "dns_label_count": float(len(labels)),
    }


def flow_features(row: dict[str, Any]) -> dict[str, float]:
    sizes = [float(value) for value in re.split(r"[|; ]+", str(row.get("packet_sizes", ""))) if value.strip()]
    bytes_out = float(row["bytes_out"])
    bytes_in = float(row["bytes_in"])
    total_bytes = bytes_out + bytes_in
    sizes = sizes or ([total_bytes / max(1.0, float(row["packets"]))] if total_bytes else [0.0])
    mean_size = sum(sizes) / len(sizes)
    return {
        "log_bytes_out": math.log1p(bytes_out),
        "log_bytes_in": math.log1p(bytes_in),
        "log_packets": math.log1p(float(row["packets"])),
        "duration": min(float(row["duration"]), 3600.0),
        "out_in_ratio": min(bytes_out / max(1.0, bytes_in), 1000.0),
        "in_out_ratio": min(bytes_in / max(1.0, bytes_out), 1000.0),
        "packet_size_mean": mean_size,
        "packet_size_std": math.sqrt(sum((size - mean_size) ** 2 for size in sizes) / len(sizes)),
        "port": float(row["dst_port"]),
        "is_tcp": float(row["protocol"] == "TCP"),
        "is_udp": float(row["protocol"] == "UDP"),
        "has_tls_fingerprint": float(bool(row["tls_ja3"] or row["tls_ja4"])),
        "is_quic": float(bool(row["quic"])),
    }