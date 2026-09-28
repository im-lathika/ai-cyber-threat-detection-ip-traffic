"""Incremental readers and deterministic synthetic flow scenarios."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterator, TextIO


def read_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield records one at a time from exporter CSV or JSON Lines."""
    with open(path, "r", newline="", encoding="utf-8") as source:
        if str(path).lower().endswith((".jsonl", ".ndjson")):
            for line in source:
                if line.strip():
                    yield json.loads(line)
        else:
            yield from csv.DictReader(source)


def read_stream(source: TextIO, filename: str) -> Iterator[dict[str, Any]]:
    """Read an uploaded file-like object incrementally."""
    if filename.lower().endswith((".jsonl", ".ndjson")):
        for line in source:
            if line.strip():
                yield json.loads(line)
    else:
        yield from csv.DictReader(source)


def synthetic_records() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def add(timestamp: float, source: str, destination: str = "198.51.100.10", **fields: Any) -> None:
        rows.append({
            "timestamp": timestamp, "src_ip": source, "dst_ip": destination,
            "src_port": 40000, "dst_port": 443, "protocol": "TCP",
            "flags": "ACK", "bytes_out": 900, "bytes_in": 1300,
            "packets": 8, "duration": 1.2, "dns_query": "", "dns_type": "",
            "tls_ja3": "baseline-ja3", "tls_ja4": "", "quic": "false",
            "packet_sizes": "128|512|1280", **fields,
        })

    # Typical low-rate traffic provides context before the attack bursts.
    for index in range(12):
        add(1000 + index * 2, f"10.0.0.{index + 1}")

    # TCP SYN surge against one service.
    for index in range(24):
        add(1030 + index * 0.1, f"203.0.113.{index + 1}", flags="SYN", bytes_out=60, bytes_in=0, packets=1, dst_port=443)

    add(1040, "192.0.2.70", protocol="UDP", dst_port=1900, bytes_out=1200, bytes_in=280000, packets=42)

    # Diverse apparent sources converge on one service, as in a spoofed-source burst.
    for index in range(44):
        add(1042 + index * 0.1, f"198.18.{index // 250}.{index % 250 + 1}", "198.51.100.77", protocol="UDP", dst_port=443, bytes_out=500, bytes_in=700, packets=2)

    # One source rapidly touches many service ports.
    for index in range(16):
        add(1050 + index * 0.2, "192.0.2.88", dst_port=1000 + index, flags="SYN", bytes_out=64, bytes_in=0, packets=1)

    add(1060, "10.0.0.44", dst_port=53, protocol="UDP", dns_query="qz7m2x9v4k8p1n6r3t5w.cloud", dns_type="TXT", bytes_out=210, bytes_in=96)
    add(1061, "10.0.0.45", dst_port=53, protocol="UDP", dns_query="dGhpcy1sb29rcy1saWtlLWFsbG93ZWQtbG9uZy1lbmNvZGVkLWRhdGEtcXVlcnktcGFydA.example", dns_type="TXT", bytes_out=1500, bytes_in=90)

    # Regular TLS metadata-only connections to the same endpoint.
    for index in range(6):
        add(1080 + index * 5, "10.0.0.66", "203.0.113.240", dst_port=8443, tls_ja3="beacon-ja3", bytes_out=420, bytes_in=690, duration=0.3)

    add(1120, "10.0.0.90", "198.51.100.90", dst_port=443, bytes_out=3_500_000, bytes_in=42000, packets=900, duration=30, tls_ja4="rare-ja4", packet_sizes="60|60|60|1400|60|60|60")
    return sorted(rows, key=lambda item: float(item["timestamp"]))


def benign_record(timestamp: float, index: int) -> dict[str, Any]:
    return {
        "timestamp": timestamp, "src_ip": f"10.10.{index % 20}.{index % 250 + 1}",
        "dst_ip": f"198.51.{index % 16}.{index % 250 + 1}", "src_port": 30000 + index % 20000,
        "dst_port": (443, 53, 22, 8080)[index % 4], "protocol": ("TCP", "UDP")[index % 2],
        "flags": "ACK", "bytes_out": 400 + index % 6000, "bytes_in": 800 + index % 12000,
        "packets": 3 + index % 30, "duration": 0.2 + (index % 80) / 10,
        "tls_ja3": "baseline-ja3" if index % 3 else "", "tls_ja4": "", "quic": "false",
        "dns_query": "", "dns_type": "", "packet_sizes": "128|512|1280",
    }