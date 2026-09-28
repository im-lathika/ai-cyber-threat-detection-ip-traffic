"""Command-line replay and throughput benchmark."""

from __future__ import annotations

import argparse
import json
import sys
import time

from .alerts import write_jsonl
from .detector import StreamDetector
from .replay import benign_record, read_records, synthetic_records


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay passive flow metadata and emit JSONL alerts")
    parser.add_argument("--input", help="CSV or JSONL flow metadata file; if omitted, run the built-in scenario")
    parser.add_argument("--benchmark", type=int, metavar="FLOWS", help="benchmark this many synthetic benign flow records")
    args = parser.parse_args()
    detector = StreamDetector()

    if args.benchmark:
        start = time.perf_counter()
        for index in range(args.benchmark):
            detector.process(benign_record(index * 0.02, index))
        elapsed = time.perf_counter() - start
        print(json.dumps({"flows": args.benchmark, "seconds": round(elapsed, 3), "flows_per_second": round(args.benchmark / elapsed, 1)}))
        return

    records = read_records(args.input) if args.input else iter(synthetic_records())
    for record in records:
        for alert in detector.process(record):
            write_jsonl(alert, sys.stdout)


if __name__ == "__main__":
    main()