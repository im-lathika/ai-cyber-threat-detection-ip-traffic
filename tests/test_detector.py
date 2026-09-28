from __future__ import annotations

import unittest

from passivewatch.detector import StreamDetector
from passivewatch.replay import synthetic_records


class StreamDetectorTests(unittest.TestCase):
    def test_synthetic_replay_emits_expected_threat_classes(self) -> None:
        detector = StreamDetector()
        alerts = [alert for row in synthetic_records() for alert in detector.process(row)]
        classes = {alert["threat_class"] for alert in alerts}

        self.assertTrue({
            "syn_flood",
            "udp_reflection_amplification",
            "spoofed_source_flood",
            "reconnaissance_port_scan",
            "dga_domain",
            "dns_tunneling",
            "botnet_c2_beaconing",
            "data_exfiltration",
        }.issubset(classes))

    def test_alert_schema_and_encryption_metadata_only_evidence(self) -> None:
        detector = StreamDetector()
        alerts = []
        for row in synthetic_records():
            alerts.extend(detector.process(row))

        for alert in alerts:
            self.assertEqual(set(alert), {"timestamp", "flow_identifier", "threat_class", "confidence", "severity", "evidence"})
            self.assertGreaterEqual(alert["confidence"], 0)
            self.assertLessEqual(alert["confidence"], 1)
        encrypted_alerts = [alert for alert in alerts if alert["threat_class"] == "malware_encrypted_session"]
        self.assertTrue(encrypted_alerts)
        for alert in encrypted_alerts:
            self.assertFalse(alert["evidence"]["payload_decrypted"])


if __name__ == "__main__":
    unittest.main()