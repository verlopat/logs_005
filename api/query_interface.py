# query_interface.py — audit trail querying and compliance report generation
# Supports forensic reconstruction, chain-of-custody validation,
# anomaly frequency analytics, and exportable compliance reports.

import csv
import json
import logging
import os
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from blockchain.sdk.fabric_client import FabricClient, FabricClientError
from storage.ipfs_client import IPFSClient, IPFSClientError

logger = logging.getLogger(__name__)


@dataclass
class ComplianceSummary:
    total_events: int
    critical_count: int
    high_count: int
    integrity_verified: int
    integrity_failed: int
    generated_at: str
    standard: str


class AuditQueryInterface:
    """
    Query layer for auditors and analysts.
    Retrieves ordered audit trails from Fabric, verifies IPFS integrity,
    and exports reports in JSON/CSV suitable for ISO 27001 / SOC 2 / NIST.
    """

    REPORT_DIR = Path(os.getenv("REPORT_DIR", "output/reports"))

    def __init__(self) -> None:
        self.fabric = FabricClient()
        self.ipfs = IPFSClient()
        self.REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        self.fabric.connect()
        logger.info("AuditQueryInterface connected.")

    def close(self) -> None:
        self.fabric.disconnect()
        logger.info("AuditQueryInterface closed.")

    # ── Core Queries ──────────────────────────────────────────────────────────

    def get_audit_trail(
        self,
        asset_id: str = "",
        from_time: str = "",
        to_time: str = "",
        verify_integrity: bool = True,
    ) -> Dict[str, Any]:
        """
        Fetch an ordered audit trail from the blockchain, optionally verifying
        every IPFS-backed payload against its on-chain hash.
        """
        try:
            result = self.fabric.query_event_history(asset_id, from_time, to_time)
        except FabricClientError as exc:
            raise RuntimeError(f"Failed to query audit trail: {exc}") from exc

        trail = result["result"]
        events = trail.get("events", [])

        verified_ok = 0
        verified_fail = 0

        if verify_integrity:
            for event in events:
                cid = event.get("ipfs_cid", "")
                expected_hash = event.get("payload_hash", "")
                if not cid or not expected_hash:
                    event["integrity_status"] = "MISSING_DATA"
                    verified_fail += 1
                    continue
                ok = self.ipfs.verify_integrity(cid, expected_hash)
                event["integrity_status"] = "VERIFIED" if ok else "FAILED"
                if ok:
                    verified_ok += 1
                else:
                    verified_fail += 1

        trail["integrity_verified"] = verified_ok
        trail["integrity_failed"] = verified_fail
        trail["generated_at"] = datetime.now(timezone.utc).isoformat()
        return trail

    def get_event_details(self, event_id: str, include_offchain_payload: bool = True) -> Dict[str, Any]:
        """
        Retrieve a single event and, optionally, its full IPFS payload.
        """
        try:
            result = self.fabric.get_event(event_id)
        except FabricClientError as exc:
            raise RuntimeError(f"Failed to get event {event_id}: {exc}") from exc

        event = result["result"]
        if include_offchain_payload and event.get("ipfs_cid"):
            try:
                event["offchain_payload"] = self.ipfs.get_event(event["ipfs_cid"])
            except IPFSClientError as exc:
                event["offchain_payload_error"] = str(exc)
        return event

    def anomaly_frequency_analytics(
        self,
        asset_id: str = "",
        from_time: str = "",
        to_time: str = "",
    ) -> Dict[str, Any]:
        """
        Return counts by severity, attack category, and asset.
        Useful for frequency analytics in compliance dashboards.
        """
        trail = self.get_audit_trail(asset_id, from_time, to_time, verify_integrity=False)
        events = trail.get("events", [])

        severity_counts = Counter()
        category_counts = Counter()
        asset_counts = Counter()
        model_counts = Counter()

        for ev in events:
            severity_counts[ev.get("severity", "UNKNOWN")] += 1
            category_counts[ev.get("attack_category", "UNKNOWN")] += 1
            asset_counts[ev.get("asset_id", "UNKNOWN")] += 1
            model_counts[ev.get("model_version", "UNKNOWN")] += 1

        analytics = {
            "total_events": len(events),
            "severity_counts": dict(severity_counts),
            "attack_category_counts": dict(category_counts),
            "asset_counts": dict(asset_counts),
            "model_version_counts": dict(model_counts),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return analytics

    # ── Report Export ─────────────────────────────────────────────────────────

    def export_compliance_report(
        self,
        standard: str = "ISO27001",
        asset_id: str = "",
        from_time: str = "",
        to_time: str = "",
    ) -> Dict[str, str]:
        """
        Generate JSON + CSV compliance reports.
        Standards supported by naming only: ISO27001, SOC2, NIST800-92.
        """
        standard = standard.upper()
        trail = self.get_audit_trail(asset_id, from_time, to_time, verify_integrity=True)
        events = trail.get("events", [])

        summary = ComplianceSummary(
            total_events=len(events),
            critical_count=sum(1 for e in events if e.get("severity") == "CRITICAL"),
            high_count=sum(1 for e in events if e.get("severity") == "HIGH"),
            integrity_verified=trail.get("integrity_verified", 0),
            integrity_failed=trail.get("integrity_failed", 0),
            generated_at=datetime.now(timezone.utc).isoformat(),
            standard=standard,
        )

        report = {
            "standard": standard,
            "summary": summary.__dict__,
            "trail": trail,
            "chain_of_custody": self._build_chain_of_custody(events),
            "analytics": self.anomaly_frequency_analytics(asset_id, from_time, to_time),
        }

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"compliance_{standard.lower()}_{asset_id or 'all'}_{timestamp}"
        json_path = self.REPORT_DIR / f"{stem}.json"
        csv_path = self.REPORT_DIR / f"{stem}.csv"

        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        self._write_csv(events, csv_path)

        logger.info("Compliance report exported | json=%s csv=%s", json_path, csv_path)
        return {
            "json_report": str(json_path),
            "csv_report": str(csv_path),
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _write_csv(events: List[Dict[str, Any]], path: Path) -> None:
        fieldnames = [
            "event_id", "timestamp", "asset_id", "severity", "attack_category",
            "confidence_score", "model_version", "payload_hash", "ipfs_cid",
            "agent_id", "agent_signature", "tx_id", "integrity_status",
        ]
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for ev in events:
                writer.writerow({k: ev.get(k, "") for k in fieldnames})

    @staticmethod
    def _build_chain_of_custody(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build a forensic chain-of-custody trail for each event.
        """
        chain = []
        for ev in events:
            chain.append({
                "event_id": ev.get("event_id"),
                "detected_at": ev.get("timestamp"),
                "detected_by": ev.get("agent_id"),
                "signed": bool(ev.get("agent_signature")),
                "stored_offchain": ev.get("ipfs_cid"),
                "anchored_onchain_tx": ev.get("tx_id"),
                "hash": ev.get("payload_hash"),
                "integrity_status": ev.get("integrity_status", "UNKNOWN"),
            })
        return chain

    # ── Context Manager ───────────────────────────────────────────────────────

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()
