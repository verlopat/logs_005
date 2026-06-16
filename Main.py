# Main.py — orchestrator entrypoint for the blockchain-enabled security logger
# User workflow: python3 Main.py <command> [options]
#
# Commands:
#   bootstrap                  Bring up Fabric network (delegates to bootstrap.sh)
#   health                     Check Fabric and IPFS connectivity
#   demo-log                   Log a sample security event end-to-end
#   verify <event_id>          Verify integrity of a stored event via IPFS + chaincode
#   history [asset_id]         Query ordered audit trail
#   report [STANDARD] [asset]  Generate compliance report (ISO27001/SOC2/NIST800-92)

import argparse
import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from api.query_interface import AuditQueryInterface
from blockchain.sdk.fabric_client import FabricClient, FabricClientError
from crypto.signer import EventSigner, SignerError
from storage.ipfs_client import IPFSClient, IPFSClientError

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("Main")

BOOTSTRAP_SCRIPT = Path("blockchain/network/scripts/bootstrap.sh")


def run_bootstrap() -> None:
    if not BOOTSTRAP_SCRIPT.exists():
        raise FileNotFoundError(f"Bootstrap script not found: {BOOTSTRAP_SCRIPT}")
    logger.info("Starting Hyperledger Fabric bootstrap...")
    subprocess.run(["bash", str(BOOTSTRAP_SCRIPT)], check=True)


def health_check() -> int:
    ipfs_ok = False
    fabric_ok = False

    try:
        with IPFSClient() as ipfs:
            ipfs_ok = ipfs.health_check()
    except Exception as exc:
        logger.error("IPFS health check failed: %s", exc)

    try:
        with FabricClient() as fabric:
            result = fabric.get_event_count("")
            fabric_ok = result.get("status") == "SUCCESS"
    except Exception as exc:
        logger.error("Fabric health check failed: %s", exc)

    logger.info("Health | IPFS=%s Fabric=%s", ipfs_ok, fabric_ok)
    return 0 if ipfs_ok and fabric_ok else 1


def build_sample_event() -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": now,
        "asset_id": "vm-prod-001",
        "severity": "CRITICAL",
        "attack_category": "PrivilegeEscalation",
        "confidence_score": 0.987,
        "model_version": "v1.0-cnn-lstm-transformer",
        "raw_network_features": {
            "src_ip": "10.0.1.4",
            "dst_ip": "10.0.2.19",
            "src_port": 54421,
            "dst_port": 22,
            "packet_count": 128,
            "avg_interarrival_ms": 1.74,
            "cpu_usage_pct": 93.2,
            "memory_usage_pct": 88.1,
            "privileged_syscalls": ["setuid", "setgid", "execve"],
        },
        "context_metadata": {
            "tenant_id": "tenant-fin-05",
            "cloud_region": "ap-south-1",
            "detector_host": "sensor-alpha-01",
            "correlation_id": str(uuid.uuid4()),
        },
    }


def demo_log() -> int:
    event_payload = build_sample_event()

    try:
        with IPFSClient() as ipfs, FabricClient() as fabric:
            signer = EventSigner()

            # 1. Sign payload
            signing = signer.sign_event(event_payload)

            # 2. Store full payload off-chain
            cid, sha256_hex = ipfs.add_event(event_payload)

            # 3. Build on-chain record
            onchain_record = {
                "event_id": event_payload["event_id"],
                "timestamp": event_payload["timestamp"],
                "asset_id": event_payload["asset_id"],
                "severity": event_payload["severity"],
                "attack_category": event_payload["attack_category"],
                "confidence_score": event_payload["confidence_score"],
                "model_version": event_payload["model_version"],
                "payload_hash": sha256_hex,
                "ipfs_cid": cid,
                "agent_id": signing.agent_id,
                "agent_signature": signing.signature_hex,
            }

            event_id = onchain_record["event_id"]
            event_json = json.dumps(onchain_record, separators=(",", ":"), sort_keys=True)
            payload_to_hash = json.dumps(event_payload, separators=(",", ":"), sort_keys=True)

            # 4. Submit to Fabric
            result = fabric.log_security_event(event_id, event_json, payload_to_hash)

            logger.info("Demo log success | event_id=%s tx_id=%s", event_id, result["tx_id"])
            print(json.dumps({
                "event_id": event_id,
                "tx_id": result["tx_id"],
                "ipfs_cid": cid,
                "payload_hash": sha256_hex,
                "agent_id": signing.agent_id,
                "status": "SUCCESS",
            }, indent=2))
            return 0

    except (IPFSClientError, FabricClientError, SignerError, Exception) as exc:
        logger.error("demo-log failed: %s", exc)
        return 1


def verify_event(event_id: str) -> int:
    try:
        with FabricClient() as fabric, IPFSClient() as ipfs:
            event = fabric.get_event(event_id)["result"]
            cid = event["ipfs_cid"]
            payload = ipfs.get_event(cid)
            payload_to_hash = json.dumps(payload, separators=(",", ":"), sort_keys=True)
            verification = fabric.verify_event(event_id, payload_to_hash)
            print(json.dumps(verification["result"], indent=2))
            return 0 if verification["result"].get("is_valid") else 2
    except Exception as exc:
        logger.error("verify failed for event %s: %s", event_id, exc)
        return 1


def show_history(asset_id: str = "") -> int:
    try:
        with AuditQueryInterface() as audit:
            trail = audit.get_audit_trail(asset_id=asset_id, verify_integrity=False)
            print(json.dumps(trail, indent=2))
            return 0
    except Exception as exc:
        logger.error("history query failed: %s", exc)
        return 1


def generate_report(standard: str = "ISO27001", asset_id: str = "") -> int:
    try:
        with AuditQueryInterface() as audit:
            paths = audit.export_compliance_report(standard=standard, asset_id=asset_id)
            print(json.dumps(paths, indent=2))
            return 0
    except Exception as exc:
        logger.error("report generation failed: %s", exc)
        return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Blockchain-enabled tamper-proof security event logger"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("bootstrap", help="Bring up Fabric network and deploy chaincode")
    sub.add_parser("health", help="Check Fabric and IPFS connectivity")
    sub.add_parser("demo-log", help="Log a sample event end-to-end")

    verify_p = sub.add_parser("verify", help="Verify integrity of a stored event")
    verify_p.add_argument("event_id", help="Event ID to verify")

    hist_p = sub.add_parser("history", help="Query ordered audit trail")
    hist_p.add_argument("asset_id", nargs="?", default="", help="Optional asset ID")

    report_p = sub.add_parser("report", help="Generate compliance report")
    report_p.add_argument("standard", nargs="?", default="ISO27001", help="ISO27001 | SOC2 | NIST800-92")
    report_p.add_argument("asset_id", nargs="?", default="", help="Optional asset ID")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.command == "bootstrap":
        run_bootstrap()
        return 0
    if args.command == "health":
        return health_check()
    if args.command == "demo-log":
        return demo_log()
    if args.command == "verify":
        return verify_event(args.event_id)
    if args.command == "history":
        return show_history(args.asset_id)
    if args.command == "report":
        return generate_report(args.standard, args.asset_id)

    logger.error("Unknown command: %s", args.command)
    return 1


if __name__ == "__main__":
    sys.exit(main())
