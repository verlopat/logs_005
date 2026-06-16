# Main.py — orchestrator entrypoint for the blockchain-enabled security logger
#
# DEFAULT (no args):  python3 Main.py
#   Runs the full pipeline automatically:
#   bootstrap → health → demo-log → verify → history → report
#
# INDIVIDUAL commands still work:
#   python3 Main.py bootstrap
#   python3 Main.py health
#   python3 Main.py demo-log
#   python3 Main.py verify <event_id>
#   python3 Main.py history [asset_id]
#   python3 Main.py report [STANDARD] [asset_id]

import argparse
import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

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

# ── ANSI helpers ────────────────────────────────────────────────────────────

def _banner(step: int, total: int, title: str) -> None:
    bar = "─" * 60
    print(f"\n\033[1;36m{'─'*60}\033[0m")
    print(f"\033[1;36m  STEP {step}/{total}: {title}\033[0m")
    print(f"\033[1;36m{bar}\033[0m")

def _ok(msg: str) -> None:
    print(f"\033[1;32m  ✅  {msg}\033[0m")

def _fail(msg: str) -> None:
    print(f"\033[1;31m  ❌  {msg}\033[0m")

def _info(msg: str) -> None:
    print(f"\033[0;37m  ℹ   {msg}\033[0m")


# ── Individual stage functions ───────────────────────────────────────────────

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
    return 0 if (ipfs_ok and fabric_ok) else 1


def build_sample_event() -> Dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
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


def demo_log() -> Dict[str, Any]:
    """Log a sample event. Returns result dict on success, raises on failure."""
    event_payload = build_sample_event()
    with IPFSClient() as ipfs, FabricClient() as fabric:
        signer = EventSigner()
        signing = signer.sign_event(event_payload)
        cid, sha256_hex = ipfs.add_event(event_payload)
        onchain_record = {
            "event_id":        event_payload["event_id"],
            "timestamp":       event_payload["timestamp"],
            "asset_id":        event_payload["asset_id"],
            "severity":        event_payload["severity"],
            "attack_category": event_payload["attack_category"],
            "confidence_score":event_payload["confidence_score"],
            "model_version":   event_payload["model_version"],
            "payload_hash":    sha256_hex,
            "ipfs_cid":        cid,
            "agent_id":        signing.agent_id,
            "agent_signature": signing.signature_hex,
        }
        event_id   = onchain_record["event_id"]
        event_json = json.dumps(onchain_record, separators=(",", ":"), sort_keys=True)
        payload_str = json.dumps(event_payload,  separators=(",", ":"), sort_keys=True)
        result = fabric.log_security_event(event_id, event_json, payload_str)
        return {
            "event_id":    event_id,
            "tx_id":       result["tx_id"],
            "ipfs_cid":    cid,
            "payload_hash":sha256_hex,
            "agent_id":    signing.agent_id,
            "status":      "SUCCESS",
        }


def verify_event(event_id: str) -> Dict[str, Any]:
    with FabricClient() as fabric, IPFSClient() as ipfs:
        event      = fabric.get_event(event_id)["result"]
        payload    = ipfs.get_event(event["ipfs_cid"])
        payload_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return fabric.verify_event(event_id, payload_str)["result"]


def show_history(asset_id: str = "") -> Dict[str, Any]:
    with AuditQueryInterface() as audit:
        return audit.get_audit_trail(asset_id=asset_id, verify_integrity=False)


def generate_report(standard: str = "ISO27001", asset_id: str = "") -> Dict[str, str]:
    with AuditQueryInterface() as audit:
        return audit.export_compliance_report(standard=standard, asset_id=asset_id)


# ── Full auto pipeline ───────────────────────────────────────────────────────

def run_full_pipeline() -> int:
    """
    Execute every stage in sequence.
    Each stage prints a numbered banner. A failure in any stage is logged
    but the pipeline continues so you can see the full picture.
    Exits with 0 only if every stage passed.
    """
    STAGES = 6
    failures: list[str] = []
    logged_event_id: Optional[str] = None

    # ── 1. Bootstrap ────────────────────────────────────────────────────────
    _banner(1, STAGES, "Bootstrap Fabric network")
    try:
        run_bootstrap()
        _ok("Network bootstrapped and chaincode deployed.")
    except Exception as exc:
        _fail(f"Bootstrap failed: {exc}")
        failures.append("bootstrap")

    # ── 2. Health ───────────────────────────────────────────────────────────
    _banner(2, STAGES, "Health check (Fabric + IPFS)")
    rc = health_check()
    if rc == 0:
        _ok("All services healthy.")
    else:
        _fail("One or more services unhealthy — continuing anyway.")
        failures.append("health")

    # ── 3. Demo log ─────────────────────────────────────────────────────────
    _banner(3, STAGES, "Log sample security event end-to-end")
    try:
        log_result = demo_log()
        logged_event_id = log_result["event_id"]
        _ok(f"Event logged.  event_id={logged_event_id}")
        _info(f"tx_id      = {log_result['tx_id']}")
        _info(f"ipfs_cid   = {log_result['ipfs_cid']}")
        _info(f"sha256     = {log_result['payload_hash']}")
        _info(f"agent      = {log_result['agent_id']}")
    except Exception as exc:
        _fail(f"demo-log failed: {exc}")
        failures.append("demo-log")

    # ── 4. Verify ───────────────────────────────────────────────────────────
    _banner(4, STAGES, "Verify event integrity")
    if logged_event_id:
        try:
            vr = verify_event(logged_event_id)
            if vr.get("is_valid"):
                _ok(f"Integrity verified.  stored_hash={vr['stored_hash'][:16]}…")
            else:
                _fail(f"Integrity FAILED: {vr.get('failure_reason', 'unknown')}")
                failures.append("verify")
        except Exception as exc:
            _fail(f"verify failed: {exc}")
            failures.append("verify")
    else:
        _info("Skipping verify — no event was logged in step 3.")

    # ── 5. Audit history ────────────────────────────────────────────────────
    _banner(5, STAGES, "Query audit trail")
    try:
        trail = show_history()
        count = trail.get("total_count", len(trail.get("events", [])))
        _ok(f"Audit trail retrieved.  total_events={count}")
        _info(f"integrity_verified={trail.get('integrity_verified', 'N/A')}  "
              f"integrity_failed={trail.get('integrity_failed', 'N/A')}")
    except Exception as exc:
        _fail(f"history query failed: {exc}")
        failures.append("history")

    # ── 6. Compliance report ────────────────────────────────────────────────
    _banner(6, STAGES, "Generate ISO 27001 compliance report")
    try:
        paths = generate_report(standard="ISO27001")
        _ok("Report generated.")
        _info(f"JSON → {paths['json_report']}")
        _info(f"CSV  → {paths['csv_report']}")
    except Exception as exc:
        _fail(f"report generation failed: {exc}")
        failures.append("report")

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    if not failures:
        print("\033[1;32m  ✅  ALL STAGES PASSED\033[0m")
        print(f"{'═'*60}\n")
        return 0
    else:
        print(f"\033[1;31m  ❌  FAILED STAGES: {', '.join(failures)}\033[0m")
        print(f"{'═'*60}\n")
        return 1


# ── CLI (individual commands still available) ────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Blockchain-enabled tamper-proof security event logger.\n"
            "Run with NO arguments to execute the full pipeline automatically."
        )
    )
    sub = parser.add_subparsers(dest="command")   # NOT required — no args = full pipeline

    sub.add_parser("bootstrap", help="Bring up Fabric network and deploy chaincode")
    sub.add_parser("health",    help="Check Fabric and IPFS connectivity")
    sub.add_parser("demo-log",  help="Log a sample event end-to-end")

    verify_p = sub.add_parser("verify", help="Verify integrity of a stored event")
    verify_p.add_argument("event_id", help="Event ID to verify")

    hist_p = sub.add_parser("history", help="Query ordered audit trail")
    hist_p.add_argument("asset_id", nargs="?", default="", help="Optional asset ID filter")

    report_p = sub.add_parser("report", help="Generate compliance report")
    report_p.add_argument("standard", nargs="?", default="ISO27001",
                          help="ISO27001 | SOC2 | NIST800-92")
    report_p.add_argument("asset_id", nargs="?", default="", help="Optional asset ID filter")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # No subcommand → run the full automated pipeline
    if not args.command:
        return run_full_pipeline()

    # Individual commands
    if args.command == "bootstrap":
        run_bootstrap()
        return 0
    if args.command == "health":
        return health_check()
    if args.command == "demo-log":
        try:
            result = demo_log()
            print(json.dumps(result, indent=2))
            return 0
        except Exception as exc:
            logger.error("demo-log failed: %s", exc)
            return 1
    if args.command == "verify":
        try:
            result = verify_event(args.event_id)
            print(json.dumps(result, indent=2))
            return 0 if result.get("is_valid") else 2
        except Exception as exc:
            logger.error("verify failed: %s", exc)
            return 1
    if args.command == "history":
        try:
            trail = show_history(args.asset_id)
            print(json.dumps(trail, indent=2))
            return 0
        except Exception as exc:
            logger.error("history query failed: %s", exc)
            return 1
    if args.command == "report":
        try:
            paths = generate_report(args.standard, args.asset_id)
            print(json.dumps(paths, indent=2))
            return 0
        except Exception as exc:
            logger.error("report generation failed: %s", exc)
            return 1

    logger.error("Unknown command: %s", args.command)
    return 1


if __name__ == "__main__":
    sys.exit(main())
