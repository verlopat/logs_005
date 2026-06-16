# ipfs_client.py — IPFS off-chain storage client
# Stores full event payloads in IPFS; returns CID for on-chain reference.
# Implements hybrid on-chain/off-chain architecture (80-90% storage reduction).

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

import requests

logger = logging.getLogger(__name__)


class IPFSClientError(Exception):
    """Raised on any IPFS operation error."""
    pass


class IPFSClient:
    """
    Client for the IPFS Kubo HTTP API.
    Stores full security event payloads off-chain and returns
    content-addressed CIDs for on-chain reference.
    """

    API_BASE = os.getenv("IPFS_API_URL", "http://localhost:5001/api/v0")
    GATEWAY  = os.getenv("IPFS_GATEWAY",  "http://localhost:8080/ipfs")
    TIMEOUT  = int(os.getenv("IPFS_TIMEOUT", "30"))

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    # ── Core Operations ───────────────────────────────────────────────────────

    def add_event(self, event_payload: Dict[str, Any]) -> Tuple[str, str]:
        """
        Serialise and pin a security event payload to IPFS.

        Args:
            event_payload : full event dict (raw features, scores, metadata)

        Returns:
            Tuple of (cid, sha256_hex)
            - cid        : IPFS content ID (use as ipfs_cid in on-chain record)
            - sha256_hex : SHA-256 hex digest of canonical JSON (use as payload_hash)
        """
        # Canonical JSON: sorted keys, no whitespace (deterministic hash)
        canonical_json = json.dumps(event_payload, sort_keys=True, separators=(',', ':'))
        payload_bytes  = canonical_json.encode('utf-8')

        # Compute SHA-256 before upload
        sha256_hex = hashlib.sha256(payload_bytes).hexdigest()

        start = time.monotonic()
        try:
            response = self._session.post(
                f"{self.API_BASE}/add",
                files={"file": ("event.json", payload_bytes, "application/json")},
                params={"pin": "true", "cid-version": "1"},
                timeout=self.TIMEOUT,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise IPFSClientError(f"IPFS add failed: {exc}") from exc

        latency_ms = round((time.monotonic() - start) * 1000, 2)
        cid = response.json().get("Hash", "")
        if not cid:
            raise IPFSClientError(f"IPFS returned no CID: {response.text}")

        logger.info(
            "IPFS add OK | cid=%s sha256=%s...%s latency=%.1fms",
            cid, sha256_hex[:8], sha256_hex[-8:], latency_ms,
        )
        return cid, sha256_hex

    def get_event(self, cid: str) -> Dict[str, Any]:
        """
        Retrieve a full event payload from IPFS by CID.

        Args:
            cid : IPFS content ID

        Returns:
            Parsed event payload dict.
        """
        start = time.monotonic()
        try:
            response = self._session.post(
                f"{self.API_BASE}/cat",
                params={"arg": cid},
                timeout=self.TIMEOUT,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise IPFSClientError(f"IPFS cat failed for CID {cid}: {exc}") from exc

        latency_ms = round((time.monotonic() - start) * 1000, 2)
        try:
            payload = response.json()
        except ValueError as exc:
            raise IPFSClientError(f"IPFS response not valid JSON for CID {cid}: {exc}") from exc

        logger.info("IPFS get OK | cid=%s latency=%.1fms", cid, latency_ms)
        return payload

    def pin(self, cid: str) -> bool:
        """
        Explicitly pin a CID to prevent garbage collection.

        Returns:
            True if pin succeeded.
        """
        try:
            response = self._session.post(
                f"{self.API_BASE}/pin/add",
                params={"arg": cid},
                timeout=self.TIMEOUT,
            )
            response.raise_for_status()
            logger.info("IPFS pin OK | cid=%s", cid)
            return True
        except requests.RequestException as exc:
            logger.warning("IPFS pin failed for cid=%s: %s", cid, exc)
            return False

    def verify_integrity(self, cid: str, expected_sha256: str) -> bool:
        """
        Fetch payload from IPFS and verify its SHA-256 matches the on-chain hash.
        Core forensic integrity check.

        Args:
            cid             : IPFS content ID
            expected_sha256 : SHA-256 hex stored on blockchain (payload_hash)

        Returns:
            True if hashes match (integrity confirmed), False otherwise.
        """
        try:
            payload = self.get_event(cid)
        except IPFSClientError as exc:
            logger.error("Integrity check failed — cannot fetch CID %s: %s", cid, exc)
            return False

        canonical_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        actual_sha256  = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

        if actual_sha256 == expected_sha256:
            logger.info("Integrity OK | cid=%s hash=%s...%s", cid, actual_sha256[:8], actual_sha256[-8:])
            return True

        logger.error(
            "INTEGRITY VIOLATION | cid=%s expected=%s...%s got=%s...%s",
            cid,
            expected_sha256[:8], expected_sha256[-8:],
            actual_sha256[:8],   actual_sha256[-8:],
        )
        return False

    def gateway_url(self, cid: str) -> str:
        """Return the HTTP gateway URL for a CID (for compliance report links)."""
        return f"{self.GATEWAY}/{cid}"

    def health_check(self) -> bool:
        """Verify IPFS node is reachable."""
        try:
            r = self._session.post(f"{self.API_BASE}/id", timeout=5)
            return r.status_code == 200
        except requests.RequestException:
            return False

    # ── Context Manager ───────────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._session.close()
