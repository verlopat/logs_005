# fabric_client.py — Python Hyperledger Fabric SDK wrapper
# Handles channel connect, identity loading, transaction submit & query
# Communicates with peers via gRPC (hfc-sdk / fabric-sdk-py)

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

from hfc.fabric import Client
from hfc.fabric.peer import create_peer
from hfc.fabric.orderer import create_orderer
from hfc.fabric.organization import create_org
from hfc.util.crypto.crypto import ecies

logger = logging.getLogger(__name__)


class FabricClientError(Exception):
    """Raised on any Fabric SDK error."""
    pass


class FabricClient:
    """
    Thin wrapper around the Hyperledger Fabric Python SDK.
    Manages channel connection, user enrollment, and
    chaincode invoke / query operations.
    """

    CHANNEL_NAME     = os.getenv("FABRIC_CHANNEL",    "securitylogchannel")
    CHAINCODE_NAME   = os.getenv("FABRIC_CHAINCODE",  "security_logger")
    ORG_NAME         = os.getenv("FABRIC_ORG",        "CloudSecOrg")
    PEER_ENDPOINT    = os.getenv("FABRIC_PEER",       "grpcs://localhost:7051")
    ORDERER_ENDPOINT = os.getenv("FABRIC_ORDERER",    "grpcs://localhost:7050")
    NETWORK_PROFILE  = os.getenv("FABRIC_NET_PROFILE", "blockchain/sdk/network_profile.json")

    def __init__(self) -> None:
        self._client: Optional[Client] = None
        self._user = None
        self._channel = None
        self._loop = asyncio.new_event_loop()

    # ── Initialisation ────────────────────────────────────────────────────────

    def connect(self) -> None:
        """
        Load network profile, enrol admin user, and attach to channel.
        Must be called once before any invoke/query.
        """
        profile_path = Path(self.NETWORK_PROFILE)
        if not profile_path.exists():
            raise FabricClientError(
                f"Network profile not found: {profile_path}. "
                "Run bootstrap.sh first to generate crypto material."
            )

        self._client = Client(net_profile=str(profile_path))
        self._client.new_channel(self.CHANNEL_NAME)
        self._channel = self._client.get_channel(self.CHANNEL_NAME)

        # Load admin identity from crypto-config
        self._user = self._client.get_user(self.ORG_NAME, "Admin")
        if self._user is None:
            raise FabricClientError(
                f"Admin user not found for org {self.ORG_NAME}. "
                "Verify crypto-config path in network_profile.json."
            )

        logger.info(
            "FabricClient connected | channel=%s chaincode=%s org=%s",
            self.CHANNEL_NAME, self.CHAINCODE_NAME, self.ORG_NAME,
        )

    def disconnect(self) -> None:
        """Close the event loop."""
        if not self._loop.is_closed():
            self._loop.close()
        logger.info("FabricClient disconnected.")

    # ── Core Operations ───────────────────────────────────────────────────────

    def invoke(self, function: str, args: list, timeout: int = 30) -> Dict[str, Any]:
        """
        Submit a transaction (write) to the blockchain.

        Args:
            function : chaincode function name (e.g. 'LogSecurityEvent')
            args     : list of string arguments
            timeout  : seconds to wait for commit confirmation

        Returns:
            dict with 'tx_id', 'status', 'payload', 'latency_ms'
        """
        self._ensure_connected()
        start = time.monotonic()

        try:
            response = self._loop.run_until_complete(
                self._client.chaincode_invoke(
                    requestor=self._user,
                    channel_name=self.CHANNEL_NAME,
                    peers=[self.PEER_ENDPOINT],
                    fcn=function,
                    args=args,
                    cc_name=self.CHAINCODE_NAME,
                    wait_for_event=True,
                    wait_for_event_timeout=timeout,
                )
            )
        except Exception as exc:
            raise FabricClientError(f"Invoke failed [{function}]: {exc}") from exc

        latency_ms = round((time.monotonic() - start) * 1000, 2)
        tx_id = self._extract_tx_id(response)

        logger.info(
            "Invoke OK | fn=%s tx_id=%s latency=%.1fms",
            function, tx_id, latency_ms,
        )
        return {
            "tx_id":      tx_id,
            "status":     "SUCCESS",
            "payload":    response,
            "latency_ms": latency_ms,
        }

    def query(self, function: str, args: list) -> Dict[str, Any]:
        """
        Execute a read-only query (no ledger write).

        Args:
            function : chaincode function name (e.g. 'QueryEventHistory')
            args     : list of string arguments

        Returns:
            dict with 'status', 'result' (parsed JSON or raw string), 'latency_ms'
        """
        self._ensure_connected()
        start = time.monotonic()

        try:
            response = self._loop.run_until_complete(
                self._client.chaincode_query(
                    requestor=self._user,
                    channel_name=self.CHANNEL_NAME,
                    peers=[self.PEER_ENDPOINT],
                    fcn=function,
                    args=args,
                    cc_name=self.CHAINCODE_NAME,
                )
            )
        except Exception as exc:
            raise FabricClientError(f"Query failed [{function}]: {exc}") from exc

        latency_ms = round((time.monotonic() - start) * 1000, 2)

        # Attempt JSON parse; fall back to raw string
        try:
            result = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            result = response

        logger.info(
            "Query OK | fn=%s latency=%.1fms",
            function, latency_ms,
        )
        return {
            "status":     "SUCCESS",
            "result":     result,
            "latency_ms": latency_ms,
        }

    # ── High-Level Chaincode Helpers ──────────────────────────────────────────

    def log_security_event(
        self,
        event_id: str,
        event_json: str,
        payload_to_hash: str,
    ) -> Dict[str, Any]:
        """Submit LogSecurityEvent transaction."""
        return self.invoke(
            "LogSecurityEvent",
            [event_id, event_json, payload_to_hash],
        )

    def verify_event(
        self,
        event_id: str,
        payload_to_hash: str,
    ) -> Dict[str, Any]:
        """Query VerifyEvent — returns VerificationResult."""
        return self.query(
            "VerifyEvent",
            [event_id, payload_to_hash],
        )

    def query_event_history(
        self,
        asset_id: str = "",
        from_time: str = "",
        to_time: str = "",
    ) -> Dict[str, Any]:
        """Query QueryEventHistory — returns AuditTrail."""
        return self.query(
            "QueryEventHistory",
            [asset_id, from_time, to_time],
        )

    def get_event(self, event_id: str) -> Dict[str, Any]:
        """Query GetEvent — returns single SecurityEvent."""
        return self.query("GetEvent", [event_id])

    def get_event_count(self, asset_id: str = "") -> Dict[str, Any]:
        """Query GetEventCount."""
        return self.query("GetEventCount", [asset_id])

    def query_events_by_severity(self, severity: str) -> Dict[str, Any]:
        """Query QueryEventsBySeverity (CRITICAL/HIGH/MEDIUM/LOW)."""
        return self.query("QueryEventsBySeverity", [severity])

    # ── Internals ─────────────────────────────────────────────────────────────

    def _ensure_connected(self) -> None:
        if self._client is None or self._channel is None:
            raise FabricClientError(
                "FabricClient not connected. Call connect() first."
            )

    @staticmethod
    def _extract_tx_id(response: Any) -> str:
        """Best-effort extraction of tx_id from SDK response."""
        if isinstance(response, str):
            return response
        if isinstance(response, dict):
            return response.get("tx_id", response.get("txId", str(response)))
        return str(response)

    # ── Context Manager ───────────────────────────────────────────────────────

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()
