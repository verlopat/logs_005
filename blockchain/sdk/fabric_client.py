# fabric_client.py — Python REST client for the Node.js Fabric Gateway API
# Replaces the old fabric-sdk-py entirely.
# Works with Python 3.14+ using only stdlib + requests.

import json
import logging
import os
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

GATEWAY_BASE_URL = os.getenv("GATEWAY_BASE_URL", "http://localhost:3000")
GATEWAY_TIMEOUT  = int(os.getenv("GATEWAY_TIMEOUT", "30"))


class FabricClientError(Exception):
    pass


class FabricClient:
    """
    Thin HTTP wrapper around the Node.js Fabric Gateway REST API.
    Drop-in replacement for the old fabric-sdk-py FabricClient —
    same method signatures, same return shapes.
    """

    def __init__(
        self,
        base_url: str = GATEWAY_BASE_URL,
        timeout:  int = GATEWAY_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self._session: Optional[requests.Session] = None

    # ── Session / lifecycle ────────────────────────────────────────────────────

    def connect(self) -> None:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
        )
        session.mount("http://",  HTTPAdapter(max_retries=retry))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers.update({"Content-Type": "application/json"})
        self._session = session
        logger.info("FabricClient connected to Gateway at %s", self.base_url)

    def disconnect(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    @property
    def session(self) -> requests.Session:
        if not self._session:
            self.connect()
        return self._session

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    # ── Internal HTTP helpers ─────────────────────────────────────────────────

    def _get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            raise FabricClientError(f"GET {path} failed: {exc}") from exc

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.post(url, json=body, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            raise FabricClientError(f"POST {path} failed: {exc}") from exc

    # ── Public chaincode methods ───────────────────────────────────────────────

    def log_security_event(
        self,
        event_id:    str,
        event_json:  str,
        payload_json: str,
    ) -> Dict[str, Any]:
        """Submit a new security event to the ledger."""
        resp = self._post("/events", {
            "event_id":    event_id,
            "event_json":  event_json,
            "payload_json": payload_json,
        })
        return {"status": resp["status"], "tx_id": resp.get("tx_id", event_id)}

    def get_event(self, event_id: str) -> Dict[str, Any]:
        """Retrieve a single event by ID."""
        return self._get(f"/events/{event_id}")

    def verify_event(self, event_id: str, payload_json: str) -> Dict[str, Any]:
        """Verify that a stored event's hash matches the given payload."""
        return self._post(f"/events/{event_id}/verify", {"payload_json": payload_json})

    def query_event_history(
        self,
        asset_id:  str = "",
        from_time: str = "",
        to_time:   str = "",
    ) -> Dict[str, Any]:
        """Query ordered audit trail, optionally filtered by asset and time."""
        return self._get("/history", params={
            "assetId": asset_id,
            "from":    from_time,
            "to":      to_time,
        })

    def get_event_count(self, asset_id: str = "") -> Dict[str, Any]:
        """Return total event count, optionally scoped to an asset."""
        return self._get("/events/count", params={"assetId": asset_id})

    def health_check(self) -> bool:
        """Return True if the Gateway API is reachable and connected."""
        try:
            resp = self._get("/health")
            return resp.get("status") == "ok" and resp.get("gateway") is True
        except FabricClientError:
            return False
