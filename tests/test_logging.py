# test_logging.py — smoke/integration tests for the security logger

import json
import uuid
from datetime import datetime, timezone

import pytest

from crypto.signer import EventSigner
from storage.ipfs_client import IPFSClient


@pytest.fixture
def sample_payload():
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset_id": "vm-test-001",
        "severity": "HIGH",
        "attack_category": "PortScan",
        "confidence_score": 0.91,
        "model_version": "v1-test",
        "raw_network_features": {
            "src_ip": "10.1.1.10",
            "dst_ip": "10.1.2.20",
            "packet_count": 42,
        },
        "context_metadata": {
            "tenant_id": "tenant-test",
            "region": "local",
        },
    }


def test_sign_and_verify_signature(sample_payload):
    priv, _ = EventSigner.generate_keypair("crypto/dev_keys_test")
    signer = EventSigner(private_key_path=priv, cert_path="missing-cert.pem")

    signing = signer.sign_event(sample_payload)
    assert signing.payload_hash
    assert signing.signature_hex
    assert signer.verify_signature(sample_payload, signing.signature_hex)


def test_ipfs_add_and_verify(monkeypatch, sample_payload):
    # This test requires local IPFS running; skip gracefully otherwise.
    ipfs = IPFSClient()
    if not ipfs.health_check():
        pytest.skip("Local IPFS not running on :5001")

    cid, sha256_hex = ipfs.add_event(sample_payload)
    assert cid
    assert len(sha256_hex) == 64
    assert ipfs.verify_integrity(cid, sha256_hex)
