# signer.py — ECDSA cryptographic event signing and verification
# Implements non-repudiation: each security event is digitally signed
# by the detection agent's private key before blockchain submission.
# Uses X.509 / ECDSA (P-256) aligned with Hyperledger Fabric CA PKI.

import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate

logger = logging.getLogger(__name__)


@dataclass
class SigningResult:
    """Result returned by sign_event."""
    payload_hash:    str   # SHA-256 hex of canonical event JSON
    signature_hex:  str   # ECDSA signature, hex-encoded
    agent_id:       str   # CN from X.509 cert (identity)
    public_key_pem: str   # PEM public key for verification


class SignerError(Exception):
    """Raised on any signing/verification error."""
    pass


class EventSigner:
    """
    ECDSA (P-256) signing and verification for security events.
    Private key and X.509 certificate are loaded from Fabric CA
    crypto-config paths (or custom .env paths).
    """

    # Default paths — override via .env
    DEFAULT_KEY_PATH  = os.getenv(
        "AGENT_PRIVATE_KEY_PATH",
        "blockchain/network/crypto-config/peerOrganizations/"
        "cloudsec.securitylog.com/users/User1@cloudsec.securitylog.com/"
        "msp/keystore/priv_sk",
    )
    DEFAULT_CERT_PATH = os.getenv(
        "AGENT_CERT_PATH",
        "blockchain/network/crypto-config/peerOrganizations/"
        "cloudsec.securitylog.com/users/User1@cloudsec.securitylog.com/"
        "msp/signcerts/User1@cloudsec.securitylog.com-cert.pem",
    )

    def __init__(
        self,
        private_key_path: Optional[str] = None,
        cert_path: Optional[str] = None,
    ) -> None:
        key_path  = Path(private_key_path or self.DEFAULT_KEY_PATH)
        cert_path = Path(cert_path or self.DEFAULT_CERT_PATH)

        self._private_key = self._load_private_key(key_path)
        self._public_key  = self._private_key.public_key()
        self._agent_id    = self._extract_cn(cert_path)
        self._public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        logger.info("EventSigner initialised | agent_id=%s", self._agent_id)

    # ── Public API ────────────────────────────────────────────────────────────

    def sign_event(self, event_payload: dict) -> SigningResult:
        """
        Compute SHA-256 of canonical event JSON and sign it with ECDSA P-256.

        Args:
            event_payload : raw event dict (pre-IPFS, pre-blockchain)

        Returns:
            SigningResult with hash, hex signature, agent_id, public key PEM.
        """
        # Canonical JSON (sorted, compact) — same as IPFSClient.add_event
        canonical_json = json.dumps(event_payload, sort_keys=True, separators=(',', ':'))
        payload_bytes  = canonical_json.encode('utf-8')
        payload_hash   = hashlib.sha256(payload_bytes).hexdigest()

        # ECDSA sign over SHA-256 digest
        try:
            signature_der = self._private_key.sign(
                payload_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception as exc:
            raise SignerError(f"ECDSA signing failed: {exc}") from exc

        signature_hex = signature_der.hex()

        logger.debug(
            "Signed event | hash=%s...%s sig=%s...%s agent=%s",
            payload_hash[:8], payload_hash[-8:],
            signature_hex[:8], signature_hex[-8:],
            self._agent_id,
        )

        return SigningResult(
            payload_hash=payload_hash,
            signature_hex=signature_hex,
            agent_id=self._agent_id,
            public_key_pem=self._public_key_pem,
        )

    def verify_signature(
        self,
        event_payload: dict,
        signature_hex: str,
        public_key_pem: Optional[str] = None,
    ) -> bool:
        """
        Verify an ECDSA signature against an event payload.

        Args:
            event_payload  : raw event dict
            signature_hex  : hex-encoded ECDSA signature
            public_key_pem : PEM public key of the signing agent.
                             If None, uses this instance's own public key.

        Returns:
            True if signature is valid, False otherwise.
        """
        canonical_json = json.dumps(event_payload, sort_keys=True, separators=(',', ':'))
        payload_bytes  = canonical_json.encode('utf-8')

        if public_key_pem:
            pub_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend(),
            )
        else:
            pub_key = self._public_key

        try:
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key.verify(
                sig_bytes,
                payload_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            logger.info("Signature VALID | agent=%s", self._agent_id)
            return True
        except InvalidSignature:
            logger.warning("Signature INVALID for agent=%s", self._agent_id)
            return False
        except Exception as exc:
            logger.error("Signature verification error: %s", exc)
            return False

    def get_agent_id(self) -> str:
        """Return the CN (common name) extracted from the X.509 certificate."""
        return self._agent_id

    def get_public_key_pem(self) -> str:
        """Return the PEM-encoded public key string."""
        return self._public_key_pem

    # ── Key Generation (dev/test only) ────────────────────────────────────────

    @staticmethod
    def generate_keypair(output_dir: str = "crypto/dev_keys") -> Tuple[str, str]:
        """
        Generate a fresh ECDSA P-256 keypair and write to disk.
        For development/testing only — production keys come from Fabric CA.

        Returns:
            Tuple of (private_key_path, public_key_path).
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        private_key = ec.generate_private_key(ec.P256(), default_backend())
        public_key  = private_key.public_key()

        priv_path = out / "priv_sk"
        pub_path  = out / "pub_key.pem"

        priv_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        logger.info("Dev keypair written to %s", out)
        return str(priv_path), str(pub_path)

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _load_private_key(path: Path):
        if not path.exists():
            raise SignerError(
                f"Private key not found: {path}. "
                "Run bootstrap.sh or EventSigner.generate_keypair() for dev keys."
            )
        try:
            return serialization.load_pem_private_key(
                path.read_bytes(),
                password=None,
                backend=default_backend(),
            )
        except Exception as exc:
            raise SignerError(f"Failed to load private key from {path}: {exc}") from exc

    @staticmethod
    def _extract_cn(cert_path: Path) -> str:
        """Extract Common Name from X.509 PEM certificate."""
        if not cert_path.exists():
            logger.warning(
                "Certificate not found at %s — using 'unknown-agent' as ID.", cert_path
            )
            return "unknown-agent"
        try:
            cert = load_pem_x509_certificate(
                cert_path.read_bytes(), default_backend()
            )
            cn_attrs = cert.subject.get_attributes_for_oid(
                # OID for commonName
                __import__(
                    'cryptography.x509.oid', fromlist=['NameOID']
                ).NameOID.COMMON_NAME
            )
            return cn_attrs[0].value if cn_attrs else "unknown-agent"
        except Exception as exc:
            logger.warning("Could not parse CN from cert %s: %s", cert_path, exc)
            return "unknown-agent"
