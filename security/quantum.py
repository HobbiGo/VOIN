"""
VOIN QUANTUM SECURITY ENGINE V1.0

Post-Quantum Digital Signature Engine (BSC Mainnet / Chain ID 56).

Standard:
NIST FIPS 204 - ML-DSA

Purpose:
- Quantum-resistant digital signatures
- Post-quantum wallet authentication
- Public/private key generation
- Signature verification
- EVM security compatibility architecture

IMPORTANT:
Requires liboqs-python and an enabled liboqs
ML-DSA implementation.
"""

import time

DEFAULT_CHAIN_ID = 56

try:
    import oqs
except ImportError:
    oqs = None


class VOINQuantumSecurityEngine:

    VERSION = "1.0.0"

    SUPPORTED_ALGORITHMS = (
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    )

    def __init__(self, algorithm="ML-DSA-65"):

        if not isinstance(algorithm, str) or algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError("Unsupported quantum algorithm")

        self.algorithm = algorithm
        self.backend_available = False

        if oqs is not None:
            enabled = oqs.get_enabled_sig_mechanisms()

            self.backend_available = (
                algorithm in enabled
            )

    def _require_backend(self):

        if oqs is None:
            raise RuntimeError(
                "PQC backend unavailable: liboqs-python is not installed"
            )

        if not self.backend_available:
            raise RuntimeError(
                f"{self.algorithm} is not enabled in liboqs"
            )

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _to_bytes(value, field_name):

        if isinstance(value, (bytes, bytearray)):
            return bytes(value)

        if isinstance(value, str):

            cleaned = value.strip()
            if cleaned.startswith(("0x", "0X")):
                cleaned = cleaned[2:]

            if not cleaned or len(cleaned) % 2 != 0:
                raise ValueError(
                    f"Invalid hexadecimal {field_name}"
                )

            try:
                return bytes.fromhex(cleaned)

            except ValueError as error:
                raise ValueError(
                    f"Invalid hexadecimal {field_name}"
                ) from error

        raise ValueError(f"Invalid {field_name}")

    def generate_keypair(self):

        self._require_backend()

        with oqs.Signature(self.algorithm) as signer:

            public_key = signer.generate_keypair()

            private_key = signer.export_secret_key()

        if not public_key or not private_key:
            raise RuntimeError("Key generation failed")

        return {
            "success": True,
            "chain_id": DEFAULT_CHAIN_ID,
            "algorithm": self.algorithm,
            "public_key": public_key.hex().lower(),
            "private_key": private_key.hex().lower(),
            "created_at": self._now_ts(),
            "engine": "VOIN Quantum Security Engine",
            "version": self.VERSION
        }

    def sign(self, message, private_key):

        self._require_backend()

        if not isinstance(message, str):
            raise ValueError("Invalid message")

        if not message:
            raise ValueError("Empty message")

        secret = self._to_bytes(
            private_key,
            "private key"
        )

        with oqs.Signature(
            self.algorithm,
            secret_key=secret
        ) as signer:

            signature = signer.sign(
                message.encode("utf-8")
            )

        return {
            "success": True,
            "chain_id": DEFAULT_CHAIN_ID,
            "algorithm": self.algorithm,
            "signature": signature.hex().lower(),
            "engine": "VOIN Quantum Security Engine",
            "version": self.VERSION
        }

    def verify(self, message, signature, public_key):

        self._require_backend()

        if not isinstance(message, str) or not message:
            return {
                "success": False,
                "chain_id": DEFAULT_CHAIN_ID,
                "status": "INVALID_MESSAGE"
            }

        try:

            signature_bytes = self._to_bytes(
                signature,
                "signature"
            )

            public_key_bytes = self._to_bytes(
                public_key,
                "public key"
            )

            with oqs.Signature(self.algorithm) as verifier:

                valid = verifier.verify(
                    message.encode("utf-8"),
                    signature_bytes,
                    public_key_bytes
                )

            if not valid:
                return {
                    "success": False,
                    "chain_id": DEFAULT_CHAIN_ID,
                    "status": "INVALID_SIGNATURE"
                }

            return {
                "success": True,
                "chain_id": DEFAULT_CHAIN_ID,
                "status": "QUANTUM_SIGNATURE_VALID",
                "algorithm": self.algorithm,
                "engine": "VOIN Quantum Security Engine",
                "version": self.VERSION
            }

        except (ValueError, TypeError):
            return {
                "success": False,
                "chain_id": DEFAULT_CHAIN_ID,
                "status": "INVALID_SIGNATURE"
            }

    @classmethod
    def engine_info(cls):

        return {
            "engine": "VOIN Quantum Security Engine",
            "version": cls.VERSION,
            "chain_id": DEFAULT_CHAIN_ID,
            "standard": "NIST FIPS 204",
            "cryptography": "Post-Quantum Cryptography",
            "signature_algorithms": list(
                cls.SUPPORTED_ALGORITHMS
            ),
            "default_algorithm": "ML-DSA-65",
            "backend": "liboqs-python",
            "backend_installed": oqs is not None,
            "status": "READY_FOR_BACKEND_CONFIGURATION"
        }
