"""Shared internal contracts. Scanners produce findings; exporters produce CBOMs."""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    KEY = "key"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class CryptoFunction(str, Enum):
    DIGEST = "digest"
    SIGN = "sign"
    VERIFY = "verify"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    KEYGEN = "keygen"
    KDF = "kdf"
    MAC = "mac"
    KEY_EXCHANGE = "key_exchange"
    UNKNOWN = "unknown"


class QuantumRiskLevel(str, Enum):
    CRITICAL = "critical"
    MEDIUM = "medium"
    SAFE = "safe"
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    file_path: str = Field(min_length=1)
    line_number: int | None = Field(default=None, ge=1)
    packet_number: int | None = Field(default=None, ge=1)
    json_path: str | None = None
    matched_snippet: str | None = None
    rule_id: str = Field(min_length=1)
    risk_reasoning: str | None = None
    nist_standard: str | None = None


class CryptoFinding(BaseModel):
    """Canonical observation, prior to or after risk enrichment.

    Missing information is represented as None (never invented).
    """
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    algorithm_name: str = Field(min_length=1)
    asset_type: AssetType = AssetType.ALGORITHM
    source_type: Literal["source-code", "cloud-posture", "network-capture"]
    key_size: int | None = Field(default=None, gt=0)
    mode: str | None = None
    padding: str | None = None
    oid: str | None = None
    protocol: str | None = None
    library: str | None = Field(default=None, min_length=1)
    scan_input_id: int | None = Field(default=None, gt=0)
    crypto_function: CryptoFunction = CryptoFunction.UNKNOWN
    observation: Literal["declared", "configured", "advertised", "negotiated", "observed"]
    quantum_risk: QuantumRiskLevel = QuantumRiskLevel.UNKNOWN
    classical_risk: QuantumRiskLevel = QuantumRiskLevel.UNKNOWN
    confidence: Literal["low", "medium", "high"] = "medium"
    evidence: list[Evidence] = Field(min_length=1)
    recommendation: str | None = None

    @field_validator("algorithm_name")
    @classmethod
    def valid_algorithm_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("algorithm_name cannot be empty")
        return value

    def to_dict(self) -> dict:
        return self.model_dump(mode="json", exclude_none=True)


def scan_contract(path: Path) -> list[CryptoFinding]:
    """Documentation-only sample signature (NOT a scanner implementation)."""
    raise NotImplementedError("Each scanner implements scan(path) -> list[CryptoFinding]")

