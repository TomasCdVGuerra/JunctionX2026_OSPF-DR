"""CycloneDX 1.6 CBOM serializer for QuantumTrace findings."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Hoisted from _finding_value() to avoid per-call dict allocation.
_FINDING_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "canonical_algorithm": (
        "canonical_algorithm",
        "algorithm_name",
        "algorithm",
    ),
    "explanation": (
        "explanation",
        "risk_reasoning",
        "description",
    ),
    "risk_rating": (
        "risk_rating",
        "quantum_risk",
        "risk",
    ),
    "quantum_vulnerable": (
        "quantum_vulnerable",
    ),
    "quantum_safe": (
        "quantum_safe",
    ),
    "source_type": (
        "source_type",
    ),
    "source_path": (
        "source_path",
        "file_path",
    ),
    "operation": (
        "operation",
        "crypto_function",
    ),
}


class CBOMSerializer:
    """Serialize internal cryptographic findings as CycloneDX 1.6 JSON."""

    def __init__(
        self,
        scanner_name: str = "OSPF-DR QuantumTrace",
        version: str = "1.0.0",
    ) -> None:
        self.scanner_name = scanner_name
        self.version = version

        self.document: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": self._current_utc_timestamp(),
                "tools": [
                    {
                        "name": (
                            scanner_name
                            if scanner_name.endswith(" Scanner")
                            else f"{scanner_name} Scanner"
                        ),
                        "version": version,
                    }
                ],
            },
            "components": [],
        }
        self._used_bom_refs: set[str] = set()

    @staticmethod
    def _current_utc_timestamp() -> str:
        """Return the current UTC timestamp in ISO 8601 format."""
        return (
            datetime.now(UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _unwrap_enum(value: Any) -> Any:
        """Return Enum.value when the supplied value is Enum-like."""
        return getattr(value, "value", value)

    @classmethod
    def _get_attribute(cls, finding: Any, *names: str, default: Any = "unknown") -> Any:
        """Read the first available attribute or dictionary key from a finding."""
        for name in names:
            if isinstance(finding, dict):
                if name in finding and finding[name] is not None:
                    return cls._unwrap_enum(finding[name])
            elif hasattr(finding, name):
                value = getattr(finding, name)
                if value is not None:
                    return cls._unwrap_enum(value)

        return default

    @classmethod
    def _finding_value(cls, finding: Any, name: str, default: Any = "unknown") -> Any:
        """Read fields from the current finding contract and legacy aliases."""
        if name == "quantum_vulnerable":
            val = cls._get_attribute(finding, "quantum_vulnerable", default=None)
            if val is not None:
                return val
            risk = cls._get_attribute(finding, "quantum_risk", "risk_rating", default=None)
            if risk is not None:
                r_str = getattr(risk, "value", str(risk)).lower()
                return r_str == "critical"
            return default

        if name == "quantum_safe":
            val = cls._get_attribute(finding, "quantum_safe", default=None)
            if val is not None:
                return val
            risk = cls._get_attribute(finding, "quantum_risk", "risk_rating", default=None)
            if risk is not None:
                r_str = getattr(risk, "value", str(risk)).lower()
                return r_str == "safe"
            return default

        names = _FINDING_FIELD_ALIASES.get(name, (name,))

        if name == "explanation":
            val = cls._get_attribute(finding, *names, default=None)
            if val is not None and val != "unknown":
                return val
            if hasattr(finding, "evidence") and finding.evidence:
                first_ev = finding.evidence[0]
                reasoning = getattr(first_ev, "risk_reasoning", None)
                if reasoning:
                    return reasoning
            elif isinstance(finding, dict) and finding.get("evidence"):
                first_ev = finding["evidence"][0]
                if isinstance(first_ev, dict):
                    reasoning = first_ev.get("risk_reasoning")
                else:
                    reasoning = getattr(first_ev, "risk_reasoning", None)
                if reasoning:
                    return reasoning
            return default

        return cls._get_attribute(finding, *names, default=default)

    @staticmethod
    def _stringify(value: Any) -> str:
        """Convert values to the string representation required by CBOM."""
        if isinstance(value, bool):
            return "true" if value else "false"

        if value is None:
            return "unknown"

        return str(value)

    def add_finding(self, finding: Any) -> None:
        """Convert one finding into a CycloneDX cryptographic component."""
        canonical_algorithm = self._stringify(
            self._finding_value(finding, "canonical_algorithm")
        )
        explanation = self._stringify(
            self._finding_value(finding, "explanation")
        )
        risk_rating = self._stringify(
            self._finding_value(finding, "risk_rating")
        )
        quantum_vulnerable = self._stringify(
            self._finding_value(
                finding,
                "quantum_vulnerable",
                default=False,
            )
        )
        quantum_safe = self._stringify(
            self._finding_value(
                finding,
                "quantum_safe",
                default=False,
            )
        )
        source_type = self._stringify(
            self._finding_value(finding, "source_type")
        )

        # Extract source path correctly from the array: finding.evidence[0].file_path if finding.evidence else "unknown"
        source_path = "unknown"
        if hasattr(finding, "evidence") and finding.evidence:
            source_path = self._stringify(finding.evidence[0].file_path)
        elif isinstance(finding, dict) and finding.get("evidence"):
            first_ev = finding["evidence"][0]
            if hasattr(first_ev, "file_path"):
                source_path = self._stringify(first_ev.file_path)
            elif isinstance(first_ev, dict) and "file_path" in first_ev:
                source_path = self._stringify(first_ev["file_path"])

        if source_path == "unknown":
            source_path = self._stringify(
                self._finding_value(finding, "source_path")
            )

        operation = self._stringify(
            self._finding_value(finding, "operation")
        )

        # Extract location and identity markers for collision resistance
        line_num = "0"
        packet_num = "0"
        rule_id = "unknown"
        json_path = "none"

        if hasattr(finding, "evidence") and finding.evidence:
            ev0 = finding.evidence[0]
            line_num = str(getattr(ev0, "line_number", None) or 0)
            packet_num = str(getattr(ev0, "packet_number", None) or 0)
            rule_id = str(getattr(ev0, "rule_id", None) or "unknown")
            json_path = str(getattr(ev0, "json_path", None) or "none")
        elif isinstance(finding, dict):
            if finding.get("evidence"):
                ev0 = finding["evidence"][0]
                if isinstance(ev0, dict):
                    line_num = str(ev0.get("line_number") or 0)
                    packet_num = str(ev0.get("packet_number") or 0)
                    rule_id = str(ev0.get("rule_id") or "unknown")
                    json_path = str(ev0.get("json_path") or "none")
                else:
                    line_num = str(getattr(ev0, "line_number", None) or 0)
                    packet_num = str(getattr(ev0, "packet_number", None) or 0)
                    rule_id = str(getattr(ev0, "rule_id", None) or "unknown")
                    json_path = str(getattr(ev0, "json_path", None) or "none")
            else:
                line_num = str(finding.get("line_number") or 0)
                packet_num = str(finding.get("packet_number") or 0)
                rule_id = str(finding.get("rule_id") or "unknown")
                json_path = str(finding.get("json_path") or "none")

        ref_seed = (
            f"{source_type}:{source_path}:{canonical_algorithm}:{operation}:"
            f"{rule_id}:{line_num}:{packet_num}:{json_path}"
        )
        base_hash = hashlib.sha256(
            ref_seed.encode("utf-8")
        ).hexdigest()[:12]
        bom_ref = f"crypto:{base_hash}"

        # Guarantee unique bom-ref across all components in the document
        counter = 1
        unique_ref = bom_ref
        while unique_ref in self._used_bom_refs:
            unique_ref = f"{bom_ref}-{counter}"
            counter += 1
        self._used_bom_refs.add(unique_ref)

        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": unique_ref,
            "name": canonical_algorithm,
            "description": explanation,
            "properties": [
                {
                    "name": "cryptotrace:riskRating",
                    "value": risk_rating,
                },
                {
                    "name": "cryptotrace:quantumVulnerable",
                    "value": quantum_vulnerable,
                },
                {
                    "name": "cryptotrace:quantumSafe",
                    "value": quantum_safe,
                },
                {
                    "name": "cryptotrace:sourceType",
                    "value": source_type,
                },
                {
                    "name": "cryptotrace:sourcePath",
                    "value": source_path,
                },
                {
                    "name": "cryptotrace:operation",
                    "value": operation,
                },
            ],
        }

        self.document["components"].append(component)

    def to_json(self, filepath: str | Path | None = None) -> str:
        """Serialize the CBOM and optionally write it to disk."""
        serialized = json.dumps(
            self.document,
            indent=2,
            ensure_ascii=False,
        ) + "\n"

        if filepath:
            with open(filepath, "w", encoding="utf-8") as output_file:
                output_file.write(serialized)

        return serialized
