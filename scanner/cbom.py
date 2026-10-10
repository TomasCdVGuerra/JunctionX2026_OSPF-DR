"""CycloneDX 1.6 CBOM serializer for QuantumTrace findings."""

import hashlib
import json
import uuid
from datetime import datetime, timezone


class CBOMSerializer:
    """Serialize internal cryptographic findings as CycloneDX 1.6 JSON."""

    def __init__(
        self,
        scanner_name="OSPF-DR QuantumTrace",
        version="1.0.0",
    ):
        self.scanner_name = scanner_name
        self.version = version

        self.document = {
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

    @staticmethod
    def _current_utc_timestamp():
        """Return the current UTC timestamp in ISO 8601 format."""
        return (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _unwrap_enum(value):
        """Return Enum.value when the supplied value is Enum-like."""
        return getattr(value, "value", value)

    @classmethod
    def _get_attribute(cls, finding, *names, default="unknown"):
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
    def _finding_value(cls, finding, name, default="unknown"):
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

        aliases = {
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

        names = aliases.get(name, (name,))
        return cls._get_attribute(finding, *names, default=default)

    @staticmethod
    def _stringify(value):
        """Convert values to the string representation required by CBOM."""
        if isinstance(value, bool):
            return "true" if value else "false"

        if value is None:
            return "unknown"

        return str(value)

    def add_finding(self, finding):
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

        ref_seed = (
            f"{source_type}:{source_path}:"
            f"{canonical_algorithm}:{operation}"
        )
        ref_hash = hashlib.sha256(
            ref_seed.encode("utf-8")
        ).hexdigest()[:12]

        component = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto:{ref_hash}",
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

    def to_json(self, filepath=None):
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
