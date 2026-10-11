"""Concise views of recorded reasoning; never changes risk classifications."""
import re
from scanner.algorithms import parse_signature_algorithm


RISK_CRITERIA = {
    "Quantum": {
        "critical": "A critical quantum vulnerability was identified in this primitive or one of its components.",
        "medium": "Quantum strength falls below the project's chosen security margin.",
        "safe": "Meets the quantum criteria evaluated for this observation.",
        "unknown": "Insufficient parameters/context, or no applicable quantum assessment rule.",
    },
    "Classical": {
        "critical": "A classical weakness or a critically inadequate parameter was identified.",
        "medium": "A known configuration requires review under the project's classical policy.",
        "safe": "Meets the classical criteria evaluated; this is not an application security certification.",
        "unknown": "Insufficient parameters/context, or no applicable classical assessment rule.",
    },
}


def _sentences(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+(?=[A-ZÀ-Ý])", text) if part.strip()]


def _short_reason(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    text = text.replace("num computador quântico criptograficamente relevante", "num computador quântico relevante")
    parts = _sentences(text)
    return " ".join(parts[:2]) if parts else "No justification recorded."


def risk_justifications(description: str, quantum: str, classical: str) -> dict[str, list[str]]:
    """Split recorded axes and component explanations, retaining missing context."""
    description = description.split("\nRecomendação gerada:", 1)[0].strip()
    match = re.search(r"Risco quântico \([^)]+\):\s*(.*?)\nRisco clássico \([^)]+\):\s*(.*)", description, re.S)
    if match:
        result = {}
        for axis, text in zip(("Quantum", "Classical"), match.groups()):
            components = re.split(r"(?=(?:Cifra simétrica|Troca de chaves|Autenticação|Chave|Hash(?: \([^)]*\))?):)", text)
            # The opening suite sentence repeats the displayed tier; its component
            # explanations carry the reasons for that tier.
            if len(components) > 1:
                # Signature introductions contain the public-key/Shor reason,
                # whereas suite introductions only repeat the overall tier.
                meaningful = components[1:]
                if components[0].strip() and not components[0].strip().startswith("Cipher suite "):
                    meaningful = components
                result[axis] = [_short_reason(component) for component in meaningful if component.strip()]
            else:
                result[axis] = [_short_reason(text)]
        return result

    # Older/network reports may carry one shared protocol explanation. Select
    # relevant recorded sentences rather than inventing a separate assessment.
    description = re.sub(r"^Network assessment: quantum=\w+; classical=\w+\.\s*", "", description)
    if description.lower() in {"", "unknown", "n/a", "none"}:
        return {axis: ["No justification recorded; inspect the evidence."] for axis in ("Quantum", "Classical")}
    sentences = _sentences(description)
    result = {}
    for axis, tier in (("Quantum", quantum.lower()), ("Classical", classical.lower())):
        keywords = ("shor", "grover", "quantum") if axis == "Quantum" else ("classical", "mode", "modulus", "group size", "collision", "cbc")
        if tier == "unknown":
            keywords = ("unknown", "missing", "unsupported", "not known", "insufficient", "cannot", "unresolved")
        relevant = [sentence for sentence in sentences if any(word in sentence.lower() for word in keywords)]
        result[axis] = [_short_reason(" ".join((relevant or sentences)[:2]))]
    return result


def risk_details(description: str, quantum: str, classical: str, *, algorithm: str | None = None) -> dict[str, dict]:
    """Explain stored tiers, missing context and already recorded review items.

    Evidence determines the specific reasons; tier definitions only explain the
    meaning of the label. No algorithm is evaluated or reclassified here.
    """
    reasons = risk_justifications(description, quantum, classical)
    result = {}
    missing_markers = ("desconhecid", "não identificad", "sem contexto", "em falta",
                       "não existe", "não conhecid", "necessári", "unknown", "missing",
                       "insufficient", "unsupported", "unresolved", "not known",
                       "not recorded", "no justification")
    for axis, tier in (("Quantum", quantum), ("Classical", classical)):
        tier = tier.lower()
        missing = [reason for reason in reasons[axis]
                   if any(marker in reason.lower() for marker in missing_markers)]
        concerns = [reason for reason in reasons[axis] if axis == "Classical"
                    and tier == "unknown" and any(word in reason.lower() for word in
                    ("revisão", "review", "weakness", "collision weakness", "deprecated"))
                    and reason not in missing]
        result[axis] = {
            "criterion": RISK_CRITERIA[axis].get(tier, "Unrecognized assessment label; inspect the complete record."),
            "reasons": reasons[axis], "missing": missing, "known_concerns": concerns,
        }
    signature = parse_signature_algorithm(algorithm)
    if signature:
        family, digest = signature
        if quantum.lower() == "critical" and any("shor" in reason.lower() for reason in reasons["Quantum"]):
            result["Quantum"]["criterion"] = f"The {family} signature component determines the Critical rating."
            result["Quantum"]["reasons"] = [
                f"{algorithm} identifies a {family} signature using {digest}.",
                f"{family} is vulnerable to Shor; the hash does not remove this public-key vulnerability.",
            ]
        if classical.lower() == "unknown" and any(
                family.lower() in reason.lower() and "desconhecid" in reason.lower()
                for reason in result["Classical"]["missing"]):
            result["Classical"]["criterion"] = f"The {family} signing-key parameters are not recorded."
            missing = (f"{family} signing-key size." if family == "RSA" else f"{family} signing-key curve and size.")
            result["Classical"]["missing"] = [missing]
            result["Classical"]["reasons"] = [
                f"{algorithm} identifies the signature algorithm, but not the {family} signing-key parameters.",
            ]
    return result
