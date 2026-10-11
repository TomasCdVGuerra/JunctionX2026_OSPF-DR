"""Convert source detector observations without guessing parameters or risk."""
import re
from pathlib import Path
from scanner.algorithms import normalise
from scanner.models import CryptoFinding, CryptoFunction, Evidence


def adapt_source_finding(raw, language: str, base_dir: Path | None = None) -> CryptoFinding:
    path = Path(raw.filename)
    try:
        display = path.relative_to(base_dir).as_posix() if base_dir else path.name
    except ValueError:
        display = path.as_posix()
    params = raw.params
    name = normalise(raw.algorithm)
    usage = params.get("function", "unknown")
    operation = CryptoFunction(usage)
    if "function" not in params and operation == CryptoFunction.UNKNOWN and "reference" not in raw.usage:
        if name.lower().startswith("hmac"):
            operation = CryptoFunction.MAC
        elif "Hash" in raw.usage and "with" not in name.lower():
            operation = CryptoFunction.DIGEST
    construction = params.get("hash_name", "")
    if construction.lower().startswith("pbkdf2withhmac"):
        name = "PBKDF2-HMAC-" + normalise(construction[len("PBKDF2WithHmac"):])
        operation = CryptoFunction.KDF
    elif name.lower().startswith("pbkdf2withhmac"):
        name = "PBKDF2-HMAC-" + normalise(name[len("PBKDF2WithHmac"):])
        operation = CryptoFunction.KDF
    elif name.lower().startswith("hmac"):
        name = "HMAC-" + normalise(name[4:].lstrip("-"))
    if name.upper().startswith("PBKDF2-HMAC-"):
        name = "PBKDF2-HMAC-" + normalise(name[len("PBKDF2-HMAC-"):])
    mode = params.get("mode_resolved", params.get("mode"))
    if isinstance(mode, str):
        mode = mode.upper().split(".")[-1].replace("MODE_", "")
        if mode not in {"ECB", "CBC", "GCM", "CCM", "CTR", "CFB", "OFB"}:
            mode = None
    if name == "ECB":
        name, mode = "unknown", "ECB"
    size = params.get("key_size")
    size = int(size) if isinstance(size, (str, int)) and re.fullmatch(r"[1-9]\d*", str(size)) else None
    return CryptoFinding(
        algorithm_name=name, source_type="source-code", key_size=size,
        library=params.get("library"),
        mode=mode, crypto_function=operation, observation="declared",
        confidence="low" if params.get("ambiguous") == "true" else "medium",
        evidence=[Evidence(file_path=display, line_number=raw.line,
                           rule_id=f"{language.upper()}-SOURCE-{operation.value.upper()}",
                           matched_snippet=raw.evidence, risk_reasoning=params.get("note"))],
    )
