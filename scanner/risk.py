"""Avaliação centralizada de risco criptográfico."""

from __future__ import annotations

import re
from typing import Any, overload

from scanner.algorithms import (
    CipherSuiteComponents,
    normalise,
    parse_legacy_cipher_suite,
    parse_signature_algorithm,
    parse_tls13_cipher_suite,
)
from scanner.models import CryptoFinding, CryptoFunction, Evidence, QuantumRiskLevel

SHOR_VULNERABLE_ALGORITHMS = {
    "RSA",
    "EC",
    "ECDSA",
    "ECDH",
    "ECDHE",
    "DSA",
    "DH",
    "Ed25519",
    "X25519",
}

SYMMETRIC_KEY_SIZES: dict[str, set[int]] = {
    "AES": {128, 192, 256},
    "SM4": {128},
    "ChaCha20": {256},
    "ChaCha20-Poly1305": {256},
}

# Limiar do modelo conservador de pesquisa quântica adotado pelo projeto.
MIN_GROVER_EXPONENT = 128


def _combine_risks(risks: list[QuantumRiskLevel]) -> QuantumRiskLevel:
    """Combina riscos sem transformar informação incompleta em segurança."""
    if not risks:
        return QuantumRiskLevel.UNKNOWN

    if QuantumRiskLevel.CRITICAL in risks:
        return QuantumRiskLevel.CRITICAL

    if QuantumRiskLevel.UNKNOWN in risks:
        return QuantumRiskLevel.UNKNOWN

    if QuantumRiskLevel.MEDIUM in risks:
        return QuantumRiskLevel.MEDIUM

    return QuantumRiskLevel.SAFE


def _evaluate_cipher_suite(name: str, components: CipherSuiteComponents) -> tuple[QuantumRiskLevel, str]:
    """Avalia os componentes identificados pelo catálogo."""
    symmetric_risk, symmetric_reasoning = evaluate_quantum_risk(
        components.symmetric_algorithm,
        components.symmetric_key_size,
    )

    risks = [symmetric_risk]
    explanations = [
        f"Cifra simétrica: {symmetric_reasoning}",
    ]

    for label, algorithm in (
        ("Troca de chaves", components.key_exchange),
        ("Autenticação", components.authentication),
    ):
        if algorithm is None:
            risks.append(QuantumRiskLevel.UNKNOWN)
            explanations.append(
                f"{label}: não identificada pelo nome do cipher suite."
            )
        else:
            component_risk, component_reasoning = evaluate_quantum_risk(
                algorithm
            )
            risks.append(component_risk)
            explanations.append(f"{label}: {component_reasoning}")

    # O hash precisa de uma regra adequada à função que desempenha.
    risks.append(QuantumRiskLevel.UNKNOWN)
    explanations.append(
        f"Hash: {components.hash_algorithm}, "
        f"função {components.hash_role}; "
        "avaliação específica ainda não implementada."
    )

    combined_risk = _combine_risks(risks)

    reasoning = (
        f"Cipher suite {name}: classificação {combined_risk.value}. "
        + " ".join(explanations)
    )

    return combined_risk, reasoning


def evaluate_quantum_risk(algorithm_name: str | None, key_size: int | None = None) -> tuple[QuantumRiskLevel, str]:
    """Avalia uma família e devolve risco quântico com justificação."""
    name = normalise(algorithm_name)

    if key_size is not None and (isinstance(key_size, bool) or not isinstance(key_size, int) or key_size <= 0):
        raise ValueError("key_size deve ser um inteiro positivo ou None")

    signature = parse_signature_algorithm(name)

    if signature is not None:
        signature_algorithm, hash_algorithm = signature

        signature_risk, signature_reasoning = evaluate_quantum_risk(
            signature_algorithm,
            key_size,
        )

        reasoning = (
            f"Assinatura {name}: "
            f"algoritmo {signature_algorithm}, hash {hash_algorithm}. "
            f"{signature_reasoning} "
            "A avaliação específica do hash ainda não está implementada."
        )

        return signature_risk, reasoning

    components = parse_tls13_cipher_suite(name)

    if components is None:
        components = parse_legacy_cipher_suite(name)

    if components is not None:
        return _evaluate_cipher_suite(name, components)

    if name in SHOR_VULNERABLE_ALGORITHMS:
        mathematical_problem = (
            "fatorização de inteiros"
            if name == "RSA"
            else "logaritmos discretos"
        )

        size_description = (
            f"chave de {key_size} bits"
            if key_size is not None
            else "tamanho de chave desconhecido"
        )

        reasoning = (
            f"{name}, com {size_description}, depende de "
            f"{mathematical_problem} e é vulnerável ao algoritmo de Shor "
            "num computador quântico criptograficamente relevante."
        )

        return QuantumRiskLevel.CRITICAL, reasoning

    if name in SYMMETRIC_KEY_SIZES:
        if key_size is None:
            return (
                QuantumRiskLevel.UNKNOWN,
                (
                    f"{name}: tamanho de chave desconhecido; "
                    "não é possível avaliar a pesquisa quântica da chave."
                ),
            )

        if key_size not in SYMMETRIC_KEY_SIZES[name]:
            return (
                QuantumRiskLevel.UNKNOWN,
                (
                    f"{name}: tamanho de chave de {key_size} bits "
                    "não reconhecido pelo catálogo."
                ),
            )

        grover_exponent = key_size // 2

        risk = (
            QuantumRiskLevel.SAFE
            if grover_exponent >= MIN_GROVER_EXPONENT
            else QuantumRiskLevel.MEDIUM
        )

        reasoning = (
            f"{name}, com chave de {key_size} bits: "
            "a pesquisa genérica da chave no modelo idealizado de Grover "
            f"tem complexidade da ordem de 2^{grover_exponent}. "
            f"Classificação {risk.value} segundo o limiar conservador "
            f"de 2^{MIN_GROVER_EXPONENT} adotado pelo projeto. "
            "Esta avaliação abrange apenas a pesquisa da chave simétrica, "
            "não o protocolo completo nem a segurança da implementação."
        )

        return risk, reasoning

    return (
        QuantumRiskLevel.UNKNOWN,
        f"Ainda não existe uma regra de risco quântico para {name} neste motor.",
    )


# Regras do projeto para uso atual; SAFE avalia apenas o critério indicado.
CLASSICAL_RSA_MIN_BITS = 2048
CLASSICAL_EC_MIN_BITS = 224
KNOWN_EC_KEY_SIZES = {192, 224, 256, 384, 521}
SHA2_ALGORITHMS = {"SHA-224", "SHA-256", "SHA-384", "SHA-512"}
COLLISION_SENSITIVE_FUNCTIONS = {
    CryptoFunction.DIGEST, CryptoFunction.SIGN, CryptoFunction.VERIFY,
}
TLS_VERSION_ALIASES = {
    "TLS1.0": "TLSv1.0", "TLSV1.0": "TLSv1.0",
    "TLS1.1": "TLSv1.1", "TLSV1.1": "TLSv1.1",
    "TLS1.2": "TLSv1.2", "TLSV1.2": "TLSv1.2",
    "TLS1.3": "TLSv1.3", "TLSV1.3": "TLSv1.3",
}


def _evaluate_classical_cipher_suite(
    name: str, components: CipherSuiteComponents,
) -> tuple[QuantumRiskLevel, str]:
    """Mantém os tamanhos simétricos separados das chaves assimétricas."""
    symmetric_risk, symmetric_reasoning = evaluate_classical_risk(
        components.symmetric_algorithm,
        components.symmetric_key_size,
        mode=components.mode,
    )
    risks = [symmetric_risk]
    explanations = [f"Cifra simétrica: {symmetric_reasoning}"]

    for label, algorithm in (
        ("Troca de chaves", components.key_exchange),
        ("Autenticação", components.authentication),
    ):
        if algorithm is None:
            risk = QuantumRiskLevel.UNKNOWN
            reasoning = "não identificada pelo nome do cipher suite."
        else:
            risk, reasoning = evaluate_classical_risk(algorithm)
        risks.append(risk)
        explanations.append(f"{label}: {reasoning}")

    hash_function = (
        CryptoFunction.MAC if components.hash_role == "mac"
        else CryptoFunction.KDF
    )
    hash_risk, hash_reasoning = evaluate_classical_risk(
        components.hash_algorithm, crypto_function=hash_function,
    )
    risks.append(hash_risk)
    explanations.append(
        f"Hash ({components.hash_role}): {hash_reasoning}"
    )
    # Reutiliza a política critical > unknown > medium > safe, sem misturar
    # avaliações quânticas com clássicas.
    combined_risk = _combine_risks(risks)
    return combined_risk, (
        f"Cipher suite {name}: risco clássico {combined_risk.value}. "
        + " ".join(explanations)
    )


def evaluate_classical_risk(
    algorithm_name: str | None,
    key_size: int | None = None,
    *,
    mode: str | None = None,
    crypto_function: CryptoFunction = CryptoFunction.UNKNOWN,
) -> tuple[QuantumRiskLevel, str]:
    """Avalia critérios clássicos conhecidos sem certificar a implementação.

    Para suites, key_size e mode externos não descrevem cada componente:
    usamos apenas os parâmetros do catálogo. SHA-1/MD5 requerem contexto.
    """
    name = normalise(algorithm_name)
    if key_size is not None and (
        isinstance(key_size, bool)
        or not isinstance(key_size, int)
        or key_size <= 0
    ):
        raise ValueError("key_size deve ser um inteiro positivo ou None")
    if mode is not None and (not isinstance(mode, str) or not mode.strip()):
        raise ValueError("mode deve ser uma string não vazia ou None")
    crypto_function = CryptoFunction(crypto_function)

    signature = parse_signature_algorithm(name)
    if signature is not None:
        family, digest = signature
        key_risk, key_reasoning = evaluate_classical_risk(family, key_size)
        hash_risk, hash_reasoning = evaluate_classical_risk(
            digest, crypto_function=CryptoFunction.SIGN,
        )
        risk = _combine_risks([key_risk, hash_risk])
        return risk, (
            f"Assinatura {name}: risco clássico {risk.value}. "
            f"Chave: {key_reasoning} Hash: {hash_reasoning}"
        )

    components = parse_tls13_cipher_suite(name) or parse_legacy_cipher_suite(name)
    if components is not None:
        return _evaluate_classical_cipher_suite(name, components)

    tls_version = TLS_VERSION_ALIASES.get(name.upper())
    if tls_version is not None:
        if tls_version in {"TLSv1.0", "TLSv1.1"}:
            return QuantumRiskLevel.CRITICAL, (
                f"{tls_version}: versão obsoleta, descontinuada pelo RFC 8996."
            )
        return QuantumRiskLevel.SAFE, (
            f"{tls_version}: versão admissível no critério de versão do projeto; "
            "isto não avalia suites, certificados ou configuração da ligação."
        )

    if name in {"DES", "3DES"}:
        return QuantumRiskLevel.CRITICAL, (
            f"{name}: inadequado para aplicar proteção nova; DES tem chave "
            "insuficiente e 3DES foi retirado para nova cifragem. "
            "Esta regra não avalia exceções para decifrar dados históricos."
        )

    if name in SYMMETRIC_KEY_SIZES:
        selected_mode = mode.strip().upper() if mode is not None else None
        if name in {"AES", "SM4"} and selected_mode == "ECB":
            return QuantumRiskLevel.CRITICAL, (
                f"{name}-ECB: revela padrões em blocos repetidos; "
                "o tamanho da chave não elimina esta fraqueza."
            )
        if key_size is None or key_size not in SYMMETRIC_KEY_SIZES[name]:
            return QuantumRiskLevel.UNKNOWN, (
                f"{name}: tamanho de chave ausente ou não reconhecido."
            )
        if name in {"AES", "SM4"} and selected_mode == "CBC":
            return QuantumRiskLevel.MEDIUM, (
                f"{name}-CBC: requer revisão de autenticação, IV e padding; "
                "medium é uma regra de revisão do projeto, não prova de ataque."
            )
        if selected_mode not in {None, "GCM", "CCM", "CTR"}:
            return QuantumRiskLevel.UNKNOWN, (
                f"{name}: modo {mode} sem regra clássica neste catálogo."
            )
        if name.startswith("ChaCha20") and selected_mode is not None:
            return QuantumRiskLevel.UNKNOWN, (
                f"{name}: modo externo {mode} incompatível com o catálogo."
            )
        return QuantumRiskLevel.SAFE, (
            f"{name}, chave de {key_size} bits: tamanho simétrico adequado. "
            "Avaliação limitada à força da chave e ao modo reconhecido; "
            "não garante autenticação, unicidade de nonce ou implementação."
        )

    if name == "RSA" or name in {"EC", "ECDSA", "ECDH", "ECDHE"}:
        if key_size is None:
            return QuantumRiskLevel.UNKNOWN, f"{name}: tamanho de chave desconhecido."
        if name != "RSA" and key_size not in KNOWN_EC_KEY_SIZES:
            return QuantumRiskLevel.UNKNOWN, f"{name}: tamanho de curva não reconhecido."
        minimum = CLASSICAL_RSA_MIN_BITS if name == "RSA" else CLASSICAL_EC_MIN_BITS
        risk = QuantumRiskLevel.CRITICAL if key_size < minimum else QuantumRiskLevel.SAFE
        return risk, (
            f"{name}, {key_size} bits: "
            f"{'abaixo do' if key_size < minimum else 'cumpre o'} "
            f"limiar clássico de {minimum} bits do projeto. "
            "Avaliação apenas do tamanho; parâmetros, curva e padding "
            "exigem verificação separada."
        )

    if name in {"MD5", "SHA-1"}:
        if crypto_function in COLLISION_SENSITIVE_FUNCTIONS:
            return QuantumRiskLevel.CRITICAL, (
                f"{name}: resistência a colisões comprometida; "
                f"inadequado para a função {crypto_function.value} neste projeto."
            )
        return QuantumRiskLevel.UNKNOWN, (
            f"{name}: a função {crypto_function.value} exige contexto; "
            "ataques de colisão não justificam automaticamente "
            "a mesma classificação para MAC ou KDF."
        )

    if name in SHA2_ALGORITHMS:
        return QuantumRiskLevel.SAFE, (
            f"{name}: família SHA-2 adequada no critério clássico do hash; "
            "não avalia chaves de MAC, iterações de KDF ou a construção completa."
        )

    return QuantumRiskLevel.UNKNOWN, (
        f"Não existe regra clássica suficiente para {name} neste motor."
    )


# Identificador reservado à avaliação derivada produzida por este módulo.
RISK_ASSESSMENT_RULE_ID = "RISK-ENGINE-ASSESSMENT"


def enrich_finding(finding: CryptoFinding) -> CryptoFinding:
    """Recalcula os riscos numa cópia, mantendo os dados observados.

    Os níveis do motor substituem classificações anteriores, incluindo UNKNOWN
    quando as regras atuais não permitem uma conclusão. A evidência original
    mantém-se intacta; apenas a avaliação derivada deste módulo é substituída
    numa nova execução. Recomendações existentes são preservadas.
    """
    quantum_risk, quantum_reasoning = evaluate_quantum_risk(
        finding.algorithm_name, finding.key_size,
    )
    classical_risk, classical_reasoning = evaluate_classical_risk(
        finding.algorithm_name,
        finding.key_size,
        mode=finding.mode,
        crypto_function=finding.crypto_function,
    )

    enriched = finding.model_copy(deep=True)
    source_evidence = [
        evidence for evidence in enriched.evidence
        if evidence.rule_id != RISK_ASSESSMENT_RULE_ID
    ]
    if not source_evidence:
        raise ValueError("O enriquecimento requer evidência original do scanner")

    # A localização ancora a avaliação ao resultado; não representa uma nova
    # observação do ficheiro nem acrescenta parâmetros ou normas inferidas.
    anchor = source_evidence[0]
    assessment = Evidence(
        file_path=anchor.file_path,
        line_number=anchor.line_number,
        packet_number=anchor.packet_number,
        json_path=anchor.json_path,
        rule_id=RISK_ASSESSMENT_RULE_ID,
        risk_reasoning=(
            f"Risco quântico ({quantum_risk.value}): {quantum_reasoning}\n"
            f"Risco clássico ({classical_risk.value}): {classical_reasoning}"
        ),
    )

    enriched.quantum_risk = quantum_risk
    enriched.classical_risk = classical_risk
    enriched.evidence = [*source_evidence, assessment]
    return enriched


def enrich_findings(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """Enriquece cada resultado preservando ordem, quantidade e originais."""
    return [enrich_finding(finding) for finding in findings]


# =====================================================================
# Centralized Post-Quantum and Classical Risk Evaluation Engine
# =====================================================================

def normalise_algorithm_name(raw_name: str) -> str:
    """Standardize algorithm string for consistent risk matching."""
    if not raw_name:
        return "unknown"
    cleaned = raw_name.strip()
    return cleaned if cleaned else "unknown"


def algorithm_family(algorithm_name: str) -> str:
    """Return top-level cryptographic family or primitive type."""
    norm = algorithm_name.strip().upper()
    if "RSA" in norm:
        return "RSA"
    if "ED25519" in norm or "EDDSA" in norm:
        return "EdDSA"
    if "ECDSA" in norm or "ECDH" in norm or "ECC" in norm or "SECP" in norm or "PRIME256" in norm:
        return "ECC"
    if "CURVE25519" in norm or "X25519" in norm:
        return "X25519"
    if "AES" in norm:
        return "AES"
    if "MD5" in norm:
        return "MD5"
    if "SHA-1" in norm or "SHA1" in norm:
        return "SHA-1"
    if "SHA-256" in norm or "SHA256" in norm:
        return "SHA-256"
    if "SHA-384" in norm or "SHA384" in norm:
        return "SHA-384"
    if "SHA-512" in norm or "SHA512" in norm:
        return "SHA-512"
    if "HMAC" in norm:
        return "HMAC"
    if "PBKDF2" in norm:
        return "PBKDF2"
    if "ML-KEM" in norm or "KYBER" in norm:
        return "ML-KEM"
    if "ML-DSA" in norm or "DILITHIUM" in norm:
        return "ML-DSA"
    if "SLH-DSA" in norm or "SPHINCS" in norm:
        return "SLH-DSA"
    if "DES" in norm:
        return "DES"
    if "DH" in norm or "DIFFIE-HELLMAN" in norm:
        return "DH"
    if "DSA" in norm:
        return "DSA"
    return "UNKNOWN"


def is_shor_vulnerable(algorithm_name: str) -> bool:
    """Return True if algorithm relies on integer factoring or discrete log broken by Shor."""
    if not algorithm_name:
        return False
    norm = algorithm_name.strip().upper()
    if any(k in norm for k in ("ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS")):
        return False
    shor_keywords = (
        "RSA",
        "ED25519",
        "EDDSA",
        "ECDSA",
        "ECDH",
        "ECC",
        "SECP256",
        "SECP384",
        "SECP521",
        "PRIME256",
        "CURVE25519",
        "X25519",
        "DIFFIE-HELLMAN",
    )
    if any(k in norm for k in shor_keywords):
        return True
    if re.search(r"\bDH\b", norm) or re.search(r"\bDHE\b", norm):
        return True
    return bool(
        re.search(r"\bDSA\b", norm)
        and "ML-DSA" not in norm
        and "SLH-DSA" not in norm
    )


def is_classically_broken(algorithm_name: str, mode: str | None = None) -> bool:
    """Return True if algorithm or mode is classically compromised."""
    norm = algorithm_name.strip().upper()
    mode_norm = (mode or "").strip().upper()
    if mode_norm == "ECB" or "ECB" in norm:
        return True
    if "MD5" in norm:
        return True
    if "SHA-1" in norm or "SHA1" in norm:
        return True
    if re.search(r"\bDES\b", norm) or "3DES" in norm or "TRIPLEDES" in norm or "TDES" in norm:
        return True
    return bool(
        "CLEARTEXT" in norm
        or "PLAINTEXT" in norm
    )


def estimate_classical_bits(
    algorithm_name: str,
    key_size: int | str | None = None,
) -> int | None:
    """Estimate classical security bit strength based on algorithm and key length."""
    norm = algorithm_name.strip().upper()
    num_key: int | None = None
    if isinstance(key_size, int):
        num_key = key_size
    elif isinstance(key_size, str) and key_size.isdigit():
        num_key = int(key_size)
    else:
        m = re.search(r"\b(1024|2048|3072|4096|128|192|256|384|512)\b", norm)
        if m:
            num_key = int(m.group(1))

    if is_classically_broken(algorithm_name):
        if "3DES" in norm or "TRIPLEDES" in norm:
            return 112
        if "DES" in norm:
            return 56
        return 0

    if "RSA" in norm:
        if num_key == 1024:
            return 80
        if num_key == 2048:
            return 112
        if num_key == 3072:
            return 128
        if num_key == 4096:
            return 152
        return num_key if num_key else None

    if any(k in norm for k in ("ED25519", "CURVE25519", "X25519", "P256", "PRIME256", "SECP256")):
        return 128
    if any(k in norm for k in ("P384", "SECP384")):
        return 192
    if any(k in norm for k in ("P521", "SECP521")):
        return 256
    if "ECDSA" in norm or "ECDH" in norm:
        return num_key // 2 if num_key else 128

    if "AES" in norm:
        if num_key in (128, 192, 256):
            return num_key
        return None

    if "SHA-256" in norm or "SHA256" in norm:
        return 128
    if "SHA-384" in norm or "SHA384" in norm:
        return 192
    if "SHA-512" in norm or "SHA512" in norm:
        return 256
    if "HMAC" in norm:
        if "384" in norm:
            return 192
        if "512" in norm:
            return 256
        return 128
    if "PBKDF2" in norm:
        return 128

    if any(k in norm for k in ("ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS")):
        if "512" in norm or "2" in norm or "44" in norm:
            return 128
        if "768" in norm or "3" in norm or "65" in norm:
            return 192
        if "1024" in norm or "5" in norm or "87" in norm:
            return 256
        return 128

    return None


def estimate_quantum_bits(
    algorithm_name: str,
    key_size: int | str | None = None,
    mode: str | None = None,
) -> int | None:
    """Estimate post-quantum security bit strength under Shor's or Grover's algorithm."""
    if is_classically_broken(algorithm_name, mode):
        return 0

    if is_shor_vulnerable(algorithm_name):
        return 0

    norm = algorithm_name.strip().upper()
    num_key: int | None = None
    if isinstance(key_size, int):
        num_key = key_size
    elif isinstance(key_size, str) and key_size.isdigit():
        num_key = int(key_size)
    else:
        m = re.search(r"\b(128|192|256|384|512)\b", norm)
        if m:
            num_key = int(m.group(1))

    if "AES" in norm:
        if num_key == 128:
            return 64
        if num_key == 192:
            return 96
        if num_key == 256:
            return 128
        return None

    if "SHA-256" in norm or "SHA256" in norm:
        return 128
    if "SHA-384" in norm or "SHA384" in norm:
        return 192
    if "SHA-512" in norm or "SHA512" in norm:
        return 256

    if "HMAC" in norm:
        if "384" in norm:
            return 192
        if "512" in norm:
            return 256
        return 128

    if "PBKDF2" in norm:
        return 128

    if any(k in norm for k in ("ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS")):
        if "512" in norm or "2" in norm or "44" in norm:
            return 128
        if "768" in norm or "3" in norm or "65" in norm:
            return 192
        if "1024" in norm or "5" in norm or "87" in norm:
            return 256
        return 128

    return None


def map_nist_standard(algorithm_name: str) -> str:
    """Return authoritative NIST standard publication reference or 'none'."""
    if not algorithm_name:
        return "none"

    norm = algorithm_name.strip().upper()

    # Post-Quantum FIPS standards
    if any(k in norm for k in ("ML-KEM", "KYBER")):
        return "FIPS 203"
    if any(k in norm for k in ("ML-DSA", "DILITHIUM")):
        return "FIPS 204"
    if any(k in norm for k in ("SLH-DSA", "SPHINCS")):
        return "FIPS 205"

    # Message authentication & KDF
    if "HMAC" in norm:
        return "FIPS 198-1"
    if "PBKDF2" in norm:
        return "SP 800-132"

    # Symmetric ciphers
    if "AES" in norm:
        return "FIPS 197"

    # Hash functions (check SHA-1/SHA-2 family before SHA-3 to avoid SHA-3 matching SHA-384)
    if any(k in norm for k in ("SHA-256", "SHA-384", "SHA-512", "SHA-224", "SHA-1", "SHA1", "SHA256", "SHA384", "SHA512")):
        return "FIPS 180-4"
    if any(k in norm for k in ("SHA3-", "SHA-3-", "SHAKE")) or re.search(r"\bSHA-?3\b", norm):
        return "FIPS 202"

    # Asymmetric signatures & key exchange
    if any(k in norm for k in ("RSA", "ECDSA", "ED25519", "EDDSA", "DSA")):
        return "FIPS 186-5"
    if any(k in norm for k in ("CURVE25519", "X25519")):
        return "SP 800-186"

    return "none"


def evaluate_risk(
    algorithm_name: str,
    key_size: int | str | None = None,
    mode: str | None = None,
) -> tuple[QuantumRiskLevel, int | None, int | None, str]:
    """Evaluate cryptographic primitive against classical and quantum threats.

    Returns:
        (risk_tier, estimated_classical_bits, estimated_quantum_bits, reasoning_sentence)
    """
    if not algorithm_name or algorithm_name.strip().lower() in ("unknown", "none", ""):
        return (
            QuantumRiskLevel.UNKNOWN,
            None,
            None,
            "Cryptographic algorithm is unspecified and cannot be evaluated.",
        )

    raw_algo = algorithm_name.strip()
    norm = raw_algo.upper()

    # Normalize integer key size if present
    num_key: int | None = None
    if isinstance(key_size, int):
        num_key = key_size
    elif isinstance(key_size, str) and key_size.isdigit():
        num_key = int(key_size)
    else:
        m = re.search(r"\b(1024|2048|3072|4096|128|192|256|384|512)\b", norm)
        if m:
            num_key = int(m.group(1))

    # Normalize mode if present
    mode_clean: str | None = None
    if mode:
        mode_clean = mode.strip().upper()
    else:
        for m_candidate in ("ECB", "GCM", "CBC", "CTR", "CFB", "OFB"):
            if re.search(rf"\b{m_candidate}\b", norm):
                mode_clean = m_candidate
                break

    # ---------------------------------------------------------
    # 1. Classical Compromises (Always CRITICAL)
    # ---------------------------------------------------------
    if mode_clean == "ECB" or "ECB" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            0,
            0,
            "AES in ECB mode lacks semantic security and leaks plaintext patterns across identical blocks.",
        )

    if "MD5" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            0,
            0,
            "MD5 is classically broken because practical collision attacks undermine its integrity guarantees.",
        )

    if "SHA-1" in norm or "SHA1" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            0,
            0,
            "SHA-1 is deprecated and vulnerable to practical collision attacks.",
        )

    if re.search(r"\bDES\b", norm) and "3DES" not in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            56,
            0,
            "DES is classically broken due to its small 56-bit key space, vulnerable to practical brute-force attacks.",
        )

    if "3DES" in norm or "TRIPLEDES" in norm or "TDES" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            112,
            0,
            "3DES is deprecated and vulnerable to the Sweet32 collision attack due to its 64-bit block size.",
        )

    if "CLEARTEXT" in norm or "PLAINTEXT" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            0,
            0,
            "Unencrypted cleartext traffic exposes data in transit without any cryptographic protection.",
        )

    # ---------------------------------------------------------
    # 2. Post-Quantum Cryptographic Standards (SAFE)
    # ---------------------------------------------------------
    if any(k in norm for k in ("ML-KEM", "KYBER")):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        q_bits = estimate_quantum_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.SAFE,
            cl_bits or 128,
            q_bits or 128,
            f"{raw_algo} is a NIST FIPS 203 standardized post-quantum lattice-based key encapsulation mechanism.",
        )

    if any(k in norm for k in ("ML-DSA", "DILITHIUM")):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        q_bits = estimate_quantum_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.SAFE,
            cl_bits or 128,
            q_bits or 128,
            f"{raw_algo} is a NIST FIPS 204 standardized post-quantum lattice-based digital signature algorithm.",
        )

    if any(k in norm for k in ("SLH-DSA", "SPHINCS")):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        q_bits = estimate_quantum_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.SAFE,
            cl_bits or 128,
            q_bits or 128,
            f"{raw_algo} is a NIST FIPS 205 standardized post-quantum stateless hash-based digital signature algorithm.",
        )

    # ---------------------------------------------------------
    # 3. Shor-Vulnerable Asymmetric Schemes (Always CRITICAL)
    # ---------------------------------------------------------
    if "RSA" in norm:
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        size_label = f"-{num_key}" if num_key else ""
        return (
            QuantumRiskLevel.CRITICAL,
            cl_bits,
            0,
            f"RSA{size_label} is vulnerable to Shor's polynomial-time factoring algorithm regardless of classical key size.",
        )

    if "ED25519" in norm or "EDDSA" in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            128,
            0,
            "Ed25519 signature algorithm is broken by Shor's quantum discrete-log algorithm.",
        )

    if any(k in norm for k in ("CURVE25519", "X25519")):
        return (
            QuantumRiskLevel.CRITICAL,
            128,
            0,
            "Curve25519 key exchange is broken by Shor's quantum discrete-log algorithm.",
        )

    if any(k in norm for k in ("ECDSA", "ECDH", "ECC", "SECP", "PRIME256")):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.CRITICAL,
            cl_bits or 128,
            0,
            f"{raw_algo} elliptic-curve cryptography is broken by Shor's quantum discrete-log algorithm.",
        )

    if "DIFFIE-HELLMAN" in norm or re.search(r"\bDH\b", norm) or re.search(r"\bDHE\b", norm):
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.CRITICAL,
            cl_bits,
            0,
            f"{raw_algo} finite-field Diffie-Hellman is vulnerable to Shor's quantum discrete-log algorithm.",
        )

    if re.search(r"\bDSA\b", norm) and "ML-DSA" not in norm and "SLH-DSA" not in norm:
        return (
            QuantumRiskLevel.CRITICAL,
            80,
            0,
            "DSA signatures are broken by Shor's quantum discrete-log algorithm.",
        )

    # ---------------------------------------------------------
    # 4. Symmetric Hashes & MACs (SAFE)
    # ---------------------------------------------------------
    if "HMAC" in norm:
        cl_bits = estimate_classical_bits(raw_algo, num_key)
        q_bits = estimate_quantum_bits(raw_algo, num_key)
        return (
            QuantumRiskLevel.SAFE,
            cl_bits or 128,
            q_bits or 128,
            f"{raw_algo} message authentication code is quantum-resistant against Grover's algorithm.",
        )

    if "PBKDF2" in norm:
        return (
            QuantumRiskLevel.SAFE,
            128,
            128,
            "PBKDF2 key derivation using SHA-256 is quantum-resistant against Grover's algorithm.",
        )

    if any(k in norm for k in ("SHA-256", "SHA256")):
        return (
            QuantumRiskLevel.SAFE,
            128,
            128,
            "SHA-256 hash function maintains 128 bits of quantum collision resistance against Grover's algorithm.",
        )

    if any(k in norm for k in ("SHA-384", "SHA384")):
        return (
            QuantumRiskLevel.SAFE,
            192,
            192,
            "SHA-384 hash function maintains 192 bits of quantum collision resistance against Grover's algorithm.",
        )

    if any(k in norm for k in ("SHA-512", "SHA512")):
        return (
            QuantumRiskLevel.SAFE,
            256,
            256,
            "SHA-512 hash function maintains 256 bits of quantum collision resistance against Grover's algorithm.",
        )

    # ---------------------------------------------------------
    # 5. Symmetric Ciphers (AES / Others)
    # ---------------------------------------------------------
    if "AES" in norm:
        # Check if mode is explicitly unknown or unresolvable
        if (
            mode_clean in ("UNKNOWN", "UNRESOLVED")
            or (mode is not None and mode.strip().lower() in ("unknown", "unresolved"))
            or "-UNKNOWN" in norm
        ):
            return (
                QuantumRiskLevel.UNKNOWN,
                None,
                None,
                "The AES key size or mode could not be proven statically, so the finding requires manual review.",
            )

        # AES mode must be proven statically; without mode information,
        # the scanner cannot distinguish secure modes (e.g. GCM) from insecure modes (e.g. ECB).
        if mode_clean is None:
            return (
                QuantumRiskLevel.UNKNOWN,
                None,
                None,
                "The AES mode or key size could not be proven statically, so the finding requires manual review.",
            )

        if num_key == 256:
            mode_desc = f"-{mode_clean}" if mode_clean and mode_clean != "256" else ""
            return (
                QuantumRiskLevel.SAFE,
                256,
                128,
                f"AES-256{mode_desc} retains approximately 128 bits of quantum security against Grover's algorithm.",
            )

        if num_key == 128:
            mode_desc = f"-{mode_clean}" if mode_clean and mode_clean != "128" else ""
            return (
                QuantumRiskLevel.MEDIUM,
                128,
                64,
                f"AES-128{mode_desc} provides only approximately 64 bits of effective quantum security under Grover's algorithm.",
            )

        if num_key == 192:
            return (
                QuantumRiskLevel.MEDIUM,
                192,
                96,
                "AES-192 provides approximately 96 bits of effective quantum security under Grover's algorithm.",
            )

        # AES with unresolved key size
        return (
            QuantumRiskLevel.UNKNOWN,
            None,
            None,
            "The AES key size or mode could not be proven statically, so the finding requires manual review.",
        )

    # ---------------------------------------------------------
    # 6. Fallback / Unrecognized Primitives (UNKNOWN)
    # ---------------------------------------------------------
    return (
        QuantumRiskLevel.UNKNOWN,
        None,
        None,
        f"Cryptographic algorithm '{raw_algo}' is unrecognized or insufficiently specified for automated quantum risk evaluation.",
    )


def build_reasoning(
    algorithm_name: str,
    quantum_risk: QuantumRiskLevel | str | None = None,
    key_size: int | str | None = None,
    mode: str | None = None,
) -> str:
    """Return a concise, single-sentence risk explanation for a cryptographic primitive."""
    del quantum_risk
    _, _, _, reasoning = evaluate_risk(
        algorithm_name=algorithm_name,
        key_size=key_size,
        mode=mode,
    )
    return reasoning


@overload
def enrich_finding_risk(finding: CryptoFinding) -> CryptoFinding:
    ...


@overload
def enrich_finding_risk(finding: dict[str, Any]) -> dict[str, Any]:
    ...


@overload
def enrich_finding_risk(finding: Any) -> Any:
    ...


def enrich_finding_risk(finding: Any) -> Any:
    """Enrich a CryptoFinding instance or dictionary with centralized quantum and classical risk evaluations.

    Risk Dimensions:
    - quantum_risk: Future quantum vulnerability (e.g. Shor's algorithm breaking RSA/ECC
      key exchange/signatures -> CRITICAL; Grover's algorithm halving symmetric bits -> MEDIUM/SAFE).
    - classical_risk: Current pre-quantum cryptographic strength (e.g. broken ciphers like
      MD5/DES/SHA-1 -> CRITICAL, deprecated key sizes like RSA-1024 -> MEDIUM, modern
      primitives like RSA-2048/AES-GCM -> SAFE).
    """
    if isinstance(finding, dict):
        algo = str(
            finding.get("algorithm_name")
            or finding.get("canonical_algorithm")
            or finding.get("algorithm")
            or ""
        )
        key_size = finding.get("key_size")
        mode = finding.get("mode")
    else:
        algo = getattr(finding, "algorithm_name", "")
        key_size = getattr(finding, "key_size", None)
        mode = getattr(finding, "mode", None)

    quantum_risk, _cl_bits, _q_bits, reasoning = evaluate_risk(
        algorithm_name=algo,
        key_size=key_size,
        mode=mode,
    )

    # Derive classical risk (pre-quantum cryptographic strength):
    # - Classically broken primitives (MD5, SHA-1, DES, 3DES, ECB mode) -> CRITICAL.
    # - Shor-vulnerable asymmetric primitives (RSA, ECC, Diffie-Hellman):
    #   * Quantum exposure is CRITICAL (must migrate to PQC).
    #   * Classical risk is SAFE for modern parameters (e.g. RSA-2048, ECC P-256),
    #     or MEDIUM for deprecated key lengths (e.g. RSA <= 1024).
    # - Symmetric / PQC primitives with adequate key lengths -> SAFE.
    if is_classically_broken(algo, mode):
        classical_risk = QuantumRiskLevel.CRITICAL
    elif quantum_risk == QuantumRiskLevel.CRITICAL:
        if "1024" in algo or (isinstance(key_size, int) and key_size <= 1024 and "RSA" in algo.upper()):
            classical_risk = QuantumRiskLevel.MEDIUM
        else:
            classical_risk = QuantumRiskLevel.SAFE
    elif quantum_risk in (QuantumRiskLevel.MEDIUM, QuantumRiskLevel.SAFE):
        classical_risk = QuantumRiskLevel.SAFE
    else:
        classical_risk = QuantumRiskLevel.UNKNOWN

    nist_std = map_nist_standard(algo)

    if isinstance(finding, dict):
        if quantum_risk != QuantumRiskLevel.UNKNOWN or finding.get("quantum_risk") in (QuantumRiskLevel.UNKNOWN, "unknown", None):
            finding["quantum_risk"] = quantum_risk
            finding["risk_rating"] = quantum_risk.value.capitalize()
        if classical_risk != QuantumRiskLevel.UNKNOWN or finding.get("classical_risk") in (QuantumRiskLevel.UNKNOWN, "unknown", None):
            finding["classical_risk"] = classical_risk
        if not finding.get("explanation") or finding.get("explanation") == "unknown":
            finding["explanation"] = reasoning
        if not finding.get("nist_standard") or finding.get("nist_standard") == "none":
            finding["nist_standard"] = nist_std
        if finding.get("evidence"):
            for ev in finding["evidence"]:
                if isinstance(ev, dict):
                    if not ev.get("risk_reasoning"):
                        ev["risk_reasoning"] = reasoning
                    if (not ev.get("nist_standard") or ev.get("nist_standard") == "none") and nist_std != "none":
                        ev["nist_standard"] = nist_std
        return finding

    # Do not replace a known, more specific scanner result with a less specific result
    if quantum_risk != QuantumRiskLevel.UNKNOWN or finding.quantum_risk == QuantumRiskLevel.UNKNOWN:
        object.__setattr__(finding, "quantum_risk", quantum_risk)

    if classical_risk != QuantumRiskLevel.UNKNOWN or finding.classical_risk == QuantumRiskLevel.UNKNOWN:
        object.__setattr__(finding, "classical_risk", classical_risk)

    if finding.evidence:
        for ev in finding.evidence:
            if not getattr(ev, "risk_reasoning", None):
                object.__setattr__(ev, "risk_reasoning", reasoning)
            if (
                not getattr(ev, "nist_standard", None)
                or ev.nist_standard == "none"
            ) and nist_std != "none":
                object.__setattr__(ev, "nist_standard", nist_std)

    return finding
