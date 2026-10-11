"""Avaliação centralizada de risco criptográfico."""

from __future__ import annotations

from scanner.algorithms import (CipherSuiteComponents, normalise, parse_legacy_cipher_suite, parse_signature_algorithm, parse_tls13_cipher_suite)
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
                f"{name}: tamanho de chave desconhecido; "
                "não é possível avaliar a pesquisa quântica da chave.",
            )

        if key_size not in SYMMETRIC_KEY_SIZES[name]:
            return (
                QuantumRiskLevel.UNKNOWN,
                f"{name}: tamanho de chave de {key_size} bits "
                "não reconhecido pelo catálogo.",
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
