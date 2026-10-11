"""Avaliação centralizada de risco criptográfico."""

from __future__ import annotations

from scanner.algorithms import (CipherSuiteComponents, normalise, parse_legacy_cipher_suite, parse_signature_algorithm, parse_tls13_cipher_suite)
from scanner.algorithms import parse_hash_construction, parse_pqc_algorithm, parse_primitive_name
from scanner.models import CryptoFinding, CryptoFunction, Evidence, QuantumRiskLevel
from scanner.nist_references import nist_references_for_algorithm


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
    "Curve25519",
}

SYMMETRIC_KEY_SIZES: dict[str, set[int]] = {
    "AES": {128, 192, 256},
    "SM4": {128},
    "ChaCha20": {256},
    "ChaCha20-Poly1305": {256},
}

# Limiar do modelo conservador de pesquisa quântica adotado pelo projeto.
MIN_GROVER_EXPONENT = 128

# Comprimento do digest; não corresponde ao tamanho de uma chave.
HASH_OUTPUT_BITS = {
    "MD5": 128, "SHA-1": 160,
    "SHA-224": 224, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512,
}
MIN_QUANTUM_COLLISION_EXPONENT = 128
COLLISION_SENSITIVE_FUNCTIONS = {
    CryptoFunction.DIGEST, CryptoFunction.SIGN, CryptoFunction.VERIFY,
}


def _evaluate_quantum_hash(
    name: str, crypto_function: CryptoFunction,
) -> tuple[QuantumRiskLevel, str]:
    """Aplica o modelo idealizado de colisões BHT, não uma estimativa prática.

    Referência: https://arxiv.org/abs/quant-ph/9705002
    DIGEST assume conservadoramente necessidade de resistência a colisões.
    MAC/KDF não herdam esta regra: a construção e os parâmetros são necessários.
    """
    if crypto_function not in COLLISION_SENSITIVE_FUNCTIONS:
        return QuantumRiskLevel.UNKNOWN, (
            f"{name}: função {crypto_function.value} sem contexto suficiente. "
            "Para MAC/KDF são necessários construção, entropia da chave ou "
            "entrada e comprimentos de tag/saída; o digest isolado não os revela. "
            "A função desconhecida também não permite escolher o ataque relevante."
        )

    output_bits = HASH_OUTPUT_BITS[name]
    # Compara sem arredondar n/3: 384/3 atinge exatamente o limiar de 128.
    risk = (
        QuantumRiskLevel.SAFE
        if output_bits >= 3 * MIN_QUANTUM_COLLISION_EXPONENT
        else QuantumRiskLevel.MEDIUM
    )
    reasoning = (
        f"{name}, digest de {output_bits} bits, função {crypto_function.value}: "
        "no modelo idealizado BHT (Brassard–Høyer–Tapp), a pesquisa genérica "
        f"de colisões requer da ordem de 2^({output_bits}/3) consultas. "
        f"Classificação {risk.value} pelo limiar conservador de "
        f"2^{MIN_QUANTUM_COLLISION_EXPONENT} do projeto. "
        "Consultas teóricas não equivalem ao custo real de um ataque; "
        "isto não é uma exigência de migração do NIST nem avalia pré-imagens."
    )
    if name in {"MD5", "SHA-1"}:
        reasoning += (
            " Este modelo genérico não descreve as fraquezas específicas "
            "já conhecidas; as colisões clássicas são avaliadas separadamente."
        )
    return risk, reasoning


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


def _evaluate_pqc(
    name: str, crypto_function: CryptoFunction,
) -> tuple[QuantumRiskLevel, str] | None:
    entry = parse_pqc_algorithm(name)
    if entry is None:
        return None
    allowed = {CryptoFunction.UNKNOWN, CryptoFunction.KEYGEN}
    allowed |= (
        {CryptoFunction.KEY_EXCHANGE} if entry.purpose == "key-establishment"
        else {CryptoFunction.SIGN, CryptoFunction.VERIFY}
    )
    if crypto_function not in allowed:
        return QuantumRiskLevel.UNKNOWN, (
            f"{name}: função {crypto_function.value} incompatível com "
            f"a finalidade {entry.purpose} do catálogo."
        )
    return QuantumRiskLevel.SAFE, (
        f"{name}: parâmetro PQC normalizado em {entry.standard}, "
        f"finalidade {entry.purpose}. Avaliação da seleção do algoritmo; "
        "não certifica implementação, protocolo ou módulo FIPS. "
        "O identificador do parâmetro não é um tamanho de chave em bits."
    )


def _named_parameters(
    name: str, key_size: int | None, mode: str | None,
) -> tuple[str, int | None, str | None, bool]:
    """Resolve só parâmetros explícitos no nome; deteta campos contraditórios."""
    parsed = parse_primitive_name(name)
    if parsed is None:
        return name, key_size, mode, False
    conflict = (
        parsed.key_size is not None and key_size is not None
        and parsed.key_size != key_size
    ) or (
        parsed.mode is not None and mode is not None
        and parsed.mode != mode.strip().upper()
    )
    return (
        parsed.family,
        key_size if key_size is not None else parsed.key_size,
        mode if mode is not None else parsed.mode,
        conflict,
    )


def _evaluate_hash_construction(name: str) -> tuple[QuantumRiskLevel, str] | None:
    parsed = parse_hash_construction(name)
    if parsed is None:
        return None
    construction, digest = parsed
    missing = (
        "entropia da chave e comprimento da tag"
        if construction == "HMAC"
        else "entropia da password, salt, iterações e comprimento derivado"
    )
    return QuantumRiskLevel.UNKNOWN, (
        f"{construction} com {digest}: faltam {missing}. "
        "O comprimento da chave/saída não demonstra entropia da entrada. "
        "A resistência a colisões do hash não classifica a construção completa."
    )


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

    # TLS 1.3 usa o mesmo hash em HKDF e no transcript. Avaliamos a exigência
    # de colisões do transcript sem declarar a construção HKDF inteira segura.
    hash_function = (
        CryptoFunction.DIGEST if components.tls_version == "TLSv1.3"
        else CryptoFunction.MAC if components.hash_role == "mac"
        else CryptoFunction.KDF
    )
    hash_risk, hash_reasoning = evaluate_quantum_risk(
        components.hash_algorithm, crypto_function=hash_function,
    )
    risks.append(hash_risk)
    explanations.append(
        f"Hash: {components.hash_algorithm}, "
        f"função {components.hash_role}; {hash_reasoning}"
    )
    if components.tls_version == "TLSv1.3":
        explanations.append(
            "O hash também protege o transcript TLS 1.3; "
            "esta regra avalia colisões do transcript, não o HKDF completo."
        )

    combined_risk = _combine_risks(risks)

    reasoning = (
        f"Cipher suite {name}: classificação {combined_risk.value}. "
        + " ".join(explanations)
    )

    return combined_risk, reasoning


def evaluate_quantum_risk(
    algorithm_name: str | None,
    key_size: int | None = None,
    *,
    mode: str | None = None,
    crypto_function: CryptoFunction = CryptoFunction.UNKNOWN,
) -> tuple[QuantumRiskLevel, str]:
    """Avalia uma família e devolve risco quântico com justificação."""
    name = normalise(algorithm_name)

    if key_size is not None and (isinstance(key_size, bool) or not isinstance(key_size, int) or key_size <= 0):
        raise ValueError("key_size deve ser um inteiro positivo ou None")
    crypto_function = CryptoFunction(crypto_function)
    if mode is not None and (not isinstance(mode, str) or not mode.strip()):
        raise ValueError("mode deve ser uma string não vazia ou None")
    family, resolved_size, resolved_mode, conflict = _named_parameters(name, key_size, mode)
    if conflict:
        return QuantumRiskLevel.UNKNOWN, f"{name}: parâmetros contraditórios entre nome e campos; rever a observação."
    if family != name:
        return evaluate_quantum_risk(
            family, resolved_size, mode=resolved_mode, crypto_function=crypto_function,
        )
    construction_result = _evaluate_hash_construction(name)
    if construction_result is not None:
        return construction_result

    pqc_result = _evaluate_pqc(name, crypto_function)
    if pqc_result is not None:
        return pqc_result

    signature = parse_signature_algorithm(name)

    if signature is not None:
        signature_algorithm, hash_algorithm = signature

        signature_risk, signature_reasoning = evaluate_quantum_risk(
            signature_algorithm,
            key_size,
        )
        hash_risk, hash_reasoning = evaluate_quantum_risk(
            hash_algorithm, crypto_function=CryptoFunction.SIGN,
        )

        reasoning = (
            f"Assinatura {name}: "
            f"algoritmo {signature_algorithm}, hash {hash_algorithm}. "
            f"{signature_reasoning} "
            f"Hash: {hash_reasoning}"
        )

        return _combine_risks([signature_risk, hash_risk]), reasoning

    components = parse_tls13_cipher_suite(name)

    if components is None:
        components = parse_legacy_cipher_suite(name)

    if components is not None:
        return _evaluate_cipher_suite(name, components)

    if name in HASH_OUTPUT_BITS:
        return _evaluate_quantum_hash(name, crypto_function)

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
    family, resolved_size, resolved_mode, conflict = _named_parameters(name, key_size, mode)
    if conflict:
        return QuantumRiskLevel.UNKNOWN, f"{name}: parâmetros contraditórios entre nome e campos; rever a observação."
    if family != name:
        return evaluate_classical_risk(
            family, resolved_size, mode=resolved_mode, crypto_function=crypto_function,
        )
    construction_result = _evaluate_hash_construction(name)
    if construction_result is not None:
        return construction_result

    if name in {"Ed25519", "X25519", "Curve25519"}:
        # 255 is the field convention; 256 is the encoded-size convention
        # used by the Go scanner. Neither is asserted to be a security level.
        allowed_sizes = {256} if name == "Ed25519" else {255, 256}
        if key_size is not None and key_size not in allowed_sizes:
            return QuantumRiskLevel.UNKNOWN, f"{name}: tamanho não reconhecido para esta família."
        return QuantumRiskLevel.SAFE, (
            f"{name}: família de curva fixa com força clássica de aproximadamente "
            "128 bits (RFC 8032/7748). Não certifica validação de pontos, "
            "implementação ou uso correto; 256 não significa 256 bits de segurança."
        )

    pqc_result = _evaluate_pqc(name, crypto_function)
    if pqc_result is not None:
        return pqc_result

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
_GENERATED_RECOMMENDATION_PREFIX = "\nRecomendação gerada: "


def recommend_for_finding(finding: CryptoFinding) -> str:
    """Sugere ações a partir dos riscos já calculados, sem mudar a observação."""
    name = normalise(finding.algorithm_name)
    primitive = parse_primitive_name(name)
    if primitive is not None:
        name = primitive.family
    actions: list[str] = []
    signature = parse_signature_algorithm(name)
    components = parse_tls13_cipher_suite(name) or parse_legacy_cipher_suite(name)
    pqc = parse_pqc_algorithm(name)
    construction = parse_hash_construction(name)
    if construction is not None:
        return (
            "Rever entropia e gestão da chave HMAC e comprimento da tag antes de concluir segurança."
            if construction[0] == "HMAC" else
            "Rever salt, iterações, entropia da password e comprimento derivado de PBKDF2; uma saída longa não garante uma password forte."
        )

    if pqc is not None:
        if QuantumRiskLevel.UNKNOWN in {finding.quantum_risk, finding.classical_risk}:
            return "Confirmar a função criptográfica: o parâmetro PQC tem finalidade incompatível com a observação."
        return (
            f"Manter {name} ({pqc.standard}) e verificar implementação, "
            "parâmetros e interoperabilidade; a deteção não certifica conformidade FIPS."
        )

    if finding.classical_risk == QuantumRiskLevel.CRITICAL:
        if name in HASH_OUTPUT_BITS or (signature is not None and signature[1] in {"MD5", "SHA-1"}):
            actions.append("Substituir o hash com colisões conhecidas por SHA-384 ou SHA-512 quando a resistência a colisões for necessária.")
        elif name in {"DES", "3DES"} or (finding.mode or (primitive.mode if primitive else None) or "").strip().upper() == "ECB":
            actions.append("Migrar a cifragem para uma construção autenticada, como AES-256-GCM, garantindo nonces únicos e gestão de chaves.")
        elif name.upper() in TLS_VERSION_ALIASES:
            actions.append("Desativar TLS 1.0/1.1 e rever suites e certificados ao adotar TLS 1.2/1.3.")
        else:
            actions.append("Corrigir o tamanho ou os parâmetros clássicos inadequados; aumentar uma chave RSA/EC não elimina o risco quântico.")
    elif finding.classical_risk == QuantumRiskLevel.MEDIUM:
        actions.append("Rever IV, autenticação e padding do modo CBC; considerar uma construção AEAD suportada.")

    if components is not None:
        actions.append(
            "Verificar troca de chaves e autenticação separadamente da cifra TLS; "
            "avaliar ML-KEM (FIPS 203) para estabelecimento de chaves e "
            "ML-DSA (FIPS 204) ou SLH-DSA (FIPS 205) para assinaturas, "
            "conforme o suporte do protocolo e dos fornecedores."
        )
    elif signature is not None or name in SHOR_VULNERABLE_ALGORITHMS:
        if signature is not None or name in {"ECDSA", "DSA", "Ed25519"} or finding.crypto_function in {CryptoFunction.SIGN, CryptoFunction.VERIFY}:
            actions.append("Planear migração de assinaturas para ML-DSA (FIPS 204) ou SLH-DSA (FIPS 205), verificando suporte de certificados, protocolos e fornecedores.")
        elif name in {"ECDH", "ECDHE", "DH", "X25519", "Curve25519"} or finding.crypto_function in {CryptoFunction.KEY_EXCHANGE, CryptoFunction.ENCRYPT, CryptoFunction.DECRYPT}:
            actions.append("Avaliar ML-KEM (FIPS 203) para estabelecer um segredo partilhado, combinado com cifragem simétrica autenticada; ML-KEM não cifra diretamente os dados.")
        else:
            actions.append("Confirmar o uso da chave: para assinaturas avaliar ML-DSA/SLH-DSA; para estabelecimento de chaves avaliar ML-KEM, com suporte do protocolo e fornecedor.")
    elif finding.quantum_risk == QuantumRiskLevel.MEDIUM:
        if name in SYMMETRIC_KEY_SIZES:
            actions.append("Avaliar AES-256 ou ChaCha20-Poly1305 com chave de 256 bits segundo o modelo conservador do projeto; verificar suporte e implementação.")
        elif name in HASH_OUTPUT_BITS:
            actions.append("Avaliar SHA-384 ou SHA-512 para atingir o limiar de colisões do modelo conservador do projeto; esta política não é uma exigência de migração do NIST.")

    if QuantumRiskLevel.UNKNOWN in {finding.quantum_risk, finding.classical_risk}:
        actions.append("Recolher os parâmetros e o contexto em falta antes de concluir segurança; unknown não significa safe.")
    if not actions:
        actions.append("Manter a seleção avaliada e verificar parâmetros, gestão de chaves e implementação; safe refere-se apenas aos critérios avaliados.")
    return " ".join(actions)


def enrich_finding(finding: CryptoFinding) -> CryptoFinding:
    """Recalcula os riscos numa cópia, mantendo os dados observados.

    Os níveis do motor substituem classificações anteriores, incluindo UNKNOWN
    quando as regras atuais não permitem uma conclusão. A evidência original
    mantém-se intacta; apenas a avaliação derivada deste módulo é substituída
    numa nova execução. Recomendações externas são preservadas; recomendações
    geradas por este motor são recalculadas quando os parâmetros mudam.
    """
    quantum_risk, quantum_reasoning = evaluate_quantum_risk(
        finding.algorithm_name, finding.key_size,
        mode=finding.mode,
        crypto_function=finding.crypto_function,
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
    # observação do ficheiro. As referências derivadas descrevem publicações
    # pertinentes; não acrescentam parâmetros nem demonstram conformidade.
    anchor = source_evidence[0]
    references = nist_references_for_algorithm(
        finding.algorithm_name, finding.crypto_function, finding.mode,
    )
    assessment = Evidence(
        file_path=anchor.file_path,
        line_number=anchor.line_number,
        packet_number=anchor.packet_number,
        json_path=anchor.json_path,
        rule_id=RISK_ASSESSMENT_RULE_ID,
        nist_standard="; ".join(references) or None,
        risk_reasoning=(
            f"Risco quântico ({quantum_risk.value}): {quantum_reasoning}\n"
            f"Risco clássico ({classical_risk.value}): {classical_reasoning}"
        ),
    )

    enriched.quantum_risk = quantum_risk
    enriched.classical_risk = classical_risk
    generated_before = any(
        evidence.rule_id == RISK_ASSESSMENT_RULE_ID
        and evidence.risk_reasoning is not None
        and _GENERATED_RECOMMENDATION_PREFIX in evidence.risk_reasoning
        and evidence.risk_reasoning.split(_GENERATED_RECOMMENDATION_PREFIX, 1)[1] == finding.recommendation
        for evidence in finding.evidence
    )
    if finding.recommendation is None or generated_before:
        enriched.recommendation = recommend_for_finding(enriched)
        assessment.risk_reasoning += _GENERATED_RECOMMENDATION_PREFIX + enriched.recommendation
    enriched.evidence = [*source_evidence, assessment]
    return enriched


def enrich_findings(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """Enriquece cada resultado preservando ordem, quantidade e originais."""
    return [enrich_finding(finding) for finding in findings]


# Compatibilidade com consumidores anteriores ao merge; uma única avaliação.
enrich_finding_risk = enrich_finding
