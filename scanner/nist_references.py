"""Referências técnicas aplicáveis; não representam certificação ou conformidade.

Publicações: https://csrc.nist.gov/publications
O mapeamento descreve a primitiva e o uso reconhecidos, sem preencher parâmetros
em falta nem alterar a classificação de risco.
"""
from scanner.algorithms import (
    normalise, parse_hash_construction, parse_legacy_cipher_suite,
    parse_pqc_algorithm, parse_primitive_name, parse_signature_algorithm,
    parse_tls13_cipher_suite,
)
from scanner.models import CryptoFunction


def nist_references_for_algorithm(
    algorithm_name: str,
    crypto_function: CryptoFunction = CryptoFunction.UNKNOWN,
    mode: str | None = None,
) -> list[str]:
    """Decompõe nomes reconhecidos e devolve referências únicas em ordem estável."""
    pqc = parse_pqc_algorithm(algorithm_name)
    if pqc is not None:
        return [pqc.standard]

    # Exact network names only. A component reference does not standardize
    # the whole hybrid or establish conformance of a captured implementation.
    if algorithm_name in {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768X25519"}:
        return ["FIPS 203 (ML-KEM component)"]
    if algorithm_name in {"ECDHE-secp256r1", "ECDHE-secp384r1", "ECDHE-secp521r1"}:
        return ["SP 800-56A Rev. 3", "SP 800-186"]
    if algorithm_name in {"DHE", "DHE-ffdhe2048", "DHE-ffdhe3072", "DHE-ffdhe4096", "DHE-ffdhe6144", "DHE-ffdhe8192"}:
        return ["SP 800-56A Rev. 3"]
    if algorithm_name in {"HKDF-SHA-256", "HKDF-SHA-384", "HKDF-SHA-512"}:
        return ["SP 800-56C Rev. 2", "FIPS 180-4"]
    if algorithm_name in {"TLS-PRF-SHA-256", "TLS-PRF-SHA-384", "TLS-PRF-MD5-SHA-1"}:
        return ["SP 800-135 Rev. 1", "SP 800-52 Rev. 2", "FIPS 180-4"]
    if normalise(algorithm_name) == "3DES":
        # Transition/deprecation guidance, not an approval for new protection.
        return ["SP 800-131A Rev. 2"]

    suite = parse_tls13_cipher_suite(algorithm_name) or parse_legacy_cipher_suite(algorithm_name)
    if suite is not None:
        refs = ["SP 800-52 Rev. 2"]
        refs += nist_references_for_algorithm(suite.symmetric_algorithm, mode=suite.mode)
        refs += nist_references_for_algorithm(suite.hash_algorithm, CryptoFunction.DIGEST)
        if suite.key_exchange:
            refs += nist_references_for_algorithm(suite.key_exchange, CryptoFunction.KEY_EXCHANGE)
        if suite.authentication:
            refs += nist_references_for_algorithm(suite.authentication, CryptoFunction.SIGN)
        return list(dict.fromkeys(refs))

    signature = parse_signature_algorithm(algorithm_name)
    if signature is not None:
        family, digest = signature
        return list(dict.fromkeys(
            nist_references_for_algorithm(family, CryptoFunction.SIGN)
            + nist_references_for_algorithm(digest, CryptoFunction.DIGEST)
        ))
    construction = parse_hash_construction(algorithm_name)
    if construction is not None:
        # A referência ao hash não avalia a construção MAC/KDF nem a sua entropia.
        return nist_references_for_algorithm(construction[1], CryptoFunction.DIGEST)

    primitive = parse_primitive_name(algorithm_name)
    name = primitive.family if primitive else normalise(algorithm_name)
    actual_mode = mode or (primitive.mode if primitive else None)
    if name == "AES":
        refs = ["FIPS 197"]
        if actual_mode and actual_mode.upper() == "GCM":
            refs.append("SP 800-38D")
        elif actual_mode and actual_mode.upper() in {"ECB", "CBC", "CTR", "CFB", "OFB"}:
            refs.append("SP 800-38A")
        return refs
    if name in {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}:
        return ["FIPS 180-4"]
    if name == "RSA":
        refs = ["SP 800-131A Rev. 2"]
        if crypto_function in {CryptoFunction.SIGN, CryptoFunction.VERIFY}:
            refs.append("FIPS 186-5")
        elif crypto_function == CryptoFunction.KEY_EXCHANGE:
            refs.append("SP 800-56B Rev. 2")
        return refs
    if name in {"EC", "ECDSA", "Ed25519"}:
        refs = ["SP 800-186"]
        if name in {"ECDSA", "Ed25519"} or crypto_function in {CryptoFunction.SIGN, CryptoFunction.VERIFY}:
            refs.append("FIPS 186-5")
        return refs
    if name in {"ECDH", "ECDHE", "DH"}:
        return ["SP 800-56A Rev. 3"]
    if algorithm_name.upper().replace(" ", "") in {
        "TLS", "TLSV1", "TLSV1.0", "TLSV1.1", "TLSV1.2", "TLSV1.3",
        "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3",
    }:
        return ["SP 800-52 Rev. 2"]
    return []


def collect_nist_references(evidence: list) -> str | None:
    """Agrega referências da descoberta e avaliação, ignorando sentinelas antigas."""
    refs = []
    for item in evidence:
        value = item.get("nist_standard") if isinstance(item, dict) else getattr(item, "nist_standard", None)
        if not isinstance(value, str):
            continue
        for ref in value.split(";"):
            ref = ref.strip()
            if ref and ref.lower() not in {"none", "unknown", "n/a"} and ref not in refs:
                refs.append(ref)
    return "; ".join(refs) or None
