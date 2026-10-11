"""Offline TLS/SSH registries and network evidence helpers.

Mappings are finite: unknown identifiers remain unknown.
Risk evaluation belongs to the protocol analyzers.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from scanner.models import CryptoFunction, Evidence

Observation = Literal[
    "declared",
    "configured",
    "advertised",
    "negotiated",
    "observed",
]


@dataclass(frozen=True)
class Primitive:
    """Representa um componente criptografico."""

    algorithm_name: str
    crypto_function: CryptoFunction
    key_size: int | None = None
    mode: str | None = None
    padding: str | None = None


@dataclass(frozen=True)
class CipherSuite:
    """Representa os componentes associados a uma cipher suite TLS."""

    name: str
    key_exchange: str | None
    authentication: str | None
    cipher: str
    key_size: int | None
    mode: str | None
    hash_name: str
    tls13: bool = False


def _suite(
    name: str,
    kex: str | None,
    auth: str | None,
    cipher: str,
    bits: int | None,
    mode: str | None,
    digest: str,
    tls13: bool = False,
) -> CipherSuite:
    return CipherSuite(
        name=name,
        key_exchange=kex,
        authentication=auth,
        cipher=cipher,
        key_size=bits,
        mode=mode,
        hash_name=digest,
        tls13=tls13,
    )


# Identificadores numericos das cipher suites.
# Suites TLS 1.3 nao determinam autenticacao ou troca de chaves.
CIPHER_SUITES: dict[int, CipherSuite] = {
    0x0001: _suite(
        "TLS_RSA_WITH_NULL_MD5",
        "RSA", None, "NULL", None, None, "MD5",
    ),
    0x0002: _suite(
        "TLS_RSA_WITH_NULL_SHA",
        "RSA", None, "NULL", None, None, "SHA-1",
    ),
    0x0004: _suite(
        "TLS_RSA_WITH_RC4_128_MD5",
        "RSA", None, "RC4", 128, None, "MD5",
    ),
    0x0005: _suite(
        "TLS_RSA_WITH_RC4_128_SHA",
        "RSA", None, "RC4", 128, None, "SHA-1",
    ),
    0x0009: _suite(
        "TLS_RSA_WITH_DES_CBC_SHA",
        "RSA", None, "DES", 56, "CBC", "SHA-1",
    ),
    0x000A: _suite(
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "RSA", None, "3DES", 168, "CBC", "SHA-1",
    ),
    0x0016: _suite(
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "DHE", "RSA", "3DES", 168, "CBC", "SHA-1",
    ),
    0x002F: _suite(
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "RSA", None, "AES", 128, "CBC", "SHA-1",
    ),
    0x0033: _suite(
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "DHE", "RSA", "AES", 128, "CBC", "SHA-1",
    ),
    0x0035: _suite(
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "RSA", None, "AES", 256, "CBC", "SHA-1",
    ),
    0x0039: _suite(
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "DHE", "RSA", "AES", 256, "CBC", "SHA-1",
    ),
    0x003C: _suite(
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "RSA", None, "AES", 128, "CBC", "SHA-256",
    ),
    0x003D: _suite(
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "RSA", None, "AES", 256, "CBC", "SHA-256",
    ),
    0x0067: _suite(
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "DHE", "RSA", "AES", 128, "CBC", "SHA-256",
    ),
    0x006B: _suite(
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "DHE", "RSA", "AES", 256, "CBC", "SHA-256",
    ),
    0x009C: _suite(
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "RSA", None, "AES", 128, "GCM", "SHA-256",
    ),
    0x009D: _suite(
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "RSA", None, "AES", 256, "GCM", "SHA-384",
    ),
    0x009E: _suite(
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "DHE", "RSA", "AES", 128, "GCM", "SHA-256",
    ),
    0x009F: _suite(
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "DHE", "RSA", "AES", 256, "GCM", "SHA-384",
    ),
    0xC009: _suite(
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "ECDHE", "ECDSA", "AES", 128, "CBC", "SHA-1",
    ),
    0xC00A: _suite(
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "ECDHE", "ECDSA", "AES", 256, "CBC", "SHA-1",
    ),
    0xC013: _suite(
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "ECDHE", "RSA", "AES", 128, "CBC", "SHA-1",
    ),
    0xC014: _suite(
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "ECDHE", "RSA", "AES", 256, "CBC", "SHA-1",
    ),
    0xC023: _suite(
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "ECDHE", "ECDSA", "AES", 128, "CBC", "SHA-256",
    ),
    0xC024: _suite(
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "ECDHE", "ECDSA", "AES", 256, "CBC", "SHA-384",
    ),
    0xC027: _suite(
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "ECDHE", "RSA", "AES", 128, "CBC", "SHA-256",
    ),
    0xC028: _suite(
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "ECDHE", "RSA", "AES", 256, "CBC", "SHA-384",
    ),
    0xC02B: _suite(
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "ECDHE", "ECDSA", "AES", 128, "GCM", "SHA-256",
    ),
    0xC02C: _suite(
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "ECDHE", "ECDSA", "AES", 256, "GCM", "SHA-384",
    ),
    0xC02F: _suite(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE", "RSA", "AES", 128, "GCM", "SHA-256",
    ),
    0xC030: _suite(
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "ECDHE", "RSA", "AES", 256, "GCM", "SHA-384",
    ),
    0xCCA8: _suite(
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "ECDHE", "RSA", "ChaCha20-Poly1305", 256, None, "SHA-256",
    ),
    0xCCA9: _suite(
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "ECDHE", "ECDSA", "ChaCha20-Poly1305", 256, None, "SHA-256",
    ),
    0xCCAA: _suite(
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "DHE", "RSA", "ChaCha20-Poly1305", 256, None, "SHA-256",
    ),
    0x1301: _suite(
        "TLS_AES_128_GCM_SHA256",
        None, None, "AES", 128, "GCM", "SHA-256", True,
    ),
    0x1302: _suite(
        "TLS_AES_256_GCM_SHA384",
        None, None, "AES", 256, "GCM", "SHA-384", True,
    ),
    0x1303: _suite(
        "TLS_CHACHA20_POLY1305_SHA256",
        None, None, "ChaCha20-Poly1305", 256, None, "SHA-256", True,
    ),
    0x1304: _suite(
        "TLS_AES_128_CCM_SHA256",
        None, None, "AES", 128, "CCM", "SHA-256", True,
    ),
    0x1305: _suite(
        "TLS_AES_128_CCM_8_SHA256",
        None, None, "AES", 128, "CCM_8", "SHA-256", True,
    ),
}


# Grupos de troca de chaves.
# Preservar o nome completo das construcoes hibridas.
GROUPS: dict[int, Primitive] = {
    23: Primitive("ECDHE-secp256r1", CryptoFunction.KEY_EXCHANGE, 256),
    24: Primitive("ECDHE-secp384r1", CryptoFunction.KEY_EXCHANGE, 384),
    25: Primitive("ECDHE-secp521r1", CryptoFunction.KEY_EXCHANGE, 521),
    29: Primitive("ECDHE-X25519", CryptoFunction.KEY_EXCHANGE, 255),
    30: Primitive("ECDHE-X448", CryptoFunction.KEY_EXCHANGE, 448),
    256: Primitive("DHE-ffdhe2048", CryptoFunction.KEY_EXCHANGE, 2048),
    257: Primitive("DHE-ffdhe3072", CryptoFunction.KEY_EXCHANGE, 3072),
    258: Primitive("DHE-ffdhe4096", CryptoFunction.KEY_EXCHANGE, 4096),
    259: Primitive("DHE-ffdhe6144", CryptoFunction.KEY_EXCHANGE, 6144),
    260: Primitive("DHE-ffdhe8192", CryptoFunction.KEY_EXCHANGE, 8192),
    512: Primitive("ML-KEM-512", CryptoFunction.KEY_EXCHANGE),
    513: Primitive("ML-KEM-768", CryptoFunction.KEY_EXCHANGE),
    514: Primitive("ML-KEM-1024", CryptoFunction.KEY_EXCHANGE),
    4587: Primitive("SecP256r1MLKEM768", CryptoFunction.KEY_EXCHANGE),
    4588: Primitive("X25519MLKEM768", CryptoFunction.KEY_EXCHANGE),
    4589: Primitive("SecP384r1MLKEM1024", CryptoFunction.KEY_EXCHANGE),
    25497: Primitive("X25519Kyber768Draft00", CryptoFunction.KEY_EXCHANGE),
    25498: Primitive("SecP256r1Kyber768Draft00", CryptoFunction.KEY_EXCHANGE),
}


# Esquemas de assinatura e respetivos componentes.
SIGNATURE_SCHEMES: dict[int, tuple[Primitive, ...]] = {}

for _prefix, _name, _padding in (
    (1, "RSA", "PKCS1v15"),
    (2, "DSA", None),
    (3, "ECDSA", None),
):
    for _hash_id, _hash in (
        (2, "SHA-1"),
        (4, "SHA-256"),
        (5, "SHA-384"),
        (6, "SHA-512"),
    ):
        SIGNATURE_SCHEMES[(_hash_id << 8) | _prefix] = (
            Primitive(_name, CryptoFunction.SIGN, padding=_padding),
            Primitive(_hash, CryptoFunction.DIGEST),
        )

for _identifier, _hash in (
    (0x0804, "SHA-256"),
    (0x0805, "SHA-384"),
    (0x0806, "SHA-512"),
    (0x0809, "SHA-256"),
    (0x080A, "SHA-384"),
    (0x080B, "SHA-512"),
):
    SIGNATURE_SCHEMES[_identifier] = (
        Primitive("RSA", CryptoFunction.SIGN, padding="PSS"),
        Primitive(_hash, CryptoFunction.DIGEST),
    )

SIGNATURE_SCHEMES[0x0807] = (
    Primitive("Ed25519", CryptoFunction.SIGN, 255),
)
SIGNATURE_SCHEMES[0x0808] = (
    Primitive("Ed448", CryptoFunction.SIGN, 448),
)


def parse_identifier(value: str | int | None) -> int | None:
    """Interpretar identificadores de 16 bits em decimal ou hexadecimal."""

    # bool e uma subclasse de int.
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, int):
        identifier = value

    elif isinstance(value, str):
        raw = value.strip().lower()

        if re.fullmatch(r"0x[0-9a-f]+", raw):
            identifier = int(raw, 16)
        elif re.fullmatch(r"[0-9]+", raw):
            identifier = int(raw, 10)
        elif re.fullmatch(r"[0-9a-f]+", raw):
            # Hexadecimal sem prefixo quando existem letras.
            identifier = int(raw, 16)
        else:
            return None
    else:
        return None

    return identifier if 0 <= identifier <= 0xFFFF else None


def is_grease(identifier: int | None) -> bool:
    """Reconhecer os identificadores GREASE de 16 bits."""

    if isinstance(identifier, bool) or not isinstance(identifier, int):
        return False

    if not 0 <= identifier <= 0xFFFF:
        return False

    high_byte = identifier >> 8
    low_byte = identifier & 0xFF

    return high_byte == low_byte and (low_byte & 0x0F) == 0x0A


def identifier_label(value: str | int) -> str:
    """Apresentar identificadores validos em hexadecimal uniforme."""

    parsed = parse_identifier(value)
    return f"0x{parsed:04x}" if parsed is not None else str(value)


class CipherSuiteVersionError(ValueError):
    """A familia da suite nao corresponde a versao TLS indicada."""


def cipher_primitives(
    suite: CipherSuite,
    version: str | None,
) -> list[Primitive]:
    """Decompor uma cipher suite nos componentes criptograficos."""

    # All SHA-2 suites in this finite registry require at least TLS 1.2
    # (RFC 5246, 5288, 5289 and 7905), including the CBC suites.
    if ((suite.tls13 and version in {"SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"})
            or (not suite.tls13 and version == "TLS 1.3")
            or (suite.hash_name in {"SHA-256", "SHA-384"}
                and version in {"SSL 3.0", "TLS 1.0", "TLS 1.1"})):
        raise CipherSuiteVersionError(f"{suite.name} is incompatible with {version}")

    primitives: list[Primitive] = []

    if suite.key_exchange:
        primitives.append(
            Primitive(suite.key_exchange, CryptoFunction.KEY_EXCHANGE)
        )

    if suite.authentication:
        primitives.append(
            Primitive(suite.authentication, CryptoFunction.SIGN)
        )

    primitives.append(
        Primitive(
            suite.cipher,
            CryptoFunction.ENCRYPT,
            suite.key_size,
            suite.mode,
        )
    )
    primitives.append(
        Primitive(suite.hash_name, CryptoFunction.DIGEST)
    )

    if suite.tls13:
        primitives.append(
            Primitive(
                f"HKDF-{suite.hash_name}",
                CryptoFunction.KDF,
            )
        )
    else:
        if suite.mode == "CBC" or suite.cipher in {"RC4", "NULL"}:
            # SSL 3.0 uses its own keyed MAC, not TLS's HMAC construction
            # (RFC 6101 section 5.2.3.1).
            mac_prefix = "SSL3-MAC" if version == "SSL 3.0" else "HMAC"
            primitives.append(
                Primitive(
                    f"{mac_prefix}-{suite.hash_name}",
                    CryptoFunction.MAC,
                )
            )

        if version == "TLS 1.2":
            # SHA-1 no nome de suites antigas identifica o MAC.
            # A PRF predefinida de TLS 1.2 utiliza SHA-256.
            prf_hash = (
                suite.hash_name
                if suite.hash_name in {"SHA-256", "SHA-384"}
                else "SHA-256"
            )
            primitives.append(
                Primitive(
                    f"TLS-PRF-{prf_hash}",
                    CryptoFunction.KDF,
                )
            )

        elif version in {"TLS 1.0", "TLS 1.1"}:
            primitives.append(
                Primitive(
                    "TLS-PRF-MD5-SHA-1",
                    CryptoFunction.KDF,
                )
            )

    return primitives


SSH_KEX = {
    "curve25519-sha256": Primitive("ECDHE-X25519", CryptoFunction.KEY_EXCHANGE, 255),
    "curve25519-sha256@libssh.org": Primitive("ECDHE-X25519", CryptoFunction.KEY_EXCHANGE, 255),
    "ecdh-sha2-nistp256": Primitive("ECDHE-secp256r1", CryptoFunction.KEY_EXCHANGE, 256),
    "ecdh-sha2-nistp384": Primitive("ECDHE-secp384r1", CryptoFunction.KEY_EXCHANGE, 384),
    "ecdh-sha2-nistp521": Primitive("ECDHE-secp521r1", CryptoFunction.KEY_EXCHANGE, 521),
    "diffie-hellman-group1-sha1": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 1024),
    "diffie-hellman-group14-sha1": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 2048),
    "diffie-hellman-group14-sha256": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 2048),
    "diffie-hellman-group16-sha512": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 4096),
    "diffie-hellman-group18-sha512": Primitive("DHE", CryptoFunction.KEY_EXCHANGE, 8192),
    "diffie-hellman-group-exchange-sha1": Primitive("DHE", CryptoFunction.KEY_EXCHANGE),
    "diffie-hellman-group-exchange-sha256": Primitive("DHE", CryptoFunction.KEY_EXCHANGE),
    "mlkem768x25519-sha256": Primitive("MLKEM768X25519", CryptoFunction.KEY_EXCHANGE),
    "sntrup761x25519-sha512": Primitive("SNTRUP761X25519", CryptoFunction.KEY_EXCHANGE),
    "sntrup761x25519-sha512@openssh.com": Primitive("SNTRUP761X25519", CryptoFunction.KEY_EXCHANGE),
}
SSH_HOST = {
    name: Primitive("RSA", CryptoFunction.SIGN, padding="PKCS1v15")
    for name in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512")
}
SSH_HOST.update({
    "ssh-dss": Primitive("DSA", CryptoFunction.SIGN),
    "ssh-ed25519": Primitive("Ed25519", CryptoFunction.SIGN, 255),
    **{name: Primitive("ECDSA", CryptoFunction.SIGN, bits)
       for name, bits in (("ecdsa-sha2-nistp256", 256), ("ecdsa-sha2-nistp384", 384),
                          ("ecdsa-sha2-nistp521", 521))},
})
SSH_CIPHERS = {
    f"aes{bits}-{mode}": Primitive("AES", CryptoFunction.ENCRYPT, bits, mode.upper())
    for bits in (128, 192, 256) for mode in ("cbc", "ctr")
}
SSH_CIPHERS.update({
    **{f"aes{bits}-gcm@openssh.com": Primitive("AES", CryptoFunction.ENCRYPT, bits, "GCM")
       for bits in (128, 256)},
    "3des-cbc": Primitive("3DES", CryptoFunction.ENCRYPT, 168, "CBC"),
    # 256 describes the underlying ChaCha key, not all SSH keying material.
    "chacha20-poly1305@openssh.com": Primitive("ChaCha20-Poly1305", CryptoFunction.ENCRYPT, 256),
    "none": Primitive("NULL", CryptoFunction.ENCRYPT),
})
SSH_MACS = {
    wire + suffix: Primitive(name, CryptoFunction.MAC)
    for wire, name in (("hmac-sha1", "HMAC-SHA-1"), ("hmac-sha2-256", "HMAC-SHA-256"),
                       ("hmac-sha2-512", "HMAC-SHA-512"), ("hmac-md5", "HMAC-MD5"))
    for suffix in ("", "-etm@openssh.com")
}
SSH_FIELDS = (
    ("kex_algorithms", SSH_KEX, CryptoFunction.KEY_EXCHANGE),
    ("server_host_key_algorithms", SSH_HOST, CryptoFunction.SIGN),
    ("encryption_client_to_server", SSH_CIPHERS, CryptoFunction.ENCRYPT),
    ("encryption_server_to_client", SSH_CIPHERS, CryptoFunction.ENCRYPT),
    ("mac_client_to_server", SSH_MACS, CryptoFunction.MAC),
    ("mac_server_to_client", SSH_MACS, CryptoFunction.MAC),
)
SSH_MARKERS = {"ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"}


_NETWORK_CONTEXT_FIELDS = (
    "packet_number", "stream_id", "timestamp", "source_ip", "destination_ip",
    "source_port", "destination_port", "server_name", "handshake_type",
    "tls_version", "protocol_banner", "is_server", "role_source",
    "protocol", "http_method", "http_host", "cipher_suite", "cipher_suite_name",
    "group", "signature_scheme", "ssh_field", "ssh_algorithm", "mapping_status",
)


def network_context(entry: dict) -> dict:
    """Selecionar contexto permitido e remover credenciais do host HTTP."""
    details = {key: entry[key] for key in _NETWORK_CONTEXT_FIELDS
               if entry.get(key) is not None}
    host = details.get("http_host")
    if isinstance(host, str):
        host = host.strip().rsplit("@", 1)[-1]
        if host:
            details["http_host"] = host
        else:
            details.pop("http_host", None)
    elif host is not None:
        details.pop("http_host", None)
    return details


def network_evidence(
    path: Path,
    entry: dict,
    rule_id: str,
    *,
    reasoning: str | None = None,
) -> Evidence:
    """Construir evidencia sem inventar numeros de pacote."""

    raw_packet = entry.get("packet_number")
    packet = None

    if isinstance(raw_packet, int) and not isinstance(raw_packet, bool):
        packet = raw_packet

    elif isinstance(raw_packet, str):
        normalized = raw_packet.strip()
        if re.fullmatch(r"[0-9]+", normalized):
            packet = int(normalized)

    if packet is not None and packet < 1:
        packet = None

    details = network_context(entry)
    details.pop("packet_number", None)
    if packet is not None:
        details["packet_number"] = packet
    snippet = json.dumps(
        details,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )

    return Evidence(
        file_path=str(path),
        packet_number=packet,
        matched_snippet=snippet,
        rule_id=rule_id,
        risk_reasoning=reasoning,
    )
