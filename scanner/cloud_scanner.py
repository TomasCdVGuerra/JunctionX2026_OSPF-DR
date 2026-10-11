"""AWS Cloud Criptographic Offline Scanner"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.models import AssetType, CryptoFinding, CryptoFunction, Evidence

KEY_SPECS: dict[str, tuple[str, int]] = {
    "RSA_2048": ("RSA", 2048),
    "RSA_3072": ("RSA", 3072),
    "RSA_4096": ("RSA", 4096),
    "ECC_NIST_P256": ("EC", 256),
    "ECC_NIST_P384": ("EC", 384),
    "ECC_NIST_P521": ("EC", 521),
    "ECC_SECG_P256K1": ("EC", 256),
}

ACM_EC_KEY_ALGORITHMS: dict[str, tuple[str, int]] = {
    "EC_prime256v1": ("EC", 256),
    "EC_secp384r1": ("EC", 384),
    "EC_secp521r1": ("EC", 521),
}

def load_json(filepath: Path) -> dict[str, Any]:
    """Lê um export JSON e garante que a raiz é um objeto."""
    try:
        with filepath.open(encoding="utf-8-sig") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON inválido em {filepath}, linha {exc.lineno}: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"Esperava um objeto JSON na raiz de {filepath}"
        )

    return data


def load_elb_policy_map(policy_file: Path) -> dict[str, Any]:
    """Carrega e valida a estrutura do mapa local de políticas ELB."""
    data = load_json(policy_file)
    policies = data.get("policies")

    if not isinstance(policies, dict):
        raise ValueError(f"Esperava um objeto policies em {policy_file}")

    for policy_name, policy in policies.items():
        if not policy_name.strip() or not isinstance(policy, dict):
            raise ValueError(
                f"Entrada de política inválida em {policy_file}: {policy_name}"
            )

        for field in ("protocols", "ciphers"):
            values = policy.get(field)

            if (
                not isinstance(values, list)
                or not values
                or not all(
                    isinstance(value, str) and value.strip()
                    for value in values
                )
            ):
                raise ValueError(
                    f"{field} deve ser uma lista não vazia de strings "
                    f"na política {policy_name}"
                )

        source_url = policy.get("source_url")

        if not isinstance(source_url, str) or not source_url.strip():
            raise ValueError(
                f"source_url ausente ou inválido na política {policy_name}"
            )

    return policies


def parse_acm_key_algorithm(key_algorithm: str | None) -> tuple[str, int | None]:
    """Interpreta o algoritmo da chave pública de um certificado."""
    if key_algorithm is None:
        return "unknown", None

    if not isinstance(key_algorithm, str) or not key_algorithm.strip():
        raise ValueError("KeyAlgorithm deve ser uma string não vazia")

    if key_algorithm in ACM_EC_KEY_ALGORITHMS:
        return ACM_EC_KEY_ALGORITHMS[key_algorithm]

    if key_algorithm in ("RSA_2048", "RSA_3072", "RSA_4096"):
        return KEY_SPECS[key_algorithm]

    return key_algorithm, None


def parse_key_spec(key_spec: str | None) -> tuple[str, int | None]:
    """Traduz uma especificação conhecida sem inventar parâmetros."""
    if key_spec is None:
        return "unknown", None

    if not isinstance(key_spec, str) or not key_spec.strip():
        raise ValueError("KeySpec deve ser uma string não vazia")

    return KEY_SPECS.get(key_spec, (key_spec, None))


def parse_kms_keys(json_data: dict[str, Any], filepath: Path) -> list[CryptoFinding]:
    """Extrai as chaves KMS e preserva a evidência de cada recurso."""
    keys = json_data.get("Keys")

    if not isinstance(keys, list):
        raise ValueError(f"Esperava uma lista Keys em {filepath}")

    findings: list[CryptoFinding] = []

    for index, key in enumerate(keys):
        location = f"$.Keys[{index}]"

        if not isinstance(key, dict):
            raise ValueError(
                f"Esperava um objeto em {location} de {filepath}"
            )

        key_spec = key.get("KeySpec")
        algorithm_name, key_size = parse_key_spec(key_spec)
        mode = None

        if key_spec == "SYMMETRIC_DEFAULT":
            algorithm_name, key_size, mode = parse_symmetric_default(json_data.get("Region"))

        evidence = Evidence(
            file_path=str(filepath),
            json_path=location,
            rule_id="AWS-KMS-KEY-SPEC",
            matched_snippet=json.dumps(key, ensure_ascii=False),
        )

        evidence_list = [evidence]

        if key_spec == "SYMMETRIC_DEFAULT" and key_size is not None:
            evidence_list.append(
                Evidence(
                    file_path=str(filepath),
                    json_path="$.Region",
                    rule_id="AWS-KMS-SYMMETRIC-REGION",
                    matched_snippet=json.dumps(json_data["Region"]),
                )
            )

        finding = CryptoFinding(
            algorithm_name=algorithm_name,
            asset_type=AssetType.KEY,
            source_type="cloud-posture",
            key_size=key_size,
            mode=mode,
            observation="configured",
            evidence=evidence_list,
        )

        findings.append(finding)

    return findings


def parse_acm_certificates(json_data: dict[str, Any], filepath: Path) -> list[CryptoFinding]:
    """Extrai a configuração da chave pública dos certificados ACM."""
    certificates = json_data.get("Certificates")

    if not isinstance(certificates, list):
        raise ValueError(f"Esperava uma lista Certificates em {filepath}")

    findings: list[CryptoFinding] = []

    for index, certificate in enumerate(certificates):
        location = f"$.Certificates[{index}]"

        if not isinstance(certificate, dict):
            raise ValueError(
                f"Esperava um objeto em {location} de {filepath}"
            )

        algorithm_name, key_size = parse_acm_key_algorithm(
            certificate.get("KeyAlgorithm")
        )

        evidence = Evidence(
            file_path=str(filepath),
            json_path=location,
            rule_id="AWS-ACM-PUBLIC-KEY",
            matched_snippet=json.dumps(certificate, ensure_ascii=False),
        )

        findings.append(
            CryptoFinding(
                algorithm_name=algorithm_name,
                asset_type=AssetType.CERTIFICATE,
                source_type="cloud-posture",
                key_size=key_size,
                observation="configured",
                evidence=[evidence],
            )
        )

        signature_algorithm = certificate.get("SignatureAlgorithm")

        if signature_algorithm is not None:
            if (
                not isinstance(signature_algorithm, str)
                or not signature_algorithm.strip()
            ):
                raise ValueError(
                    f"SignatureAlgorithm inválido em {location} de {filepath}"
                )

            signature_evidence = Evidence(
                file_path=str(filepath),
                json_path=f"{location}.SignatureAlgorithm",
                rule_id="AWS-ACM-SIGNATURE",
                matched_snippet=json.dumps(certificate, ensure_ascii=False),
            )

            findings.append(
                CryptoFinding(
                    algorithm_name=signature_algorithm,
                    asset_type=AssetType.ALGORITHM,
                    source_type="cloud-posture",
                    crypto_function=CryptoFunction.SIGN,
                    observation="configured",
                    evidence=[signature_evidence],
                )
            )

    return findings


def parse_symmetric_default(region: str | None,) -> tuple[str, int | None, str | None]:
    """Resolve a configuração simétrica KMS quando existe região."""
    if region is None:
        return "SYMMETRIC_DEFAULT", None, None

    if not isinstance(region, str) or not region.strip():
        raise ValueError("Region deve ser uma string não vazia")

    if region.startswith("cn-"):
        return "SM4", 128, None

    return "AES", 256, "GCM"


def expand_elb_policy(listener: dict[str, Any], filepath: Path, location: str, policy_map: dict[str, Any], policy_file: Path) -> list[CryptoFinding]:
    """Extrai protocolos e cipher suites permitidos pela política ELB."""
    if listener.get("Protocol") not in ("HTTPS", "TLS"):
        return []

    policy_name = listener.get("SslPolicy")

    if policy_name is None:
        return []

    if not isinstance(policy_name, str) or not policy_name.strip():
        raise ValueError(f"SslPolicy inválido em {location} de {filepath}")

    policy = policy_map.get(policy_name)

    if policy is None:
        return []

    findings: list[CryptoFinding] = []

    for protocol in policy["protocols"]:
        findings.append(
            CryptoFinding(
                algorithm_name=protocol,
                asset_type=AssetType.PROTOCOL,
                source_type="cloud-posture",
                protocol=protocol,
                observation="configured",
                evidence=[
                    Evidence(
                        file_path=str(filepath),
                        json_path=f"{location}.SslPolicy",
                        rule_id="AWS-ELB-POLICY-REFERENCE",
                        matched_snippet=json.dumps(
                            listener, ensure_ascii=False
                        ),
                    ),
                    Evidence(
                        file_path=str(policy_file),
                        json_path=(
                            f"$.policies[{json.dumps(policy_name)}].protocols"
                        ),
                        rule_id="AWS-ELB-POLICY-PROTOCOL",
                        matched_snippet=json.dumps(
                            policy, ensure_ascii=False
                        ),
                    ),
                ],
            )
        )

    for cipher_index, cipher in enumerate(policy["ciphers"]):
        findings.append(
            CryptoFinding(
                algorithm_name=cipher,
                asset_type=AssetType.ALGORITHM,
                source_type="cloud-posture",
                protocol="TLS",
                observation="configured",
                evidence=[
                    Evidence(
                        file_path=str(filepath),
                        json_path=f"{location}.SslPolicy",
                        rule_id="AWS-ELB-POLICY-REFERENCE",
                        matched_snippet=json.dumps(
                            listener, ensure_ascii=False
                        ),
                    ),
                    Evidence(
                        file_path=str(policy_file),
                        json_path=(
                            f"$.policies[{json.dumps(policy_name)}]"
                            f".ciphers[{cipher_index}]"
                        ),
                        rule_id="AWS-ELB-POLICY-CIPHER",
                        matched_snippet=json.dumps(
                            policy, ensure_ascii=False
                        ),
                    ),
                ],
            )
        )

    return findings


def parse_load_balancers(json_data: dict[str, Any], filepath: Path, policy_map: dict[str, Any] | None = None, policy_file: Path | None = None) -> list[CryptoFinding]:
    """Extrai os protocolos configurados nos listeners ELB."""
    if policy_map is not None and policy_file is None:
        raise ValueError(
            "policy_file é obrigatório quando forneces policy_map"
        )
    
    load_balancers = json_data.get("LoadBalancers")

    if not isinstance(load_balancers, list):
        raise ValueError(f"Esperava uma lista LoadBalancers em {filepath}")

    findings: list[CryptoFinding] = []

    for lb_index, load_balancer in enumerate(load_balancers):
        lb_location = f"$.LoadBalancers[{lb_index}]"

        if not isinstance(load_balancer, dict):
            raise ValueError(
                f"Esperava um objeto em {lb_location} de {filepath}"
            )

        listeners = load_balancer.get("Listeners")

        if not isinstance(listeners, list):
            raise ValueError(
                f"Esperava uma lista Listeners em {lb_location} de {filepath}"
            )

        for listener_index, listener in enumerate(listeners):
            location = f"{lb_location}.Listeners[{listener_index}]"

            if not isinstance(listener, dict):
                raise ValueError(
                    f"Esperava um objeto em {location} de {filepath}"
                )

            protocol = listener.get("Protocol")

            if protocol is not None and (
                not isinstance(protocol, str)
                or not protocol.strip()
            ):
                raise ValueError(
                    f"Protocol inválido em {location} de {filepath}"
                )

            evidence = Evidence(
                file_path=str(filepath),
                json_path=location,
                rule_id="AWS-ELB-LISTENER-PROTOCOL",
                matched_snippet=json.dumps(listener, ensure_ascii=False),
            )

            findings.append(
                CryptoFinding(
                    algorithm_name=protocol or "unknown",
                    asset_type=AssetType.PROTOCOL,
                    source_type="cloud-posture",
                    protocol=protocol,
                    observation="configured",
                    evidence=[evidence],
                )
            )

            if policy_map is not None and policy_file is not None:
                findings.extend(
                    expand_elb_policy(
                        listener,
                        filepath,
                        location,
                        policy_map,
                        policy_file,
                    )
                )

    return findings


def scan(path: Path) -> list[CryptoFinding]:
    """Analisa um ficheiro de configuração cloud suportado."""
    if path.is_dir():
        raise ValueError(
            "Esperava um ficheiro JSON cloud, mas recebi uma pasta"
        )

    json_data = load_json(path)

    if "Keys" in json_data:
        return parse_kms_keys(json_data, path)

    if "Certificates" in json_data:
        return parse_acm_certificates(json_data, path)

    if "LoadBalancers" in json_data:
        return parse_load_balancers(json_data, path)

    raise ValueError(f"Formato cloud ainda não suportado em {path}")
