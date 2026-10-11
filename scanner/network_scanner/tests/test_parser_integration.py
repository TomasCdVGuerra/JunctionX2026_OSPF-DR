"""Integration tests exercise actual TShark reads of capture formats and frames."""
from __future__ import annotations

import json
import logging
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from scanner.models import CryptoFinding, CryptoFunction, QuantumRiskLevel
from scanner.network_scanner.parser import tshark_parser as parser

CAPTURE = Path(__file__).resolve().parents[3] / "support-materials" / "network-capture" / "network.pcap"


@pytest.fixture(scope="module")
def tshark() -> str:
    try:
        return parser.find_tshark_binary()
    except parser.PcapParserError as exc:
        pytest.skip(f"TShark unavailable: {exc}")


@pytest.fixture(scope="module")
def captured(tshark) -> dict:
    assert CAPTURE.is_file(), f"Required challenge capture is missing: {CAPTURE}"
    return parser.parse_network_pcap(str(CAPTURE))


def test_real_capture_metadata_is_traceable_and_client_hello_never_selects(captured):
    tls, ssh, cleartext = (captured[name] for name in ("tls_sessions", "ssh_sessions", "cleartext_traffic"))
    assert (len(tls), len(ssh), len(cleartext)) == (194, 96, 28)
    assert captured["pcap_file"] == str(CAPTURE)
    for entries in (tls, ssh, cleartext):
        assert len({entry["packet_number"] for entry in entries}) == len(entries)
        assert all(isinstance(entry["packet_number"], int) and entry["packet_number"] > 0 for entry in entries)
        assert all(entry["stream_id"] is not None and entry["timestamp"] for entry in entries)
        assert all(entry["source_ip"] and entry["destination_ip"] for entry in entries)
    clients = [entry for entry in tls if entry["handshake_type"] == "Client Hello"]
    servers = [entry for entry in tls if entry["handshake_type"] == "Server Hello"]
    assert clients and servers
    assert all(entry["selected_cipher"] is None and entry["selected_group"] is None for entry in clients)
    assert all(entry["selected_cipher"] in entry["cipher_suites"] for entry in servers)
    frame23 = next(entry for entry in clients if entry["packet_number"] == 23)
    assert frame23["server_name"] == "app16.lab"
    assert frame23["tls_version"] == "TLS 1.3"
    assert frame23["cipher_suites"] == ["0x1301", "0x1302", "0x1303"]


def test_real_hybrid_key_share_is_selected_by_server_and_only_advertised_by_client(captured):
    tls = {entry["packet_number"]: entry for entry in captured["tls_sessions"]}
    client, server = tls[404], tls[406]
    assert client["stream_id"] == server["stream_id"] == "26"
    assert client["handshake_type"] == "Client Hello"
    assert client["selected_group"] is None
    assert "4588" in client["key_share_groups"]  # 0x11ec: X25519MLKEM768
    assert server["handshake_type"] == "Server Hello"
    assert server["selected_group"] == "4588"
    assert server["selected_cipher"] == "0x1302"
    assert server["tls_version"] == "TLS 1.3"
    assert (server["source_ip"], server["destination_ip"]) == (client["destination_ip"], client["source_ip"])


def test_real_two_server_hellos_in_one_frame_are_rejected(tshark, tmp_path, caplog):
    """Duplicate one captured ServerHello inside one TLS record/TCP frame."""
    raw = CAPTURE.read_bytes()
    assert raw[:4] == b"\xd4\xc3\xb2\xa1"  # The challenge capture is little-endian Ethernet PCAP.
    offset = 24
    for _ in range(25):  # Frame 25 contains one complete TLS 1.3 ServerHello.
        seconds, fractional, captured_length, _ = struct.unpack_from("<IIII", raw, offset)
        frame = raw[offset + 16:offset + 16 + captured_length]
        offset += 16 + captured_length
    assert frame[12:14] == b"\x08\x00" and frame[23] == 6  # IPv4/TCP.
    ip_offset = 14
    ip_length = (frame[ip_offset] & 0x0F) * 4
    tcp_offset = ip_offset + ip_length
    tcp_length = (frame[tcp_offset + 12] >> 4) * 4
    payload_offset = tcp_offset + tcp_length
    record = frame[payload_offset:ip_offset + struct.unpack_from("!H", frame, ip_offset + 2)[0]]
    assert record[0] == 22 and record[5] == 2  # TLS handshake record, ServerHello message.
    assert len(record) == 5 + int.from_bytes(record[3:5], "big")
    assert len(record[5:]) == 4 + int.from_bytes(record[6:9], "big")
    handshakes = record[5:] * 2
    payload = record[:3] + struct.pack("!H", len(handshakes)) + handshakes
    doubled = bytearray(frame[:payload_offset] + payload)
    struct.pack_into("!H", doubled, ip_offset + 2, len(doubled) - ip_offset)

    def checksum(data):
        padded = data + bytes(len(data) % 2)
        total = sum(struct.unpack(f"!{len(padded) // 2}H", padded))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    # Length changes require fresh IP and TCP checksums, including the pseudo-header.
    struct.pack_into("!H", doubled, ip_offset + 10, 0)
    struct.pack_into("!H", doubled, ip_offset + 10, checksum(bytes(doubled[ip_offset:tcp_offset])))
    struct.pack_into("!H", doubled, tcp_offset + 16, 0)
    pseudo_header = bytes(doubled[ip_offset + 12:ip_offset + 20]) + struct.pack("!BBH", 0, 6, len(doubled) - tcp_offset)
    struct.pack_into("!H", doubled, tcp_offset + 16, checksum(pseudo_header + bytes(doubled[tcp_offset:])))
    path = tmp_path / "two-server-hellos.pcap"
    path.write_bytes(classic_header() + struct.pack("<IIII", seconds, fractional, len(doubled), len(doubled)) + doubled)

    # Verify the actual dissector sees two Hello occurrences in a single frame.
    result = subprocess.run([tshark, "-n", "-2", "-r", str(path), "-T", "json",
                             "-e", "frame.number", "-e", "tls.handshake.type"],
                            check=True, capture_output=True, text=True, timeout=30)
    [packet] = json.loads(result.stdout)
    layers = packet["_source"]["layers"]
    assert layers["frame.number"] == ["1"]
    assert layers["tls.handshake.type"] == ["2", "2"]
    with caplog.at_level(logging.WARNING, logger=parser.__name__):
        assert parser.extract_tls_metadata(str(path)) == []
    assert "Skipping ambiguous TLS Hello frame" in caplog.text


def test_real_ssh_identifications_and_kex_lists_do_not_create_cleartext_false_positives(captured):
    ssh = {entry["packet_number"]: entry for entry in captured["ssh_sessions"]}
    banner, client, server = ssh[6], ssh[10], ssh[12]
    assert banner["protocol_banner"].startswith("SSH-2.0-OpenSSH_")
    assert banner["kex_algorithms"] == []
    assert banner["is_server"] is True
    assert client["is_server"] is False and server["is_server"] is True
    assert client["stream_id"] == server["stream_id"] == "0"
    assert client["kex_algorithms"] == ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"]
    assert client["server_host_key_algorithms"] == ["ssh-rsa"]
    assert all("," not in name for entry in ssh.values() for name in entry["kex_algorithms"])
    clear_frames = {entry["packet_number"] for entry in captured["cleartext_traffic"]}
    assert clear_frames.isdisjoint(ssh)
    assert {6, 8, 10, 12}.isdisjoint(clear_frames)


def test_real_cleartext_contains_http_requests_and_responses_and_excludes_database_upgrades(captured):
    clear = {entry["packet_number"]: entry for entry in captured["cleartext_traffic"]}
    request, response = clear[447], clear[449]
    assert request["protocol"] == response["protocol"] == "HTTP"
    assert request["http_method"] == "GET" and request["http_host"] == "intranet03.lab"
    assert response["http_method"] is None and response["matched_snippet"] == "HTTP 200"
    assert request["stream_id"] == response["stream_id"] == "29"
    # These are actual PG SSLRequest/SSLResponse frames, followed by TLS traffic.
    upgrade_frames = {105, 107, 139, 141, 212, 214, 242, 244, 387, 389, 430, 432, 905, 907, 1587, 1589}
    assert upgrade_frames.isdisjoint(clear)
    assert all(entry["protocol"] == "HTTP" for entry in clear.values())
    assert all("tcp.payload" not in entry and "http_uri" not in entry for entry in clear.values())


def classic_header(endian="<", nanoseconds=False) -> bytes:
    return struct.pack(endian + "IHHIIII", 0xA1B23C4D if nanoseconds else 0xA1B2C3D4,
                       2, 4, 0, 0, 65535, 1)


@pytest.mark.parametrize("endian", ["<", ">"], ids=["little-endian", "big-endian"])
@pytest.mark.parametrize("nanoseconds", [False, True], ids=["microsecond", "nanosecond"])
def test_empty_classic_capture_variants_are_valid(tshark, tmp_path, endian, nanoseconds):
    path = tmp_path / "empty.pcap"
    path.write_bytes(classic_header(endian, nanoseconds))
    result = parser.parse_network_pcap(str(path))
    assert result == {"pcap_file": str(path), "tls_sessions": [], "ssh_sessions": [], "cleartext_traffic": []}


def block(kind: int, body: bytes) -> bytes:
    length = len(body) + 12
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def pcapng_header(linktype=1, snaplen=65535) -> bytes:
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", linktype, 0, snaplen))
    return section + interface


def test_empty_pcapng_section_and_interface_are_valid(tshark, tmp_path):
    path = tmp_path / "empty.pcapng"
    path.write_bytes(pcapng_header())
    result = parser.parse_network_pcap(str(path))
    assert all(result[key] == [] for key in ("tls_sessions", "ssh_sessions", "cleartext_traffic"))


def _write_pcapng_from_classic(source: Path, destination: Path) -> None:
    """Fallback when editcap is absent: preserve captured bytes and timestamps."""
    raw = source.read_bytes()
    endian, resolution = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }[raw[:4]]
    snaplen, linktype = struct.unpack_from(endian + "II", raw, 16)
    converted = bytearray(pcapng_header(linktype, snaplen))
    offset = 24
    while offset < len(raw):
        seconds, fractional, captured_length, original_length = struct.unpack_from(endian + "IIII", raw, offset)
        payload = raw[offset + 16:offset + 16 + captured_length]
        assert len(payload) == captured_length
        timestamp = seconds * 1_000_000 + fractional * 1_000_000 // resolution
        body = struct.pack("<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, captured_length, original_length)
        body += payload + bytes((-len(payload)) % 4)
        converted.extend(block(6, body))
        offset += 16 + captured_length
    destination.write_bytes(converted)


def test_real_capture_pcapng_roundtrip_preserves_extracted_handshakes_and_cleartext(tshark, captured, tmp_path):
    converted = tmp_path / "network.pcapng"
    beside = Path(tshark).with_name("editcap.exe" if os.name == "nt" else "editcap")
    editcap = str(beside) if beside.is_file() else shutil.which("editcap")
    if editcap:
        subprocess.run([editcap, "-F", "pcapng", str(CAPTURE), str(converted)],
                       check=True, capture_output=True, timeout=30)
    else:
        _write_pcapng_from_classic(CAPTURE, converted)
    assert converted.read_bytes()[:4] == b"\x0a\x0d\x0d\x0a"
    parsed = parser.parse_network_pcap(str(converted))
    assert parsed["pcap_file"] == str(converted)
    for category in ("tls_sessions", "ssh_sessions", "cleartext_traffic"):
        assert parsed[category] == captured[category]


@pytest.mark.parametrize("raw", [
    b"this is not a capture", b"\xd4\xc3\xb2\xa1\x02",
    classic_header() + b"\x00" * 7,
    classic_header() + struct.pack("<IIII", 1, 0, 64, 64) + b"\x00" * 4,
], ids=["invalid-magic", "truncated-global-header", "truncated-packet-header", "truncated-packet-data"])
def test_corrupted_and_truncated_capture_produces_clear_parser_error(tshark, tmp_path, raw):
    path = tmp_path / "broken.pcap"
    path.write_bytes(raw)
    with pytest.raises(parser.PcapParserError) as exc:
        parser.parse_network_pcap(str(path))
    message = str(exc.value)
    assert "tshark" in message.lower()
    assert any(word in message.lower() for word in ("cut short", "capture file", "truncat", "corrupt")), message


def test_missing_capture_error_identifies_the_input_file_without_calling_tshark(tmp_path):
    path = tmp_path / "missing.pcap"
    with pytest.raises(parser.PcapParserError) as exc:
        parser.parse_network_pcap(str(path))
    assert str(path) in str(exc.value)
    assert "encontrado" in str(exc.value)


def test_real_capture_shared_models_and_json_preserve_packet_evidence(captured):
    findings = parser.scan(CAPTURE)
    payload = json.loads(parser.parse_network_json(CAPTURE))
    assert findings and payload == [finding.to_dict() for finding in findings]
    assert [CryptoFinding.model_validate(item) for item in payload] == findings
    frames = {entry["packet_number"] for category in ("tls_sessions", "ssh_sessions", "cleartext_traffic")
              for entry in captured[category]}
    assert all(e.file_path == str(CAPTURE) and e.packet_number in frames
               for finding in findings for e in finding.evidence)
    assert all(finding.source_type == "network-capture"
               and finding.quantum_risk == finding.classical_risk == QuantumRiskLevel.UNKNOWN
               for finding in findings)
    selected = [f for f in findings if f.evidence[0].packet_number == 406]
    assert any(f.algorithm_name == "X25519MLKEM768" and f.observation == "negotiated"
               for f in selected)
    assert any(f.algorithm_name == "AES" and f.key_size == 256 and f.mode == "GCM"
               for f in selected)
    rsa = [f for f in findings if f.algorithm_name == "RSA"]
    assert rsa and all(f.key_size is None for f in rsa)
    ssh_frames = {entry["packet_number"] for entry in captured["ssh_sessions"]}
    assert all(f.observation == "advertised" for f in findings
               if f.evidence[0].packet_number in ssh_frames and f.crypto_function != CryptoFunction.UNKNOWN)
