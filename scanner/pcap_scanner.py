# Purpose:
# Analyzes network PCAP packet captures for in-transit cryptographic protocols, TLS versions, negotiated cipher suites, and cleartext traffic.
#
# Responsibilities:
# - Parse standard PCAP files without requiring mandatory external C binary libraries.
# - Dissect TLS Handshake records (ClientHello, ServerHello) to extract negotiated cipher suites and TLS protocol versions (TLS 1.2, TLS 1.3).
# - Identify SSH transport handshakes and application layer protocols.
# - Detect unencrypted cleartext protocols on common ports (HTTP on 80, Postgres on 5432) and flag lack of encryption.
# - Associate detected cipher suites with standard IANA identifiers, cryptographic strengths, and post-quantum risks.
#
# Planned interface:
# - parse_pcap(filepath: Path) -> list[CryptoFinding]: extracts network cryptographic assets and observed cipher suites.
# - extract_tls_handshake(payload: bytes) -> tuple[str, str]: returns (tls_version, cipher_suite) or ("unknown", "unknown").
# - identify_cleartext_traffic(packet: bytes) -> Optional[CryptoFinding]: flags unencrypted protocols.
#
# Rules and edge cases:
# - Handle both little-endian and big-endian PCAP capture formats cleanly.
# - Packet truncation and corrupted frames must be handled gracefully without crashing the analyzer.
# - In ServerHello handshakes, cipher suite ID occurs after the session ID field; handle variable session ID lengths dynamically.
# - Cleartext protocols (HTTP, unencrypted database) must be flagged with explicit warnings in evidence.
#
# Scoring link:
# - Coverage (25%): Extends audit capabilities to live network traffic captures covering active cipher suite negotiation.
# - Accuracy (40%): Distinguishes legacy TLS 1.0/1.1 and deprecated cipher suites (e.g. 3DES, static RSA key exchange) from modern TLS 1.3.
