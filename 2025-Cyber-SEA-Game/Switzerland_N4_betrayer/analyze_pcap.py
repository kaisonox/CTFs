import argparse
import collections
import ipaddress
from typing import Dict, Tuple, Set, List

from scapy.all import rdpcap, Packet, TCP, UDP, IP, IPv6, DNS, DNSQR, DNSRR, Raw
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.type import univ, char


def safe_ip(pkt: Packet) -> Tuple[str, str]:
    src = dst = "?"
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    return src, dst


def get_ports(pkt: Packet) -> Tuple[int, int]:
    sport = dport = -1
    if TCP in pkt:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    return sport, dport


def summarize_pcap(pcap_path: str) -> None:
    packets: List[Packet] = rdpcap(pcap_path)

    proto_counts: collections.Counter = collections.Counter()
    hosts: Set[str] = set()
    conv_counts: Dict[Tuple[str, str, int, int, str], int] = collections.Counter()
    host_pair_counts: Dict[Tuple[str, str], int] = collections.Counter()

    dns_queries: List[Tuple[str, str]] = []  # (src_ip, qname)
    dns_answers: List[Tuple[str, str, str]] = []  # (src_ip, qname, rdata)
    http_like: List[Tuple[str, str, str]] = []  # (src_ip, dst_ip, first_line)
    smb_like_conv: Set[Tuple[str, str, int, int]] = set()
    kerberos_like_conv: Set[Tuple[str, str, int, int]] = set()
    kerberos_msgs: List[Dict[str, str]] = []  # type, src, dst, realm, cname

    def extract_strings_from_asn1(node) -> List[str]:
        vals: List[str] = []
        try:
            if isinstance(node, (char.GeneralString, char.UTF8String, char.VisibleString, char.PrintableString, char.IA5String)):
                s = str(node)
                if s:
                    vals.append(s)
            elif isinstance(node, (univ.OctetString,)):
                # try decode as utf-8/utf-16le
                raw = bytes(node)
                for enc in ("utf-8", "utf-16le"):
                    try:
                        s = raw.decode(enc)
                        if s:
                            vals.append(s)
                            break
                    except Exception:
                        pass
            elif isinstance(node, (univ.Sequence, univ.Set)):
                for sub in node:
                    vals.extend(extract_strings_from_asn1(sub))
            elif isinstance(node, (univ.SequenceOf, univ.SetOf)):
                for sub in node:
                    vals.extend(extract_strings_from_asn1(sub))
        except Exception:
            pass
        return vals

    # Collected NTLM/NTLMv2 tuples from SMB (Type 2 + Type 3)
    ntlm_challenges: List[Dict[str, str]] = []  # server, challenge, target
    ntlm_auths: List[Dict[str, str]] = []  # user, domain, host, ntlmv2, lmv2
    ntlmssp_hits = 0

    # Simple TCP reassembly buffers per direction for SMB/Kerberos
    tcp_buffers: Dict[Tuple[str, int, str, int], bytearray] = {}

    for pkt in packets:
        src, dst = safe_ip(pkt)
        if src != "?":
            hosts.add(src)
        if dst != "?":
            hosts.add(dst)

        layer = None
        if TCP in pkt:
            layer = "TCP"
        elif UDP in pkt:
            layer = "UDP"
        elif IP in pkt or IPv6 in pkt:
            layer = "IP"
        else:
            layer = pkt.__class__.__name__
        proto_counts[layer] += 1

        sport, dport = get_ports(pkt)
        if src != "?" and dst != "?" and sport != -1 and dport != -1:
            key = (src, dst, sport, dport, layer)
            conv_counts[key] += 1
            hp = (src, dst)
            host_pair_counts[hp] += 1

        # DNS
        if UDP in pkt and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53) and DNS in pkt:
            dns = pkt[DNS]
            if dns.qr == 0 and DNSQR in dns and dns.qd is not None:
                try:
                    qname = dns.qd.qname.decode().rstrip('.')
                except Exception:
                    qname = str(dns.qd.qname)
                dns_queries.append((src, qname))
            elif dns.qr == 1 and dns.ancount > 0:
                for i in range(dns.ancount):
                    rr = dns.an[i]
                    try:
                        name = rr.rrname.decode().rstrip('.')
                    except Exception:
                        name = str(rr.rrname)
                    rdata = None
                    if hasattr(rr, 'rdata'):
                        rdata = rr.rdata if isinstance(rr.rdata, str) else getattr(rr, 'rdata', None)
                    if rdata is None and hasattr(rr, 'rdata') and isinstance(rr.rdata, bytes):
                        try:
                            rdata = rr.rdata.decode(errors='ignore')
                        except Exception:
                            rdata = str(rr.rdata)
                    dns_answers.append((src, name, str(rdata)))

        # Simple HTTP/HTTP proxy detection in Raw over TCP 80/8080/8000/443 (if plaintext)
        if TCP in pkt and Raw in pkt and (pkt[TCP].dport in {80, 8080, 8000, 8008, 3128, 8888} or pkt[TCP].sport in {80, 8080, 8000, 8008, 3128, 8888}):
            payload = bytes(pkt[Raw].load)
            first_line = payload.split(b"\r\n", 1)[0][:120]
            try:
                first_line_str = first_line.decode('utf-8', errors='ignore')
            except Exception:
                first_line_str = repr(first_line)
            if any(first_line_str.startswith(m) for m in ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "HTTP/"]):
                http_like.append((src, dst, first_line_str))

        # SMB (ports 445/139) and NTLMSSP extraction
        if TCP in pkt and (pkt[TCP].dport in {445, 139} or pkt[TCP].sport in {445, 139}):
            smb_like_conv.add((src, dst, sport, dport))
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                # buffer reassembly
                key = (src, sport, dst, dport)
                tcp_buffers.setdefault(key, bytearray()).extend(payload)
                idx = 0
                signature = b"NTLMSSP\x00"
                while True:
                    i = payload.find(signature, idx)
                    if i < 0:
                        break
                    ntlmssp_hits += 1
                    # Expect at least 12 bytes after signature for MessageType
                    if i + 12 <= len(payload):
                        try:
                            mtype = int.from_bytes(payload[i+8:i+12], "little")
                        except Exception:
                            mtype = -1
                        # Type 2: challenge; parse TargetName and ServerChallenge
                        if mtype == 2 and i + 48 <= len(payload):
                            # Offsets relative to start of NTLMSSP header
                            # TARGET_NAME: 2 len, 2 max, 4 off @ 12
                            t_len = int.from_bytes(payload[i+12:i+14], "little")
                            t_off = int.from_bytes(payload[i+16:i+20], "little")
                            server_challenge = payload[i+24:i+32].hex()
                            target = ""
                            if 0 <= t_off and i + t_off + t_len <= len(payload):
                                t_bytes = payload[i + t_off:i + t_off + t_len]
                                try:
                                    target = t_bytes.decode("utf-16le", errors="ignore")
                                except Exception:
                                    target = t_bytes.hex()
                            ntlm_challenges.append({
                                "server": dst,
                                "challenge": server_challenge,
                                "target": target,
                            })
                        # Type 3: authenticate; parse DomainName, UserName, Workstation, NTLMv2 response
                        elif mtype == 3 and i + 64 <= len(payload):
                            # Field helper
                            def get_field(off: int) -> bytes:
                                flen = int.from_bytes(payload[i+off:i+off+2], "little")
                                foff = int.from_bytes(payload[i+off+4:i+off+8], "little")
                                if foff >= 0 and i + foff + flen <= len(payload):
                                    return payload[i + foff:i + foff + flen]
                                return b""

                            dom_bytes = get_field(28)   # DomainName fields at 28
                            user_bytes = get_field(36)  # UserName at 36
                            host_bytes = get_field(44)  # Workstation at 44
                            lmresp = get_field(12)      # LM response at 12
                            ntresp = get_field(20)      # NT response at 20

                            def ucs2(b: bytes) -> str:
                                try:
                                    return b.decode("utf-16le", errors="ignore").strip("\x00")
                                except Exception:
                                    return b.hex()

                            domain = ucs2(dom_bytes)
                            user = ucs2(user_bytes)
                            host = ucs2(host_bytes)
                            ntlmv2_hex = ntresp.hex() if ntresp else ""
                            lmv2_hex = lmresp.hex() if lmresp else ""
                            if user or domain:
                                ntlm_auths.append({
                                    "src": src,
                                    "dst": dst,
                                    "domain": domain,
                                    "user": user,
                                    "host": host,
                                    "ntlmv2": ntlmv2_hex,
                                    "lmv2": lmv2_hex,
                                })
                    idx = i + len(signature)

        # Kerberos (88)
        if (TCP in pkt or UDP in pkt) and (dport == 88 or sport == 88):
            kerberos_like_conv.add((src, dst, sport, dport))
            if Raw in pkt:
                pdata = bytes(pkt[Raw].load)
                if TCP in pkt:
                    key = (src, sport, dst, dport)
                    tcp_buffers.setdefault(key, bytearray()).extend(pdata)
                try:
                    msg, _ = ber_decoder.decode(pdata)
                    strings = extract_strings_from_asn1(msg)
                    # Heuristics: realm often contains a dot and is uppercase (e.g., WINDOMAIN.LOCAL)
                    realm_candidates = [s for s in strings if "." in s and s.upper() == s and 3 <= len(s) <= 64]
                    # cname parts: short tokens possibly lower/Title case
                    cname_candidates = [s for s in strings if 1 <= len(s) <= 64 and "/" not in s and "=" not in s]
                    realm = realm_candidates[0] if realm_candidates else ''
                    cname = None
                    # pick first plausible username-like token
                    for s in cname_candidates:
                        if s and any(c.isalpha() for c in s) and s.upper() != s and "." not in s:
                            cname = s
                            break
                    kerberos_msgs.append({
                        'type': 'KERB',
                        'src': src,
                        'dst': dst,
                        'realm': realm,
                        'cname': cname or '',
                    })
                except Exception:
                    pass

    print("=== PCAP Overview ===")
    print(f"File: {pcap_path}")
    print(f"Total packets: {len(packets)}")

    print("\nTop layers:")
    for layer, cnt in proto_counts.most_common():
        print(f"  {layer}: {cnt}")

    print("\nHosts (top 20):")
    for ip in list(sorted(hosts))[:20]:
        print(f"  {ip}")

    print("\nTop conversations (by 5-tuple, top 20):")
    for (s, d, sp, dp, l), cnt in conv_counts.most_common(20):
        print(f"  {s}:{sp} -> {d}:{dp} [{l}] packets={cnt}")

    print("\nTop host pairs (top 20):")
    for (s, d), cnt in host_pair_counts.most_common(20):
        print(f"  {s} -> {d} packets={cnt}")

    if dns_queries or dns_answers:
        print("\nDNS queries (top 20):")
        for src, q in dns_queries[:20]:
            print(f"  {src} -> {q}")
        print("DNS answers (top 20):")
        for src, name, rdata in dns_answers[:20]:
            print(f"  {src} {name} -> {rdata}")

    if http_like:
        print("\nHTTP-like first lines (top 20):")
        for src, dst, fl in http_like[:20]:
            print(f"  {src} -> {dst} | {fl}")

    if smb_like_conv:
        print("\nSMB-like conversations (ports 139/445):")
        for s, d, sp, dp in list(smb_like_conv)[:20]:
            print(f"  {s}:{sp} -> {d}:{dp}")

    if kerberos_like_conv:
        print("\nKerberos-like conversations (port 88):")
        for s, d, sp, dp in list(kerberos_like_conv)[:20]:
            print(f"  {s}:{sp} -> {d}:{dp}")
        if kerberos_msgs:
            print("Kerberos principals (samples):")
            for it in kerberos_msgs[:5]:
                who = it['cname'] if it['cname'] else '?'
                realm = it['realm'] if it['realm'] else '?'
                print(f"  {it['type']} {who}@{realm} {it['src']} -> {it['dst']}")

    # Quick heuristic hints for credential leaks
    print("\n=== Potential Credential Hints ===")
    corp_hosts = {"192.168.56.104", "192.168.56.33"}
    if any(h in hosts for h in corp_hosts):
        print("Involved hosts of interest detected: 192.168.56.104 and/or 192.168.56.33")
    # Look for possible NTLM/SMB auth (139/445) or Kerberos (88)
    if smb_like_conv:
        print("SMB traffic present — check for NTLM authentication (NTLMSSP) in SMB payloads.")
    if kerberos_like_conv:
        print("Kerberos traffic present — ticket exchanges may contain usernames/realm.")
    # Look for HTTP basic-like strings in Raw
    leaked_strings = []
    for pkt in packets:
        if Raw in pkt:
            pl = bytes(pkt[Raw].load)
            if b"Authorization: Basic " in pl:
                leaked_strings.append("HTTP Basic Authorization header present")
            if b"NTLMSSP" in pl:
                leaked_strings.append("NTLMSSP blob detected (possible NTLM auth)")
            if b"krb" in pl.lower():
                leaked_strings.append("Kerberos-related bytes found in payload")
    if leaked_strings:
        print("Indicators:")
        for s in sorted(set(leaked_strings)):
            print(f"  - {s}")

    # Rescan reassembled buffers for NTLMSSP and Kerberos strings
    for (s_ip, s_port, d_ip, d_port), buf in tcp_buffers.items():
        data = bytes(buf)
        # NTLMSSP blocks
        if d_port in {445, 139} or s_port in {445, 139}:
            signature = b"NTLMSSP\x00"
            idx = 0
            while True:
                i = data.find(signature, idx)
                if i < 0:
                    break
                ntlmssp_hits += 1
                if i + 12 <= len(data):
                    try:
                        mtype = int.from_bytes(data[i+8:i+12], "little")
                    except Exception:
                        mtype = -1
                    if mtype == 2 and i + 48 <= len(data):
                        t_len = int.from_bytes(data[i+12:i+14], "little")
                        t_off = int.from_bytes(data[i+16:i+20], "little")
                        server_challenge = data[i+24:i+32].hex()
                        target = ""
                        if 0 <= t_off and i + t_off + t_len <= len(data):
                            t_bytes = data[i + t_off:i + t_off + t_len]
                            try:
                                target = t_bytes.decode("utf-16le", errors="ignore")
                            except Exception:
                                target = t_bytes.hex()
                        ntlm_challenges.append({
                            "server": d_ip,
                            "challenge": server_challenge,
                            "target": target,
                        })
                    elif mtype == 3 and i + 64 <= len(data):
                        def get_field(off: int) -> bytes:
                            flen = int.from_bytes(data[i+off:i+off+2], "little")
                            foff = int.from_bytes(data[i+off+4:i+off+8], "little")
                            if foff >= 0 and i + foff + flen <= len(data):
                                return data[i + foff:i + foff + flen]
                            return b""
                        dom_bytes = get_field(28)
                        user_bytes = get_field(36)
                        host_bytes = get_field(44)
                        lmresp = get_field(12)
                        ntresp = get_field(20)
                        def ucs2(b: bytes) -> str:
                            try:
                                return b.decode("utf-16le", errors="ignore").strip("\x00")
                            except Exception:
                                return b.hex()
                        domain = ucs2(dom_bytes)
                        user = ucs2(user_bytes)
                        host = ucs2(host_bytes)
                        ntlmv2_hex = ntresp.hex() if ntresp else ""
                        lmv2_hex = lmresp.hex() if lmresp else ""
                        if user or domain:
                            ntlm_auths.append({
                                "src": s_ip,
                                "dst": d_ip,
                                "domain": domain,
                                "user": user,
                                "host": host,
                                "ntlmv2": ntlmv2_hex,
                                "lmv2": lmv2_hex,
                            })
                idx = i + len(signature)
        # Kerberos ASN.1
        if d_port == 88 or s_port == 88:
            try:
                msg, _ = ber_decoder.decode(data)
                strings = extract_strings_from_asn1(msg)
                realm_candidates = [s for s in strings if "." in s and s.upper() == s and 3 <= len(s) <= 64]
                cname_candidates = [s for s in strings if 1 <= len(s) <= 64 and "/" not in s and "=" not in s]
                realm = realm_candidates[0] if realm_candidates else ''
                cname = None
                for s in cname_candidates:
                    if s and any(c.isalpha() for c in s) and s.upper() != s and "." not in s:
                        cname = s
                        break
                kerberos_msgs.append({
                    'type': 'KERB-STREAM',
                    'src': s_ip,
                    'dst': d_ip,
                    'realm': realm,
                    'cname': cname or '',
                })
            except Exception:
                pass

    if ntlmssp_hits:
        print(f"\nNTLMSSP signature occurrences: {ntlmssp_hits}")
    if ntlm_challenges or ntlm_auths:
        print("\n=== NTLM/SMB Authentication Artifacts ===")
        if ntlm_challenges:
            print("Type 2 (Server Challenge) samples:")
            for it in ntlm_challenges[:3]:
                print(f"  server={it['server']} target={it['target']} challenge={it['challenge']}")
        if ntlm_auths:
            print("Type 3 (Authenticate) samples:")
            for it in ntlm_auths[:5]:
                print(f"  {it['domain']}\\{it['user']} from {it['host']} -> {it['dst']}")
                if it['ntlmv2']:
                    # Print NTProofStr (first 16 bytes) and response size
                    ntproof = it['ntlmv2'][:32]
                    print(f"    NTLMv2 NTProofStr={ntproof} len={len(it['ntlmv2'])//2} bytes")
                if it['lmv2']:
                    print(f"    LMv2 len={len(it['lmv2'])//2} bytes")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scapy PCAP overview analyzer")
    parser.add_argument("pcap", help="Path to pcap/pcapng file")
    args = parser.parse_args()
    summarize_pcap(args.pcap)


if __name__ == "__main__":
    main()


