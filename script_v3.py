from scapy.all import rdpcap
from collections import defaultdict

# === CONFIG ===
PCAP_FILE = "/home/nutria/Downloads/vpns/vpnbookfr2.pcap"
N = 100
MAX_UDP_PAYLOAD = 1000  # Soglia massima per escludere flussi QUIC

# === FUNZIONI ===

def parse_tcp_stream(fragments, flow_key):
    fragments.sort(key=lambda x: x[0])
    full_stream = b''.join(payload for _, payload in fragments)

    i = 0
    pkt_count = 0
    while i + 2 <= len(full_stream) and pkt_count < N:
        length = int.from_bytes(full_stream[i:i+2], byteorder='big')
        start = i + 2
        end = start + length

        if end > len(full_stream):
            break

        pkt_payload = full_stream[start:end]
        if len(pkt_payload) >= 1:
            opcode = (pkt_payload[0] & 0xF8) >> 3
            print(f"[DEBUG] Flusso {flow_key} - TCP Opcode estratto: {opcode}")
            yield opcode

        i = end
        pkt_count += 1

def estrai_opcode_udp(pkt, flow_key):
    if pkt.haslayer('UDP') and pkt['UDP'].payload:
        payload = bytes(pkt['UDP'].payload)
        opcode = (payload[0] & 0xF8) >> 3
        print(f"[DEBUG] Flusso {flow_key} - UDP Opcode estratto: {opcode}")
        return opcode
    return None

def normalizza_chiave(ip_src, port_src, ip_dst, port_dst):
    if (ip_src, port_src) <= (ip_dst, port_dst):
        return (ip_src, port_src, ip_dst, port_dst)
    else:
        return (ip_dst, port_dst, ip_src, port_src)

def analizza_flussi(packets):
    flows = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer('IP') and pkt.haslayer('TCP') and pkt['TCP'].payload:
            ip = pkt['IP']
            tcp = pkt['TCP']
            key = normalizza_chiave(ip.src, tcp.sport, ip.dst, tcp.dport)
            flows[key].append(('TCP', tcp.seq, bytes(tcp.payload)))
        elif pkt.haslayer('IP') and pkt.haslayer('UDP') and pkt['UDP'].payload:
            ip = pkt['IP']
            udp = pkt['UDP']
            key = normalizza_chiave(ip.src, udp.sport, ip.dst, udp.dport)
            flows[key].append(('UDP', None, bytes(udp.payload)))

    risultati = []
    flussi_openvpn = []

    for key, fragments in flows.items():
        opcode_set = set()
        cr = None
        sr = None

        tcp_fragments = [(seq, payload) for proto, seq, payload in fragments if proto == 'TCP'][:N]
        udp_fragments = [payload for proto, _, payload in fragments if proto == 'UDP'][:N]

        pkt_count = 0
        non_openvpn = False

        # Controllo se i primi due pacchetti UDP superano la soglia
        udp_payload_sizes = [len(payload) for payload in udp_fragments[:2]]
        if any(size > MAX_UDP_PAYLOAD for size in udp_payload_sizes):
            print(f"[INFO] Flusso {key} escluso: primi due pacchetti UDP > {MAX_UDP_PAYLOAD} byte (probabile QUIC)")
            continue

        if tcp_fragments:
            for opcode in parse_tcp_stream(tcp_fragments, key):
                if pkt_count == 0:
                    cr = opcode
                elif pkt_count == 1:
                    sr = opcode
                else:
                    if (opcode == cr or opcode == sr) and len(opcode_set) >= 4:
                        print(f"[INFO] Flusso {key} classificato come NON OpenVPN (opcode ripetuto CR/SR)")
                        non_openvpn = True
                        break
                opcode_set.add(opcode)
                pkt_count += 1
                if pkt_count >= N:
                    break

        if pkt_count < N and not non_openvpn and udp_fragments:
            for payload in udp_fragments:
                if payload and pkt_count < N:
                    opcode = (payload[0] & 0xF8) >> 3
                    if pkt_count == 0:
                        cr = opcode
                    elif pkt_count == 1:
                        sr = opcode
                    else:
                        if (opcode == cr or opcode == sr) and len(opcode_set) >= 4:
                            print(f"[INFO] Flusso {key} classificato come NON OpenVPN (opcode ripetuto CR/SR)")
                            non_openvpn = True
                            break
                    opcode_set.add(opcode)
                    pkt_count += 1

        is_openvpn = False
        if not non_openvpn:
            is_openvpn = 4 <= len(opcode_set) <= 10

        risultati.append({
            'flusso': key,
            'opcodes': sorted(opcode_set),
            'openvpn': is_openvpn
        })

        if is_openvpn:
            flussi_openvpn.append(key)

    return risultati, flussi_openvpn

def main():
    packets = rdpcap(PCAP_FILE)
    print(f"[+] Letti {len(packets)} pacchetti da {PCAP_FILE}")

    risultati, flussi_openvpn = analizza_flussi(packets)

    print(f"\n[+] Flussi bidirezionali analizzati: {len(risultati)}\n")

    for risultato in risultati:
        print(f"Flusso {risultato['flusso']}:\n    Opcode individuati: {risultato['opcodes']}\n    Risultato: {'OpenVPN' if risultato['openvpn'] else 'Non OpenVPN'}\n")

    print("\n[+] Lista dei flussi classificati come OpenVPN:")
    for flusso in flussi_openvpn:
        print(f"   - {flusso}")

if __name__ == "__main__":
    main()

