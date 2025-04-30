from scapy.all import rdpcap  # Importa la funzione rdpcap da Scapy per leggere pacchetti da un file pcap
from collections import defaultdict  # Importa defaultdict per gestire i flussi TCP e UDP in modo efficiente
import argparse

# === CONFIG ===
def get_args():
    parser = argparse.ArgumentParser(description="Analizzatore di flussi per identificare traffico OpenVPN")
    parser.add_argument("pcap_file", help="Percorso del file .pcap da analizzare")
    return parser.parse_args()  # Percorso del file PCAP da analizzare
N = 100  # Numero massimo di pacchetti da analizzare per ogni flusso
MAX_UDP_PAYLOAD = 1000  # Soglia massima dimensione dei primi due pacchetti UDP (usato per evitare pacchetti QUIC)

# === FUNZIONI ===

def parse_tcp_stream(fragments, flow_key):
    # Ordina i frammenti del flusso TCP in base al numero di sequenza
    fragments.sort(key=lambda x: x[0])
    # Ricostruisce il flusso completo concatenando tutti i payload
    full_stream = b''.join(payload for _, payload in fragments)

    i = 0  # Indice di posizione nel flusso
    pkt_count = 0  # Contatore per i pacchetti elaborati
    while i + 2 <= len(full_stream) and pkt_count < N:
        # Estrae la lunghezza del pacchetto (2 byte)
        length = int.from_bytes(full_stream[i:i+2], byteorder='big')
        start = i + 2  # Punto di partenza del pacchetto
        end = start + length  # Punto finale del pacchetto

        if end > len(full_stream):  # Se il pacchetto è incompleto, interrompi
            break

        # Estrae il payload del pacchetto
        pkt_payload = full_stream[start:end]
        if len(pkt_payload) >= 1:  # Se il pacchetto ha almeno un byte
            # Estrae l'opcode dal primo byte del payload
            opcode = (pkt_payload[0] & 0xF8) >> 3
            print(f"[DEBUG] Flusso {flow_key} - TCP Opcode estratto: {opcode}")
            yield opcode  # Restituisce l'opcode per l'analisi

        i = end  # Aggiorna l'indice per il prossimo pacchetto
        pkt_count += 1  # Incrementa il contatore dei pacchetti

def analizza_flussi(packets):
    # Crea due dizionari per memorizzare i flussi TCP e UDP
    flows_tcp = defaultdict(lambda: {'C2S': [], 'S2C': []})  # Flussi TCP direzione client a server (C2S) e server a client (S2C)
    flows_udp = defaultdict(list)  # Flussi UDP

    # Itera su tutti i pacchetti
    for pkt in packets:
        if pkt.haslayer('IP') and pkt.haslayer('TCP') and pkt['TCP'].payload:
            # Se il pacchetto è TCP e ha un payload
            ip = pkt['IP']  # Estrae il layer IP
            tcp = pkt['TCP']  # Estrae il layer TCP
            # Crea una chiave unica per il flusso (src_ip, src_port, dst_ip, dst_port)
            key = (min(ip.src, ip.dst), min(tcp.sport, tcp.dport), max(ip.src, ip.dst), max(tcp.sport, tcp.dport))
            # Determina la direzione del flusso (C2S o S2C)
            direction = 'C2S' if (ip.src, tcp.sport) <= (ip.dst, tcp.dport) else 'S2C'
            # Aggiunge il pacchetto al flusso corrispondente
            flows_tcp[key][direction].append(('TCP', tcp.seq, bytes(tcp.payload)))
        elif pkt.haslayer('IP') and pkt.haslayer('UDP') and pkt['UDP'].payload:
            # Se il pacchetto è UDP e ha un payload
            ip = pkt['IP']  # Estrae il layer IP
            udp = pkt['UDP']  # Estrae il layer UDP
            # Crea una chiave unica per il flusso (src_ip, src_port, dst_ip, dst_port)
            key = (min(ip.src, ip.dst), min(udp.sport, udp.dport), max(ip.src, ip.dst), max(udp.sport, udp.dport))
            # Aggiunge il payload UDP al flusso
            flows_udp[key].append(bytes(udp.payload))

    risultati = []  # Lista per i risultati finali
    flussi_openvpn = []  # Lista per i flussi classificati come OpenVPN

    # Analizza i flussi TCP
    for key, flow_directions in flows_tcp.items():
        opcode_set_total = set()  # Set per raccogliere gli opcodes unici per il flusso
        for direction, fragments in flow_directions.items():
            opcode_set = set()  # Set per raccogliere gli opcodes per una direzione specifica
            cr = None  # Codice di inizio connessione (client)
            sr = None  # Codice di risposta (server)
            pkt_count = 0  # Contatore pacchetti per la direzione
            non_openvpn = False  # Flag per segnare se il flusso è NON OpenVPN

            # Limita il numero di frammenti TCP da analizzare
            tcp_fragments = [(seq, payload) for proto, seq, payload in fragments if proto == 'TCP'][:N]

            if tcp_fragments:
                for opcode in parse_tcp_stream(tcp_fragments, f"{key} {direction}"):
                    if pkt_count == 0:
                        cr = opcode  # Primo opcode come CR
                    elif pkt_count == 1:
                        sr = opcode  # Secondo opcode come SR
                    else:
                        # Se il flusso ha più di 4 opcodes e l'opcode è uguale a CR o SR, non è OpenVPN
                        if (opcode == cr or opcode == sr) and len(opcode_set) >= 4:
                            print(f"[INFO] Flusso {key} direzione {direction} classificato come NON OpenVPN (opcode ripetuto CR/SR)")
                            non_openvpn = True
                            break
                    opcode_set.add(opcode)
                    pkt_count += 1
                    if pkt_count >= N:
                        break

            opcode_set_total.update(opcode_set)

        # Se il numero di opcodes è tra 4 e 10, è classificato come OpenVPN
        is_openvpn = False
        if 4 <= len(opcode_set_total) <= 10:
            is_openvpn = True

        risultati.append({
            'flusso': key,
            'opcodes': sorted(opcode_set_total),
            'openvpn': is_openvpn
        })

        if is_openvpn:
            flussi_openvpn.append(key)

    # Analizza i flussi UDP
    for key, udp_payloads in flows_udp.items():
        opcode_set = set()  # Set per raccogliere gli opcodes per UDP
        pkt_count = 0  # Contatore pacchetti UDP
        cr = None  # Codice di inizio connessione UDP
        sr = None  # Codice di risposta UDP
        non_openvpn = False  # Flag per segnare se il flusso UDP è NON OpenVPN

        # Verifica se i primi due pacchetti UDP sono troppo grandi (probabile QUIC)
        udp_payload_sizes = [len(payload) for payload in udp_payloads[:2]]
        if any(size > MAX_UDP_PAYLOAD for size in udp_payload_sizes):
            print(f"[INFO] Flusso UDP {key} escluso: primi due pacchetti UDP troppo grandi (probabile QUIC)")
            continue

        # Analizza i pacchetti UDP fino a N
        for payload in udp_payloads[:N]:
            if payload and pkt_count < N:
                # Estrae l'opcode dal primo byte del payload UDP
                opcode = (payload[0] & 0xF8) >> 3
                if pkt_count == 0:
                    cr = opcode  # Primo opcode come CR
                elif pkt_count == 1:
                    sr = opcode  # Secondo opcode come SR
                else:
                    # Se l'opcode è uguale a CR o SR e ci sono più di 4 opcodes, non è OpenVPN
                    if (opcode == cr or opcode == sr) and len(opcode_set) >= 4:
                        print(f"[INFO] Flusso UDP {key} classificato come NON OpenVPN (opcode ripetuto CR/SR)")
                        non_openvpn = True
                        break
                opcode_set.add(opcode)
                pkt_count += 1

        is_openvpn = False
        if not non_openvpn and 4 <= len(opcode_set) <= 10:
            is_openvpn = True

        risultati.append({
            'flusso': key,
            'opcodes': sorted(opcode_set),
            'openvpn': is_openvpn
        })

        if is_openvpn:
            flussi_openvpn.append(key)

    return risultati, flussi_openvpn  # Restituisce i risultati finali e la lista dei flussi OpenVPN

def main():
    args = get_args()
    pcap_path = args.pcap_file
    
    # Legge il file PCAP e carica i pacchetti
    packets = rdpcap(pcap_path)
    print(f"[+] Letti {len(packets)} pacchetti da {pcap_path}")

    # Analizza i flussi TCP e UDP
    risultati, flussi_openvpn = analizza_flussi(packets)

    # Stampa i risultati
    print(f"\n[+] Flussi analizzati: {len(risultati)}\n")

    for risultato in risultati:
        print(f"""Flusso {risultato['flusso']}:
    Opcode individuati: {risultato['opcodes']}
    Risultato: {'OpenVPN' if risultato['openvpn'] else 'Non OpenVPN'}\n""")

    # Stampa i flussi classificati come OpenVPN
    print("\n[+] Lista dei flussi classificati come OpenVPN:")
    for flusso in flussi_openvpn:
        print(f"   - {flusso}")

if __name__ == "__main__":
    main()  # Esegui la funzione principale quando il file viene eseguito come script
