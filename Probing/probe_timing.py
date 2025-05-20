# Importa i moduli necessari
import socket       # Per la comunicazione TCP/IP
import time         # Per misurare il tempo di risposta e gestire attese
import csv          # Per leggere e scrivere file CSV
import os           # Per generare payload random
import argparse     # Per gestire input da riga di comando

# === PARSING ARGOMENTI DA RIGA DI COMANDO ===
parser = argparse.ArgumentParser(description="TCP probing tool.")  # Crea un parser per descrivere lo script
parser.add_argument("input_file", help="Path to input CSV file")   # Aggiunge l'argomento obbligatorio per il file di input
parser.add_argument("output_file", help="Path to output CSV file") # Aggiunge l'argomento obbligatorio per il file di output
args = parser.parse_args()  # Analizza gli argomenti ricevuti da terminale

# === CONFIGURAZIONE ===
INPUT_FILE = args.input_file          # File CSV da cui leggere gli indirizzi da testare
OUTPUT_FILE = args.output_file        # File CSV dove scrivere i risultati
INTERVAL_SECONDS = 2                  # Intervallo tra un probe e l’altro (in secondi)
TIMEOUT = 5                           # Timeout per la risposta dal server (in secondi)

# === DEFINIZIONE DEI PROBE DA INVIARE ===
probes = [
    ("BaseProbe1", b"\x00\x0E\x38" + b"\x41" * 8 + b"\x00\x00\x00\x00\x00"),  # Payload binario predefinito
    ("BaseProbe2", b"\x00\x0E\x38" + b"\x41" * 8 + b"\x00\x00\x00\x00"),
    ("TCP_Generic", b"\x0d\x0a\x0d\x0a"),                                     # Simula fine intestazione HTTP
    ("One_Zero", b"\x00"),                                                   # Un singolo byte nullo
    ("Two_Zero", b"\x00\x00"),                                               # Due byte nulli
    ("Epmd", b"\x00\x01\x6e"),                                               # Probe specifico per Erlang Port Mapper Daemon
    ("SSH", b"SSH-2.0-OpenSSH_8.1\r\n"),                                      # Banner finto SSH
    ("HTTP_GET", b"GET / HTTP/1.0\r\n\r\n"),                                  # Richiesta HTTP GET
    ("TLS", bytes.fromhex("16030100d9010000d50303" + "00" * 211)),            # Handshake TLS incompleto
    ("2K_Random", os.urandom(2000))                                          # Payload casuale di 2000 byte
]

# === FUNZIONE PER INVIARE UN PROBE E MISURARE LA RISPOSTA ===
def test_probe(ip, port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Crea socket TCP
        s.settimeout(TIMEOUT)                                  # Imposta timeout
        s.connect((ip, port))                                  # Si connette all’host di destinazione
        s.sendall(payload)                                     # Invia il payload

        start = time.time()                                    # Inizia il timer
        try:
            data = s.recv(4096)                                # Attende una risposta (fino a 4096 byte)
            end = time.time()                                  # Registra il tempo al ricevimento
            duration = round(end - start, 3)                   # Calcola durata arrotondata
            if data:                                           # Se c'è risposta
                print("   risposta ")
            else:                                              # Socket chiuso senza dati
                print("   Nessuna risposta (socket chiuso)")
        except socket.timeout:                                 # Timeout scaduto
            print("   Timeout (nessuna risposta)")
            duration = round(time.time() - start, 3)           # Registra comunque il tempo
        except socket.error as e:                              # Errore di ricezione
            print(f"   Errore ricezione: {e}")
            duration = round(time.time() - start, 3)
        finally:
            s.close()                                          # Chiude il socket in ogni caso
        return duration                                        # Ritorna il tempo di risposta
    except Exception as e:                                     # Qualsiasi altro errore (es. connessione fallita)
        print(f"   Connessione fallita: {e}")
        return 0.0                                             # Nessuna risposta, ritorna 0

# === CICLO PRINCIPALE: LEGGE IL FILE DI INPUT E PROVA I SERVER ===
with open(INPUT_FILE, newline='') as infile, open(OUTPUT_FILE, 'w', newline='') as outfile:
    reader = csv.reader(infile)             # Lettore CSV per leggere IP, porta e protocollo
    writer = csv.writer(outfile)           # Scrittore CSV per salvare i risultati

    for row in reader:
        if not row or len(row) < 3:        # Salta righe vuote o incomplete
            continue

        ip, port, proto = row[0].strip(), int(row[1]), row[2].strip().upper()  # Estrae e normalizza i valori

        if proto != "TCP":                 # Solo il protocollo TCP è supportato
            print(f" Salto {ip}:{port}/{proto} (solo TCP supportato)")
            continue

        print(f"\n Testing {ip}:{port}...")  # Inizia test per questo IP/porta

        durate = []                        # Lista dei tempi di risposta per ogni probe
        for name, payload in probes:       # Ciclo su ogni tipo di probe
            print(f"-> Inviando {name}...")
            t = test_probe(ip, port, payload)        # Testa il probe
            print(f"    Tempo di risposta: {t}s")   # Stampa il risultato
            durate.append(t)                         # Salva il tempo
            time.sleep(INTERVAL_SECONDS)             # Aspetta prima del prossimo probe

        writer.writerow([ip, port, proto] + durate)  # Scrive la riga con tutti i risultati nel CSV

# === MESSAGGIO FINALE ===
print(f"\n CSV completato: '{OUTPUT_FILE}'")  # Messaggio di completamento

