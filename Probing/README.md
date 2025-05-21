# Active Probing OpenVPN Traffic Classifier

Questo script Python conduce un'attività di Active Porbing su una lista di server e misura i tempi di chiusura della connessione a una serie di payload inviati. I payload inviati ai server sono pubblicati
nello studio di [Xue et al.](https://www.usenix.org/system/files/sec22-xue-diwen.pdf)

## Requisiti

- Python 3.7 o superiore

## Utilizzo
Per eseguire lo script è necessario passare come argomento
- File CSV di input contenente gli indirizzi IP dei server da sondare
- Nome del file CSV di output

```bash
python3 probe_timing.py input.csv output.csv
```
Esempio:
```bash
python3 probe_timing.py online_servers.csv probed_servers.csv
```
## Output
Il file di output.csv conterrà, per ogni server, una riga con:

```bash
IP,Port,Protocol,<tempo_sonda_1>,<tempo_sonda_2>,...,<tempo_sonda_n>
```
Se un probe non riceve risposta entro il timeout, il valore registrato sarà 0.0

## Validazione e testing
Se Il file online_servers.csv incluso nella repository contiene una lista di server pubblici presi dal progetto VPNGate, che pubblica periodicamente IP di server OpenVPN a scopo accademico, e altri server di diverso tipo. Nello specifico:

- 21 Server OpenVPN;
- 3 HTTP;
- 3 FTP;
- 1 SMTP.

Non si garantisce che siano attivi al momento dell'esecuzione. La disposibilità dei server dipende dal mantenimento da parte dei rispettivi volontari.

NB: Affinchè il file di output venga generato correttamente è importante non interrompere forzatamente l'esecuzione dello script.

## Probes Utilizzati

| First Header  | Second Header |
| ------------- | ------------- |
| BaseProbe1  | x00x0ex38.{8}x00x00x00x00x00  |
| BaseProbe2  | x00x0ex38.{8}x00x00x00x00  |
| TCP Generic  | x0dx0ax0dx0a |
| One Zero  | x00  |
| Two Zero  | x00x00  |
| Epmd  | x00x01x6e  |
| SSH  | SSH-2.0-OpenSSH_8.1/r/n  |
| HTTP-GET  | GET/HTTP/1.0 /r /n /r /n  |
| TLS  | Typical Client Hello by Chromium  |
| 2K-Random  | Random 2000 Bytes  |


--- 
Script sviluppato da Francesco Magrì per fini di analisi del traffico di rete e fingerprinting del traffico VPN. 
