# Opcode Based OpenVPN Traffic Classifier

Questo script Python analizza un file `.pcap` per identificare flussi di rete potenzialmente riconducibili a traffico OpenVPN.  
Supporta sia flussi TCP che UDP e utilizza euristiche basate sugli opcode dei pacchetti per classificare il traffico. L'algoritmo
è basato sullo studio di [Xue et al.](https://www.usenix.org/system/files/sec22-xue-diwen.pdf)

## Requisiti

- Python 3.7 o superiore
- [Scapy](https://scapy.net/) (per leggere e analizzare i pacchetti `.pcap`)

## Installazione delle dipendenze

Installa le dipendenze con:

```bash
pip install scapy
```
## Utilizzo
Per eseguire lo script è necessario passare come argomento il file .pcap:
```bash
python3 script_v3.py /percorso/del/file.pcap
```
Esempio:
```bash
python3 script_v3.py ~/Downloads/traffic_capture.pcap
```
## Output
Lo script mostrerà
- Il numero totale di pacchetti letti.
- I flussi TCP e UDP analizzati.
- Per ogni flusso:
  - Opcode estratti.
  - Classificazione come OpenVPN o Non OpenVPN.
- Elenco finale dei flussi classificati come traffico OpenVPN.


--- 
Script sviluppato da Francesco Magrì per fini di analisi del traffico di rete e fingerprinting del traffico VPN. 
