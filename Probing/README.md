# Active Probing OpenVPN Traffic Classifier

This Python script runs an Active Porbing task on a list of servers and measures the connection closing times for a series of payloads sent. The payloads sent to the servers are published in the paper by [Xue et al.](https://www.usenix.org/system/files/sec22-xue-diwen.pdf)

## Requirements

- Python 3.7 or higher

## Usage
To run the script you need to pass one of the following as an argument
- To Probe multiple targets (1° Mode): Input CSV file containing IP addresses and ports of the servers to probe and Output CSV file name
```bash
python3 probing_script.py -i input.csv -o output.csv
```
- To Probe a single target (2° Mode): IP address and port of the target server
```bash
python3 probing_script.py --addr 10.204.32.123 -p 23
```

## Output
(1° Mode) The output.csv file will contain, for each server, a line with:
```bash
IP,Port,<probe_time_1>,<probe_time_2>,...,<probe_time_n>,<service_found>
```
(2° Mode) The script prints the result of each probe (Short Close or Long Close) with the possible service detected

If a socket has problems, the value logged will be 0.0

## Patterns
The patterns folder contains the patterns.json detected during the testing phase for some services. If one of the patterns matches perfectly (or with at most one mismatch) with the result of the probe, the server is cataloged with the name of the corresponding pattern. The script is designed so that anyone can add other patterns to make the detection more accurate and varied.

## Validation and testing
If The online_servers.csv file included in the repository contains a list of public servers taken from the VPNGate project, which periodically publishes OpenVPN server IPs for academic purposes, and other servers of various types. Specifically:

- 21 OpenVPN;
- 3 HTTP;
- 3 FTP;
- 1 SMTP.

There is no guarantee that they will be active at the time of execution. Server availability depends on maintenance by their respective volunteers.

NB: In order for the output file to be generated correctly, it is important not to forcibly interrupt the execution of the script.

## Probes Used

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
Script developed by Francesco Magrì for network traffic analysis and VPN traffic fingerprinting purposes. 
