# Importing the necessary modules
import socket       # For the TCP/IP communication
import time         # To measure response time and manage waiting times
import csv          # To read and write CSV files
import os           # To generate random payloads
import argparse     # To handle command line input
from concurrent.futures import ThreadPoolExecutor, as_completed
from matcher import load_all_patterns, match_result_to_patterns
import textwrap

# === PARSING COMMAND LINE ARGUMENTS ===
parser = argparse.ArgumentParser(
    prog="prober",
    description="TCP Probing tool to identify servers' nature",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=textwrap.dedent("""\
        Example of use:
          python tcp_prober.py [-i input.csv -o output.csv] [--addr 192.168.1.1 -p 443]

        Structure of the input csv file:
          IP,Port
          192.168.1.1,22
          10.0.0.1,80

        INFO:
          - Only TCP connections are supported
          - All payloads will be sent for each IP:Port
    """)
)
parser.add_argument("-i", "--input", type=str, default="input.csv", help="CSV input file")
parser.add_argument("-o", "--output", type=str, default="output.csv", help="CSV output file")
parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout in seconds for server response (default: 5s)")
parser.add_argument("--addr", type=str, help="Target's IP address")
parser.add_argument("-p", "--port", type=int, help="Target's Port")
parser.add_argument("-pA", "--print-all", action="store_true", help="Print all probing details")

args = parser.parse_args()

# === CONFIGURATION ===
patterns = load_all_patterns()
INPUT_FILE = args.input         # CSV file to read the addresses to probe from
OUTPUT_FILE = args.output       # CSV file to write the results to
TIMEOUT = int(args.timeout)     # Timeout for response from server (in seconds)
# === DEFINITION OF PROBES TO BE SENT===
probes = [
    ("BaseProbe1", b"\x00\x0E\x38" + b"\x41" * 8 + b"\x00\x00\x00\x00\x00"),  # Default binary payload
    ("BaseProbe2", b"\x00\x0E\x38" + b"\x41" * 8 + b"\x00\x00\x00\x00"),
    ("TCP_Generic", b"\x0d\x0a\x0d\x0a"),                                     # Simulate HTTP header end
    ("One_Zero", b"\x00"),                                                   # A single null byte
    ("Two_Zero", b"\x00\x00"),                                               # Two null bytes
    ("Epmd", b"\x00\x01\x6e"),                                               # Specific probe for Erlang Port Mapper Daemon
    ("SSH", b"SSH-2.0-OpenSSH_8.1\r\n"),                                      # SSH Fake Banner
    ("HTTP_GET", b"GET / HTTP/1.0\r\n\r\n"),                                  # HTTP GET request
    ("TLS", bytes.fromhex("16030100d9010000d50303" + "00" * 211)),            # Incomplete TLS handshake
    ("2K_Random", os.urandom(2000))                                          # Random payload of 2000 bytes
]

def classify_duration(t):
    if t == 0.0:
        return "Error"
    elif t >= TIMEOUT - 0.5:
        return "Long Close"
    elif t < 2.0:
        return "Short Close"
    else:
        return "Other"
    
def print_summary_table(results):
    print("\n=== Overview ===")
    print("{:<20} {:<10} {:<15}".format("Probe", "Duration", "Result"))
    print("-" * 45)
    for r in results:
        print("{:<20} {:<10} {:<15}".format(r["probe_name"], str(r["duration"]), r["status"]))
    print("-" * 45)

# === FUNZIONE PER INVIARE UN PROBE E MISURARE LA RISPOSTA ===
def probe_single_target(ip, port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
        s.settimeout(TIMEOUT)                                  # Set timeout
        s.connect((ip, port))                                  # Connects to the destination host
        s.sendall(payload)                                     # Send the payload

        start = time.time()                                    # Start the timer
        try:
            data = s.recv(4096)                                # Waiting for a response (up to 4096 bytes)
            end = time.time()                                  # Record time at reception
            duration = round(end - start, 3)                   # Calculate rounded duration
            if data:
                if args.print_all:                                           # If there is a response
                    print("   Reply " + str(data))
            else:
                if args.print_all:                                              # Socket closed without data
                    print("   No Reply (socket closed)")
        except socket.timeout:
            if args.print_all:                                 # Timeout expired
                print("   Timeout (No Reply)")
            duration = round(time.time() - start, 3)           # Record time anyway
        except socket.error as e:
            if args.print_all:                              # Reception error
                print(f"   Reception Error: {e}")
            duration = round(time.time() - start, 3)
        finally:
            s.close()                                          # Close the socket anyway
        return duration                                        # Return response time
    except Exception as e:
        if args.print_all:                                     # Any other errors (e.g. connection failed)
            print(f"   Connection Failed: {e}")
        return 0.0                                             # No response, returns 0


def send_multiple_probes(ip, port):
    print(f"\n Testing {ip}:{port}...")
    results = []
    
    def wrapped_probe(name, payload):
        if args.print_all:
            print(f"-> Sending {name}...")
        t = probe_single_target(ip, port, payload)
        status = classify_duration(t)
        if args.print_all:
            print(f"    Response Time: {t}s -> {status}")
        return {
            "probe_name": name,
            "duration": t,
            "status": status
        }
    # To run each probe in a different thread
    with ThreadPoolExecutor(max_workers=len(probes)) as executor:
        futures = [executor.submit(wrapped_probe, name, payload) for name, payload in probes]
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                if args.print_all:
                    print(f"   Probe Error: {e}")

    # Sort the results in the same original sequence as the probes
    results.sort(key=lambda r: [name for name, _ in probes].index(r["probe_name"]))

    print_summary_table(results)
    
    # Matching results with patterns
    matched_labels = match_result_to_patterns(results, patterns)

    print(f"    Match: {matched_labels}")

    return results

def probes_from_csv():
    with open(INPUT_FILE, newline='') as infile, open(OUTPUT_FILE, 'w', newline='') as outfile:
            reader = csv.reader(infile)             # CSV reader to read IP and port
            writer = csv.writer(outfile)           # CSV writer to save results

            for row in reader:
                if not row or len(row) < 2:        # Skip blank or incomplete lines
                    continue

                ip, port = row[0].strip(), int(row[1])  # Extracts and normalizes values
                durations = send_multiple_probes(ip, port)
                matched = match_result_to_patterns(durations, patterns)
                writer.writerow([ip, port] + [r["duration"] for r in durations] + [str(matched)])


def main():
    if args.addr and args.port:
        # If the user passed both --addr and --port, probe that address.
        print(f"Probing {args.addr}:{args.port}...")
        results = send_multiple_probes(args.addr, args.port)
    elif args.input and args.output: #If the user has passed a csv file
        print(f"Probing Targets on file {args.input}...")
        probes_from_csv()
        print(f"\n CSV Completed: '{OUTPUT_FILE}'")
    else: print(f"\n Please, give an IP Address with Port or a csv file. For Help -h")

if __name__ == "__main__":
    main()  # Run main function when file is run as script


