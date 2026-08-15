import socket
import threading

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 3306: "MySQL",
    5432: "PostgreSQL", 8080: "HTTP-Alt",
}

open_ports = []
lock = threading.Lock()

def scan_port(target: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        service = COMMON_PORTS.get(port, "Unknown")
        with lock:
            open_ports.append((port, service))

def scan_target(target: str):
    print(f"Scanning {target}...\n")
    threads = []
    for port in range(1, 1025):
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    for port, service in sorted(open_ports):
        print(f"  [{port}] {service} — OPEN")
    print("\nDone.")

scan_target("scanme.nmap.org")


