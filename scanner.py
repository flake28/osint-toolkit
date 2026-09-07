import argparse
import asyncio
import json
import socket
import sys
import time
from dataclasses import dataclass, field, asdict

# ── palette ──────────────────────────────────────────────────────
DIM   = "\033[2m"
BOLD  = "\033[1m"
RST   = "\033[0m"
GREEN = "\033[32m"
RED   = "\033[31m"
CYAN  = "\033[36m"
YELLOW = "\033[33m"

if sys.platform == "win32":
    import os; os.system("")  # enable ANSI on windows

# ── known services ───────────────────────────────────────────────
SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    43: "whois", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
    80: "http", 110: "pop3", 111: "rpc", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "submission", 631: "ipp",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5672: "amqp",
    5900: "vnc", 6379: "redis", 6443: "k8s-api", 8080: "http-alt",
    8443: "https-alt", 9090: "prometheus", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


# ── data ─────────────────────────────────────────────────────────
@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str = ""
    latency_ms: float = 0.0


@dataclass
class ScanReport:
    target: str
    ip: str
    ports_scanned: int = 0
    open_ports: list = field(default_factory=list)
    elapsed_s: float = 0.0


# ── core scanner ─────────────────────────────────────────────────
class Scanner:
    def __init__(self, target: str, ports: list[int], *,
                 concurrency: int = 200,
                 timeout: float = 1.0,
                 grab_banner: bool = False):
        self.target = target
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.ip = ""
        self._sem: asyncio.Semaphore = None
        self._results: list[PortResult] = []
        self._done = 0
        self._total = len(ports)

    # ── resolve ──────────────────────────────────────────────────
    def resolve(self) -> str:
        try:
            self.ip = socket.gethostbyname(self.target)
            return self.ip
        except socket.gaierror:
            return ""

    # ── single port probe ────────────────────────────────────────
    async def _probe(self, port: int):
        t0 = time.perf_counter()
        async with self._sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.ip, port),
                    timeout=self.timeout,
                )
                latency = (time.perf_counter() - t0) * 1000

                banner = ""
                if self.grab_banner:
                    try:
                        writer.write(b"\r\n")
                        await writer.drain()
                        data = await asyncio.wait_for(
                            writer._transport._protocol._stream_reader.read(256),  # noqa
                            timeout=self.timeout,
                        )
                        banner = data.decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                service = SERVICES.get(port, "unknown")
                self._results.append(PortResult(
                    port=port, state="open", service=service,
                    banner=banner, latency_ms=round(latency, 1),
                ))
            except (asyncio.TimeoutError, OSError):
                pass
            finally:
                self._done += 1

    # ── progress printer ─────────────────────────────────────────
    async def _progress(self):
        while self._done < self._total:
            pct = self._done / self._total * 100
            bar_w = 30
            filled = int(bar_w * self._done / self._total)
            bar = "█" * filled + "░" * (bar_w - filled)
            sys.stderr.write(
                f"\r  {DIM}{bar} {pct:5.1f}%  ({self._done}/{self._total}){RST}"
            )
            sys.stderr.flush()
            await asyncio.sleep(0.15)
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()

    # ── run ───────────────────────────────────────────────────────
    async def run(self) -> ScanReport:
        self._sem = asyncio.Semaphore(self.concurrency)
        t0 = time.perf_counter()

        tasks = [self._probe(p) for p in self.ports]
        progress = asyncio.create_task(self._progress())
        await asyncio.gather(*tasks)
        self._done = self._total  # signal progress to stop
        await progress

        elapsed = time.perf_counter() - t0
        self._results.sort(key=lambda r: r.port)

        return ScanReport(
            target=self.target,
            ip=self.ip,
            ports_scanned=self._total,
            open_ports=self._results,
            elapsed_s=round(elapsed, 2),
        )


# ── port parser ──────────────────────────────────────────────────
def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or '1-1024,8080,9090'."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


# ── display ──────────────────────────────────────────────────────
def print_report(report: ScanReport):
    print(f"\n  {BOLD}portscan report{RST}")
    print(f"  {DIM}{'─' * 48}{RST}")
    print(f"  target    {report.target} ({report.ip})")
    print(f"  scanned   {report.ports_scanned} ports in {report.elapsed_s}s")
    print(f"  open      {len(report.open_ports)}")
    print(f"  {DIM}{'─' * 48}{RST}")

    if not report.open_ports:
        print(f"\n  {YELLOW}no open ports found{RST}\n")
        return

    # header
    print(f"  {DIM}{'PORT':<10}{'STATE':<10}{'SERVICE':<16}{'LATENCY':<10}{'BANNER'}{RST}")

    for r in report.open_ports:
        port_str = f"{r.port}/tcp"
        banner = r.banner[:50] if r.banner else ""
        print(
            f"  {GREEN}{port_str:<10}{RST}"
            f"{BOLD}{'open':<10}{RST}"
            f"{CYAN}{r.service:<16}{RST}"
            f"{DIM}{r.latency_ms:>6.1f} ms{RST}"
            f"  {DIM}{banner}{RST}"
        )

    print(f"  {DIM}{'─' * 48}{RST}\n")


# ── cli ──────────────────────────────────────────────────────────
def cli():
    ap = argparse.ArgumentParser(
        prog="portscan",
        description="lightweight async port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  portscan scanme.nmap.org\n"
               "  portscan 10.0.0.1 -p 1-65535 -c 500\n"
               "  portscan 10.0.0.1 -p 22,80,443 --banner\n",
    )
    ap.add_argument("target", help="hostname or IP")
    ap.add_argument("-p", "--ports", default="1-1024",
                    help="port spec: '80' or '1-1024' or '22,80,443' (default: 1-1024)")
    ap.add_argument("-c", "--concurrency", type=int, default=200,
                    help="max concurrent probes (default: 200)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0,
                    help="connect timeout in seconds (default: 1.0)")
    ap.add_argument("--banner", action="store_true",
                    help="attempt banner grab on open ports")
    ap.add_argument("--json", metavar="FILE",
                    help="write JSON report to FILE")
    return ap.parse_args()


def main():
    args = cli()
    ports = parse_ports(args.ports)

    print(f"\n  {DIM}portscan · {len(ports)} ports · concurrency {args.concurrency}{RST}")

    scanner = Scanner(
        target=args.target,
        ports=ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        grab_banner=args.banner,
    )

    ip = scanner.resolve()
    if not ip:
        print(f"  {RED}error: cannot resolve {args.target}{RST}")
        sys.exit(1)

    print(f"  {DIM}resolved → {ip}{RST}\n")

    report = asyncio.run(scanner.run())
    print_report(report)

    if args.json:
        with open(args.json, "w") as f:
            data = asdict(report)
            json.dump(data, f, indent=2)
        print(f"  {DIM}saved → {args.json}{RST}\n")


if __name__ == "__main__":
    main()


