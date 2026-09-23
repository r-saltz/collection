#!/usr/bin/env python3
"""
DNS Domain Activity Checker - Live Progress Edition
Verifies if domains are active by checking DNS resolution.

Display modes (--mode):
  live    -> Header top, results scroll middle, progress bar fixed bottom
  compact -> One line per result, no progress bar
  table   -> Formatted table output after all checks complete
  quiet   -> Only summary at end, no per-domain output

Usage:
    python3 dns_checker.py example.com
    python3 dns_checker.py -f domains.txt
    python3 dns_checker.py -f domains.txt --mode table
    python3 dns_checker.py -f domains.txt --mode compact --no-color
"""

import socket
import sys
import argparse
import json
import time
import os
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ═══════════════════════════════════════════════════════════════
#  Colors
# ═══════════════════════════════════════════════════════════════

class C:
    RESET    = "\033[0m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"
    RED      = "\033[91m"
    GREEN    = "\033[92m"
    YELLOW   = "\033[93m"
    BLUE     = "\033[94m"
    CYAN     = "\033[96m"
    WHITE    = "\033[97m"
    BG_GREEN = "\033[42m"
    BG_RED   = "\033[41m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


STATS_LINES = 3


# ═══════════════════════════════════════════════════════════════
#  Display Base Class
# ═══════════════════════════════════════════════════════════════

class DisplayBase:
    """Common state and helpers shared by all display modes."""

    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.active = 0
        self.inactive = 0
        self.start_time = time.time()
        self.results = []
        self.lock = threading.Lock()

    def _elapsed(self) -> str:
        return str(timedelta(seconds=int(time.time() - self.start_time)))

    def _eta(self) -> str:
        if self.completed == 0:
            return "--:--:--"
        elapsed = time.time() - self.start_time
        remaining = (elapsed / self.completed) * (self.total - self.completed)
        return str(timedelta(seconds=int(remaining)))

    def _speed(self) -> float:
        return self.completed / max(time.time() - self.start_time, 0.1)

    def _progress_bar(self, width: int = 30) -> str:
        pct = self.completed / self.total if self.total else 0
        filled = int(width * pct)
        return (
            f"{C.BG_GREEN}{C.WHITE}{'█' * filled}{C.RESET}"
            f"{C.DIM}{'░' * (width - filled)}{C.RESET}"
        )

    def _tw(self) -> int:
        try:
            return os.get_terminal_size().columns
        except OSError:
            return 100

    def _th(self) -> int:
        try:
            return os.get_terminal_size().lines
        except OSError:
            return 40

    @staticmethod
    def _go(row: int, col: int = 1):
        sys.stdout.write(f"\033[{row};{col}H")

    @staticmethod
    def _fmt_records(records: dict) -> str:
        parts = []
        for rtype, values in records.items():
            if rtype in ("A", "AAAA"):
                parts.append(f"{C.CYAN}{rtype}{C.RESET}:{values[0]}")
            elif rtype == "MX":
                parts.append(f"{C.YELLOW}MX{C.RESET}:{values[0].split()[1] if values else ''}")
            elif rtype == "NS":
                parts.append(f"{C.BLUE}NS{C.RESET}:{len(values)}")
            elif rtype == "TXT":
                parts.append(f"{C.DIM}TXT{C.RESET}:{len(values)}")
            elif rtype == "SOA":
                parts.append(f"{C.DIM}SOA{C.RESET}:✓")
            elif rtype == "CNAME":
                parts.append(f"{C.CYAN}CNAME{C.RESET}:{values[0]}")
        return " ".join(parts) if parts else f"{C.DIM}no records{C.RESET}"

    @staticmethod
    def _fmt_status(is_active: bool) -> str:
        if is_active:
            return f"{C.GREEN}✓ ACTIVE{C.RESET}"
        return f"{C.RED}✗ INACTIVE{C.RESET}"

    def _count_result(self, result: dict):
        with self.lock:
            self.completed += 1
            if result.get("active"):
                self.active += 1
            else:
                self.inactive += 1
            self.results.append(result)

    # abstract
    def start(self): ...
    def update(self, result: dict): ...
    def finish(self): ...


# ═══════════════════════════════════════════════════════════════
#  Mode: live  (default)
# ═══════════════════════════════════════════════════════════════

class DisplayLive(DisplayBase):
    """Header top, scrolling results middle, fixed progress bar bottom."""

    def __init__(self, total: int):
        super().__init__(total)
        self._is_tty = sys.stdout.isatty()
        self._scroll_top = 4
        self._scroll_bottom = 24
        self._stats_row = 22

    def _draw_header(self):
        w = self._tw()
        print(f"{C.BOLD}{C.CYAN}╔{'═' * (w - 2)}╗{C.RESET}")
        title = " 🔍 DNS Domain Activity Checker "
        pad = w - 2 - len(title) - 1
        print(f"{C.BOLD}{C.CYAN}║{C.RESET}{title}{' ' * max(pad, 1)}{C.BOLD}{C.CYAN}║{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}╚{'═' * (w - 2)}╝{C.RESET}")

    def _draw_stats(self):
        w = self._tw()
        r = self._stats_row
        bar = self._progress_bar(35)
        pct = (self.completed / self.total * 100) if self.total else 0

        self._go(r, 1)
        sys.stdout.write(f"\033[2K  {C.DIM}{'━' * (w - 4)}{C.RESET}")
        self._go(r + 1, 1)
        sys.stdout.write(
            f"\033[2K  {bar}  {C.BOLD}{pct:5.1f}%{C.RESET}  "
            f"({self.completed}/{self.total})"
        )
        self._go(r + 2, 1)
        sys.stdout.write(
            f"\033[2K  "
            f"{C.GREEN}✓ Active: {self.active}{C.RESET}  "
            f"{C.RED}✗ Inactive: {self.inactive}{C.RESET}  "
            f"{C.DIM}⏱ {self._elapsed()}{C.RESET}  "
            f"{C.DIM}⏳ ETA {self._eta()}{C.RESET}  "
            f"{C.DIM}⚡ {self._speed():.1f} dom/s{C.RESET}"
        )
        sys.stdout.flush()

    def start(self):
        if not self._is_tty:
            print(f"[*] Checking {self.total} domain(s)...")
            return
        h = self._th()
        self._scroll_top = 4
        self._scroll_bottom = h - STATS_LINES
        self._stats_row = h - STATS_LINES + 1
        sys.stdout.write("\033[2J\033[H")
        self._draw_header()
        sys.stdout.write(f"\033[{self._scroll_top};{self._scroll_bottom}r")
        self._draw_stats()
        self._go(self._scroll_top, 1)
        sys.stdout.flush()

    def update(self, result: dict):
        self._count_result(result)
        domain = result["domain"]
        is_active = result.get("active", False)
        line = (
            f"  {self._fmt_status(is_active)}  "
            f"{C.BOLD}{domain:<40}{C.RESET}  "
            f"{self._fmt_records(result.get('records', {}))}"
        )
        if self._is_tty:
            print(line)
            sys.stdout.write("\033[s")
            self._draw_stats()
            sys.stdout.write("\033[u")
        else:
            print(line)
        sys.stdout.flush()

    def finish(self):
        if self._is_tty:
            sys.stdout.write("\033[r")
            self._go(self._stats_row + STATS_LINES + 1, 1)
        self._print_summary()

    def _print_summary(self):
        w = self._tw()
        print(f"\n{C.BOLD}{'═' * w}{C.RESET}")
        print(f"  {C.BOLD}📊 SUMMARY{C.RESET}")
        print(f"  {'─' * 40}")
        print(f"  Total checked : {C.BOLD}{self.total}{C.RESET}")
        print(f"  {C.GREEN}✓ Active      : {self.active}{C.RESET}")
        print(f"  {C.RED}✗ Inactive    : {self.inactive}{C.RESET}")
        print(f"  {C.DIM}⏱ Total time  : {self._elapsed()}{C.RESET}")
        print(f"  {C.DIM}⚡ Avg speed   : {self._speed():.1f} domains/sec{C.RESET}")
        print(f"{C.BOLD}{'═' * w}{C.RESET}")


# ═══════════════════════════════════════════════════════════════
#  Mode: compact
# ═══════════════════════════════════════════════════════════════

class DisplayCompact(DisplayBase):
    """One line per result, no progress bar, minimal output."""

    def start(self):
        pass

    def update(self, result: dict):
        self._count_result(result)
        domain = result["domain"]
        is_active = result.get("active", False)
        if is_active:
            icon = f"{C.GREEN}✓{C.RESET}"
        else:
            icon = f"{C.RED}✗{C.RESET}"
        print(f"  {icon} {domain}")

    def finish(self):
        total = self.total
        act = self.active
        inact = self.inactive
        print(f"\n  {C.BOLD}[{act}/{total} active | {inact} inactive | {self._elapsed()} | {self._speed():.1f} dom/s]{C.RESET}")


# ═══════════════════════════════════════════════════════════════
#  Mode: table
# ═══════════════════════════════════════════════════════════════

class DisplayTable(DisplayBase):
    """Formatted table output after all checks complete."""

    def start(self):
        print(f"\n  {C.DIM}[*] Checking {self.total} domain(s)...{C.RESET}")

    def update(self, result: dict):
        self._count_result(result)
        # dot progress
        pct = self.completed / self.total * 100
        bar_w = 30
        filled = int(bar_w * self.completed / self.total)
        bar = f"{C.GREEN}{'█' * filled}{C.DIM}{'░' * (bar_w - filled)}{C.RESET}"
        sys.stdout.write(f"\r  {bar}  {pct:5.1f}%  ({self.completed}/{self.total})")
        sys.stdout.flush()

    def finish(self):
        sys.stdout.write("\033[2K\r")
        sys.stdout.flush()

        # Calculate column widths
        domains = [r["domain"] for r in self.results]
        max_dom = max(len(d) for d in domains) if domains else 10
        max_dom = max(max_dom, 8)

        # Header
        w = max_dom + 30
        print(f"\n{'─' * w}")
        print(
            f"  {C.BOLD}{('Domain').ljust(max_dom)}  "
            f"{'Status':<10}  "
            f"{'A/AAAA':<20}  "
            f"{'Records'}{C.RESET}"
        )
        print(f"{'─' * w}")

        for r in self.results:
            domain = r["domain"]
            is_active = r.get("active", False)
            records = r.get("records", {})

            if is_active:
                status = f"{C.GREEN}ACTIVE{C.RESET}"
                icon = f"{C.GREEN}✓{C.RESET}"
            else:
                status = f"{C.RED}INACTIVE{C.RESET}"
                icon = f"{C.RED}✗{C.RESET}"

            # Primary IP
            ip = ""
            if "A" in records:
                ip = records["A"][0]
            elif "AAAA" in records:
                ip = records["AAAA"][0]

            # Record summary
            rec_parts = []
            if "MX" in records:
                rec_parts.append(f"MX:{records['MX'][0].split()[1]}")
            if "NS" in records:
                rec_parts.append(f"NS:{len(records['NS'])}")
            if "TXT" in records:
                rec_parts.append(f"TXT:{len(records['TXT'])}")
            if "SOA" in records:
                rec_parts.append("SOA")
            rec_str = " ".join(rec_parts)

            print(
                f"  {icon} {domain.ljust(max_dom)}  "
                f"{status:<20}  "
                f"{ip:<20}  "
                f"{rec_str}"
            )

        # Summary
        print(f"{'─' * w}")
        print(
            f"  {C.GREEN}✓ {self.active} active{C.RESET}  "
            f"{C.RED}✗ {self.inactive} inactive{C.RESET}  "
            f"{C.DIM}⏱ {self._elapsed()}{C.RESET}  "
            f"{C.DIM}⚡ {self._speed():.1f} dom/s{C.RESET}"
        )
        print(f"{'─' * w}\n")


# ═══════════════════════════════════════════════════════════════
#  Mode: quiet
# ═══════════════════════════════════════════════════════════════

class DisplayQuiet(DisplayBase):
    """Only summary at end, no per-domain output."""

    def start(self):
        pass

    def update(self, result: dict):
        self._count_result(result)

    def finish(self):
        print(
            f"  {C.BOLD}{self.total}{C.RESET} checked  "
            f"{C.GREEN}✓ {self.active}{C.RESET}  "
            f"{C.RED}✗ {self.inactive}{C.RESET}  "
            f"{C.DIM}{self._elapsed()}  {self._speed():.1f} dom/s{C.RESET}"
        )


# ═══════════════════════════════════════════════════════════════
#  File writer (incremental)
# ═══════════════════════════════════════════════════════════════

class FileOutput:
    """Writes results to file incrementally as they arrive."""

    def __init__(self, path: str):
        self._fh = open(path, "w", encoding="utf-8")
        self._fh.write(
            f"# DNS Domain Check - {datetime.now():%Y-%m-%d %H:%M:%S}\n"
        )
        self._fh.write(
            f"# {'Domain':<40} {'Status':<10} {'Records'}\n"
        )
        self._fh.write("# " + "-" * 80 + "\n")
        self._fh.flush()

    def write(self, result: dict):
        domain = result["domain"]
        status = "ACTIVE" if result.get("active") else "INACTIVE"
        recs = result.get("records", {})
        rec_str = (
            ", ".join(f"{k}:{v[0]}" for k, v in recs.items() if v)
            if recs else "-"
        )
        self._fh.write(f"  {domain:<40} {status:<10} {rec_str}\n")
        self._fh.flush()

    def close(self, total: int, active: int, inactive: int):
        self._fh.write(
            f"\n# Summary: {total} checked | "
            f"{active} active | {inactive} inactive\n"
        )
        self._fh.close()


# ═══════════════════════════════════════════════════════════════
#  Display factory
# ═══════════════════════════════════════════════════════════════

DISPLAY_MODES = {
    "live": DisplayLive,
    "compact": DisplayCompact,
    "table": DisplayTable,
    "quiet": DisplayQuiet,
}


# ═══════════════════════════════════════════════════════════════
#  DNS Checking Functions
# ═══════════════════════════════════════════════════════════════

def check_domain_basic(domain: str) -> dict:
    result = {
        "domain": domain, "active": False, "records": {},
        "error": None, "timestamp": datetime.now().isoformat(),
    }
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        if ips:
            result["active"] = True
            result["records"]["A"] = list(set(ip[4][0] for ip in ips))
    except socket.gaierror:
        pass
    try:
        ips6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
        if ips6:
            result["active"] = True
            result["records"]["AAAA"] = list(set(ip[4][0] for ip in ips6))
    except socket.gaierror:
        pass
    if not result["active"]:
        result["error"] = "DNS resolution failed - domain not found"
    return result


def check_domain_full(domain: str, nameserver: str = None) -> dict:
    result = {
        "domain": domain, "active": False, "records": {},
        "nameserver": nameserver or "system default",
        "error": None, "timestamp": datetime.now().isoformat(),
    }
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.timeout = 5
    resolver.lifetime = 10
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records = [str(rdata) for rdata in answers]
            if records:
                result["records"][rtype] = records
                result["active"] = True
        except (
            dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.name.EmptyLabel,
        ):
            pass
        except Exception:
            pass
    if not result["active"]:
        result["error"] = "No DNS records found - domain appears inactive"
    return result


def check_domain(domain: str, nameserver: str = None) -> dict:
    domain = domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]
    if not domain:
        return {"domain": domain, "active": False, "error": "Empty domain"}
    if HAS_DNSPYTHON:
        return check_domain_full(domain, nameserver)
    return check_domain_basic(domain)


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="DNS Domain Activity Checker - Live Progress Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Display Modes (--mode):\n"
            "  live     Header + scrolling results + fixed progress bar (default)\n"
            "  compact  One line per domain, no progress bar\n"
            "  table    Formatted table after all checks complete\n"
            "  quiet    Only summary at end\n"
            "\n"
            "Examples:\n"
            "  python3 dns_checker.py example.com\n"
            "  python3 dns_checker.py -f domains.txt\n"
            "  python3 dns_checker.py -f domains.txt --mode table\n"
            "  python3 dns_checker.py -f domains.txt --mode compact --no-color\n"
            "  python3 dns_checker.py -f domains.txt -j -o results.json\n"
            "  python3 dns_checker.py example.com --ns 8.8.8.8\n"
        ),
    )

    parser.add_argument("domains", nargs="*", help="Domain(s) to check")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("--ns", "--nameserver", help="DNS nameserver to use")
    parser.add_argument(
        "--mode", choices=list(DISPLAY_MODES.keys()), default="live",
        help="Display mode (default: live)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output (for piping)",
    )
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON at end")
    parser.add_argument("-o", "--output", help="Save results to file (live incremental)")
    parser.add_argument(
        "-w", "--workers", type=int, default=20,
        help="Max concurrent threads (default: 20)",
    )

    args = parser.parse_args()

    # Disable colors if requested or piped
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    # Collect domains
    domains = list(args.domains) if args.domains else []
    if args.file:
        try:
            with open(args.file) as f:
                domains.extend(
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                )
        except FileNotFoundError:
            print(f"{C.RED}Error: File '{args.file}' not found{C.RESET}")
            sys.exit(1)

    if not domains:
        parser.print_help()
        sys.exit(1)

    if not HAS_DNSPYTHON:
        print(f"\n  {C.YELLOW}[!] dnspython not installed - using basic socket resolution{C.RESET}")
        print(f"  {C.DIM}    Install for full features: pip install dnspython{C.RESET}")

    # Init display mode
    display_cls = DISPLAY_MODES[args.mode]
    display = display_cls(total=len(domains))

    # Init file output
    file_out = None
    if args.output:
        file_out = FileOutput(args.output)

    display.start()

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [
                executor.submit(check_domain, d, args.ns)
                for d in domains
            ]
            for future in futures:
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        "domain": "unknown", "active": False,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                    }
                display.update(result)
                if file_out:
                    file_out.write(result)

        display.finish()

        if file_out:
            file_out.close(display.total, display.active, display.inactive)

    except KeyboardInterrupt:
        if isinstance(display, DisplayLive) and sys.stdout.isatty():
            sys.stdout.write("\033[r")
        print(f"\n  {C.YELLOW}[!] Interrupted - {display.completed}/{display.total} completed{C.RESET}")
        display.finish()
        if file_out:
            file_out.close(display.total, display.active, display.inactive)
        sys.exit(130)

    # JSON output
    if args.json:
        json_out = json.dumps(display.results, indent=2, ensure_ascii=False)
        print(f"\n{C.DIM}[JSON Output]{C.RESET}")
        print(json_out)
        if args.output and args.output.endswith(".json"):
            with open(args.output, "w") as f:
                f.write(json_out)
            print(f"\n  {C.GREEN}[*] JSON saved to {args.output}{C.RESET}")


if __name__ == "__main__":
    main()
