#!/usr/bin/env python3
"""
DNS Domain Activity Checker - Live Progress Edition
Verifies if domains are active by checking DNS resolution.

Usage:
    python3 dns_checker.py example.com
    python3 dns_checker.py -f domains.txt
    python3 dns_checker.py domain1.com domain2.com domain3.com
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

# ANSI colors
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_GREEN = "\033[42m"
    BG_RED   = "\033[41m"
    BG_BLUE  = "\033[44m"


class LiveProgress:
    """Live progress display with real-time updates."""
    
    def __init__(self, total: int, output_file: str = None, json_output: bool = False):
        self.total = total
        self.completed = 0
        self.active = 0
        self.inactive = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.results = []
        self.output_file = output_file
        self.json_output = json_output
        self._file_handle = None
        
        if output_file and not json_output:
            self._file_handle = open(output_file, "w", encoding="utf-8")
            self._file_handle.write(f"# DNS Domain Check Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self._file_handle.write(f"# {'Domain':<40} {'Status':<10} {'Records'}\n")
            self._file_handle.write("# " + "-" * 80 + "\n")
            self._file_handle.flush()
    
    def _elapsed(self) -> str:
        return str(timedelta(seconds=int(time.time() - self.start_time)))
    
    def _eta(self) -> str:
        if self.completed == 0:
            return "--:--:--"
        elapsed = time.time() - self.start_time
        avg = elapsed / self.completed
        remaining = avg * (self.total - self.completed)
        return str(timedelta(seconds=int(remaining)))
    
    def _progress_bar(self, width: int = 30) -> str:
        pct = self.completed / self.total if self.total else 0
        filled = int(width * pct)
        bar = f"{C.BG_GREEN}{C.WHITE}{'█' * filled}{C.RESET}{C.DIM}{'░' * (width - filled)}{C.RESET}"
        return bar
    
    def _get_terminal_width(self) -> int:
        try:
            return os.get_terminal_size().columns
        except OSError:
            return 100
    
    def _clear_lines(self, n: int):
        for _ in range(n):
            sys.stdout.write("\033[2K")  # Clear line
            sys.stdout.write("\033[1A")  # Move up
        sys.stdout.write("\033[2K")  # Clear current
    
    def _format_records(self, records: dict) -> str:
        parts = []
        for rtype, values in records.items():
            if rtype in ("A", "AAAA"):
                parts.append(f"{C.CYAN}{rtype}{C.RESET}: {values[0]}")
            elif rtype == "MX":
                parts.append(f"{C.YELLOW}MX{C.RESET}: {values[0].split()[1] if values else ''}")
            elif rtype == "NS":
                parts.append(f"{C.BLUE}NS{C.RESET}: {len(values)} servers")
            elif rtype == "TXT":
                parts.append(f"{C.DIM}TXT{C.RESET}: {len(values)} records")
            elif rtype == "SOA":
                parts.append(f"{C.DIM}SOA{C.RESET}: ✓")
        return " | ".join(parts) if parts else f"{C.DIM}no records{C.RESET}"
    
    def _draw_header(self):
        w = self._get_terminal_width()
        print(f"\n{C.BOLD}{C.CYAN}╔{'═' * (w - 2)}╗{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}║{C.RESET}  {C.BOLD}🔍 DNS Domain Activity Checker{C.RESET}{' ' * (w - 35)}{C.BOLD}{C.CYAN}║{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}╚{'═' * (w - 2)}╝{C.RESET}")
    
    def _draw_stats(self):
        bar = self._progress_bar(35)
        pct = (self.completed / self.total * 100) if self.total else 0
        
        stats_line1 = f"  {bar}  {C.BOLD}{pct:5.1f}%{C.RESET}  ({self.completed}/{self.total})"
        stats_line2 = (f"  {C.GREEN}✓ Active: {self.active}{C.RESET}  "
                       f"{C.RED}✗ Inactive: {self.inactive}{C.RESET}  "
                       f"{C.DIM}⏱ Elapsed: {self._elapsed()}{C.RESET}  "
                       f"{C.DIM}⏳ ETA: {self._eta()}{C.RESET}")
        
        print(stats_line1)
        print(stats_line2)
    
    def start(self):
        self._draw_header()
        self._draw_stats()
        sys.stdout.flush()
    
    def update(self, result: dict):
        with self.lock:
            self.completed += 1
            if result.get("active"):
                self.active += 1
            else:
                self.inactive += 1
            self.results.append(result)
            
            # Save to file immediately
            if self._file_handle:
                domain = result["domain"]
                status = "ACTIVE" if result.get("active") else "INACTIVE"
                recs = result.get("records", {})
                rec_str = ", ".join(f"{k}:{v[0]}" for k, v in recs.items() if v) if recs else "-"
                self._file_handle.write(f"  {domain:<40} {status:<10} {rec_str}\n")
                self._file_handle.flush()
            
            # Redraw live display (scroll mode - print result, then refresh stats)
            domain = result["domain"]
            active = result.get("active", False)
            
            if active:
                icon = f"{C.GREEN}✓{C.RESET}"
                status_str = f"{C.GREEN}ACTIVE{C.RESET}"
            else:
                icon = f"{C.RED}✗{C.RESET}"
                status_str = f"{C.RED}INACTIVE{C.RESET}"
            
            records_str = self._format_records(result.get("records", {}))
            
            # Print result line (scrolling, not in-place)
            print(f"  {icon} {C.BOLD}{domain:<40}{C.RESET} {status_str:<20} {records_str}")
            
            # Overwrite stats at bottom
            self._draw_stats()
            sys.stdout.flush()
    
    def finish(self):
        if self._file_handle:
            self._file_handle.write(f"\n# Summary: {self.total} checked | {self.active} active | {self.inactive} inactive\n")
            self._file_handle.close()
        
        w = self._get_terminal_width()
        print(f"\n{C.BOLD}{'═' * w}{C.RESET}")
        print(f"  {C.BOLD}📊 SUMMARY{C.RESET}")
        print(f"  {'─' * 40}")
        print(f"  Total checked : {C.BOLD}{self.total}{C.RESET}")
        print(f"  {C.GREEN}✓ Active      : {self.active}{C.RESET}")
        print(f"  {C.RED}✗ Inactive    : {self.inactive}{C.RESET}")
        print(f"  {C.DIM}⏱ Total time  : {self._elapsed()}{C.RESET}")
        print(f"  {C.DIM}⚡ Avg speed   : {self.total / max(time.time() - self.start_time, 0.1):.1f} domains/sec{C.RESET}")
        print(f"{C.BOLD}{'═' * w}{C.RESET}")


# ─── DNS Checking Functions ─────────────────────────────────────────

def check_domain_basic(domain: str) -> dict:
    """Check domain using standard socket library (always available)."""
    result = {
        "domain": domain,
        "active": False,
        "records": {},
        "error": None,
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        if ips:
            result["active"] = True
            result["records"]["A"] = list(set(ip[4][0] for ip in ips))
    except socket.gaierror:
        pass
    
    try:
        ips_v6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
        if ips_v6:
            result["active"] = True
            result["records"]["AAAA"] = list(set(ip[4][0] for ip in ips_v6))
    except socket.gaierror:
        pass
    
    if not result["active"]:
        result["error"] = "DNS resolution failed - domain not found"
    
    return result


def check_domain_full(domain: str, nameserver: str = None) -> dict:
    """Check domain using dnspython for detailed DNS records."""
    result = {
        "domain": domain,
        "active": False,
        "records": {},
        "nameserver": nameserver or "system default",
        "error": None,
        "timestamp": datetime.now().isoformat()
    }
    
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.timeout = 5
    resolver.lifetime = 10
    
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = [str(rdata) for rdata in answers]
            if records:
                result["records"][rtype] = records
                result["active"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.name.EmptyLabel):
            pass
        except Exception:
            pass
    
    if not result["active"]:
        result["error"] = "No DNS records found - domain appears inactive"
    
    return result


def check_domain(domain: str, nameserver: str = None) -> dict:
    """Check single domain - uses dnspython if available, fallback to basic."""
    domain = domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0]
    
    if not domain:
        return {"domain": domain, "active": False, "error": "Empty domain"}
    
    if HAS_DNSPYTHON:
        return check_domain_full(domain, nameserver)
    else:
        return check_domain_basic(domain)


# ─── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DNS Domain Activity Checker - Live Progress Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 dns_checker.py example.com
  python3 dns_checker.py google.com github.com cloudflare.com
  python3 dns_checker.py -f domains.txt
  python3 dns_checker.py -f domains.txt -j -o results.json
  python3 dns_checker.py example.com --ns 8.8.8.8
"""
    )
    
    parser.add_argument("domains", nargs="*", help="Domain(s) to check")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("--ns", "--nameserver", help="DNS nameserver to use")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON at end")
    parser.add_argument("-o", "--output", help="Save results to file (live writing)")
    parser.add_argument("-w", "--workers", type=int, default=20, help="Max concurrent threads (default: 20)")
    
    args = parser.parse_args()
    
    # Collect domains
    domains = list(args.domains) if args.domains else []
    
    if args.file:
        try:
            with open(args.file, "r") as f:
                file_domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                domains.extend(file_domains)
        except FileNotFoundError:
            print(f"{C.RED}Error: File '{args.file}' not found{C.RESET}")
            sys.exit(1)
    
    if not domains:
        parser.print_help()
        sys.exit(1)
    
    # Show library status
    if not HAS_DNSPYTHON:
        print(f"\n  {C.YELLOW}[!] dnspython not installed - using basic socket resolution{C.RESET}")
        print(f"  {C.DIM}    Install for full features: pip install dnspython{C.RESET}")
    
    # Initialize live progress
    progress = LiveProgress(
        total=len(domains),
        output_file=args.output,
        json_output=args.json
    )
    progress.start()
    
    # Run checks with live updates
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_domain = {
            executor.submit(check_domain, domain, args.ns): domain
            for domain in domains
        }
        
        for future in as_completed(future_to_domain):
            try:
                result = future.result()
            except Exception as e:
                domain = future_to_domain[future]
                result = {
                    "domain": domain,
                    "active": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
            progress.update(result)
    
    progress.finish()
    
    # JSON output at end
    if args.json:
        json_out = json.dumps(progress.results, indent=2, ensure_ascii=False)
        print(f"\n{C.DIM}[JSON Output]{C.RESET}")
        print(json_out)
        if args.output and args.output.endswith(".json"):
            with open(args.output, "w") as f:
                f.write(json_out)
            print(f"\n  {C.GREEN}[*] JSON saved to {args.output}{C.RESET}")


if __name__ == "__main__":
    main()
