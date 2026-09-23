#!/usr/bin/env python3
"""DNS Domain Activity Checker
Verify domain activity via DNS resolution with detailed record output.

Features:
  - Multi-threaded concurrent domain checking
  - A, AAAA, MX, NS, TXT, SOA, CNAME record resolution
  - Incremental file output (crash-safe)
  - Custom nameserver support
  - Graceful CTRL+C handling
"""

import socket, sys, os, json, time, signal, argparse, threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

VERSION = "2.0"

# ═══════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


# ═══════════════════════════════════════════════════════════════
# CTRL+C Graceful Shutdown
# ═══════════════════════════════════════════════════════════════
_shutdown = False
def _sigint_handler(sig, frame):
    global _shutdown
    if _shutdown:
        print("\n\033[31m[!] Force quit\033[0m")
        sys.exit(1)
    _shutdown = True
    print("\n\033[33m[!] CTRL+C \u2014 finishing current domains, then saving...\033[0m")
signal.signal(signal.SIGINT, _sigint_handler)


# ═══════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════
def banner():
    print(f"""{C.CYAN}{C.BOLD}
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551  \u2584\u2588\u2588\u2584 \u2584\u2588\u2588\u2584  \u2584\u2588\u2588\u2580\u2580\u2588\u2584 \u2584\u2588\u2588\u2580\u2584 \u2584\u2588\u2588\u2584  \u2584\u2588\u2588\u2580\u2580\u2588\u2584  \u2584\u2588\u2588\u2580\u2580\u2588\u2584 \u2584\u2588\u2588\u2580\u2588\u2588\u2584\u2584\u2588\u2588\u2584   \u2551
\u2551  \u2588\u2588\u2580 \u2580\u2588\u2588\u2588  \u2588\u2588\u2580 \u2588\u2588\u2580 \u2588\u2588\u2588  \u2588\u2588\u2588  \u2588\u2588\u2580 \u2588\u2588\u2580 \u2588\u2588\u2580 \u2588\u2588\u2588  \u2588\u2588  \u2580\u2588\u2588\u2580 \u2580\u2588\u2588\u2580  \u2551
\u2551  \u2588\u2588       \u2588\u2588\u2580 \u2588\u2588\u2580 \u2588\u2588\u2580 \u2588\u2588\u2580  \u2588\u2588       \u2588\u2588\u2580 \u2588\u2588\u2580 \u2588\u2588\u2580  \u2588\u2588\u2580\u2588\u2588  \u2588\u2588   \u2588\u2588    \u2551
\u2551  \u2588\u2588       \u2588\u2588     \u2580\u2588\u2580  \u2580\u2588\u2580   \u2588\u2588       \u2580\u2588\u2580   \u2580\u2588\u2580  \u2588\u2588   \u2588\u2588   \u2588\u2588    \u2551
\u2551       DNS Domain Activity Checker {VERSION:<19}  \u2551
\u255a{'\u2550' * 49}\u255d{C.RESET}
""")
    lib = f"{C.GREEN}dnspython{C.RESET}" if HAS_DNSPYTHON else f"{C.YELLOW}socket only (pip install dnspython for full){C.RESET}"
    print(f"  {C.WHITE}Library : {lib}")
    print(f"  {C.WHITE}Usage   : python3 dns_checker.py [options]{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
# DNS Checking
# ═══════════════════════════════════════════════════════════════
def check_domain_basic(domain: str) -> dict:
    result = {"domain": domain, "active": False, "records": {}, "error": None,
              "timestamp": datetime.now().isoformat()}
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
        result["error"] = "DNS resolution failed"
    return result


def check_domain_full(domain: str, nameserver: str = None) -> dict:
    result = {"domain": domain, "active": False, "records": {},
              "nameserver": nameserver or "system default", "error": None,
              "timestamp": datetime.now().isoformat()}
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
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.name.EmptyLabel):
            pass
        except Exception:
            pass
    if not result["active"]:
        result["error"] = "No DNS records found"
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
# Progress Bar
# ═══════════════════════════════════════════════════════════════
class Progress:
    def __init__(self, total: int):
        self.total = total
        self.done = 0
        self.active = 0
        self.inactive = 0
        self.start = time.time()
        self.lock = threading.Lock()

    def update(self, result: dict):
        with self.lock:
            self.done += 1
            if result.get("active"):
                self.active += 1
            else:
                self.inactive += 1

    def bar(self) -> str:
        elapsed = time.time() - self.start
        speed = self.done / max(elapsed, 0.01)
        pct = int(self.done / self.total * 100) if self.total > 0 else 0
        filled = int(20 * self.done / self.total) if self.total > 0 else 0
        bar_str = "\u2588" * filled + "\u2591" * (20 - filled)
        return (
            f"\r  [{bar_str}] {self.done}/{self.total} ({pct}%)"
            f" | {C.GREEN}Active:{self.active}{C.RESET}"
            f" | {C.RED}Inactive:{self.inactive}{C.RESET}"
            f" | {speed:.0f}/s"
            f" | {elapsed:.0f}s"
        )


# ═══════════════════════════════════════════════════════════════
# Display Functions
# ═══════════════════════════════════════════════════════════════
def print_target_info(result: dict, verbose: bool = False):
    domain = result["domain"]
    records = result.get("records", {})
    is_active = result.get("active", False)
    error = result.get("error")

    if is_active:
        print(f"{C.GREEN}[+] {domain}")

        # A record
        if "A" in records:
            for i, ip in enumerate(records["A"]):
                branch = "\u251c\u2500" if "AAAA" in records or "MX" in records or "NS" in records or "TXT" in records or "SOA" in records else "\u2514\u2500"
                print(f"{C.GREEN}{branch} A          {C.CYAN}{ip}{C.RESET}")

        # AAAA record
        if "AAAA" in records:
            remaining = ["MX", "NS", "TXT", "SOA", "CNAME"]
            has_more = any(r in records for r in remaining)
            branch = "\u251c\u2500" if has_more else "\u2514\u2500"
            for i, ip in enumerate(records["AAAA"]):
                if i == len(records["AAAA"]) - 1 and not has_more:
                    branch = "\u2514\u2500"
                sub_branch = "\u2502 " if i < len(records["AAAA"]) - 1 else "  "
                if i == 0:
                    print(f"{C.GREEN}{branch} AAAA       {C.CYAN}{ip}{C.RESET}")
                else:
                    print(f"{C.GREEN}{sub_branch}            {C.CYAN}{ip}{C.RESET}")

        # MX record
        if "MX" in records:
            remaining = ["NS", "TXT", "SOA", "CNAME"]
            has_more = any(r in records for r in remaining)
            for i, mx in enumerate(records["MX"]):
                parts = mx.split()
                pref = parts[0] if parts else "?"
                host = parts[1] if len(parts) > 1 else mx
                if i == 0:
                    branch = "\u251c\u2500" if has_more or i < len(records["MX"]) - 1 else "\u2514\u2500"
                    print(f"{C.GREEN}{branch} MX         {C.YELLOW}{host} {C.DIM}(pri:{pref}){C.RESET}")
                else:
                    is_last = (i == len(records["MX"]) - 1) and not has_more
                    branch = "\u2514\u2500" if is_last else "\u251c\u2500"
                    sub = "\u2502" if not is_last else " "
                    print(f"{C.GREEN} {sub}            {C.YELLOW}{host} {C.DIM}(pri:{pref}){C.RESET}")

        # NS record
        if "NS" in records:
            remaining = ["TXT", "SOA", "CNAME"]
            has_more = any(r in records for r in remaining)
            for i, ns in enumerate(records["NS"]):
                is_last = (i == len(records["NS"]) - 1)
                branch = "\u2514\u2500" if is_last and not has_more else "\u251c\u2500"
                sub = "\u2502" if not is_last or has_more else " "
                if i == 0:
                    branch = "\u251c\u2500" if has_more or not is_last else "\u2514\u2500"
                    print(f"{C.GREEN}{branch} NS         {C.BLUE}{ns}{C.RESET}")
                else:
                    print(f"{C.GREEN} {sub}            {C.BLUE}{ns}{C.RESET}")

        # TXT record
        if "TXT" in records:
            remaining = ["SOA", "CNAME"]
            has_more = any(r in records for r in remaining)
            count = len(records["TXT"])
            branch = "\u251c\u2500" if has_more else "\u2514\u2500"
            # Show first 2 TXT, summarize rest
            shown = records["TXT"][:2]
            for i, txt in enumerate(shown):
                is_last_txt = (i == len(shown) - 1) and count <= 2 and not has_more
                b = "\u2514\u2500" if is_last_txt else "\u251c\u2500"
                sub = "\u2502" if not is_last_txt else " "
                txt_short = txt[:80] + "..." if len(txt) > 80 else txt
                if i == 0:
                    print(f"{C.GREEN}{b} TXT        {C.DIM}{txt_short}{C.RESET}")
                else:
                    print(f"{C.GREEN} {sub}            {C.DIM}{txt_short}{C.RESET}")
            if count > 2:
                extra = count - 2
                is_last_txt = not has_more
                b = "\u2514\u2500" if is_last_txt else "\u251c\u2500"
                print(f"{C.GREEN}{b}            {C.DIM}... +{extra} more TXT records{C.RESET}")

        # SOA record
        if "SOA" in records:
            remaining = ["CNAME"]
            has_more = any(r in records for r in remaining)
            branch = "\u251c\u2500" if has_more else "\u2514\u2500"
            soa = records["SOA"][0].split()
            primary = soa[0] if soa else "?"
            print(f"{C.GREEN}{branch} SOA        {C.DIM}{primary}{C.RESET}")

        # CNAME record
        if "CNAME" in records:
            print(f"{C.GREEN}\u2514\u2500 CNAME      {C.CYAN}{records['CNAME'][0]}{C.RESET}")

        # If no records detail but active
        if not records:
            print(f"{C.GREEN}\u2514\u2500 Status     {C.GREEN}ACTIVE (resolved){C.RESET}")

        print(f"{C.RESET}", end="")

    elif error:
        if verbose:
            print(f"{C.RED}[-] {domain}")
            print(f"{C.RED}\u251c\u2500 Error      {error}{C.RESET}")
            print(f"{C.RED}\u2514\u2500 Status     INACTIVE{C.RESET}")
            print(f"{C.RESET}", end="")
        else:
            print(f"{C.RED}[-] {domain} \u2014 {error}{C.RESET}")


# ═══════════════════════════════════════════════════════════════
# File Output (incremental, crash-safe)
# ═══════════════════════════════════════════════════════════════
class FileOutput:
    def __init__(self, path: str, json_mode: bool = False):
        self.path = path
        self.json_mode = json_mode
        self.results = []
        self.lock = threading.Lock()
        if not json_mode:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# DNS Domain Check - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
                f.write(f"# {'Domain':<40} {'Status':<10} {'Records'}\n")
                f.write("# " + "-" * 80 + "\n")

    def write(self, result: dict):
        with self.lock:
            self.results.append(result)
            if self.json_mode:
                # Rewrite full JSON each time (crash-safe snapshot)
                with open(self.path, "w") as f:
                    json.dump(self.results, f, indent=2, ensure_ascii=False)
            else:
                domain = result["domain"]
                status = "ACTIVE" if result.get("active") else "INACTIVE"
                recs = result.get("records", {})
                rec_str = ", ".join(f"{k}:{v[0]}" for k, v in recs.items() if v) if recs else "-"
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(f"  {domain:<40} {status:<10} {rec_str}\n")

    def close(self, total: int, active: int, inactive: int):
        if not self.json_mode:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(f"\n# Summary: {total} checked | {active} active | {inactive} inactive\n")


# ═══════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════
def print_summary(progress: Progress):
    elapsed = time.time() - progress.start
    speed = progress.done / max(elapsed, 0.01)
    print()
    print(f"{C.CYAN}{C.BOLD}{'='*50}")
    print(f"  SUMMARY")
    print(f"{'='*50}{C.RESET}")
    print(f"  {C.WHITE}Total       {C.BOLD}{progress.done}{C.RESET}")
    print(f"  {C.GREEN}Active      {progress.active}{C.RESET}")
    print(f"  {C.RED}Inactive    {progress.inactive}{C.RESET}")
    print(f"  {C.DIM}Time        {elapsed:.1f}s ({speed:.1f} domains/sec){C.RESET}")
    print(f"{C.CYAN}{'='*50}{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description=f"DNS Checker {VERSION} - Domain Activity Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Single domain:    python3 dns_checker.py example.com
  Multiple domains: python3 dns_checker.py google.com github.com
  From file:        python3 dns_checker.py -f domains.txt
  With output:      python3 dns_checker.py -f domains.txt -o results.txt
  JSON output:      python3 dns_checker.py -f domains.txt -j -o results.json
  Custom DNS:       python3 dns_checker.py -f domains.txt --ns 8.8.8.8
  Verbose mode:     python3 dns_checker.py -f domains.txt -v
  No color:         python3 dns_checker.py -f domains.txt --no-color
"""
    )

    parser.add_argument("domains", nargs="*", help="Domain(s) to check")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("--ns", "--nameserver", help="DNS nameserver to use")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-w", "--workers", type=int, default=20, help="Concurrent threads (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show inactive domain details")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"DNS Checker {VERSION}")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    banner()

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
            print(f"{C.RED}[-] File not found: {args.file}{C.RESET}")
            sys.exit(1)

    if not domains:
        parser.print_help()
        sys.exit(1)

    total = len(domains)
    print(f"{C.CYAN}[*] Loaded {total} domains{C.RESET}")
    print(f"{C.CYAN}[*] Using {args.workers} workers, nameserver: {args.ns or 'system default'}{C.RESET}")
    print()

    # Init progress & file output
    progress = Progress(total)
    file_out = FileOutput(args.output, json_mode=args.json) if args.output else None

    # Run checks in original order
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_domain, d, args.ns) for d in domains]
        for future in futures:
            if _shutdown:
                break
            try:
                result = future.result(timeout=30)
            except Exception as e:
                result = {"domain": "unknown", "active": False, "error": str(e),
                          "timestamp": datetime.now().isoformat()}

            progress.update(result)

            # Clear progress line, print result, redraw progress
            sys.stdout.write("\r" + " " * 120 + "\r")
            sys.stdout.flush()
            print_target_info(result, verbose=args.verbose)
            sys.stdout.write(progress.bar())
            sys.stdout.flush()

            if file_out:
                file_out.write(result)

    # Final newline after progress bar
    sys.stdout.write("\n")
    sys.stdout.flush()

    # Close file output
    if file_out:
        file_out.close(progress.done, progress.active, progress.inactive)

    # Summary
    if progress.done > 1:
        print_summary(progress)

    if _shutdown:
        print(f"  {C.YELLOW}[!] Interrupted \u2014 {progress.done}/{total} completed{C.RESET}")
        if file_out:
            print(f"  {C.DIM}[*] Partial results saved to {args.output}{C.RESET}")


def run():
    main()

if __name__ == "__main__":
    main()
