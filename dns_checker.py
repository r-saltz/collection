#!/usr/bin/env python3
"""DNS Domain Activity Checker v2.1
Check A record only. Green = active, Red = inactive.

Usage:
    python3 dns_checker.py example.com
    python3 dns_checker.py -f domains.txt
    python3 dns_checker.py -f domains.txt -o results.txt
"""

import socket, sys, os, json, time, signal, argparse, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

VERSION = "2.1"

# ═══════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
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
    print(f"  {C.WHITE}Check   : A Record only")
    print(f"  {C.WHITE}Usage   : python3 dns_checker.py [options]{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
# DNS Check - A Record Only
# ═══════════════════════════════════════════════════════════════
def check_domain(domain: str) -> dict:
    domain = domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    if not domain:
        return {"domain": domain, "active": False, "ip": None, "error": "Empty domain"}

    result = {"domain": domain, "active": False, "ip": None, "error": None,
              "timestamp": datetime.now().isoformat()}
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        if ips:
            result["active"] = True
            result["ip"] = list(set(ip[4][0] for ip in ips))
    except socket.gaierror:
        result["error"] = "DNS resolution failed"
    return result


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
# Display
# ═══════════════════════════════════════════════════════════════
def print_result(result: dict, verbose: bool = False):
    domain = result["domain"]
    is_active = result.get("active", False)
    ips = result.get("ip")
    error = result.get("error")

    if is_active:
        ip_str = ", ".join(ips) if ips else "resolved"
        print(f"  {C.GREEN}\u251c\u2500 {domain}{C.RESET}")
        for ip in ips:
            print(f"  {C.GREEN}\u2502  \u2192 {ip}{C.RESET}")
    else:
        print(f"  {C.RED}\u251c\u2500 {domain}{C.RESET}")
        if verbose and error:
            print(f"  {C.RED}\u2502  \u2716 {error}{C.RESET}")


def print_summary(progress: Progress):
    elapsed = time.time() - progress.start
    speed = progress.done / max(elapsed, 0.01)
    print()
    print(f"  {C.GREEN}\u2514\u2500{C.RESET} Done")
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
# File Output (incremental)
# ═══════════════════════════════════════════════════════════════
class FileOutput:
    def __init__(self, path: str, json_mode: bool = False):
        self.path = path
        self.json_mode = json_mode
        self.results = []
        self.lock = threading.Lock()
        if not json_mode:
            with open(path, "w") as f:
                f.write(f"# DNS Domain Check - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
                f.write(f"# {'Domain':<40} {'Status':<10} {'IP'}\n")
                f.write("# " + "-" * 70 + "\n")

    def write(self, result: dict):
        with self.lock:
            self.results.append(result)
            if self.json_mode:
                with open(self.path, "w") as f:
                    json.dump(self.results, f, indent=2)
            else:
                domain = result["domain"]
                status = "ACTIVE" if result.get("active") else "INACTIVE"
                ips = ", ".join(result.get("ip", [])) or "-"
                with open(self.path, "a") as f:
                    f.write(f"  {domain:<40} {status:<10} {ips}\n")

    def close(self, total, active, inactive):
        if not self.json_mode:
            with open(self.path, "a") as f:
                f.write(f"\n# Summary: {total} checked | {active} active | {inactive} inactive\n")


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description=f"DNS Checker {VERSION} - A Record Domain Activity Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 dns_checker.py example.com
  python3 dns_checker.py -f domains.txt
  python3 dns_checker.py -f domains.txt -o results.txt
  python3 dns_checker.py -f domains.txt -j -o results.json
  python3 dns_checker.py -f domains.txt -v
  python3 dns_checker.py -f domains.txt --no-color
"""
    )

    parser.add_argument("domains", nargs="*", help="Domain(s) to check")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-w", "--workers", type=int, default=20, help="Concurrent threads (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show error details for inactive")
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
    print(f"  {C.CYAN}[*] Loaded {total} domains | {args.workers} workers{C.RESET}")
    print()

    # Init
    progress = Progress(total)
    file_out = FileOutput(args.output, json_mode=args.json) if args.output else None

    # Run checks
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_domain, d) for d in domains]
        for future in futures:
            if _shutdown:
                break
            try:
                result = future.result(timeout=15)
            except Exception as e:
                result = {"domain": "unknown", "active": False, "ip": None,
                          "error": str(e), "timestamp": datetime.now().isoformat()}

            progress.update(result)

            # Clear progress line, print result, redraw progress
            sys.stdout.write("\r" + " " * 120 + "\r")
            sys.stdout.flush()
            print_result(result, verbose=args.verbose)
            sys.stdout.write(progress.bar())
            sys.stdout.flush()

            if file_out:
                file_out.write(result)

    # Final
    sys.stdout.write("\n")
    sys.stdout.flush()

    if file_out:
        file_out.close(progress.done, progress.active, progress.inactive)

    if progress.done > 1:
        print_summary(progress)

    if _shutdown:
        print(f"  {C.YELLOW}[!] Interrupted \u2014 {progress.done}/{total} completed{C.RESET}")
        if file_out:
            print(f"  {C.DIM}[*] Partial results saved to {args.output}{C.RESET}")


if __name__ == "__main__":
    main()
