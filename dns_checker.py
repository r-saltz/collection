#!/usr/bin/env python3
"""DNS Domain Activity Checker v3.0 (Async / aiodns)
Check A record only. Green = active, Red = inactive.

Features:
  - Async DNS resolution via aiodns
  - Semaphore-based concurrency (100-500+ coroutines)
  - In-place progress bar with live stats
  - Incremental crash-safe file output
  - Graceful CTRL+C handling

Usage:
    python3 dns_checker.py example.com
    python3 dns_checker.py -f domains.txt
    python3 dns_checker.py -f domains.txt -o results.txt
    python3 dns_checker.py -f domains.txt -w 200
"""

import socket, sys, os, json, time, signal, argparse, asyncio
from datetime import datetime

try:
    import aiodns
except ImportError:
    print("\033[91m[!] aiodns required: pip install aiodns\033[0m")
    sys.exit(1)

VERSION = "3.0"

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
\u2551       DNS Domain Activity Checker {VERSION:<12} (async/aiodns)  \u2551
\u255a{'\u2550' * 49}\u255d{C.RESET}
""")
    print(f"  {C.WHITE}Check   : A Record only")
    print(f"  {C.WHITE}Engine  : aiodns + asyncio.Semaphore{C.RESET}")
    print(f"  {C.WHITE}Usage   : python3 dns_checker.py [options]{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
# Progress Bar (thread-safe via asyncio.Lock)
# ═══════════════════════════════════════════════════════════════
class Progress:
    def __init__(self, total: int):
        self.total = total
        self.done = 0
        self.active = 0
        self.inactive = 0
        self.start = time.time()
        self.lock = asyncio.Lock()

    async def update(self, is_active: bool):
        async with self.lock:
            self.done += 1
            if is_active:
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
# File Output (incremental, crash-safe)
# ═══════════════════════════════════════════════════════════════
class FileOutput:
    def __init__(self, path: str, json_mode: bool = False):
        self.path = path
        self.json_mode = json_mode
        self.results = []
        self.lock = asyncio.Lock()
        if not json_mode:
            with open(path, "w") as f:
                f.write(f"# DNS Domain Check - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
                f.write(f"# {'Domain':<40} {'Status':<10} {'IP'}\n")
                f.write("# " + "-" * 70 + "\n")

    async def write(self, result: dict):
        async with self.lock:
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
# Async DNS Check (aiodns)
# ═══════════════════════════════════════════════════════════════
_print_lock = asyncio.Lock()
_weblive_lock = asyncio.Lock()

async def check_domain(domain: str, resolver: aiodns.DNSResolver, sem: asyncio.Semaphore,
                        progress: Progress, file_out: FileOutput, verbose: bool):
    global _shutdown
    if _shutdown:
        return

    domain = domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    if not domain:
        return

    result = {"domain": domain, "active": False, "ip": None, "error": None,
              "timestamp": datetime.now().isoformat()}

    async with sem:
        try:
            resp = await resolver.getaddrinfo(domain, socket.AF_INET)
            result["active"] = True
            # Extract IPs from AddrInfoResult nodes
            ips = []
            if hasattr(resp, 'nodes'):
                for node in resp.nodes:
                    if hasattr(node, 'addr') and node.addr:
                        ip = node.addr[0] if isinstance(node.addr, tuple) else node.addr
                        if isinstance(ip, bytes):
                            ip = ip.decode()
                        ips.append(ip)
            elif hasattr(resp, 'addresses'):
                ips = resp.addresses
            result["ip"] = list(set(ips)) if ips else ["resolved"]
        except aiodns.error.DNSError as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = str(e)

    await progress.update(result["active"])

    # Print result + refresh progress bar
    async with _print_lock:
        sys.stdout.write("\r" + " " * 120 + "\r")
        sys.stdout.flush()
        print_result(result, verbose=verbose)
        sys.stdout.write(progress.bar())
        sys.stdout.flush()

    if file_out:
        await file_out.write(result)

    # Save active domains to weblive.txt (default)
    if result["active"]:
        async with _weblive_lock:
            with open("weblive.txt", "a") as f:
                f.write(domain + "\n")


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════
async def async_main(args):
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
            return

    if not domains:
        return

    total = len(domains)
    print(f"  {C.CYAN}[*] Loaded {total} domains | {args.workers} workers{C.RESET}")
    print()

    # Init weblive.txt (default output - active domains only)
    with open("weblive.txt", "w") as f:
        f.write(f"# Active domains - {datetime.now():%Y-%m-%d %H:%M:%S}\n")

    # Init
    resolver = aiodns.DNSResolver(timeout=5, tries=2, rotate=True)
    sem = asyncio.Semaphore(args.workers)
    progress = Progress(total)
    file_out = FileOutput(args.output, json_mode=args.json) if args.output else None

    # Run all tasks
    tasks = [
        check_domain(d, resolver, sem, progress, file_out, args.verbose)
        for d in domains
    ]
    await asyncio.gather(*tasks)

    # Final
    sys.stdout.write("\n")
    sys.stdout.flush()

    if file_out:
        file_out.close(progress.done, progress.active, progress.inactive)

    if progress.done > 1:
        print_summary(progress)

    # Show weblive.txt info
    if progress.active > 0:
        print(f"  {C.GREEN}[*] {progress.active} active domains saved to weblive.txt{C.RESET}")
        print()

    if _shutdown:
        print(f"  {C.YELLOW}[!] Interrupted \u2014 {progress.done}/{total} completed{C.RESET}")
        if file_out:
            print(f"  {C.DIM}[*] Partial results saved to {args.output}{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description=f"DNS Checker {VERSION} - Async A-Record Domain Activity Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 dns_checker.py example.com
  python3 dns_checker.py -f domains.txt
  python3 dns_checker.py -f domains.txt -w 200
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
    parser.add_argument("-w", "--workers", type=int, default=100, help="Concurrent workers (default: 100)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show error details for inactive")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"DNS Checker {VERSION}")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    banner()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
