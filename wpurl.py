#!/usr/bin/env python3
"""wpurl.py — WordPress URL Finder

Flow: domains.txt → DNS check → WordPress detect → output

Standalone single-file tool. Find WordPress sites from domain lists.
Filters out inactive domains first via DNS, then probes for WordPress.

Requires: aiohttp (pip install aiohttp)

Flags:
    -f FILE     File with domains (one per line)
    -w N        Concurrent workers (default: 100)
    -t N        HTTP timeout in seconds (default: 10)
    -o FILE     Output file (default: wordpress.txt)

Usage:
    python3 wpurl.py -f domains.txt
    python3 wpurl.py -f domains.txt -w 200 -t 15 -o wp_sites.txt
    python3 wpurl.py google.com example.com
"""

import socket, sys, os, ssl, time, signal, argparse, asyncio
from datetime import datetime

try:
    import aiohttp
except ImportError:
    print("\033[91m[!] aiohttp required: pip install aiohttp\033[0m")
    sys.exit(1)

VERSION = "1.0"

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
# CTRL+C
# ═══════════════════════════════════════════════════════════════
_shutdown = False
def _sigint_handler(sig, frame):
    global _shutdown
    if _shutdown:
        print("\n\033[31m[!] Force quit\033[0m")
        sys.exit(1)
    _shutdown = True
    print("\n\033[33m[!] CTRL+C \u2014 finishing, then saving...\033[0m")
signal.signal(signal.SIGINT, _sigint_handler)


# ═══════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════
def banner():
    print(f"""{C.CYAN}{C.BOLD}
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551                                                  \u2551
\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2584\u2588\u2588\u2580\u2588\u2588 \u2584\u2588\u2588\u2584 \u2588\u2588\u2580\u2580\u2588\u2588 \u2584\u2588\u2588\u2584   \u2584\u2588\u2588\u2580\u2580\u2588\u2588 \u2584\u2588\u2588\u2580\u2584  \u2584\u2588\u2588\u2580\u2588\u2588\u2584   \u2584\u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2580\u2588\u2588 \u2588\u2588 \u2588\u2588\u2580 \u2580\u2588\u2588 \u2580\u2588\u2588  \u2588\u2588\u2580 \u2588\u2588 \u2580\u2588\u2588 \u2588\u2588 \u2580\u2588\u2588 \u2588\u2588 \u2580\u2588\u2588\u2580 \u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2588\u2588  \u2588\u2588 \u2588\u2588      \u2588\u2588  \u2588\u2588  \u2588\u2588  \u2588\u2588 \u2588\u2588 \u2588\u2588  \u2588\u2588 \u2588\u2588 \u2588\u2588  \u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2588\u2588  \u2580\u2588\u2580  \u2580\u2588\u2580   \u2580\u2588\u2580  \u2580\u2588\u2580  \u2580\u2588\u2580  \u2588\u2588  \u2580\u2588\u2580 \u2588\u2588   \u2580\u2588\u2580     \u2551
\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588     \u2551
\u2551       wpurl {VERSION:<18} WordPress URL Finder    \u2551
\u255a{'\u2550' * 49}\u255d{C.RESET}
""")


# ═══════════════════════════════════════════════════════════════
# Progress Bar
# ═══════════════════════════════════════════════════════════════
class Progress:
    def __init__(self, total: int, label: str = ""):
        self.total = total
        self.done = 0
        self.stats = {}
        self.start = time.time()
        self.lock = asyncio.Lock()
        self.label = label

    async def update(self, key: str):
        async with self.lock:
            self.done += 1
            self.stats[key] = self.stats.get(key, 0) + 1

    def bar(self) -> str:
        elapsed = time.time() - self.start
        speed = self.done / max(elapsed, 0.01)
        pct = int(self.done / self.total * 100) if self.total > 0 else 0
        filled = int(20 * self.done / self.total) if self.total > 0 else 0
        bar_str = "\u2588" * filled + "\u2591" * (20 - filled)
        parts = []
        for k, v in self.stats.items():
            if k == "wordpress":
                parts.append(f"{C.GREEN}{k}:{v}{C.RESET}")
            elif k == "active":
                parts.append(f"{C.CYAN}{k}:{v}{C.RESET}")
            elif k == "inactive":
                parts.append(f"{C.RED}{k}:{v}{C.RESET}")
            else:
                parts.append(f"{C.DIM}{k}:{v}{C.RESET}")
        stats_str = " | ".join(parts) if parts else ""
        return (
            f"\r  [{bar_str}] {self.done}/{self.total} ({pct}%)"
            f" | {stats_str}"
            f" | {speed:.0f}/s"
            f" | {elapsed:.0f}s"
        )


# ═══════════════════════════════════════════════════════════════
# Shared Helpers
# ═══════════════════════════════════════════════════════════════
_print_lock = asyncio.Lock()

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

def normalize(raw: str) -> str:
    d = raw.strip().lower()
    d = d.replace("http://", "").replace("https://", "").split("/")[0]
    return d


def load_targets(args) -> list:
    targets = list(args.targets) if args.targets else []
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend(
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                )
        except FileNotFoundError:
            print(f"{C.RED}[-] File not found: {args.file}{C.RESET}")
            return []
    return [normalize(t) for t in targets if normalize(t)]


def print_summary(phase: str, progress: Progress):
    elapsed = time.time() - progress.start
    speed = progress.done / max(elapsed, 0.01)
    print()
    print(f"  {C.GREEN}\u2514\u2500{C.RESET} Done")
    print()
    print(f"{C.CYAN}{C.BOLD}{'='*50}")
    print(f"  {phase} SUMMARY")
    print(f"{'='*50}{C.RESET}")
    print(f"  {C.WHITE}Total       {C.BOLD}{progress.done}{C.RESET}")
    for k, v in progress.stats.items():
        if k == "wordpress":
            print(f"  {C.GREEN}WordPress    {v}{C.RESET}")
        elif k == "active":
            print(f"  {C.CYAN}Active       {v}{C.RESET}")
        elif k == "inactive":
            print(f"  {C.RED}Inactive     {v}{C.RESET}")
        else:
            print(f"  {C.DIM}{k.capitalize():<12}{v}{C.RESET}")
    print(f"  {C.DIM}Time        {elapsed:.1f}s ({speed:.1f} domains/sec){C.RESET}")
    print(f"{C.CYAN}{'='*50}{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
# Phase 1: DNS Check
# ═══════════════════════════════════════════════════════════════
async def dns_check(domain: str, sem: asyncio.Semaphore,
                    progress: Progress, verbose: bool) -> bool:
    global _shutdown
    if _shutdown:
        return False

    active = False
    async with sem:
        try:
            loop = asyncio.get_event_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, family=socket.AF_INET),
                timeout=5
            )
            if infos:
                active = True
        except Exception:
            pass

    await progress.update("active" if active else "inactive")

    async with _print_lock:
        sys.stdout.write(progress.bar())
        sys.stdout.flush()

    return active


async def phase_dns(domains: list, workers: int, verbose: bool) -> list:
    print(f"\n  {C.CYAN}{C.BOLD}[1/2 DNS]{C.RESET} Checking {len(domains)} domains | {workers} workers")
    print()

    sem = asyncio.Semaphore(workers)
    progress = Progress(len(domains), "DNS")

    results = await asyncio.gather(*[
        dns_check(d, sem, progress, verbose) for d in domains
    ])

    active_domains = [d for d, ok in zip(domains, results) if ok]

    sys.stdout.write("\n")
    sys.stdout.flush()

    if progress.done > 1:
        print_summary("DNS", progress)

    print(f"  {C.GREEN}[*] {len(active_domains)} active domains{C.RESET}")
    print()

    return active_domains


# ═══════════════════════════════════════════════════════════════
# Phase 2: WordPress Detection
# ═══════════════════════════════════════════════════════════════
WP_BODY_SIGS = [
    "wp-content/", "wp-includes/", "/wp-json", "/wp-login.php",
    "wp-embed.min.js", "wp-includes/js/", "wp-content/themes/",
    "wp-content/plugins/",
]
WP_HEADER_SIGS = ["x-powered-by: wordpress", "link: <http.*wp-json"]


async def http_get(session, url: str, timeout: int) -> tuple:
    ct = aiohttp.ClientTimeout(total=timeout, connect=5)
    try:
        async with session.get(url, timeout=ct, allow_redirects=True, ssl=False) as resp:
            body = await resp.text(errors="ignore")
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            return resp.status, headers, body.lower()
    except Exception:
        return 0, {}, ""


async def phase_wp(domains: list, workers: int, timeout: int) -> list:
    print(f"\n  {C.YELLOW}{C.BOLD}[2/2 WP]{C.RESET} Scanning {len(domains)} domains | {workers} workers | timeout {timeout}s")
    print()

    sem = asyncio.Semaphore(workers)
    progress = Progress(len(domains), "WP")
    wp_domains = []

    connector = aiohttp.TCPConnector(limit=workers, ttl_dns_cache=300, ssl=SSL_CTX)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        # Patch session into is_wordpress
        async def _wp_scan(domain, sem, progress, wp_domains, timeout):
            global _shutdown
            if _shutdown:
                return
            async with sem:
                wp = await _is_wp(session, domain, timeout)
            await progress.update("wordpress" if wp else "other")
            if wp:
                wp_domains.append(domain)
            async with _print_lock:
                sys.stdout.write(progress.bar())
                sys.stdout.flush()

        tasks = [_wp_scan(d, sem, progress, wp_domains, timeout) for d in domains]
        await asyncio.gather(*tasks)

    sys.stdout.write("\n")
    sys.stdout.flush()

    if progress.done > 1:
        print_summary("WORDPRESS", progress)

    return wp_domains


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════
async def _is_wp(session, domain: str, timeout: int) -> bool:
    url = f"https://{domain}"
    status, headers, body = await http_get(session, url, timeout)

    score = 0
    for sig in WP_HEADER_SIGS:
        key, _, val = sig.partition(": ")
        if val in headers.get(key, ""):
            score += 3
    for sig in WP_BODY_SIGS:
        if sig in body:
            score += 1
    if 'content="wordpress' in body:
        score += 5
    if score >= 4:
        return True

    s2, _, b2 = await http_get(session, f"{url}/wp-login.php", timeout)
    if s2 == 200 and ("wp-login" in b2 or "wordpress" in b2):
        return True

    s3, _, b3 = await http_get(session, f"{url}/wp-json", timeout)
    if s3 == 200 and ("wp-json" in b3 or "namespaces" in b3):
        return True

    return False


async def async_main(args):
    domains = load_targets(args)
    if not domains:
        print(f"{C.RED}[-] No targets provided.{C.RESET}")
        return

    print(f"  {C.CYAN}[*] Loaded {len(domains)} targets{C.RESET}")

    # Phase 1: DNS
    active_domains = await phase_dns(domains, args.workers, args.verbose)
    if not active_domains:
        print(f"  {C.YELLOW}[!] No active domains found.{C.RESET}")
        return

    # Phase 2: WordPress
    wp_domains = await phase_wp(active_domains, args.workers, args.timeout)

    # Output
    out_file = args.output
    with open(out_file, "w") as f:
        for d in sorted(set(wp_domains)):
            f.write(d + "\n")

    if wp_domains:
        print(f"  {C.GREEN}{C.BOLD}[*] {len(wp_domains)} WordPress sites \u2192 {out_file}{C.RESET}")
    else:
        print(f"  {C.YELLOW}[*] No WordPress sites found.{C.RESET}")

    if _shutdown:
        print(f"  {C.YELLOW}[!] Interrupted \u2014 partial results saved to {out_file}{C.RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description=f"wpurl {VERSION} - WordPress URL Finder (DNS check + WP detect)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 wpurl.py -f domains.txt
  python3 wpurl.py -f domains.txt -w 200 -t 15 -o wp_sites.txt
  python3 wpurl.py google.com example.com
"""
    )

    parser.add_argument("targets", nargs="*", help="Target domain(s)")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Concurrent workers (default: 100)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", default="wordpress.txt", help="Output file (default: wordpress.txt)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show inactive domains")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"wpurl {VERSION}")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    banner()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
