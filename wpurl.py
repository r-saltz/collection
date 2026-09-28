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

import socket, sys, os, ssl, time, signal, argparse, asyncio, random
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

try:
    import aiohttp
except ImportError:
    print("\033[91m[!] aiohttp required: pip install aiohttp\033[0m")
    sys.exit(1)

try:
    import dns.resolver
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

VERSION = "1.3"

DNS_SERVERS = [
    "8.8.8.8",       # Google
    "8.8.4.4",       # Google
    "1.1.1.1",       # Cloudflare
    "1.0.0.1",       # Cloudflare
    "9.9.9.9",       # Quad9
    "149.112.112.112",  # Quad9
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
]

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
# DNS Resolver Pool (Round-Robin + Retry)
# ═══════════════════════════════════════════════════════════════
class DNSResolverPool:
    """Pool of DNS resolvers with random selection and retry."""

    def __init__(self, servers: list):
        self.servers = servers
        self._executor = ThreadPoolExecutor(max_workers=500)

    def _make_resolver(self, server: str):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.lifetime = 2
        resolver.timeout = 2
        return resolver

    async def resolve(self, domain: str, max_retries: int = 2) -> bool:
        """Resolve domain A record. Returns True if active.
        Random resolver selection, retry with different resolver on failure."""
        loop = asyncio.get_event_loop()
        used = set()
        for attempt in range(max_retries):
            # Pick random server not yet used
            available = [s for s in self.servers if s not in used]
            if not available:
                break
            server = random.choice(available)
            used.add(server)
            try:
                resolver = self._make_resolver(server)
                answers = await loop.run_in_executor(
                    self._executor, resolver.resolve, domain, 'A'
                )
                if answers:
                    return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return False
            except (dns.resolver.NoNameservers, dns.resolver.Timeout,
                    dns.exception.DNSException, OSError):
                continue
            except Exception:
                continue
        return False


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
                    progress: Progress, verbose: bool,
                    resolver_pool: DNSResolverPool = None) -> bool:
    global _shutdown
    if _shutdown:
        return False

    active = False
    async with sem:
        if resolver_pool and HAS_DNSPYTHON:
            active = await resolver_pool.resolve(domain)
        else:
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


async def phase_dns(domains: list, workers: int, verbose: bool,
                    dns_servers: list = None) -> list:
    resolver_pool = None
    if HAS_DNSPYTHON and dns_servers:
        resolver_pool = DNSResolverPool(dns_servers)
        print(f"\n  {C.CYAN}{C.BOLD}[1/2 DNS]{C.RESET} Checking {len(domains)} domains | {workers} workers | {len(dns_servers)} resolvers{C.RESET}")
    else:
        print(f"\n  {C.CYAN}{C.BOLD}[1/2 DNS]{C.RESET} Checking {len(domains)} domains | {workers} workers{C.RESET}")
    print()

    sem = asyncio.Semaphore(workers)
    progress = Progress(len(domains), "DNS")

    results = await asyncio.gather(*[
        dns_check(d, sem, progress, verbose, resolver_pool) for d in domains
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
# REST API endpoints for probing
WP_REST_ENDPOINTS = [
    "/wp-json/wp/v2/pages?per_page=1&_fields=id,slug,link,template",
    "/?rest_route=/wp/v2/pages&per_page=1&_fields=id,slug,link,template",
    "/wp-json/batch/v1",
    "/wp/v2/block-renderer/core/paragraph",
]

# Endpoints for template extraction
WP_TEMPLATE_ENDPOINT = "/wp-json/wp/v2/pages?per_page=100&_fields=id,slug,link,template"
WP_TEMPLATE_ALT = "/?rest_route=/wp/v2/pages&per_page=100&_fields=id,slug,link,template"


async def http_get(session, url: str, timeout: int) -> tuple:
    ct = aiohttp.ClientTimeout(total=timeout, connect=5)
    try:
        async with session.get(url, timeout=ct, allow_redirects=True, ssl=False) as resp:
            body = await resp.text(errors="ignore")
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            return resp.status, headers, body.lower()
    except Exception:
        return 0, {}, ""


async def http_get_json(session, url: str, timeout: int) -> tuple:
    """GET request returning (status, json_data or None)."""
    ct = aiohttp.ClientTimeout(total=timeout, connect=5)
    try:
        async with session.get(url, timeout=ct, allow_redirects=True, ssl=False) as resp:
            if resp.status == 200:
                try:
                    data = await resp.json()
                    return resp.status, data
                except Exception:
                    pass
            return resp.status, None
    except Exception:
        return 0, None


async def extract_templates(session, domain: str, timeout: int) -> list:
    """Extract templates from WP pages via REST API."""
    url = f"https://{domain}"

    # Try primary endpoint
    s, data = await http_get_json(session, f"{url}{WP_TEMPLATE_ENDPOINT}", timeout)
    if s == 200 and isinstance(data, list):
        templates = []
        for page in data:
            tpl = page.get("template", "")
            slug = page.get("slug", "")
            if tpl:
                templates.append(f"{slug}={tpl}")
        return templates

    # Try alternative endpoint
    s2, data2 = await http_get_json(session, f"{url}{WP_TEMPLATE_ALT}", timeout)
    if s2 == 200 and isinstance(data2, list):
        templates = []
        for page in data2:
            tpl = page.get("template", "")
            slug = page.get("slug", "")
            if tpl:
                templates.append(f"{slug}={tpl}")
        return templates

    return []


async def _is_wp(session, domain: str, timeout: int) -> bool:
    url = f"https://{domain}"

    # 1. Check main page headers + body
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

    # 2. Probe wp-login.php
    s2, _, b2 = await http_get(session, f"{url}/wp-login.php", timeout)
    if s2 == 200 and ("wp-login" in b2 or "wordpress" in b2):
        return True

    # 3. Probe wp-json
    s3, _, b3 = await http_get(session, f"{url}/wp-json", timeout)
    if s3 == 200 and ("wp-json" in b3 or "namespaces" in b3):
        return True

    # 4. Probe REST API endpoints
    for endpoint in WP_REST_ENDPOINTS:
        s, data = await http_get_json(session, f"{url}{endpoint}", timeout)
        if s == 200 and data is not None:
            if isinstance(data, (list, dict)):
                return True

    # 5. Probe REST API via JSON body check
    for endpoint in WP_REST_ENDPOINTS:
        s, _, b = await http_get(session, f"{url}{endpoint}", timeout)
        if s == 200 and b:
            if any(sig in b for sig in ["wp-json", "namespace", "wp/v2", "block-renderer", "batch"]):
                return True

    return False


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
                templates = await extract_templates(session, domain, timeout)
                wp_domains.append({"domain": domain, "templates": templates})
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

    # 1. Probe /wp-json
    s1, _, b1 = await http_get(session, f"{url}/wp-json", timeout)
    if s1 == 200 and ("wp-json" in b1 or "namespaces" in b1):
        return True

    # 2. Probe REST API JSON endpoints
    for endpoint in WP_REST_ENDPOINTS:
        s, data = await http_get_json(session, f"{url}{endpoint}", timeout)
        if s == 200 and data is not None:
            if isinstance(data, (list, dict)):
                return True

    # 3. Probe REST API body check
    for endpoint in WP_REST_ENDPOINTS:
        s, _, b = await http_get(session, f"{url}{endpoint}", timeout)
        if s == 200 and b:
            if any(sig in b for sig in ["wp-json", "namespace", "wp/v2", "block-renderer", "batch"]):
                return True

    return False


async def async_main(args):
    domains = load_targets(args)
    if not domains:
        print(f"{C.RED}[-] No targets provided.{C.RESET}")
        return

    print(f"  {C.CYAN}[*] Loaded {len(domains)} targets{C.RESET}")

    # DNS servers
    dns_servers = DNS_SERVERS
    if HAS_DNSPYTHON:
        print(f"  {C.CYAN}[*] DNS resolvers: {len(dns_servers)} servers (round-robin + retry){C.RESET}")
    else:
        print(f"  {C.YELLOW}[*] dnspython not installed, using system resolver{C.RESET}")

    # Phase 1: DNS
    active_domains = await phase_dns(domains, args.workers, args.verbose, dns_servers)
    if not active_domains:
        print(f"  {C.YELLOW}[!] No active domains found.{C.RESET}")
        return

    # Phase 2: WordPress
    wp_domains = await phase_wp(active_domains, args.workers, args.timeout)

    # Output (domains only)
    out_file = args.output
    with open(out_file, "w") as f:
        for item in sorted(wp_domains, key=lambda x: x["domain"]):
            f.write(item["domain"] + "\n")

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
