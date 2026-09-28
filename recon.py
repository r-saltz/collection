#!/usr/bin/env python3
"""Recon Toolkit v1.0 — Unified DNS Checker + CMS Detector

Single-file recon pipeline: DNS activity check + CMS detection.
Zero external dependencies (stdlib only for DNS, aiohttp for CMS).

Pipeline:
  domains.txt → dns_checker → active domains → cmsdetect → result/

Modules:
  --dns   : Check domain A-record activity (asyncio.getaddrinfo)
  --cms   : Detect CMS (Laravel, WordPress, Vite.js) via HTTP probing
  --all   : Run DNS → CMS pipeline (only scan active domains)

Usage:
    python3 recon.py -f domains.txt --all
    python3 recon.py -f domains.txt --dns
    python3 recon.py -f domains.txt --cms
    python3 recon.py -f domains.txt --dns --cms
    python3 recon.py -f domains.txt --all -w 200 --timeout 10 -o output/
    python3 recon.py google.com example.com --all

Output:
    -o DIR/weblive.txt     : Active domains (dns module)
    -o DIR/laravel.txt     : Laravel domains (cms module)
    -o DIR/wordpress.txt   : WordPress domains (cms module)
    -o DIR/vite.txt        : Vite.js domains (cms module)
"""

import socket, sys, os, ssl, json, time, signal, argparse, asyncio
from datetime import datetime

VERSION = "1.0"

# ═══════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
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
    print("\n\033[33m[!] CTRL+C \u2014 finishing current targets, then saving...\033[0m")
signal.signal(signal.SIGINT, _sigint_handler)


# ═══════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════
def banner():
    print(f"""{C.CYAN}{C.BOLD}
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588     \u2551
\u2551   \u2588\u2588\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2580\u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2584\u2588\u2588\u2580\u2588\u2588   \u2584\u2588\u2588\u2584 \u2588\u2588   \u2584\u2588\u2588\u2584 \u2584\u2588\u2588\u2584  \u2584\u2588\u2588\u2584  \u2584\u2588\u2588\u2584\u2588\u2588\u2580\u2584\u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2580\u2588\u2588 \u2588\u2588   \u2588\u2588\u2580 \u2580\u2588\u2588 \u2588\u2588   \u2588\u2588\u2580 \u2580\u2588\u2588  \u2588\u2588  \u2588\u2588 \u2580\u2588\u2588\u2580 \u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2588\u2588  \u2588\u2588   \u2588\u2588      \u2588\u2588 \u2588\u2588   \u2588\u2588  \u2588\u2588  \u2588\u2588  \u2588\u2588  \u2588\u2588 \u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2588\u2588  \u2580\u2588\u2580   \u2580\u2588\u2580   \u2580\u2588\u2580  \u2580\u2588\u2580   \u2580\u2588\u2580  \u2588\u2588   \u2580\u2588\u2580  \u2580\u2588\u2580     \u2551
\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588     \u2551
\u2551   \u2588\u2588       Recon Toolkit {VERSION:<20} (async/stdlib)  \u2551
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
        color_map = {
            "active": C.GREEN, "inactive": C.RED,
            "laravel": C.MAGENTA, "wordpress": C.YELLOW, "vite": C.GREEN, "unknown": C.DIM,
        }
        for k, v in self.stats.items():
            color = color_map.get(k, C.WHITE)
            parts.append(f"{color}{k}:{v}{C.RESET}")
        stats_str = " | ".join(parts) if parts else ""
        return (
            f"\r  [{bar_str}] {self.done}/{self.total} ({pct}%)"
            f" | {stats_str}"
            f" | {speed:.0f}/s"
            f" | {elapsed:.0f}s"
        )


# ═══════════════════════════════════════════════════════════════
# File Writer
# ═══════════════════════════════════════════════════════════════
class DomainWriter:
    def __init__(self, path: str):
        self.path = path
        self.lock = asyncio.Lock()

    async def write(self, domain: str):
        async with self.lock:
            with open(self.path, "a") as f:
                f.write(domain + "\n")


# ═══════════════════════════════════════════════════════════════
# Shared
# ═══════════════════════════════════════════════════════════════
_print_lock = asyncio.Lock()

def normalize_domain(raw: str) -> str:
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
    return [normalize_domain(t) for t in targets if normalize_domain(t)]


def print_summary(label: str, progress: Progress):
    elapsed = time.time() - progress.start
    speed = progress.done / max(elapsed, 0.01)
    print()
    print(f"  {C.GREEN}\u2514\u2500{C.RESET} Done")
    print()
    print(f"{C.CYAN}{C.BOLD}{'='*50}")
    print(f"  {label} SUMMARY")
    print(f"{'='*50}{C.RESET}")
    print(f"  {C.WHITE}Total       {C.BOLD}{progress.done}{C.RESET}")
    color_map = {
        "active": C.GREEN, "inactive": C.RED,
        "laravel": C.MAGENTA, "wordpress": C.YELLOW, "vite": C.GREEN, "unknown": C.DIM,
    }
    for k, v in progress.stats.items():
        color = color_map.get(k, C.WHITE)
        print(f"  {color}{k.capitalize():<12}{v}{C.RESET}")
    print(f"  {C.DIM}Time        {elapsed:.1f}s ({speed:.1f} targets/sec){C.RESET}")
    print(f"{C.CYAN}{'='*50}{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════
# MODULE: DNS CHECKER
# ═══════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════

async def dns_check_domain(domain: str, sem: asyncio.Semaphore,
                            progress: Progress, writer: DomainWriter,
                            verbose: bool) -> dict:
    global _shutdown
    if _shutdown:
        return {"domain": domain, "active": False}

    result = {"domain": domain, "active": False, "error": None}

    async with sem:
        try:
            loop = asyncio.get_event_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, family=socket.AF_INET),
                timeout=5
            )
            if infos:
                result["active"] = True
        except (socket.gaierror, OSError) as e:
            result["error"] = str(e)
        except asyncio.TimeoutError:
            result["error"] = "DNS timeout"
        except Exception as e:
            result["error"] = str(e)

    key = "active" if result["active"] else "inactive"
    await progress.update(key)

    async with _print_lock:
        sys.stdout.write("\r" + " " * 120 + "\r")
        sys.stdout.flush()
        color = C.GREEN if result["active"] else C.RED
        print(f"  {color}\u251c\u2500 {domain}{C.RESET}")
        if verbose and result.get("error"):
            print(f"  {C.RED}\u2502  \u2716 {result['error']}{C.RESET}")
        sys.stdout.write(progress.bar())
        sys.stdout.flush()

    if result["active"] and writer:
        await writer.write(domain)

    return result


async def run_dns(domains: list, workers: int, verbose: bool,
                   writer: DomainWriter) -> list:
    print(f"\n  {C.CYAN}{C.BOLD}[DNS]{C.RESET} Checking {len(domains)} domains | {workers} workers")
    print()

    sem = asyncio.Semaphore(workers)
    progress = Progress(len(domains), "DNS")

    tasks = [
        dns_check_domain(d, sem, progress, writer, verbose)
        for d in domains
    ]
    results = await asyncio.gather(*tasks)

    sys.stdout.write("\n")
    sys.stdout.flush()

    if progress.done > 1:
        print_summary("DNS", progress)

    active = [r for r in results if r["active"]]
    if active and writer:
        print(f"  {C.GREEN}[*] {len(active)} active domains saved to {writer.path}{C.RESET}")
        print()

    return results


# ═══════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════
# MODULE: CMS DETECTOR
# ═══════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

WP_BODY_SIGS = [
    "wp-content/", "wp-includes/", "/wp-json", "/wp-login.php",
    "wp-embed.min.js", "wp-includes/js/", "wp-content/themes/", "wp-content/plugins/",
]
WP_HEADER_SIGS = ["x-powered-by: wordpress", "link: <http.*wp-json"]
LARAVEL_COOKIE_SIGS = ["xsrf-token", "laravel_session", "XSRF-TOKEN"]
LARAVEL_HEADER_SIGS = ["x-powered-by: laravel"]
LARAVEL_BODY_SIGS = ["laravel", "csrf-token", "laravel_session"]
VITE_BODY_SIGS = [
    "/@vite/", "@vite/client", "__vite__", "vite/client",
    "vite-modulepreload", "vite-plugin-", "@vitejs/", "vite-hmr",
    "create-vite", "modulepreload-polyfill",
]
VITE_HEADER_SIGS = ["x-powered-by: vite", "server: vite"]


async def http_fetch(session, url: str, timeout: int = 10) -> tuple:
    import aiohttp
    ct = aiohttp.ClientTimeout(total=timeout, connect=5)
    try:
        async with session.get(url, timeout=ct, allow_redirects=True, ssl=False) as resp:
            body = await resp.text(errors="ignore")
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies = {k.lower(): v.lower() for k, v in resp.cookies.items()}
            return resp.status, headers, body.lower(), cookies
    except Exception:
        return 0, {}, "", {}


async def detect_cms(session, url: str, timeout: int = 10) -> str:
    url = url.strip().rstrip("/")
    if not url:
        return "unknown"
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    status, headers, body, cookies = await http_fetch(session, url, timeout)

    # WordPress
    wp_score = 0
    for sig in WP_HEADER_SIGS:
        key, _, val = sig.partition(": ")
        if val in headers.get(key, ""):
            wp_score += 3
    for sig in WP_BODY_SIGS:
        if sig in body:
            wp_score += 1
    if 'content="wordpress' in body:
        wp_score += 5

    # Laravel
    lar_score = 0
    for sig in LARAVEL_COOKIE_SIGS:
        if sig.lower() in cookies:
            lar_score += 3
    for sig in LARAVEL_HEADER_SIGS:
        key, _, val = sig.partition(": ")
        if val in headers.get(key, ""):
            lar_score += 3
    if status == 419:
        lar_score += 2
    for sig in LARAVEL_BODY_SIGS:
        if sig in body:
            lar_score += 1
    if "csrf-token" in body and "laravel" in body:
        lar_score += 3

    # Vite
    vite_score = 0
    for sig in VITE_HEADER_SIGS:
        key, _, val = sig.partition(": ")
        if val in headers.get(key, ""):
            vite_score += 5
    for sig in VITE_BODY_SIGS:
        if sig in body:
            vite_score += 2

    # Probes if inconclusive
    if wp_score < 4:
        s, _, b, _ = await http_fetch(session, f"{url}/wp-login.php", timeout)
        if s == 200 and ("wp-login" in b or "wordpress" in b):
            wp_score += 5
        s2, _, b2, _ = await http_fetch(session, f"{url}/wp-json", timeout)
        if s2 == 200 and ("wp-json" in b2 or "namespaces" in b2):
            wp_score += 3

    if lar_score < 4:
        s, _, b, _ = await http_fetch(session, f"{url}/api", timeout)
        if s in (200, 401, 403, 405, 429):
            lar_score += 2
        if s == 200 and "laravel" in b:
            lar_score += 3
        ls, _, lb, lc = await http_fetch(session, f"{url}/login", timeout)
        for sig in LARAVEL_COOKIE_SIGS:
            if sig.lower() in lc:
                lar_score += 3
        if ls == 200 and "csrf-token" in lb:
            lar_score += 2

    if vite_score < 4:
        s, _, b, _ = await http_fetch(session, f"{url}/@vite/client", timeout)
        if s == 200 and ("vite" in b or "import" in b):
            vite_score += 5

    scores = {"wordpress": wp_score, "laravel": lar_score, "vite": vite_score}
    best = max(scores, key=scores.get)
    best_score = scores[best]
    others = [s for k, s in scores.items() if k != best]

    if best_score >= 4 and best_score > max(others):
        return best
    return "unknown"


async def cms_scan_target(session, url: str, sem: asyncio.Semaphore,
                            progress: Progress, writers: dict,
                            verbose: bool, timeout: int) -> str:
    global _shutdown
    if _shutdown:
        return "unknown"

    domain = normalize_domain(url)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    async with sem:
        cms = await detect_cms(session, url, timeout)

    await progress.update(cms)

    writer = writers.get(cms)
    if writer:
        await writer.write(domain)

    async with _print_lock:
        sys.stdout.write("\r" + " " * 120 + "\r")
        sys.stdout.flush()
        color_map = {"laravel": C.MAGENTA, "wordpress": C.YELLOW, "vite": C.GREEN}
        if cms in color_map:
            print(f"  {color_map[cms]}\u251c\u2500 {domain} \u2192 {cms.capitalize()}{C.RESET}")
        elif verbose:
            print(f"  {C.DIM}\u251c\u2500 {domain} \u2192 Unknown{C.RESET}")
        sys.stdout.write(progress.bar())
        sys.stdout.flush()

    return cms


async def run_cms(domains: list, workers: int, timeout: int,
                   verbose: bool, out_dir: str) -> dict:
    import aiohttp

    print(f"\n  {C.CYAN}{C.BOLD}[CMS]{C.RESET} Scanning {len(domains)} targets | {workers} workers | timeout {timeout}s")
    print()

    os.makedirs(out_dir, exist_ok=True)

    writers = {
        "laravel": DomainWriter(os.path.join(out_dir, "laravel.txt")),
        "wordpress": DomainWriter(os.path.join(out_dir, "wordpress.txt")),
        "vite": DomainWriter(os.path.join(out_dir, "vite.txt")),
    }

    sem = asyncio.Semaphore(workers)
    progress = Progress(len(domains), "CMS")
    connector = aiohttp.TCPConnector(limit=workers, ttl_dns_cache=300, ssl=SSL_CTX)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [
            cms_scan_target(session, t, sem, progress, writers, verbose, timeout)
            for t in domains
        ]
        await asyncio.gather(*tasks)

    sys.stdout.write("\n")
    sys.stdout.flush()

    if progress.done > 1:
        print_summary("CMS", progress)

    for cms_type, writer in writers.items():
        count = progress.stats.get(cms_type, 0)
        if count > 0:
            color_map = {"laravel": C.MAGENTA, "wordpress": C.YELLOW, "vite": C.GREEN}
            print(f"  {color_map[cms_type]}[*] {count} {cms_type.capitalize()} targets \u2192 {writer.path}{C.RESET}")
    if any(progress.stats.get(c, 0) > 0 for c in writers):
        print()

    return progress.stats


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
async def async_main(args):
    domains = load_targets(args)
    if not domains:
        print(f"{C.RED}[-] No targets provided.{C.RESET}")
        return

    print(f"  {C.CYAN}[*] Loaded {len(domains)} targets{C.RESET}")

    out_dir = args.output.rstrip("/")
    os.makedirs(out_dir, exist_ok=True)

    weblive_path = os.path.join(out_dir, "weblive.txt")
    active_domains = domains

    # --- DNS Module ---
    if args.dns or args.all:
        writer = DomainWriter(weblive_path)
        with open(weblive_path, "w") as f:
            f.write(f"# Active domains - {datetime.now():%Y-%m-%d %H:%M:%S}\n")

        results = await run_dns(domains, args.workers, args.verbose, writer)
        active_domains = [r["domain"] for r in results if r["active"]]

        if not active_domains:
            print(f"  {C.YELLOW}[!] No active domains found. Skipping CMS.{C.RESET}")
            return

        if args.all and active_domains:
            print(f"  {C.CYAN}[*] Pipeline: {len(active_domains)} active domains \u2192 CMS scan{C.RESET}")

    # --- CMS Module ---
    if args.cms or args.all:
        cms_domains = active_domains if args.all else domains
        if not cms_domains:
            print(f"  {C.YELLOW}[!] No targets for CMS scan.{C.RESET}")
            return
        await run_cms(cms_domains, args.workers, args.timeout, args.verbose, out_dir)

    # --- Summary ---
    if _shutdown:
        print(f"  {C.YELLOW}[!] Interrupted \u2014 partial results saved to {out_dir}/{C.RESET}")



def main():
    parser = argparse.ArgumentParser(
        description=f"Recon Toolkit {VERSION} - Unified DNS Checker + CMS Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 recon.py -f domains.txt --all
  python3 recon.py -f domains.txt --dns
  python3 recon.py -f domains.txt --cms
  python3 recon.py -f domains.txt --dns --cms
  python3 recon.py -f domains.txt --all -w 200 --timeout 15 -o output/
  python3 recon.py google.com example.com --all
"""
    )

    parser.add_argument("targets", nargs="*", help="Target domain(s)")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("-o", "--output", default="result", help="Output directory (default: result)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Concurrent workers (default: 100)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show inactive/unknown targets")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    # Module selection
    group = parser.add_argument_group("modules")
    group.add_argument("--dns", action="store_true", help="Run DNS activity check")
    group.add_argument("--cms", action="store_true", help="Run CMS detection")
    group.add_argument("--all", action="store_true", help="Run full pipeline (DNS \u2192 CMS)")

    parser.add_argument("--version", action="version", version=f"Recon Toolkit {VERSION}")

    args = parser.parse_args()

    # Default to --all if no module specified
    if not (args.dns or args.cms or args.all):
        args.all = True

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    banner()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
