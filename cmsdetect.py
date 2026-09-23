#!/usr/bin/env python3
"""CMS Detector v1.0 (Async / aiohttp)
Detect Laravel and WordPress CMS from URL lists.

Detection:
  - WordPress: wp-content, wp-includes, wp-login, wp-json, generator meta
  - Laravel: XSRF-TOKEN, laravel_session, /api routes, 419 status

Output:
  - result/laravel.txt   (Laravel domains)
  - result/wordpress.txt (WordPress domains)

Usage:
    python3 cmsdetect.py example.com
    python3 cmsdetect.py -f domains.txt
    python3 cmsdetect.py -f domains.txt -o result/
    python3 cmsdetect.py -f domains.txt -w 200
"""

import sys, os, ssl, json, time, signal, argparse, asyncio
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
# SSL
# ═══════════════════════════════════════════════════════════════
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


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
\u2551   \u2584\u2584\u2580 \u2580\u2588\u2588\u2580 \u2580\u2588\u2588\u2580  \u2588\u2588\u2584\u2588\u2588  \u2588\u2588\u2584\u2584\u2588\u2588\u2584\u2588\u2588  \u2588\u2588\u2580\u2580 \u2588\u2588\u2580\u2580\u2588\u2588\u2584\u2588\u2588\u2580  \u2588\u2588\u2580     \u2551
\u2551   \u2588\u2588\u2588\u2580\u2588\u2588 \u2580\u2588\u2588\u2580 \u2588\u2588\u2580 \u2580\u2588\u2588 \u2588\u2588 \u2580\u2588\u2588 \u2588\u2588 \u2588\u2588\u2580  \u2588\u2588 \u2580\u2588\u2588\u2580 \u2588\u2588\u2580 \u2580\u2588\u2588  \u2580\u2588\u2588     \u2551
\u2551   \u2588\u2588 \u2580 \u2588\u2588   \u2588\u2588  \u2588\u2588   \u2588\u2588 \u2588\u2588  \u2588\u2588 \u2588\u2588     \u2588\u2588   \u2588\u2588 \u2588\u2588   \u2588\u2588  \u2588\u2588     \u2551
\u2551   \u2588\u2588   \u2588\u2588   \u2580\u2588\u2580  \u2580\u2588\u2588   \u2580\u2588\u2580  \u2580\u2588\u2580     \u2580\u2588\u2580   \u2580\u2588\u2580  \u2580\u2588\u2580  \u2580\u2588\u2580     \u2551
\u2551       CMS Detector {VERSION:<22} (async/aiohttp)  \u2551
\u255a{'\u2550' * 49}\u255d{C.RESET}
""")
    print(f"  {C.WHITE}Detect  : Laravel, WordPress")
    print(f"  {C.WHITE}Output  : result/laravel.txt, result/wordpress.txt{C.RESET}")
    print(f"  {C.WHITE}Usage   : python3 cmsdetect.py [options]{C.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════
# Progress Bar
# ═══════════════════════════════════════════════════════════════
class Progress:
    def __init__(self, total: int):
        self.total = total
        self.done = 0
        self.laravel = 0
        self.wordpress = 0
        self.unknown = 0
        self.start = time.time()
        self.lock = asyncio.Lock()

    async def update(self, cms: str):
        async with self.lock:
            self.done += 1
            if cms == "laravel":
                self.laravel += 1
            elif cms == "wordpress":
                self.wordpress += 1
            else:
                self.unknown += 1

    def bar(self) -> str:
        elapsed = time.time() - self.start
        speed = self.done / max(elapsed, 0.01)
        pct = int(self.done / self.total * 100) if self.total > 0 else 0
        filled = int(20 * self.done / self.total) if self.total > 0 else 0
        bar_str = "\u2588" * filled + "\u2591" * (20 - filled)
        return (
            f"\r  [{bar_str}] {self.done}/{self.total} ({pct}%)"
            f" | {C.MAGENTA}Laravel:{self.laravel}{C.RESET}"
            f" | {C.YELLOW}WordPress:{self.wordpress}{C.RESET}"
            f" | {C.DIM}Other:{self.unknown}{C.RESET}"
            f" | {speed:.0f}/s"
            f" | {elapsed:.0f}s"
        )


# ═══════════════════════════════════════════════════════════════
# CMS Detection Signatures
# ═══════════════════════════════════════════════════════════════
WP_BODY_SIGS = [
    "wp-content/",
    "wp-includes/",
    "/wp-json",
    "/wp-login.php",
    "wp-embed.min.js",
    "wp-includes/js/",
    "wp-content/themes/",
    "wp-content/plugins/",
]

WP_HEADER_SIGS = [
    "x-powered-by: wordpress",
    "link: <http.*wp-json",
]

LARAVEL_COOKIE_SIGS = [
    "xsrf-token",
    "laravel_session",
    "XSRF-TOKEN",
]

LARAVEL_HEADER_SIGS = [
    "x-powered-by: laravel",
]

LARAVEL_BODY_SIGS = [
    "laravel",
    "csrf-token",
    "laravel_session",
]


# ═══════════════════════════════════════════════════════════════
# HTTP Request Helper
# ═══════════════════════════════════════════════════════════════
async def fetch(session: aiohttp.ClientSession, url: str, timeout: int = 10) -> tuple:
    """GET request returning (status, headers_dict, body_str, cookies_dict)."""
    ct = aiohttp.ClientTimeout(total=timeout, connect=5)
    try:
        async with session.get(url, timeout=ct, allow_redirects=True, ssl=False) as resp:
            body = await resp.text(errors="ignore")
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies = {k.lower(): v.lower() for k, v in resp.cookies.items()}
            return resp.status, headers, body.lower(), cookies
    except Exception:
        return 0, {}, "", {}


# ═══════════════════════════════════════════════════════════════
# Detection Logic
# ═══════════════════════════════════════════════════════════════
async def detect_cms(session: aiohttp.ClientSession, url: str, timeout: int = 10) -> str:
    """Detect CMS type. Returns 'wordpress', 'laravel', or 'unknown'."""
    url = url.strip().rstrip("/")
    if not url:
        return "unknown"

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # ── Step 1: Probe / (main page) ──────────────────────────
    status, headers, body, cookies = await fetch(session, url, timeout)

    # Check WordPress
    wp_score = 0
    # Header checks
    for sig in WP_HEADER_SIGS:
        key, _, val = sig.partition(": ")
        h_val = headers.get(key, "")
        if val in h_val:
            wp_score += 3
    # Body checks
    for sig in WP_BODY_SIGS:
        if sig in body:
            wp_score += 1
    # Generator meta tag (strong WP signal)
    if "content=\"wordpress" in body:
        wp_score += 5

    # Check Laravel
    lar_score = 0
    # Cookie checks (strong signal)
    for sig in LARAVEL_COOKIE_SIGS:
        if sig.lower() in cookies:
            lar_score += 3
    # Header checks
    for sig in LARAVEL_HEADER_SIGS:
        key, _, val = sig.partition(": ")
        h_val = headers.get(key, "")
        if val in h_val:
            lar_score += 3
    # 419 status (Laravel CSRF protection)
    if status == 419:
        lar_score += 2
    # Body checks
    for sig in LARAVEL_BODY_SIGS:
        if sig in body:
            lar_score += 1
    # Laravel token meta
    if "csrf-token" in body and "laravel" in body:
        lar_score += 3

    # ── Step 2: Probe known paths if main page inconclusive ──
    # WordPress probe
    if wp_score < 3:
        wp_status, _, wp_body, _ = await fetch(session, f"{url}/wp-login.php", timeout)
        if wp_status == 200 and ("wp-login" in wp_body or "wordpress" in wp_body):
            wp_score += 5

        wp_status2, _, wp_body2, _ = await fetch(session, f"{url}/wp-json", timeout)
        if wp_status2 == 200 and ("wp-json" in wp_body2 or "namespaces" in wp_body2):
            wp_score += 3

        wp_status3, _, wp_body3, _ = await fetch(session, f"{url}/xmlrpc.php", timeout)
        if wp_status3 == 200 and ("xml-rpc" in wp_body3 or "xmlrpc" in wp_body3):
            wp_score += 3

    # Laravel probe
    if lar_score < 3:
        # Try /api route (Laravel default)
        api_status, api_headers, api_body, _ = await fetch(session, f"{url}/api", timeout)
        if api_status in (200, 401, 403, 405, 429):
            lar_score += 2
        if api_status == 200 and "laravel" in api_body:
            lar_score += 3

        # Try /login (common Laravel route)
        login_status, _, login_body, login_cookies = await fetch(session, f"{url}/login", timeout)
        for sig in LARAVEL_COOKIE_SIGS:
            if sig.lower() in login_cookies:
                lar_score += 3
        if login_status == 200 and "csrf-token" in login_body:
            lar_score += 2
        if login_status == 419:
            lar_score += 2

    # ── Step 3: Score comparison ──────────────────────────────
    # WordPress needs strong evidence
    if wp_score >= 4 and wp_score > lar_score:
        return "wordpress"
    # Laravel needs strong evidence
    if lar_score >= 4 and lar_score > wp_score:
        return "laravel"
    # Both detected (rare, e.g. WP with Laravel-like cache)
    if wp_score >= 4 and lar_score >= 4:
        return "wordpress" if wp_score >= lar_score else "laravel"

    return "unknown"


# ═══════════════════════════════════════════════════════════════
# Async Scan Worker
# ═══════════════════════════════════════════════════════════════
_print_lock = asyncio.Lock()

async def scan_target(session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore,
                       progress: Progress, out_files: dict, verbose: bool, timeout: int):
    global _shutdown
    if _shutdown:
        return

    url = url.strip().rstrip("/")
    if not url:
        return

    domain = url.replace("http://", "").replace("https://", "").split("/")[0]

    async with sem:
        cms = await detect_cms(session, url, timeout)

    await progress.update(cms)

    # Save to result files
    if cms == "laravel":
        async with out_files["laravel_lock"]:
            with open(out_files["laravel_path"], "a") as f:
                f.write(domain + "\n")
    elif cms == "wordpress":
        async with out_files["wp_lock"]:
            with open(out_files["wp_path"], "a") as f:
                f.write(domain + "\n")

    # Print result
    async with _print_lock:
        sys.stdout.write("\r" + " " * 120 + "\r")
        sys.stdout.flush()
        if cms == "laravel":
            print(f"  {C.MAGENTA}\u251c\u2500 {domain} \u2192 Laravel{C.RESET}")
        elif cms == "wordpress":
            print(f"  {C.YELLOW}\u251c\u2500 {domain} \u2192 WordPress{C.RESET}")
        elif verbose:
            print(f"  {C.DIM}\u251c\u2500 {domain} \u2192 Unknown{C.RESET}")
        sys.stdout.write(progress.bar())
        sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════
def print_summary(progress: Progress, out_dir: str):
    elapsed = time.time() - progress.start
    speed = progress.done / max(elapsed, 0.01)
    print()
    print(f"  {C.GREEN}\u2514\u2500{C.RESET} Done")
    print()
    print(f"{C.CYAN}{C.BOLD}{'='*50}")
    print(f"  SUMMARY")
    print(f"{'='*50}{C.RESET}")
    print(f"  {C.WHITE}Total       {C.BOLD}{progress.done}{C.RESET}")
    print(f"  {C.MAGENTA}Laravel     {progress.laravel}{C.RESET}")
    print(f"  {C.YELLOW}WordPress   {progress.wordpress}{C.RESET}")
    print(f"  {C.DIM}Unknown     {progress.unknown}{C.RESET}")
    print(f"  {C.DIM}Time        {elapsed:.1f}s ({speed:.1f} targets/sec){C.RESET}")
    print(f"{C.CYAN}{'='*50}{C.RESET}")
    print()
    if progress.laravel > 0:
        print(f"  {C.MAGENTA}[*] {progress.laravel} Laravel targets \u2192 {out_dir}/laravel.txt{C.RESET}")
    if progress.wordpress > 0:
        print(f"  {C.YELLOW}[*] {progress.wordpress} WordPress targets \u2192 {out_dir}/wordpress.txt{C.RESET}")
    if progress.laravel > 0 or progress.wordpress > 0:
        print()


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════
async def async_main(args):
    # Collect targets
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
            return

    if not targets:
        return

    total = len(targets)
    out_dir = args.output.rstrip("/")

    # Create output directory
    os.makedirs(out_dir, exist_ok=True)

    # Init output files
    lar_path = os.path.join(out_dir, "laravel.txt")
    wp_path = os.path.join(out_dir, "wordpress.txt")

    with open(lar_path, "w") as f:
        f.write(f"# Laravel targets - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
    with open(wp_path, "w") as f:
        f.write(f"# WordPress targets - {datetime.now():%Y-%m-%d %H:%M:%S}\n")

    out_files = {
        "laravel_path": lar_path,
        "wp_path": wp_path,
        "laravel_lock": asyncio.Lock(),
        "wp_lock": asyncio.Lock(),
    }

    print(f"  {C.CYAN}[*] Loaded {total} targets | {args.workers} workers | timeout {args.timeout}s{C.RESET}")
    print(f"  {C.CYAN}[*] Output: {out_dir}/{C.RESET}")
    print()

    # Init
    sem = asyncio.Semaphore(args.workers)
    progress = Progress(total)
    connector = aiohttp.TCPConnector(limit=args.workers, ttl_dns_cache=300, ssl=SSL_CTX)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [
            scan_target(session, t, sem, progress, out_files, args.verbose, args.timeout)
            for t in targets
        ]
        await asyncio.gather(*tasks)

    # Final
    sys.stdout.write("\n")
    sys.stdout.flush()

    print_summary(progress, out_dir)

    if _shutdown:
        print(f"  {C.YELLOW}[!] Interrupted \u2014 {progress.done}/{total} completed{C.RESET}")
        print(f"  {C.DIM}[*] Partial results saved to {out_dir}/{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description=f"CMS Detector {VERSION} - Detect Laravel & WordPress (Async)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 cmsdetect.py example.com
  python3 cmsdetect.py -f domains.txt
  python3 cmsdetect.py -f domains.txt -o result/
  python3 cmsdetect.py -f domains.txt -w 200
  python3 cmsdetect.py -f domains.txt -v
  python3 cmsdetect.py -f domains.txt --no-color
"""
    )

    parser.add_argument("targets", nargs="*", help="Target URL(s) to scan")
    parser.add_argument("-f", "--file", help="File with target URLs (one per line)")
    parser.add_argument("-o", "--output", default="result", help="Output directory (default: result)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Concurrent workers (default: 100)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show unknown targets too")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--version", action="version", version=f"CMS Detector {VERSION}")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    banner()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
