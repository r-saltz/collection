#!/usr/bin/env python3
"""
DNS Domain Activity Checker
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
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


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
        # Check A record (IPv4)
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        if ips:
            result["active"] = True
            result["records"]["A"] = list(set(ip[4][0] for ip in ips))
    except socket.gaierror:
        pass
    
    try:
        # Check AAAA record (IPv6)
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
            records = []
            for rdata in answers:
                records.append(str(rdata))
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
    # Remove protocol if accidentally included
    domain = domain.replace("http://", "").replace("https://", "")
    # Remove trailing slash/path
    domain = domain.split("/")[0]
    
    if not domain:
        return {"domain": domain, "active": False, "error": "Empty domain"}
    
    if HAS_DNSPYTHON:
        return check_domain_full(domain, nameserver)
    else:
        return check_domain_basic(domain)


def check_domains_bulk(domains: list, nameserver: str = None, max_workers: int = 20) -> list:
    """Check multiple domains concurrently."""
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(check_domain, domain, nameserver): domain
            for domain in domains
        }
        
        for future in as_completed(future_to_domain):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                domain = future_to_domain[future]
                results.append({
                    "domain": domain,
                    "active": False,
                    "error": str(e)
                })
    
    # Sort by original order
    domain_order = {d: i for i, d in enumerate(domains)}
    results.sort(key=lambda r: domain_order.get(r["domain"], 999))
    
    return results


def format_result(result: dict, verbose: bool = False) -> str:
    """Format a single result for console output."""
    domain = result["domain"]
    active = result.get("active", False)
    
    if active:
        status = "\033[92m✓ ACTIVE\033[0m"
    else:
        status = "\033[91m✗ INACTIVE\033[0m"
    
    line = f"  {status}  {domain}"
    
    if verbose and result.get("records"):
        for rtype, values in result["records"].items():
            for v in values:
                line += f"\n         {rtype}: {v}"
    
    if result.get("error") and verbose:
        line += f"\n         Error: {result['error']}"
    
    return line


def print_summary(results: list):
    """Print summary statistics."""
    total = len(results)
    active = sum(1 for r in results if r.get("active"))
    inactive = total - active
    
    print("\n" + "=" * 50)
    print(f"  Summary: {total} checked | "
          f"\033[92m{active} active\033[0m | "
          f"\033[91m{inactive} inactive\033[0m")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="DNS Domain Activity Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 dns_checker.py example.com
  python3 dns_checker.py google.com github.com
  python3 dns_checker.py -f domains.txt
  python3 dns_checker.py -f domains.txt --json -o results.json
  python3 dns_checker.py example.com --ns 8.8.8.8
"""
    )
    
    parser.add_argument("domains", nargs="*", help="Domain(s) to check")
    parser.add_argument("-f", "--file", help="File with domains (one per line)")
    parser.add_argument("--ns", "--nameserver", help="DNS nameserver to use")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed records")
    parser.add_argument("-w", "--workers", type=int, default=20, help="Max concurrent threads")
    
    args = parser.parse_args()
    
    # Collect domains
    domains = list(args.domains) if args.domains else []
    
    if args.file:
        try:
            with open(args.file, "r") as f:
                file_domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                domains.extend(file_domains)
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)
    
    if not domains:
        parser.print_help()
        sys.exit(1)
    
    # Check library status
    if not HAS_DNSPYTHON:
        print("\n[!] dnspython not installed - using basic socket resolution")
        print("    Install for full features: pip install dnspython\n")
    
    print(f"\n[*] Checking {len(domains)} domain(s)...")
    
    # Run checks
    results = check_domains_bulk(domains, args.ns, args.workers)
    
    # Output results
    if args.json:
        output = json.dumps(results, indent=2, ensure_ascii=False)
        print(output)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"\n[*] Results saved to {args.output}")
    else:
        print("\nResults:")
        print("-" * 50)
        for result in results:
            print(format_result(result, args.verbose))
        print_summary(results)
        
        if args.output:
            output = json.dumps(results, indent=2, ensure_ascii=False)
            with open(args.output, "w") as f:
                f.write(output)
            print(f"\n[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
