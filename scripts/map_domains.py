#!/usr/bin/env python3
import sys
import urllib.request
import urllib.parse
import re
import os

def map_domains(query):
    # Format the query and URL
    encoded_query = urllib.parse.quote_plus(query)
    url = f"https://viewdns.info/reversewhois/?q={encoded_query}"
    
    # Set headers to look like a standard browser request
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    }
    
    req = urllib.request.Request(url, headers=headers)
    
    print(f"[*] Querying reverse WHOIS for '{query}'...")
    try:
        with urllib.request.urlopen(req) as response:
            html = response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Error querying database: {e}", file=sys.stderr)
        return []
    
    # Regex to find domain names within table cell tags (<td>)
    # ViewDNS class structure: <td class="px-6 py-4 whitespace-nowrap text-base font-medium text-gray-900 dark:text-gray-100">domain</td>
    domain_pattern = re.compile(r'<td[^>]*>([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</td>')
    domains = domain_pattern.findall(html)
    
    # Deduplicate and sort
    domains = sorted(list(set(domains)))
    
    return domains

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 map_domains.py <query_or_domain_or_email>", file=sys.stderr)
        print("Example: python3 map_domains.py \"Acme Corp\"", file=sys.stderr)
        sys.exit(1)
        
    query = sys.argv[1]
    domains = map_domains(query)
    
    if not domains:
        print("[-] No related domains found or rate-limit encountered.")
        sys.exit(0)
        
    print(f"[+] Found {len(domains)} related domains:")
    for domain in domains:
        print(domain)
        
    # Optional: Write output to a file in the out/ directory
    output_dir = "out/domain_maps"
    os.makedirs(output_dir, exist_ok=True)
    safe_filename = re.sub(r'[^a-zA-Z0-9_-]', '_', query.lower())
    output_file = os.path.join(output_dir, f"{safe_filename}_domains.txt")
    
    try:
        with open(output_file, 'w') as f:
            for domain in domains:
                f.write(domain + '\n')
        print(f"[*] Saved domains to {output_file}")
    except Exception as e:
        print(f"[-] Warning: Could not write output to file: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
