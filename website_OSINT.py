import socket
import requests
import dns.resolver
import whois
import ssl
import subprocess
import sys
from datetime import datetime
import nmap3
import tldextract
import shodan
import geoip2.database
import json
import os
import time
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re
import urllib3
import builtwith
import sublist3r
import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import ipaddress
from PIL import Image
import io

# Disable SSL warnings for requests (for testing purposes)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def install_missing_modules():
    required_modules = [
        "requests", "dnspython", "python-whois", "nmap3", "tldextract",
        "shodan", "geoip2", "beautifulsoup4", "builtwith",
        "sublist3r", "networkx", "matplotlib", "ipaddress", "pillow"
    ]
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            print(f"⚠️ {module} not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

install_missing_modules()

# API Keys and GeoIP Database (Only Shodan and VirusTotal free tiers used)
SHODAN_API_KEY = "bDpCOOeu9afKPgIS7tydBEGxm4wZpufV"      # Your Shodan API key
VIRUSTOTAL_API_KEY = "3d61088e1c3f23311545ec9bf64038ba4d24dfcd0e8e41738fb0d3d4811fb190"  # Your VirusTotal API key
GEOIP_DB = "GeoLite2-City.mmdb"             # Download from maxmind.com (optional)

# Email Configuration for Reporting
EMAIL_ADDRESS = "tanwiraasif11111@gmail.com"  # Your email
EMAIL_PASSWORD = "your_email_password"  # Replace with App Password from Gmail (placeholder for now)
CYBERCRIME_EMAIL = "cybercrime@nic.in"  # Example for India's cybercrime portal

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

def get_random_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

def get_subdomains(domain):
    try:
        print("\n🔍 Subdomain Enumeration (via Sublist3r):")
        subdomains = sublist3r.main(domain, 40, savefile=False, verbose=False, enable_bruteforce=False)
        subdomain_ips = {}
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                subdomain_ips[sub] = ip
                print(f"   - {sub} → {ip}")
            except socket.gaierror:
                print(f"   - {sub} → Not resolved")
        return subdomain_ips
    except Exception as e:
        print(f"⚠️ Subdomain enumeration failed - {e}")
        return {}

def check_breaches(domain):
    try:
        print("\n🌐 Breach Check (Manual Suggestion):")
        print("   - OSINT Tip: Visit https://haveibeenpwned.com/ and manually search for this domain")
        print("   - Alternative: Check web content for breach indicators")
        response = requests.get(f"https://{domain}", timeout=5, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text().lower()
        if "breach" in text or "leak" in text:
            print("   - ⚠️ Possible breach/leak keywords detected in content")
        else:
            print("   - No obvious breach indicators found")
    except Exception as e:
        print(f"⚠️ Breach check failed - {e}")

def check_dark_web(domain):
    try:
        print("\n🕸️ Dark Web Mentions (Placeholder):")
        print("   - OSINT Tip: Use Ahmia.fi API or a legal dark web search tool to check for mentions")
        print("   - Note: Direct dark web access requires Tor and legal clearance")
    except Exception as e:
        print(f"⚠️ Dark web check failed - {e}")

def get_tech_stack_advanced(domain):
    try:
        print("\n🛠️ Advanced Tech Stack Detection (via BuiltWith):")
        tech = builtwith.builtwith(f"https://{domain}")
        for category, techs in tech.items():
            print(f"   - {category}: {', '.join(techs)}")
    except Exception as e:
        print(f"⚠️ Advanced tech stack detection failed - {e}")

def get_certificate_transparency(domain):
    try:
        print("\n🔐 Certificate Transparency Logs (Manual Suggestion):")
        print("   - OSINT Tip: Visit https://crt.sh/?q=%25." + domain + " to check for certificates manually")
        print("   - Note: This provides free subdomain discovery via certificate logs")
    except Exception as e:
        print(f"⚠️ Certificate transparency check failed - {e}")

def get_passive_dns(domain):
    try:
        print("\n⏳ Passive DNS History (Manual Suggestion):")
        print("   - OSINT Tip: Use free tools like ViewDNS.info or SecurityTrails free tier to check historical DNS")
        print("   - Note: Requires manual lookup")
    except Exception as e:
        print(f"⚠️ Passive DNS check failed - {e}")

def check_passive_total(domain, ip):
    try:
        print("\n⏳ Passive Total (via RiskIQ) - Manual Suggestion:")
        print("   - OSINT Tip: Use RiskIQ PassiveTotal free community tools or ViewDNS.info for historical data")
        print("   - Note: Requires manual lookup or free tier account")
    except Exception as e:
        print(f"⚠️ Passive Total check failed - {e}")

def check_virustotal(domain, ip):
    try:
        print("\n🛡️ Malware/Phishing Check (via VirusTotal):")
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=5)
        data = response.json()
        if data.get("data"):
            attributes = data["data"][0]["attributes"]
            print(f"   - Malicious Votes: {attributes.get('total_votes', {}).get('malicious', 0)}")
            print(f"   - Last Analysis: {attributes.get('last_analysis_date')}")
            if attributes.get("categories"):
                print(f"   - Categories: {attributes.get('categories')}")
        else:
            print("   - No VirusTotal data found (free tier limit may apply)")
    except Exception as e:
        print(f"⚠️ VirusTotal check failed - {e}")

def check_tor_exit_node(ip):
    try:
        print("\n🌐 Tor Exit Node Check:")
        tor_list_url = "https://check.torproject.org/torbulkexitlist"
        response = requests.get(tor_list_url, timeout=5)
        tor_ips = response.text.splitlines()
        if ip in tor_ips:
            print(f"   - ⚠️ IP {ip} is a Tor Exit Node")
        else:
            print(f"   - IP {ip} is not a Tor Exit Node")
    except Exception as e:
        print(f"⚠️ Tor exit node check failed - {e}")

def crawl_for_content_clues(domain):
    try:
        print("\n🔍 Web Crawl for Content Clues:")
        response = requests.get(f"https://{domain}", timeout=5, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text().lower()
        keywords = ["adult", "private", "video", "stream", "download", "xxx"]
        found = False
        for keyword in keywords:
            if keyword in text:
                print(f"   - ⚠️ Suspicious Keyword Detected: {keyword}")
                found = True
        if not found:
            print("   - No suspicious keywords found")
    except Exception as e:
        print(f"⚠️ Web crawl failed - {e}")

def scan_ip_range(ip):
    try:
        print("\n🌐 IP Range Scanning:")
        net = ipaddress.ip_network(f"{ip}/24", strict=False)  # Scan /24 range
        for addr in net:
            addr_str = str(addr)
            try:
                host = socket.gethostbyaddr(addr_str)
                print(f"   - {addr_str} → {host[0]}")
            except socket.herror:
                continue
            time.sleep(0.5)  # Avoid rate limiting
    except Exception as e:
        print(f"⚠️ IP range scanning failed - {e}")

def google_dorking(domain):
    try:
        print("\n🔎 Google Dorking for Deep Web Insights:")
        dorks = [
            f"site:{domain} -inurl:(signup login)",
            f"site:*.edu {domain} -inurl:(signup login)",
            f"site:*.gov {domain} -inurl:(signup login)",
            f"filetype:pdf {domain}"
        ]
        for dork in dorks:
            url = f"https://www.google.com/search?q={dork}"
            headers = get_random_headers()
            response = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a')
            found = False
            for result in results:
                href = result.get('href', '')
                if domain in href and "google" not in href:
                    print(f"   - Found: {href}")
                    found = True
                    break
            if not found:
                print(f"   - No results for {dork}")
            time.sleep(2)  # Avoid rate limiting
    except Exception as e:
        print(f"⚠️ Google dorking failed - {e}")

def check_robots_txt(domain):
    try:
        print("\n🤖 Robots.txt Analysis:")
        response = requests.get(f"https://{domain}/robots.txt", timeout=5, verify=False)
        if response.status_code == 200:
            print("   - Robots.txt Found:")
            for line in response.text.splitlines():
                if line.strip().startswith("Disallow:"):
                    print(f"      - {line}")
        else:
            print("   - No robots.txt found")
    except Exception as e:
        print(f"⚠️ Robots.txt analysis failed - {e}")

def check_dnssec(domain):
    try:
        print("\n🔒 DNSSEC Validation:")
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        if answers:
            print("   - DNSSEC Enabled")
        else:
            print("   - ⚠️ DNSSEC Not Enabled")
    except Exception as e:
        print(f"⚠️ DNSSEC check failed - {e}")

def compare_wayback_snapshots(domain):
    try:
        print("\n📜 Web Archive Comparison (Wayback Machine):")
        url = f"https://archive.org/wayback/available?url={domain}"
        response = requests.get(url, timeout=5)
        data = response.json()
        snapshots = data.get('archived_snapshots', {}).get('closest', {})
        if snapshots:
            timestamps = [snapshots['timestamp']]
            for i in range(1, min(3, len(data.get('archived_snapshots', {}).get('snapshots', [])))):
                timestamps.append(data['archived_snapshots']['snapshots'][i]['timestamp'])
            for ts in timestamps:
                snapshot_url = f"https://web.archive.org/web/{ts}/{domain}"
                resp = requests.get(snapshot_url, timeout=5)
                if resp.status_code == 200:
                    print(f"   - Snapshot {ts}: Available")
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    text = soup.get_text().lower()
                    if any(kw in text for kw in ["adult", "private", "video"]):
                        print(f"   - ⚠️ Suspicious content detected in {ts}")
                else:
                    print(f"   - Snapshot {ts}: Unavailable")
    except Exception as e:
        print(f"⚠️ Wayback comparison failed - {e}")

def check_threat_feeds(domain, ip):
    try:
        print("\n⚠️ Threat Intelligence Feeds (Manual Suggestion):")
        print("   - OSINT Tip: Use free AlienVault OTX community tools at otx.alienvault.com")
        print("   - Note: Requires manual lookup")
    except Exception as e:
        print(f"⚠️ Threat feed check failed - {e}")

def capture_screenshot(domain):
    try:
        print("\n📸 Capturing Screenshot:")
        url = f"https://{domain}"
        headers = get_random_headers()
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        if response.status_code == 200:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            time.sleep(2)  # Allow page to load
            screenshot = driver.get_screenshot_as_png()
            driver.quit()
            img = Image.open(io.BytesIO(screenshot))
            filename = f"screenshot_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            img.save(filename)
            print(f"   - Screenshot saved as {filename}")
            return filename
        else:
            print("   - Failed to capture screenshot")
            return None
    except Exception as e:
        print(f"⚠️ Screenshot capture failed - {e}")
        return None

def correlate_findings(domain, subdomain_ips, ip_neighbors, emails):
    try:
        print("\n🔗 Correlation Analysis:")
        correlations = {}
        for sub, ip in subdomain_ips.items():
            if ip in correlations:
                correlations[ip].append(sub)
            else:
                correlations[ip] = [sub]
        for neighbor in ip_neighbors:
            try:
                neighbor_ip = socket.gethostbyname(neighbor)
                if neighbor_ip in correlations:
                    correlations[neighbor_ip].append(neighbor)
                else:
                    correlations[neighbor_ip] = [neighbor]
            except socket.gaierror:
                continue
        for email in emails:
            domain_part = email.split('@')[1]
            if domain_part in correlations:
                correlations[domain_part].append(email)
            else:
                correlations[domain_part] = [email]
        for key, items in correlations.items():
            print(f"   - Related Entities for {key}: {', '.join(items)}")
    except Exception as e:
        print(f"⚠️ Correlation analysis failed - {e}")

def get_social_media_mentions(domain):
    try:
        print("\n📢 Social Media & Forum Mentions (Basic Search):")
        search_terms = [f"site:twitter.com {domain}", f"site:reddit.com {domain}", f"site:*.org {domain} -inurl:(signup login)"]
        for term in search_terms:
            url = f"https://www.google.com/search?q={term}"
            headers = get_random_headers()
            response = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a')
            found = False
            for result in results:
                href = result.get('href', '')
                if domain in href and "google" not in href:
                    print(f"   - Found on {term.split()[0]}: {href}")
                    found = True
                    break
            if not found:
                print(f"   - No mentions found on {term.split()[0]}")
            time.sleep(2)  # Avoid rate limiting
    except Exception as e:
        print(f"⚠️ Social media mentions search failed - {e}")

def check_ssl_vulnerabilities(domain):
    try:
        print("\n🔒 SSL/TLS Vulnerability Check:")
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                protocol = ssock.version()
                cipher = ssock.cipher()
                print(f"   - Protocol: {protocol}")
                print(f"   - Cipher: {cipher[0]}")
                if protocol in ["SSLv3", "TLSv1", "TLSv1.1"]:
                    print("   - ⚠️ Outdated Protocol Detected (Vulnerable)")
                if "RC4" in cipher[0] or "MD5" in cipher[0]:
                    print("   - ⚠️ Weak Cipher Detected (Vulnerable)")
    except Exception as e:
        print(f"⚠️ SSL vulnerability check failed - {e}")

def check_cloudflare(domain):
    try:
        print("\n☁️ Cloudflare/CDN Detection:")
        response = requests.get(f"https://{domain}", timeout=5, verify=False)
        headers = response.headers
        if "CF-RAY" in headers or "cloudflare" in headers.get("Server", "").lower():
            print("   - Cloudflare Detected")
            print("   - OSINT Tip: Check DNS history (e.g., ViewDNS.info) or use tools like CloudFail to uncover origin IP")
        else:
            print("   - No Cloudflare Detected")
    except Exception as e:
        print(f"⚠️ Cloudflare detection failed - {e}")

def harvest_emails(domain):
    try:
        print("\n📧 Email Harvesting from Website:")
        response = requests.get(f"https://{domain}", timeout=5, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
        if emails:
            for email in set(emails):
                print(f"   - {email}")
        else:
            print("   - No emails found")
        return emails if emails else []
    except Exception as e:
        print(f"⚠️ Email harvesting failed - {e}")
        return []

def reverse_whois(domain):
    try:
        print("\n🔍 Reverse WHOIS Lookup (Other Domains by Same Registrant):")
        w = whois.whois(domain)
        registrant_email = w.get("registrant_email", w.get("emails", ""))
        if registrant_email:
            print(f"   - Registrant Email: {registrant_email}")
            print("   - OSINT Tip: Use ViewDNS.info free reverse WHOIS to find other domains")
        else:
            print("   - No registrant email found in WHOIS data")
    except Exception as e:
        print(f"⚠️ Reverse WHOIS lookup failed - {e}")

def get_wayback_info(domain):
    try:
        print("\n📜 Wayback Machine (Internet Archive) Snapshots:")
        url = f"https://archive.org/wayback/available?url={domain}"
        response = requests.get(url, timeout=5)
        data = response.json()
        if data['archived_snapshots']:
            closest = data['archived_snapshots']['closest']
            print(f"   - Closest Snapshot: {closest['timestamp']} ({closest['url']})")
        else:
            print("   - No snapshots found")
    except Exception as e:
        print(f"⚠️ Wayback Machine query failed - {e}")

def compare_wayback_snapshots(domain):
    try:
        print("\n📜 Web Archive Comparison (Wayback Machine):")
        url = f"https://archive.org/wayback/available?url={domain}"
        response = requests.get(url, timeout=5)
        data = response.json()
        snapshots = data.get('archived_snapshots', {}).get('closest', {})
        if snapshots:
            timestamps = [snapshots['timestamp']]
            for i in range(1, min(3, len(data.get('archived_snapshots', {}).get('snapshots', [])))):
                timestamps.append(data['archived_snapshots']['snapshots'][i]['timestamp'])
            for ts in timestamps:
                snapshot_url = f"https://web.archive.org/web/{ts}/{domain}"
                resp = requests.get(snapshot_url, timeout=5)
                if resp.status_code == 200:
                    print(f"   - Snapshot {ts}: Available")
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    text = soup.get_text().lower()
                    if any(kw in text for kw in ["adult", "private", "video"]):
                        print(f"   - ⚠️ Suspicious content detected in {ts}")
                else:
                    print(f"   - Snapshot {ts}: Unavailable")
    except Exception as e:
        print(f"⚠️ Wayback comparison failed - {e}")

def get_dns_records(domain):
    try:
        print("\n📋 Additional DNS Records:")
        mx_records = dns.resolver.resolve(domain, 'MX')
        print("   - MX Records (Mail Servers):")
        for mx in mx_records:
            print(f"      - {mx.exchange} (Priority: {mx.preference})")
        txt_records = dns.resolver.resolve(domain, 'TXT')
        print("   - TXT Records:")
        for txt in txt_records:
            print(f"      - {txt}")
        ns_records = dns.resolver.resolve(domain, 'NS')
        print("   - NS Records:")
        for ns in ns_records:
            print(f"      - {ns}")
    except Exception as e:
        print(f"⚠️ DNS records query failed - {e}")

def check_dnssec(domain):
    try:
        print("\n🔒 DNSSEC Validation:")
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        if answers:
            print("   - DNSSEC Enabled")
        else:
            print("   - ⚠️ DNSSEC Not Enabled")
    except Exception as e:
        print(f"⚠️ DNSSEC check failed - {e}")

def check_exposed_directories(domain):
    try:
        print("\n🔎 Directory Brute-Forcing (Basic):")
        common_dirs = ["/admin", "/backup", "/config", "/wp-admin", "/login", "/phpinfo.php"]
        for dir in common_dirs:
            url = f"https://{domain}{dir}"
            try:
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code != 404:
                    print(f"   - Found: {url} (Status: {response.status_code})")
            except requests.RequestException:
                continue
            time.sleep(1)  # Avoid rate limiting
    except Exception as e:
        print(f"⚠️ Directory brute-forcing failed - {e}")

def check_robots_txt(domain):
    try:
        print("\n🤖 Robots.txt Analysis:")
        response = requests.get(f"https://{domain}/robots.txt", timeout=5, verify=False)
        if response.status_code == 200:
            print("   - Robots.txt Found:")
            for line in response.text.splitlines():
                if line.strip().startswith("Disallow:"):
                    print(f"      - {line}")
        else:
            print("   - No robots.txt found")
    except Exception as e:
        print(f"⚠️ Robots.txt analysis failed - {e}")

def get_ip_neighbors(ip):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        query = f"ip:{ip}"
        results = api.search(query)
        print("\n🌐 IP Neighbor Analysis (Domains on Same IP):")
        neighbors = []
        for result in results['matches']:
            hostnames = result.get('hostnames', [])
            if hostnames:
                print(f"   - {', '.join(hostnames)}")
                neighbors.extend(hostnames)
        return neighbors
    except shodan.APIError as e:
        print(f"⚠️ IP neighbor analysis failed - {e}")
        return []

def get_shodan_info(domain):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host_info = api.host(domain)
        print("\n🔍 Shodan Intelligence:")
        print(f"   - IP: {host_info['ip_str']}")
        print(f"   - Hostnames: {', '.join(host_info.get('hostnames', []))}")
        print(f"   - Open Ports: {', '.join(map(str, host_info.get('ports', [])))}")
        print(f"   - OS: {host_info.get('os', 'Unknown')}")
        print(f"   - Vulnerabilities: {', '.join(host_info.get('vulns', {}).keys())}")
        return get_ip_neighbors(host_info['ip_str'])
    except shodan.APIError as e:
        print(f"⚠️ Shodan query failed - {e}")
        return []

def get_geolocation(ip):
    try:
        print("\n📍 Geolocation (Trying GeoIP2 Database):")
        reader = geoip2.database.Reader(GEOIP_DB)
        response = reader.city(ip)
        print(f"   - Country: {response.country.name}")
        print(f"   - City: {response.city.name}")
        print(f"   - Latitude: {response.location.latitude}")
        print(f"   - Longitude: {response.location.longitude}")
        reader.close()
        return response
    except Exception as e:
        print(f"⚠️ GeoIP2 Database failed - {e}")
        print("📍 Falling back to ip-api.com (free online API):")
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            if data["status"] == "success":
                print(f"   - Country: {data['country']}")
                print(f"   - City: {data['city']}")
                print(f"   - Latitude: {data['lat']}")
                print(f"   - Longitude: {data['lon']}")
            else:
                print("   - Failed to get geolocation from ip-api.com")
        except Exception as e:
            print(f"⚠️ ip-api.com geolocation failed - {e}")
        return None

def get_tech_stack(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5, verify=False)
        headers = response.headers
        print("\n🛠️ Tech Stack (Based on Headers):")
        server = headers.get("Server", "Unknown")
        print(f"   - Server: {server}")
        if "X-Powered-By" in headers:
            print(f"   - Powered By: {headers['X-Powered-By']}")
        if "X-AspNet-Version" in headers:
            print(f"   - ASP.NET Version: {headers['X-AspNet-Version']}")
    except Exception as e:
        print(f"⚠️ Tech stack detection failed - {e}")

def check_vulnerabilities(domain):
    try:
        print("\n🛡️ Vulnerability Check (Basic):")
        response = requests.get(f"https://{domain}", timeout=5, verify=False)
        headers = response.headers
        server = headers.get("Server", "").lower()
        if "apache" in server and "2.2" in server:
            print("   - ⚠️ Possible Outdated Apache 2.2 Detected (Vulnerable)")
        if "nginx" in server and "1.4" in server:
            print("   - ⚠️ Possible Outdated Nginx 1.4 Detected (Vulnerable)")
    except Exception as e:
        print(f"⚠️ Vulnerability check failed - {e}")

def generate_network_graph(domain, subdomain_ips, ip_neighbors):
    try:
        print("\n🌐 Generating Network Graph:")
        G = nx.Graph()
        # Add main domain
        G.add_node(domain, type="domain")
        # Add subdomains
        for sub, ip in subdomain_ips.items():
            G.add_node(sub, type="subdomain")
            G.add_node(ip, type="ip")
            G.add_edge(sub, ip)
            G.add_edge(domain, sub)
        # Add IP neighbors
        for neighbor in ip_neighbors:
            G.add_node(neighbor, type="neighbor")
            G.add_edge(ip, neighbor)

        # Generate plot
        plt.figure(figsize=(12, 10))
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=1500, font_size=10)
        buf = BytesIO()
        plt.savefig(buf, format="png")
        buf.seek(0)
        img_str = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
        return img_str
    except Exception as e:
        print(f"⚠️ Network graph generation failed - {e}")
        return None

def capture_screenshot(domain):
    try:
        print("\n📸 Capturing Screenshot:")
        url = f"https://{domain}"
        headers = get_random_headers()
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        if response.status_code == 200:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            time.sleep(2)  # Allow page to load
            screenshot = driver.get_screenshot_as_png()
            driver.quit()
            img = Image.open(io.BytesIO(screenshot))
            filename = f"screenshot_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            img.save(filename)
            print(f"   - Screenshot saved as {filename}")
            return filename
        else:
            print("   - Failed to capture screenshot")
            return None
    except Exception as e:
        print(f"⚠️ Screenshot capture failed - {e}")
        return None

def save_report(domain, data, graph_img, screenshot_file):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Text Report
    txt_filename = f"osint_report_{domain}_{timestamp}.txt"
    with open(txt_filename, "w") as f:
        f.write(f"BugHunter OSINT Report by Tanwir Aasif\n")
        f.write(f"Target: {domain}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-" * 50 + "\n")
        f.write(data + "\n")
    print(f"\n📝 Text Report saved as {txt_filename}")

    # HTML Report with Dashboard
    html_filename = f"osint_report_{domain}_{timestamp}.html"
    graph_html = f'<img src="data:image/png;base64,{graph_img}" alt="Network Graph" style="max-width: 100%;">' if graph_img else "Graph generation failed."
    screenshot_html = f'<img src="screenshot_{domain}_{timestamp}.png" alt="Screenshot" style="max-width: 100%;">' if screenshot_file else "Screenshot unavailable."
    html_content = f"""
    <html>
    <head><title>OSINT Report - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; }}
        .section {{ margin: 15px 0; padding: 10px; background: #fff; border-radius: 5px; }}
        .section a {{ color: #0066cc; text-decoration: none; }}
        .section a:hover {{ text-decoration: underline; }}
        pre {{ background: #e8e8e8; padding: 10px; border-radius: 5px; }}
        img {{ max-width: 100%; }}
    </style>
    </head>
    <body>
        <h1>BugHunter OSINT Report by Tanwir Aasif</h1>
        <h2>Target: {domain}</h2>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <hr>
        <div class="section"><h2>Dashboard</h2>
            <ul>
                <li><a href="#dns">DNS Data</a></li>
                <li><a href="#whois">WHOIS Data</a></li>
                <li><a href="#ssl">SSL Info</a></li>
                <li><a href="#shodan">Shodan Data</a></li>
                <li><a href="#graph">Network Graph</a></li>
                <li><a href="#screenshot">Screenshot</a></li>
            </ul>
        </div>
        <pre id="dns">{data.split('WHOIS Data:')[0]}</pre>
        <pre id="whois">{'WHOIS Data:' + data.split('WHOIS Data:')[1].split('SSL Certificate:')[0]}</pre>
        <pre id="ssl">{'SSL Certificate:' + data.split('SSL Certificate:')[1].split('Shodan Intelligence:')[0]}</pre>
        <pre id="shodan">{'Shodan Intelligence:' + data.split('Shodan Intelligence:')[1]}</pre>
        <h2 id="graph">Network Graph</h2>
        {graph_html}
        <h2 id="screenshot">Screenshot</h2>
        {screenshot_html}
    </body>
    </html>
    """
    with open(html_filename, "w") as f:
        f.write(html_content)
    print(f"📝 HTML Report with Dashboard saved as {html_filename}")
    return txt_filename, html_filename, screenshot_file

def email_report(domain, txt_filename, html_filename, screenshot_file):
    try:
        print("\n📧 Sending Report to Cybercrime Authorities:")
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = CYBERCRIME_EMAIL
        msg['Subject'] = f"OSINT Report for {domain} - Tanwir Aasif"

        body = f"""
Dear Cybercrime Team,

I am Tanwir Aasif, a cybersecurity student and bug hunter. I have compiled an OSINT report for the domain {domain}, which may be linked to illegal activities. My goal is to help protect the innocent by providing actionable intelligence.

Please find the report attached. I hope this information is useful for your investigations.

Thank you,
Tanwir Aasif
"""
        msg.attach(MIMEText(body, 'plain'))

        # Attach files
        for filename in [txt_filename, html_filename]:
            with open(filename, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {filename}",
            )
            msg.attach(part)
        if screenshot_file:
            with open(screenshot_file, "rb") as attachment:
                part = MIMEBase("image", "png")
                part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {screenshot_file}",
            )
            msg.attach(part)

        # Send email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_ADDRESS, CYBERCRIME_EMAIL, text)
        server.quit()
        print(f"   - Report sent to {CYBERCRIME_EMAIL}")
    except Exception as e:
        print(f"⚠️ Email sending failed - {e}")

def correlate_findings(domain, subdomain_ips, ip_neighbors, emails):
    try:
        print("\n🔗 Correlation Analysis:")
        correlations = {}
        for sub, ip in subdomain_ips.items():
            if ip in correlations:
                correlations[ip].append(sub)
            else:
                correlations[ip] = [sub]
        for neighbor in ip_neighbors:
            try:
                neighbor_ip = socket.gethostbyname(neighbor)
                if neighbor_ip in correlations:
                    correlations[neighbor_ip].append(neighbor)
                else:
                    correlations[neighbor_ip] = [neighbor]
            except socket.gaierror:
                continue
        for email in emails:
            domain_part = email.split('@')[1]
            if domain_part in correlations:
                correlations[domain_part].append(email)
            else:
                correlations[domain_part] = [email]
        for key, items in correlations.items():
            print(f"   - Related Entities for {key}: {', '.join(items)}")
    except Exception as e:
        print(f"⚠️ Correlation analysis failed - {e}")

def get_website_info(domain):
    report_data = ""
    print("\n🌐 BugHunter OSINT Report by Tanwir Aasif 🌐")
    print("════════════════════════════")
    print(f"🌐 Target: {domain}")

    # DNS Resolution
    try:
        ipv4_addresses = [ip.to_text() for ip in dns.resolver.resolve(domain, 'A')]
        report_data += "\n📌 IPv4 Address(es):"
        for ip in ipv4_addresses:
            report_data += f"\n   - {ip}"
            get_geolocation(ip)
            check_tor_exit_node(ip)
            check_virustotal(domain, ip)
            scan_ip_range(ip)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
        report_data += "\n⚠️ Error: Couldn’t resolve IPv4 addresses."
        print(report_data)

    try:
        ipv6_addresses = [ip.to_text() for ip in dns.resolver.resolve(domain, 'AAAA')]
        if ipv6_addresses:
            report_data += "\n📌 IPv6 Address(es):"
            for ip in ipv6_addresses:
                report_data += f"\n   - {ip}"
    except dns.resolver.NoAnswer:
        pass

    # HTTP Headers
    try:
        response = requests.get(f"https://{domain}", timeout=5, verify=False)
        report_data += "\n📡 HTTP Headers:"
        for key, value in response.headers.items():
            report_data += f"\n   🔹 {key}: {value}"
    except requests.RequestException as e:
        report_data += f"\n⚠️ Error: HTTP request failed - {e}"

    # WHOIS Information
    try:
        w = whois.whois(domain)
        report_data += "\n🕵️‍♂️ WHOIS Data:"
        report_data += f"\n   🔹 Registrar: {w.registrar}"
        report_data += f"\n   🔹 Creation Date: {w.creation_date}"
        report_data += f"\n   🔹 Expiration Date: {w.expiration_date}"
        report_data += f"\n   🔹 Name Servers: {', '.join(w.name_servers)}"
    except Exception as e:
        report_data += f"\n⚠️ Error: WHOIS lookup failed - {e}"

    # SSL Certificate Info
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                report_data += "\n🔒 SSL Certificate:"
                report_data += f"\n   - Issued To: {cert['subject'][0][0][1]}"
                report_data += f"\n   - Valid From: {datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')}"
                report_data += f"\n   - Valid Until: {datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')}"
    except Exception as e:
        report_data += f"\n⚠️ Error: SSL info unavailable - {e}"

    # Advanced Features
    subdomain_ips = get_subdomains(domain)
    ip_neighbors = get_shodan_info(domain)
    emails = harvest_emails(domain)
    graph_img = generate_network_graph(domain, subdomain_ips, ip_neighbors)
    screenshot_file = capture_screenshot(domain)
    check_breaches(domain)
    check_dark_web(domain)
    get_tech_stack_advanced(domain)
    get_certificate_transparency(domain)
    get_passive_dns(domain)
    check_passive_total(domain, ipv4_addresses[0] if ipv4_addresses else "")
    check_virustotal(domain, ipv4_addresses[0] if ipv4_addresses else "")
    check_tor_exit_node(ipv4_addresses[0] if ipv4_addresses else "")
    crawl_for_content_clues(domain)
    scan_ip_range(ipv4_addresses[0] if ipv4_addresses else "")
    google_dorking(domain)
    check_robots_txt(domain)
    check_dnssec(domain)
    compare_wayback_snapshots(domain)
    check_threat_feeds(domain, ipv4_addresses[0] if ipv4_addresses else "")
    get_social_media_mentions(domain)
    check_ssl_vulnerabilities(domain)
    check_cloudflare(domain)
    reverse_whois(domain)
    get_wayback_info(domain)
    get_dns_records(domain)
    check_exposed_directories(domain)
    get_tech_stack(domain)
    check_vulnerabilities(domain)
    correlate_findings(domain, subdomain_ips, ip_neighbors, emails)

    # Save and Email Report
    txt_filename, html_filename, screenshot_file = save_report(domain, report_data, graph_img, screenshot_file)
    email_report(domain, txt_filename, html_filename, screenshot_file)

if __name__ == "__main__":
    print("Script by Tanwir Aasif - BugHunter Edition")
    domain = input("🔎 Enter Website (without http/https): ").strip()
    get_website_info(domain)
