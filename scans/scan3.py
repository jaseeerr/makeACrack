#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urlparse

# ---------- helpers ----------
BOLD = "1"
CYAN = "36"
GREEN = "32"
YELLOW = "33"
RED = "31"

def color(s, code): return f"\033[{code}m{s}\033[0m"

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def install_whatweb_if_needed() -> bool:
    if have("whatweb"):
        return True
    print("[makeAcrack] whatweb not found; attempting to install (Debian/Kali)...")
    if sys.platform.startswith("linux") and have("apt-get"):
        try:
            subprocess.check_call(["sudo", "apt-get", "update"], stdout=sys.stdout, stderr=sys.stderr)
            subprocess.check_call(["sudo", "apt-get", "install", "-y", "whatweb"], stdout=sys.stdout, stderr=sys.stderr)
        except Exception as e:
            print(f"[makeAcrack] whatweb install failed: {e}")
    else:
        print("[makeAcrack] automatic install not supported on this OS. Please install `whatweb` and re-run.")
    return have("whatweb")

def run(cmd, **kwargs) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, **kwargs)
        return out
    except subprocess.CalledProcessError as e:
        return e.output

def normalize_target(t: str) -> str:
    """Accept domain or URL; return netloc; also give http/https URLs."""
    t = t.strip()
    if not t:
        return t
    if "://" not in t:
        netloc = t
        http = f"http://{netloc}"
        https = f"https://{netloc}"
    else:
        u = urlparse(t)
        netloc = u.netloc or u.path
        http = f"http://{netloc}"
        https = f"https://{netloc}"
    return netloc, http, https

# ---------- parsing ----------
HDR_RE = re.compile(r"^([\w-]+):\s*(.+)$", re.IGNORECASE)

def parse_curl_headers(block: str):
    """
    Accept a 'curl -I' output block, return dict of headers + first status line.
    curl -I may show multiple header blocks if redirects aren't followed (we won't -L).
    We'll parse the FIRST block we get.
    """
    lines = [ln.strip("\r") for ln in block.splitlines() if ln.strip()]
    status = ""
    headers = {}
    for ln in lines:
        if ln.upper().startswith("HTTP/"):
            if not status:
                status = ln  # first status
            continue
        m = HDR_RE.match(ln)
        if m:
            k, v = m.group(1), m.group(2)
            if k.lower() not in headers:
                headers[k.lower()] = v
    return status, headers

def parse_whatweb_lines(text: str):
    """
    WhatWeb output examples (space-separated tokens; details in []):
      http://host [301 Moved Permanently] Country[GB], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[82.112.227.70], ...
      https://host/ [200 OK] ... Title[AutoInvoice], nginx[1.18.0]
    We'll collect a per-URL dict → {url, status, facts:{key:[values...]}}.
    """
    entries = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # First token is URL
        parts = line.split(None, 1)
        if len(parts) == 1:
            continue
        url, rest = parts[0], parts[1]

        # Status like [200 OK] / [301 Moved Permanently] appears early; pick first [...]
        status_match = re.search(r"\[([0-9]{3} [^\]]+)\]", rest)
        status = status_match.group(1) if status_match else ""

        # Key[Val] (possibly multiple, comma separated)
        facts = {}
        for key, val in re.findall(r"([A-Za-z0-9_-]+)\[([^\]]+)\]", rest):
            facts.setdefault(key, []).append(val)
        entries.append({"url": url, "status": status, "facts": facts, "raw": raw})
    return entries

def pick_title(facts) -> str:
    vals = facts.get("Title") or facts.get("title") or []
    return vals[0] if vals else ""

def pick_server(facts) -> str:
    # HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)] → join them
    httpserver = facts.get("HTTPServer") or []
    if httpserver:
        return " / ".join(httpserver)
    # fallback nginx[1.18.0]
    if "nginx" in facts:
        return f"nginx[{', '.join(facts['nginx'])}]"
    return ""

def pick_redirect(facts, curl_headers) -> str:
    # Prefer WhatWeb RedirectLocation[...] then curl header Location
    redirs = facts.get("RedirectLocation") or facts.get("Redirect") or []
    if redirs:
        return redirs[0]
    loc = curl_headers.get("location")
    return loc or ""

def looks_like_modern_frontend(facts) -> bool:
    # crude hint: HTML5 / Script[module] present
    return ("HTML5" in facts) or ("Script" in facts and any("module" in v.lower() for v in facts["Script"]))

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="makeAcrack scan3 (headers + tech ID via curl/whatweb)")
    ap.add_argument("--target", required=True, help="Domain or URL, e.g., autoinvoice.example.com")
    args = ap.parse_args()

    if not have("curl"):
        print("[makeAcrack] Missing required tool: curl", file=sys.stderr)
        sys.exit(2)
    if not install_whatweb_if_needed():
        sys.exit(2)

    netloc, http_url, https_url = normalize_target(args.target)

    # ---- curl -I on HTTP (no -L; we want to see the 301 + Location) ----
    print(color(f"\n[curl] HEAD {http_url}", CYAN))
    curl_out = run(["curl", "-I", "--max-redirs", "0", "--connect-timeout", "10", http_url])
    # Print raw (verbose by default)
    print(curl_out.rstrip())
    status_line, headers = parse_curl_headers(curl_out)

    # ---- whatweb on http + https ----
    print(color(f"\n[whatweb] {http_url}", CYAN))
    ww_http = run(["whatweb", http_url])
    print(ww_http.rstrip())

    print(color(f"\n[whatweb] {https_url}", CYAN))
    ww_https = run(["whatweb", https_url])
    print(ww_https.rstrip())

    ww_entries = parse_whatweb_lines(ww_http + "\n" + ww_https)

    # Pull most meaningful piece: prefer the HTTPS 200 entry if exists
    https_200 = next((e for e in ww_entries if e["url"].startswith("https://") and e["status"].startswith("200")), None)
    https_any = next((e for e in ww_entries if e["url"].startswith("https://")), None)
    best = https_200 or https_any or (ww_entries[0] if ww_entries else None)

    # Extract highlights
    server = ""
    title = ""
    redirect_to = ""
    tech_hints = []
    ip = ""
    country = ""

    # From whatweb facts
    if best:
        facts = best["facts"]
        server = pick_server(facts)
        title  = pick_title(facts)
        redirect_to = pick_redirect(facts, headers)
        ip_vals = facts.get("IP") or []
        if ip_vals:
            ip = ip_vals[0]
        ctry_vals = facts.get("Country") or facts.get("CountryCode") or []
        if ctry_vals:
            country = ctry_vals[0]
        # quick tech hints
        if "HTML5" in facts: tech_hints.append("HTML5")
        if "Script" in facts and any("module" in v.lower() for v in facts["Script"]):
            tech_hints.append("ES modules (modern JS)")
        if "nginx" in facts:
            tech_hints.append(f"nginx[{', '.join(facts['nginx'])}]")
        if "HTTPServer" in facts:
            # avoid duplicate with pick_server
            pass

    # From curl headers for redirect
    if not redirect_to:
        redirect_to = headers.get("location", "")

    # If server still empty, try curl Server:
    if not server:
        server = headers.get("server", "")

    # Compose a friendly breakdown
    print(color("\nNice grab 👌 — here’s the breakdown short and sharp:\n", BOLD))

    if server:
        print(f"• Server: {server} → web server identified.")
    else:
        print("• Server: (not clearly identified)")

    if status_line.startswith("HTTP/1.1 301") or redirect_to:
        print("• Redirect: HTTP → HTTPS (TLS enforced)." if redirect_to else "• Redirect: possible, verify manually.")
    else:
        print("• Redirect: not observed on HTTP.")

    if title:
        print(f"• Title: {title} → likely a custom app.")
    else:
        print("• Title: (no page title observed)")

    if country:
        print(f"• Geolocation hint: {country}")
    if ip:
        print(f"• Origin IP: {ip}")

    if tech_hints:
        print(f"• Tech hints: {', '.join(tech_hints)}")
    else:
        print("• Tech hints: (generic)")

    if not headers.get("x-powered-by"):
        print("• No obvious X-Powered-By header → backend stack not disclosed.")

    # Quick next steps
    print("\n" + color("👉 Meaning:", BOLD), "Likely a custom web app fronted by nginx. Next moves:")
    print("  - Check /robots.txt and /sitemap.xml")
    print("  - Directory brute-force (gobuster/feroxbuster) for /admin, /api, etc.")
    print("  - Inspect cookies:")
    print(f"    curl -k -I -s -D - {https_url} | grep -i set-cookie")
    print("  - Run nuclei on the HTTPS endpoint for quick wins.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)
