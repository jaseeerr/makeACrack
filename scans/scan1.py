#!/usr/bin/env python3
import argparse
import subprocess
import sys
import re
import os
from datetime import datetime
from shutil import which

# ========== attempt to import rich (auto-install if missing) ==========
RICH_AVAILABLE = False
def _attempt_import_rich():
    global RICH_AVAILABLE
    try:
        import rich  # noqa
        from rich.console import Console  # noqa
        from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn  # noqa
        RICH_AVAILABLE = True
    except Exception:
        RICH_AVAILABLE = False

_attempt_import_rich()

if not RICH_AVAILABLE:
    print("[makeAcrack] 'rich' not found; attempting to install it now...", flush=True)
    try:
        subprocess.check_blue_call = subprocess.check_call  # alias to avoid shadowing
        subprocess.check_blue_call([sys.executable, "-m", "pip", "install", "--user", "rich"], stdout=sys.stdout, stderr=sys.stderr)
    except Exception as e:
        print(f"[makeAcrack] Failed to install 'rich' automatically ({e}). Falling back to simple progress.\n", flush=True)
    _attempt_import_rich()

# Safe imports (only if available)
if RICH_AVAILABLE:
    from rich.console import Console
    from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn
    console = Console()

# ---------- utils ----------
def run(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out
    except subprocess.CalledProcessError as e:
        return e.output

def save_text(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def color(s, code):
    return f"\033[{code}m{s}\033[0m"

BOLD = "1"
GREEN = "32"
YELLOW = "33"
CYAN = "36"
RED = "31"

# ---------- parsers ----------
WHOIS_FIELDS = {
    "domain": re.compile(r"^\s*Domain Name:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "registry_domain_id": re.compile(r"^\s*Registry Domain ID:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "registrar": re.compile(r"^\s*Registrar:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "registrar_whois": re.compile(r"^\s*Registrar WHOIS Server:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "registrar_url": re.compile(r"^\s*Registrar URL:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "updated_date": re.compile(r"^\s*Updated Date:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "creation_date": re.compile(r"^\s*Creation Date:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "expiry_date": re.compile(r"^\s*Registry Expiry Date:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "iana_id": re.compile(r"^\s*Registrar IANA ID:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "abuse_email": re.compile(r"^\s*Registrar Abuse Contact Email:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "abuse_phone": re.compile(r"^\s*Registrar Abuse Contact Phone:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "status": re.compile(r"^\s*Domain Status:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "nameservers": re.compile(r"^\s*Name Server:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
    "dnssec": re.compile(r"^\s*DNSSEC:\s*(.+)\s*$", re.IGNORECASE | re.MULTILINE),
}

def parse_whois(text):
    data = {}
    for key, rx in WHOIS_FIELDS.items():
        if key in ("nameservers", "status"):
            data[key] = rx.findall(text)
        else:
            m = rx.search(text)
            data[key] = m.group(1).strip() if m else None
    if data.get("nameservers"):
        data["nameservers"] = [ns.strip().rstrip(".") for ns in data["nameservers"]]
    else:
        data["nameservers"] = []
    return data

def parse_dig_answer(text):
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[2] in ("IN", "CH", "HS"):
            name, ttl, clas, rtype = parts[:4]
            rest = " ".join(parts[4:])
            lines.append((name.rstrip("."), ttl, clas, rtype, rest))
        elif len(parts) >= 4:
            name, clas, rtype = parts[:3]
            rest = " ".join(parts[3:])
            lines.append((name.rstrip("."), "", clas, rtype, rest))
    return lines

# ---------- progress helpers ----------
class StepProgress:
    def __init__(self, domain, total_steps):
        self.domain = domain
        self.total = total_steps
        self.current = 0
        self.rich_task = None
        self.use_rich = RICH_AVAILABLE

        if self.use_rich:
            self.progress = Progress(
                TextColumn("[bold]Scanning[/bold] " + domain),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("•"),
                TimeElapsedColumn(),
                transient=True  # auto clear when done
            )
            self.progress.start()
            self.rich_task = self.progress.add_task(f"scan:{domain}", total=total_steps)
        else:
            print(f"Scanning {domain} ...", flush=True)
            self._print_ascii()

    def advance(self, note=""):
        self.current += 1
        if self.use_rich:
            if note:
                self.progress.update(self.rich_task, advance=1, description=f"{note}")
            else:
                self.progress.update(self.rich_task, advance=1)
        else:
            if note:
                print(f"  - {note}", flush=True)
            self._print_ascii()

    def _print_ascii(self):
        pct = int((self.current / self.total) * 100)
        pct = min(100, max(0, pct))
        bar_len = 28
        filled = int((pct / 100) * bar_len)
        bar = "[" + "#" * filled + "-" * (bar_len - filled) + f"] {pct}%"
        print("    " + bar, flush=True)

    def stop(self):
        if self.use_rich:
            self.progress.stop()

# ---------- main scan ----------
def main():
    ap = argparse.ArgumentParser(description="makeAcrack scan1 (whois + basic DNS)")
    ap.add_argument("--domain", required=True, help="Domain to scan, e.g., example.com")
    args = ap.parse_args()
    domain = args.domain.strip()

    # steps: whois, A, MX, NS, CNAME, SOA, parsing -> 7 (saving now optional at the end)
    steps = StepProgress(domain, total_steps=7)

    # 1) WHOIS
    whois_raw = run(["whois", domain])
    steps.advance("whois")

    # 2) dig A
    dig_a_raw = run(["dig", "+noall", "+answer", domain])
    steps.advance("dig A")

    # 3) dig MX
    dig_mx_raw = run(["dig", "+noall", "+answer", "mx", domain])
    steps.advance("dig MX")

    # 4) dig NS
    dig_ns_raw = run(["dig", "+noall", "+answer", "ns", domain])
    steps.advance("dig NS")

    # 5) dig CNAME
    dig_cname_raw = run(["dig", "+noall", "+answer", "cname", domain])
    steps.advance("dig CNAME")

    # 6) dig SOA
    dig_soa_raw = run(["dig", "+noall", "+answer", "soa", domain])
    steps.advance("dig SOA")

    # Parse
    w = parse_whois(whois_raw)
    a_records = parse_dig_answer(dig_a_raw)
    mx_records = parse_dig_answer(dig_mx_raw)
    ns_records = parse_dig_answer(dig_ns_raw)
    cname_records = parse_dig_answer(dig_cname_raw)
    soa_records = parse_dig_answer(dig_soa_raw)
    steps.advance("parsed & formatted")

    # progress complete
    steps.stop()

    # ---------- Human-friendly Output ----------
    print(color(f"{domain} is the domain, let's start.\n", BOLD))

    print(color("Whois Info", BOLD))
    if w.get("registrar"):
        print(f"Registrar: {w['registrar']}", flush=True)
    if w.get("creation_date"):
        print(f"Domain created: {w['creation_date']}", flush=True)
    if w.get("updated_date"):
        print(f"Updated: {w['updated_date']}", flush=True)
    if w.get("expiry_date"):
        print(f"Expiry: {w['expiry_date']}", flush=True)
    if w.get("iana_id"):
        print(f"Registrar IANA ID: {w['iana_id']}", flush=True)
    if w.get("abuse_email"):
        print(f"Registrar Abuse Contact Email: {w['abuse_email']}", flush=True)
    if w.get("abuse_phone"):
        print(f"Registrar Abuse Contact Phone: {w['abuse_phone']}", flush=True)

    if w.get("nameservers"):
        print("Nameservers:")
        for ns in w["nameservers"]:
            print(f"  - {ns}")
    else:
        print("Nameservers: (none found)")

    if w.get("dnssec"):
        print(f"DNSSEC: {w['dnssec']}")
    if w.get("status"):
        print("Status:")
        for st in w["status"]:
            print(f"  - {st}")
    print()

    # DIG A
    print(color("Dig (A record)", BOLD))
    if a_records:
        for name, ttl, clas, rtype, rest in a_records:
            print(f"{name}  IN  A  {rest}")
        ips = [rest for _,_,_,_,rest in a_records]
        print(color("\nInterpretation:", CYAN))
        print(f"- The domain resolves to: {', '.join(ips)}")
    else:
        print("No A records found.")
    print()

    # DIG MX
    print(color("Dig (MX record)", BOLD))
    if mx_records:
        for name, ttl, clas, rtype, rest in mx_records:
            print(f"{name}  IN  MX  {rest}")
        print(color("\nInterpretation:", CYAN))
        print("- Mail exchangers are configured; email likely handled at these hosts.")
    else:
        print("No MX record.")
        print(color("\nInterpretation:", CYAN))
        print("- No configured mail server for this domain (either email not used or handled via subdomain/third-party not exposed).")
    print()

    # DIG CNAME
    print(color("Dig (CNAME record)", BOLD))
    if cname_records:
        for name, ttl, clas, rtype, rest in cname_records:
            print(f"{name}  IN  CNAME  {rest}")
        print(color("\nInterpretation:", CYAN))
        print("- Domain is aliased via CNAME (CDN or another host may be in front).")
    else:
        print("No CNAME entry.")
        print(color("\nInterpretation:", CYAN))
        print("- The apex appears to point directly (no alias).")
    print()

    # DIG NS
    print(color("Dig (NS record)", BOLD))
    if ns_records:
        for name, ttl, clas, rtype, rest in ns_records:
            print(f"{name}  IN  NS  {rest}")
        print(color("\nInterpretation:", CYAN))
        print("- Authoritative nameservers listed above.")
    else:
        print("No NS records returned in ANSWER (check SOA/authority).")
    print()

    # DIG SOA (extra context)
    if soa_records:
        print(color("Dig (SOA record)", BOLD))
        for name, ttl, clas, rtype, rest in soa_records:
            print(f"{name}  IN  SOA  {rest}")
        print()

    # Quick notes
    cdn_like = any("cloudflare" in ns.lower() for ns in w.get("nameservers", []))
    print(color("Quick Notes", BOLD))
    if not cname_records and not cdn_like:
        print("- No CNAME at apex and nameservers not Cloudflare → traffic likely hits origin directly.")
    else:
        print("- DNS suggests some indirection (CNAME and/or CDN-like NS). Investigate further if needed.")

    if w.get("dnssec") and w["dnssec"].lower() != "unsigned":
        print("- DNSSEC enabled.")
    else:
        print("- DNSSEC: unsigned (no DNSSEC protection).")

    # ----- Ask whether to save raw outputs (default: No) -----
    choice = input("\nDo you want to save raw outputs? (default = No) [1/yes to save]: ").strip().lower()
    if choice in ("1", "yes", "y"):
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        outdir = os.path.join(os.path.dirname(__file__), "..", "results", domain, timestamp)
        outdir = os.path.abspath(outdir)
        save_text(os.path.join(outdir, "whois.txt"), whois_raw)
        save_text(os.path.join(outdir, "dig_A.txt"), dig_a_raw)
        save_text(os.path.join(outdir, "dig_MX.txt"), dig_mx_raw)
        save_text(os.path.join(outdir, "dig_NS.txt"), dig_ns_raw)
        save_text(os.path.join(outdir, "dig_CNAME.txt"), dig_cname_raw)
        save_text(os.path.join(outdir, "dig_SOA.txt"), dig_soa_raw)
        print(color(f"\nRaw outputs saved to: {outdir}", GREEN))
    else:
        print(color("\nResults not saved.", YELLOW))

if __name__ == "__main__":
    try:
        # sanity check for whois/dig presence; if missing, warn early
        missing = []
        for cmd in ("whois", "dig"):
            if which(cmd) is None:
                missing.append(cmd)
        if missing:
            print(f"[makeAcrack] Missing required tools: {', '.join(missing)}")
            if sys.platform.startswith("linux"):
                print("  Try: sudo apt-get update && sudo apt-get install -y whois dnsutils")
            sys.exit(2)

        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)
