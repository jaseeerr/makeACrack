#!/usr/bin/env python3
"""
scan2a.py

Classify subdomains as Active vs Inactive using ProjectDiscovery httpx.

- PRIMARY PATH: use `httpx -json` for structured, reliable parsing.
- FALLBACK:     if JSON lines fail, parse text lines robustly.

Active = any observed 200 OK where title doesn't look like an error page.
Inactive = otherwise (5xx/4xx, 200 with error-like title, 404, unparsed).

Usage:
  python3 scan2a.py /path/to/subdomains.txt
"""

import argparse
import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

HTTPX_DEFAULT_PORTS = "80,443,8080,8443,8000,3000"

ERROR_TITLE_PATTERNS = [
    r"\b404\b",
    r"404\s*-\s*Page\s*Not\s*Found",
    r"\bForbidden\b",
    r"\bBad\s*Gateway\b",
    r"\bError\b",
    r"\bNot\s*Found\b",
    r"\bAccess\s*Denied\b",
    r"\bUnauthorized\b",
    r"\bMaintenance\b",
    r"\bComing\s*Soon\b",
    r"\bDefault\s*Page\b",
]
ERROR_TITLE_REGEX = re.compile("|".join(f"(?:{p})" for p in ERROR_TITLE_PATTERNS), re.IGNORECASE)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$", re.ASCII)

def ask_yes(prompt: str) -> bool:
    ans = input(f"{prompt} (default = No) [1/yes]: ").strip().lower()
    return ans in ("1", "yes", "y")

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s"
    )

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")

# =========================
# JSON-PATH IMPLEMENTATION
# =========================
def run_httpx_stream_json(subdomains_file: Path, ports: str) -> Iterable[Dict]:
    """
    Run httpx with -json and yield parsed JSON objects per line.
    """
    cmd = [
        "httpx",
        "-l", str(subdomains_file),
        "-silent",
        "-json",
        "-title",
        "-fr",
        "-ip",
        "-td",
        "-p", ports,
    ]
    logging.info(f"[makeAcrack] running: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True
        )
    except FileNotFoundError:
        print("[makeAcrack] httpx not found on PATH. Please install ProjectDiscovery httpx.", file=sys.stderr)
        sys.exit(2)

    assert proc.stdout is not None
    for line in proc.stdout:
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
            yield obj
        except json.JSONDecodeError:
            # Rare; ignore malformed lines
            continue

    _, stderr = proc.communicate()
    if stderr:
        for err_line in stderr.strip().splitlines():
            logging.debug(f"httpx stderr: {err_line}")
    if proc.returncode not in (0,):
        logging.warning(f"[makeAcrack] httpx exited with code {proc.returncode}")

def extract_from_json_obj(obj: Dict) -> Dict:
    """
    Normalize httpx JSON to: {url, codes:[int], title}
    """
    url = obj.get("url") or obj.get("host") or obj.get("input") or ""
    title = obj.get("title") or obj.get("web-title") or obj.get("page_title") or ""
    codes: List[int] = []

    possible_code_keys = ["status_code", "status-code", "status", "final_status_code"]
    for k in possible_code_keys:
        v = obj.get(k)
        if isinstance(v, int):
            codes = [v]; break
        if isinstance(v, str) and v.isdigit():
            codes = [int(v)]; break

    # Include redirect chain codes if present
    for chain_key in ["chain", "redirect_chain", "history"]:
        chain = obj.get(chain_key)
        if isinstance(chain, list):
            for hop in chain:
                for k in possible_code_keys:
                    v = (hop or {}).get(k)
                    if isinstance(v, int):
                        codes.append(v)
                    elif isinstance(v, str) and v.isdigit():
                        codes.append(int(v))

    # Dedup while preserving order
    if codes:
        seen = set(); dedup = []
        for c in codes:
            if c not in seen:
                dedup.append(c); seen.add(c)
        codes = dedup

    return {"url": url, "codes": codes, "title": title}

# =========================
# TEXT FALLBACK PARSER
# =========================
def parse_httpx_text_line(line: str) -> Dict:
    """
    Parse a non-JSON httpx line robustly:
      <url> [codes] [title] [ip] [tech] [redirect]
    """
    raw = strip_ansi(line.rstrip("\n"))
    if not raw.strip():
        return {"url": "", "codes": [], "title": ""}

    # URL first token
    first_space = raw.find(" ")
    url = raw if first_space == -1 else raw[:first_space]
    if url and not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    # Collect bracket groups
    groups = re.findall(r"\[([^\]]*)\]", raw)

    # Find status codes group
    codes: List[int] = []
    for g in groups:
        g2 = re.sub(r"[^0-9,]", "", g)
        if g2 and all(part.isdigit() for part in g2.split(",") if part):
            try:
                codes = [int(p) for p in g2.split(",") if p]
                break
            except Exception:
                pass

    # Find a plausible title
    title = ""
    def is_title(s: str) -> bool:
        if not s: return False
        s = s.strip()
        if IPV4_PATTERN.match(s): return False
        if s.lower().startswith(("http://", "https://")): return False
        return bool(re.search(r"[A-Za-z]", s))
    for g in groups:
        if is_title(g):
            title = g.strip()
            break

    return {"url": url, "codes": codes, "title": title}

# =========================
# CLASSIFICATION
# =========================
def looks_like_error_title(title: str) -> bool:
    return bool(title) and ERROR_TITLE_REGEX.search(title) is not None

def classify(entry: Dict) -> bool:
    """
    Return True if ACTIVE else False.
    Active if (200 present) and title not error-like.
    """
    codes = entry.get("codes") or []
    title = entry.get("title") or ""
    if 200 in codes and not looks_like_error_title(title):
        return True
    return False

# =========================
# MAIN
# =========================
def main():
    setup_logging()

    ap = argparse.ArgumentParser(description="Classify subdomains as ACTIVE vs INACTIVE via httpx")
    ap.add_argument("subdomains", type=Path, help="Path to subdomains.txt (from scan2.py)")
    ap.add_argument("--ports", default=HTTPX_DEFAULT_PORTS, help=f"Ports to probe (default: {HTTPX_DEFAULT_PORTS})")
    args = ap.parse_args()

    subs_file = args.subdomains
    if not subs_file.exists():
        print(f"[makeAcrack] subdomains file not found: {subs_file}", file=sys.stderr)
        sys.exit(2)

    out_dir = subs_file.parent  # save next to subdomains file if user opts in

    # Run httpx (-json) and collect structured entries
    active: List[Dict] = []
    inactive: List[Dict] = []

    for obj in run_httpx_stream_json(subs_file, args.ports):
        entry = extract_from_json_obj(obj)
        if not entry.get("url"):
            continue
        is_active = classify(entry)
        (active if is_active else inactive).append(entry)

    # Print results to screen
    def fmt_codes(codes: List[int]) -> str:
        return ",".join(str(c) for c in codes) if codes else "—"

    print("\n=== Active subdomains (running a live app/service) ===")
    if not active:
        print("(none)")
    else:
        for e in active:
            print(f"- {e['url']}  [{fmt_codes(e.get('codes', []))}]  [{e.get('title') or '—'}]")

    print("\n=== Inactive / broken / placeholder subdomains ===")
    if not inactive:
        print("(none)")
    else:
        for e in inactive:
            print(f"- {e['url']}  [{fmt_codes(e.get('codes', []))}]  [{e.get('title') or '—'}]")

    # Ask whether to save
    if ask_yes("\nDo you want to save these ACTIVE/INACTIVE lists?"):
        active_path = out_dir / "active_subdomains.txt"
        inactive_path = out_dir / "inactive_subdomains.txt"
        active_path.write_text("\n".join(e["url"] for e in active) + ("\n" if active else ""), encoding="utf-8")
        inactive_path.write_text("\n".join(e["url"] for e in inactive) + ("\n" if inactive else ""), encoding="utf-8")
        print(f"\n[makeAcrack] Saved:\n  - {active_path}\n  - {inactive_path}")
    else:
        print("\n[makeAcrack] Results not saved.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)
