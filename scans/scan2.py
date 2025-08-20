#!/usr/bin/env python3
import argparse
import os
import re
import signal
import subprocess
import sys
import time
import shutil
from datetime import datetime
from shutil import which
import ipaddress

# ================== rich bootstrap (auto-install) ==================
RICH_AVAILABLE = False
def _try_import_rich():
    global RICH_AVAILABLE
    try:
        import rich  # noqa
        from rich.console import Console  # noqa
        from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn  # noqa
        RICH_AVAILABLE = True
    except Exception:
        RICH_AVAILABLE = False

_try_import_rich()
if not RICH_AVAILABLE:
    print("[makeAcrack] 'rich' not found; attempting to install it now...", flush=True)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "rich"],
                              stdout=sys.stdout, stderr=sys.stderr)
    except Exception as e:
        print(f"[makeAcrack] Failed to install 'rich' automatically ({e}). Falling back to simple progress.\n", flush=True)
    _try_import_rich()

if RICH_AVAILABLE:
    from rich.console import Console
    from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn
    console = Console()

# ================== helpers ==================
BOLD = "1"
CYAN = "36"

def color(s, code):
    return f"\033[{code}m{s}\033[0m"

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def read_text(path):
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def write_text(path, content):
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

class StepProgress:
    def __init__(self, domain, total_steps):
        self.domain = domain
        self.total = total_steps
        self.current = 0
        self.use_rich = RICH_AVAILABLE
        self.rich_task = None

        if self.use_rich:
            self.progress = Progress(
                TextColumn("[bold]Scanning[/bold] " + domain),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("•"),
                TimeElapsedColumn(),
                transient=True
            )
            self.progress.start()
            self.rich_task = self.progress.add_task(f"scan2:{domain}", total=total_steps)
        else:
            print(f"Scanning {domain} ...", flush=True)
            self._ascii()

    def advance(self, note=""):
        self.current += 1
        if self.use_rich:
            desc = note if note else f"step {self.current}/{self.total}"
            self.progress.update(self.rich_task, advance=1, description=desc)
        else:
            if note:
                print(f"  - {note}", flush=True)
            self._ascii()

    def _ascii(self):
        pct = int((self.current / self.total) * 100)
        pct = min(100, max(0, pct))
        bar_len = 28
        filled = int((pct / 100) * bar_len)
        bar = "[" + "#" * filled + "-" * (bar_len - filled) + f"] {pct}%"
        print("    " + bar, flush=True)

    def stop(self):
        if self.use_rich:
            self.progress.stop()

def install_amass_if_needed():
    if which("amass") is not None:
        print("[makeAcrack] amass: found", flush=True)
        return True

    print("[makeAcrack] amass: not found", flush=True)

    if sys.platform.startswith("linux") and which("apt-get") is not None:
        print("[makeAcrack] attempting: sudo apt-get update && sudo apt-get install -y amass", flush=True)
        try:
            subprocess.check_call(["sudo", "apt-get", "update"], stdout=sys.stdout, stderr=sys.stderr)
            subprocess.check_call(["sudo", "apt-get", "install", "-y", "amass"], stdout=sys.stdout, stderr=sys.stderr)
        except Exception as e:
            print(f"[makeAcrack] apt install failed: {e}", flush=True)
    else:
        print("[makeAcrack] automatic install not supported on this platform.", flush=True)

    if which("amass") is None:
        print("[makeAcrack] Please install 'amass' manually and re-run.", flush=True)
        return False

    print("[makeAcrack] amass installed.", flush=True)
    return True

def run_amass_with_timeout(domain, out_path, timeout_seconds):
    """
    Run: amass enum -d <domain> -o <out_path>
    Timeout after `timeout_seconds`. On timeout: send SIGINT (Ctrl+C), then terminate/kill if needed.
    Proceed with whatever data was written to the output file.
    """
    ensure_dir(os.path.dirname(out_path))
    print(f"[makeAcrack] running: amass enum -d {domain} -o {out_path}", flush=True)

    proc = subprocess.Popen(
        ["amass", "enum", "-d", domain, "-o", out_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    start = time.time()
    timed_out = False

    try:
        while True:
            if proc.poll() is not None:
                break
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
            else:
                print(line.rstrip())
            if time.time() - start > timeout_seconds:
                timed_out = True
                break
    except KeyboardInterrupt:
        try:
            proc.send_signal(signal.SIGINT)
        except Exception:
            pass
        raise

    if timed_out:
        print(f"[makeAcrack] amass exceeded {timeout_seconds}s. Sending Ctrl+C...", flush=True)
        try:
            proc.send_signal(signal.SIGINT)
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("[makeAcrack] amass not stopping gracefully, terminating...", flush=True)
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                print("[makeAcrack] forcing kill...", flush=True)
                try:
                    proc.kill()
                except Exception:
                    pass

    return os.path.exists(out_path)

# -------- hostname cleaning (RFC-ish + domain scoping) --------
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

def is_valid_hostname(host: str) -> bool:
    if not host:
        return False
    if len(host) > 253:
        return False
    if host.startswith(".") or host.endswith("."):
        return False
    parts = host.split(".")
    return all(HOST_LABEL_RE.match(p) for p in parts)

def looks_like_ip_or_cidr(s: str) -> bool:
    if "/" in s:
        return True
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def extract_clean_subs(raw_lines, root_domain: str, include_apex: bool = True):
    """
    Build a clean set of FQDNs that end with the root_domain.
    - Drop IPs, CIDRs, pure numbers, garbage.
    - Accept lines with '(FQDN)' by taking the first field.
    - Normalize: lowercase, strip trailing dot.
    - include_apex: if True, include the apex 'root_domain' itself.
    """
    out = []
    root = root_domain.lower().strip(".")
    has_fqdn_pattern = any("(FQDN)" in ln for ln in raw_lines)

    for ln in raw_lines:
        s = ln.strip().lower()
        if not s or s.startswith("#"):
            continue

        if has_fqdn_pattern:
            s = s.split()[0]

        s = s.rstrip(".")

        if " " in s or any(c in s for c in ['/', '\\', '\t', '@', ':']):
            continue
        if s.isdigit():
            continue
        if looks_like_ip_or_cidr(s):
            continue
        if not is_valid_hostname(s):
            continue

        if s == root:
            if include_apex:
                out.append(s)
            continue
        if not s.endswith("." + root):
            continue

        out.append(s)

    return sorted(set(out), key=lambda x: x.lower())

def ask_yes(prompt: str) -> bool:
    ans = input(f"{prompt} (default = No) [1/yes]: ").strip().lower()
    return ans in ("1", "yes", "y")

# ================== main ==================
def main():
    parser = argparse.ArgumentParser(description="makeAcrack scan2 (amass subdomain enumeration)")
    parser.add_argument("--domain", required=True, help="Domain to scan, e.g., example.com")
    args = parser.parse_args()
    domain = args.domain.strip()

    # ask user timeout (minutes) with default 6
    try:
        mins_str = input("Enter minutes to run amass scan (default 6): ").strip()
        timeout_minutes = int(mins_str) if mins_str else 6
        if timeout_minutes <= 0:
            timeout_minutes = 6
    except Exception:
        timeout_minutes = 6
    timeout_seconds = timeout_minutes * 60
    print(f"[makeAcrack] Running amass for {timeout_minutes} minutes max (will terminate after that)...")

    # results dir (we may delete it if user declines saving)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    run_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results", domain, timestamp))
    ensure_dir(run_dir)

    amass_out = os.path.join(run_dir, "amass_subs.txt")
    subs_clean_tmp = os.path.join(run_dir, "subs_clean.txt")
    subdomains_final = os.path.join(run_dir, "subdomains.txt")

    steps = StepProgress(domain, total_steps=6)

    # Step 1: tool check / install
    ok = install_amass_if_needed()
    steps.advance("checked/installed amass")
    if not ok:
        steps.stop()
        sys.exit(2)

    # Step 2: run amass with timeout
    _ = run_amass_with_timeout(domain, amass_out, timeout_seconds)
    steps.advance("amass enum completed (or timed out)")

    # Step 3: read & print amass_subs.txt
    raw = read_text(amass_out)
    raw_lines = [ln for ln in raw.splitlines() if ln.strip()]
    print("\n" + color("amass_subs.txt (raw)", BOLD))
    if raw_lines:
        for ln in raw_lines:
            print(ln)
    else:
        print("(empty)")
    steps.advance("displayed raw amass output")

    # Step 4: create subs_clean.txt using strict filters
    cleaned = extract_clean_subs(raw_lines, root_domain=domain, include_apex=True)
    write_text(subs_clean_tmp, "\n".join(cleaned) + ("\n" if cleaned else ""))
    steps.advance("generated subs_clean.txt")

    # Step 5: print subs_clean.txt
    print("\n" + color("subs_clean.txt", BOLD))
    if cleaned:
        for sub in cleaned:
            print(sub)
    else:
        print("(empty)")
    steps.advance("displayed cleaned subs")

    # Step 6: rename to subdomains.txt and delete amass_subs.txt
    try:
        if os.path.exists(subdomains_final):
            os.remove(subdomains_final)
        os.replace(subs_clean_tmp, subdomains_final)
    except Exception as e:
        print(f"[makeAcrack] rename failed: {e}", file=sys.stderr)
        write_text(subdomains_final, "\n".join(cleaned) + ("\n" if cleaned else ""))

    try:
        if os.path.exists(amass_out):
            os.remove(amass_out)
    except Exception as e:
        print(f"[makeAcrack] warning: could not delete amass_subs.txt ({e})", file=sys.stderr)

    steps.stop()

    print(f"\nSubdomains file: {subdomains_final}")

    # ---------- Ask to SAVE scan2 results (default = No) ----------
    save_scan2 = ask_yes("Do you want to save these scan2 results?")
    # We'll potentially need the files if the user wants to run scan2a; delay deletion until after that step.
    need_cleanup = not save_scan2

    # ---------- Ask to run scan2a (Active service detection) ----------
    run_active = ask_yes("Do you want to list subdomains with an active app/service (run scan2a)?")
    if run_active:
        # Call scan2a.py with the subdomains file; scan2a will prompt its own save choice.
        here = os.path.abspath(os.path.dirname(__file__))
        scan2a_path = os.path.join(here, "scan2a.py")
        py = sys.executable or "python3"
        print("\n[makeAcrack] Launching scan2a...")
        try:
            # Pass the subdomains file path; scan2a prints and (optionally) saves in the same directory.
            subprocess.check_call([py, scan2a_path, subdomains_final])
        except subprocess.CalledProcessError as e:
            print(f"[makeAcrack] scan2a exited with non-zero code: {e.returncode}", file=sys.stderr)
        except FileNotFoundError:
            print("[makeAcrack] scan2a.py not found in scans/; make sure it's placed next to scan2.py", file=sys.stderr)

    # Cleanup if user chose not to save
    if need_cleanup:
        try:
            shutil.rmtree(run_dir, ignore_errors=True)
            print("[makeAcrack] Results not saved. Temporary files cleaned up.")
        except Exception as e:
            print(f"[makeAcrack] cleanup warning: {e}")

    # Final tip
    print(color("Tip:", CYAN), "If you saved ACTIVE lists from scan2a, feed them into nuclei/dirb or your xsscan next.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)
