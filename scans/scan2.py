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
import threading
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
YELLOW = "33"
GREEN = "32"

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

def append_text(path, content):
    ensure_dir(os.path.dirname(path))
    with open(path, "a", encoding="utf-8") as f:
        f.write(content)

class StepProgress:
    def __init__(self, domain, total_steps):
        self.domain = domain
        self.total = max(1, total_steps)
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
            self.rich_task = self.progress.add_task(f"scan2:{domain}", total=self.total)
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

def input_nonempty(prompt: str, default: str = "") -> str:
    s = input(prompt).strip()
    return s if s else default

# ================== tool checks / installers ==================
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

def install_subfinder_if_needed():
    if which("subfinder") is not None:
        print("[makeAcrack] subfinder: found", flush=True)
        return True
    print("[makeAcrack] subfinder: not found", flush=True)
    if sys.platform.startswith("linux") and which("apt-get") is not None:
        print("[makeAcrack] attempting: sudo apt-get update && sudo apt-get install -y subfinder", flush=True)
        try:
            subprocess.check_call(["sudo", "apt-get", "update"], stdout=sys.stdout, stderr=sys.stderr)
            subprocess.check_call(["sudo", "apt-get", "install", "-y", "subfinder"], stdout=sys.stdout, stderr=sys.stderr)
        except Exception as e:
            print(f"[makeAcrack] apt install failed: {e}", flush=True)
    else:
        print("[makeAcrack] automatic install not supported on this platform.", flush=True)
    if which("subfinder") is None:
        print("[makeAcrack] Please install 'subfinder' manually and re-run.", flush=True)
        return False
    print("[makeAcrack] subfinder installed.", flush=True)
    return True

def install_assetfinder_if_needed():
    if which("assetfinder") is not None:
        print("[makeAcrack] assetfinder: found", flush=True)
        return True
    print("[makeAcrack] assetfinder: not found", flush=True)
    if sys.platform.startswith("linux") and which("apt-get") is not None:
        print("[makeAcrack] attempting: sudo apt-get update && sudo apt-get install -y assetfinder", flush=True)
        try:
            subprocess.check_call(["sudo", "apt-get", "update"], stdout=sys.stdout, stderr=sys.stderr)
            subprocess.check_call(["sudo", "apt-get", "install", "-y", "assetfinder"], stdout=sys.stdout, stderr=sys.stderr)
        except Exception as e:
            print(f"[makeAcrack] apt install failed: {e}", flush=True)
    else:
        print("[makeAcrack] automatic install not supported on this platform.", flush=True)
    if which("assetfinder") is None:
        print("[makeAcrack] Please install 'assetfinder' manually and re-run.", flush=True)
        return False
    print("[makeAcrack] assetfinder installed.", flush=True)
    return True

# ================== runners (with timeouts) ==================
def _pump_lines(proc, tee_path=None):
    """
    Read stdout line-by-line, echo to console, and tee to a file if provided.
    """
    if tee_path:
        ensure_dir(os.path.dirname(tee_path))
        f = open(tee_path, "w", encoding="utf-8")
    else:
        f = None

    try:
        while True:
            if proc.poll() is not None:
                # flush remaining
                tail = proc.stdout.read()
                if tail:
                    print(tail.rstrip())
                    if f:
                        f.write(tail)
                break
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            print(line.rstrip())
            if f:
                f.write(line)
    finally:
        if f:
            f.close()

def run_proc_with_timeout(cmd, timeout_seconds, tee_path=None, graceful_sig=signal.SIGINT, name="proc"):
    """
    Start cmd (list), stream output, and enforce timeout.
    On timeout: send graceful signal, then terminate/kill if needed.
    Returns exitcode (0 if we're not sure), and ensures tee_path file exists (possibly empty).
    """
    print(f"[makeAcrack] running: {' '.join(cmd)}", flush=True)
    ensure_dir(os.path.dirname(tee_path)) if tee_path else None

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    pump_thread = threading.Thread(target=_pump_lines, args=(proc, tee_path), daemon=True)
    pump_thread.start()

    start = time.time()
    timed_out = False
    try:
        while True:
            if proc.poll() is not None:
                break
            if time.time() - start > timeout_seconds:
                timed_out = True
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        try:
            proc.send_signal(graceful_sig)
        except Exception:
            pass
        raise

    if timed_out:
        print(f"[makeAcrack] {name} exceeded {timeout_seconds}s. Sending Ctrl+C/terminate...", flush=True)
        try:
            proc.send_signal(graceful_sig)
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print(f"[makeAcrack] {name} not stopping gracefully, terminating...", flush=True)
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                print(f"[makeAcrack] forcing kill for {name}...", flush=True)
                try:
                    proc.kill()
                except Exception:
                    pass

    pump_thread.join(timeout=2.0)
    code = proc.returncode if proc.returncode is not None else 0
    if tee_path and not os.path.exists(tee_path):
        write_text(tee_path, "")
    return code

# ================== main ==================
def main():
    parser = argparse.ArgumentParser(description="makeAcrack scan2 (multi-source subdomain enumeration)")
    parser.add_argument("--domain", required=True, help="Domain to scan, e.g., example.com")
    args = parser.parse_args()
    domain = args.domain.strip()

    # ask user timeout (minutes) with default 6
    try:
        mins_str = input("Enter minutes to run each source (default 6): ").strip()
        timeout_minutes = int(mins_str) if mins_str else 6
        if timeout_minutes <= 0:
            timeout_minutes = 6
    except Exception:
        timeout_minutes = 6
    timeout_seconds = timeout_minutes * 60
    print(f"[makeAcrack] Each selected source will run for up to {timeout_minutes} minute(s).")

    # choose sources
    print("\nChoose sources (you can enable multiple):")
    use_amass = ask_yes("Use amass?")
    use_subfinder = ask_yes("Use subfinder?")
    use_assetfinder = ask_yes("Use assetfinder?")
    if not any([use_amass, use_subfinder, use_assetfinder]):
        print("[makeAcrack] No sources selected; enabling amass by default.")
        use_amass = True

    # brute-force option
    brute = False
    wordlist_path = ""
    if ask_yes("Enable brute-force mode (wordlist) where supported?"):
        brute = True
        wordlist_path = input_nonempty("Path to wordlist (leave empty to skip brute): ")
        if not wordlist_path or not os.path.exists(wordlist_path):
            print("[makeAcrack] Wordlist not provided or not found; brute mode disabled.")
            brute = False

    # ASN / IP range expansion (amass only)
    use_asn_ip = False
    asn_list = []
    ip_ranges = []
    if use_amass and ask_yes("Use ASN/IP range expansion with amass?"):
        use_asn_ip = True
        asn_csv = input_nonempty("Enter comma-separated ASNs (e.g., 13335,15169) or blank to skip: ")
        ip_csv = input_nonempty("Enter comma-separated CIDRs (e.g., 192.0.2.0/24,2001:db8::/32) or blank to skip: ")
        if asn_csv.strip():
            asn_list = [a.strip() for a in asn_csv.split(",") if a.strip().isdigit()]
        if ip_csv.strip():
            # filter basic validity
            for cidr in [c.strip() for c in ip_csv.split(",") if c.strip()]:
                try:
                    _ = ipaddress.ip_network(cidr, strict=False)
                    ip_ranges.append(cidr)
                except Exception:
                    print(f"[makeAcrack] Skipping invalid CIDR: {cidr}")

    # results dir (we may delete it if user declines saving)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    run_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results", domain, timestamp))
    ensure_dir(run_dir)

    # file paths
    amass_out = os.path.join(run_dir, "amass_subs.txt")
    subfinder_out = os.path.join(run_dir, "subfinder_subs.txt")
    assetfinder_out = os.path.join(run_dir, "assetfinder_subs.txt")
    merged_raw = os.path.join(run_dir, "merged_raw.txt")
    subs_clean_tmp = os.path.join(run_dir, "subs_clean.txt")
    subdomains_final = os.path.join(run_dir, "subdomains.txt")

    # steps: check tools + N sources run + print raws + clean + show clean + finalize/rename
    total_steps = 2  # initial + finalize
    total_steps += (1 if use_amass else 0) + (1 if use_subfinder else 0) + (1 if use_assetfinder else 0)  # run
    total_steps += 2  # show raws + clean
    steps = StepProgress(domain, total_steps=total_steps)

    # Step 1: tool check / install
    tools_ok = True
    if use_amass:
        tools_ok = tools_ok and install_amass_if_needed()
    if use_subfinder:
        tools_ok = tools_ok and install_subfinder_if_needed()
    if use_assetfinder:
        tools_ok = tools_ok and install_assetfinder_if_needed()
    steps.advance("checked/installed tools")
    if not tools_ok:
        steps.stop()
        sys.exit(2)

    # Step 2: run selected sources (in parallel)
    threads = []
    results = []

    def run_amass():
        cmd = ["amass", "enum", "-d", domain, "-o", amass_out]
        if brute and wordlist_path:
            cmd += ["-brute", "-w", wordlist_path]
        if use_asn_ip:
            if asn_list:
                cmd += ["-asn"] + asn_list
            if ip_ranges:
                cmd += ["-ip"] + ip_ranges
        code = run_proc_with_timeout(cmd, timeout_seconds, tee_path=None, graceful_sig=signal.SIGINT, name="amass")
        # amass writes directly to -o path; ensure file exists
        if not os.path.exists(amass_out):
            write_text(amass_out, "")
        results.append(("amass", code))

    def run_subfinder():
        # subfinder can write to -o; we'll use -silent to reduce noise
        cmd = ["subfinder", "-d", domain, "-silent", "-all", "-o", subfinder_out]
        if brute and wordlist_path:
            # subfinder's -w is used for passive/brute resolvers depending on config; include anyway for breadth
            cmd += ["-w", wordlist_path]
        code = run_proc_with_timeout(cmd, timeout_seconds, tee_path=None, graceful_sig=signal.SIGINT, name="subfinder")
        if not os.path.exists(subfinder_out):
            write_text(subfinder_out, "")
        results.append(("subfinder", code))

    def run_assetfinder():
        # assetfinder prints to stdout; we tee to file
        cmd = ["assetfinder", "--subs-only", domain]
        code = run_proc_with_timeout(cmd, timeout_seconds, tee_path=assetfinder_out, graceful_sig=signal.SIGINT, name="assetfinder")
        if not os.path.exists(assetfinder_out):
            write_text(assetfinder_out, "")
        results.append(("assetfinder", code))

    if use_amass:
        t = threading.Thread(target=run_amass, daemon=True); threads.append(t); t.start()
    if use_subfinder:
        t = threading.Thread(target=run_subfinder, daemon=True); threads.append(t); t.start()
    if use_assetfinder:
        t = threading.Thread(target=run_assetfinder, daemon=True); threads.append(t); t.start()

    for t in threads:
        t.join()

    steps.advance("sources completed (or timed out)")

    # Step 3: read & print per-source raw outputs
    print("\n" + color("Raw outputs per source", BOLD))
    if use_amass:
        print(color("\namass_subs.txt (raw)", BOLD))
        raw = read_text(amass_out)
        if raw.strip():
            print(raw.rstrip())
        else:
            print("(empty)")
    if use_subfinder:
        print(color("\nsubfinder_subs.txt (raw)", BOLD))
        raw = read_text(subfinder_out)
        if raw.strip():
            print(raw.rstrip())
        else:
            print("(empty)")
    if use_assetfinder:
        print(color("\nassetfinder_subs.txt (raw)", BOLD))
        raw = read_text(assetfinder_out)
        if raw.strip():
            print(raw.rstrip())
        else:
            print("(empty)")
    steps.advance("displayed raw outputs")

    # Step 4: merge and clean
    all_lines = []
    if use_amass:
        all_lines += [ln for ln in read_text(amass_out).splitlines() if ln.strip()]
    if use_subfinder:
        all_lines += [ln for ln in read_text(subfinder_out).splitlines() if ln.strip()]
    if use_assetfinder:
        all_lines += [ln for ln in read_text(assetfinder_out).splitlines() if ln.strip()]

    write_text(merged_raw, "\n".join(all_lines) + ("\n" if all_lines else ""))

    cleaned = extract_clean_subs(all_lines, root_domain=domain, include_apex=True)
    write_text(subs_clean_tmp, "\n".join(cleaned) + ("\n" if cleaned else ""))

    print("\n" + color("subs_clean.txt (merged & filtered)", BOLD))
    if cleaned:
        for sub in cleaned:
            print(sub)
    else:
        print("(empty)")

    steps.advance("merged & cleaned")

    # Step 5: finalize filenames (subdomains.txt) and remove noisy raw files we don't need later
    try:
        if os.path.exists(subdomains_final):
            os.remove(subdomains_final)
        os.replace(subs_clean_tmp, subdomains_final)
    except Exception as e:
        print(f"[makeAcrack] rename failed: {e}", file=sys.stderr)
        write_text(subdomains_final, "\n".join(cleaned) + ("\n" if cleaned else ""))

    steps.advance("finalized files")
    steps.stop()

    print(f"\nSubdomains file: {subdomains_final}")

    # ---------- Ask to SAVE scan2 results (default = No) ----------
    save_scan2 = ask_yes("Do you want to save these scan2 results?")
    need_cleanup = not save_scan2

    # ---------- Ask to run scan2a (Active service detection) ----------
    run_active = ask_yes("Do you want to list subdomains with an active app/service (run scan2a)?")
    if run_active:
        here = os.path.abspath(os.path.dirname(__file__))
        scan2a_path = os.path.join(here, "scan2a.py")
        py = sys.executable or "python3"
        print("\n[makeAcrack] Launching scan2a...")
        try:
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
    # Source summary
    enabled = []
    if use_amass: enabled.append("amass")
    if use_subfinder: enabled.append("subfinder")
    if use_assetfinder: enabled.append("assetfinder")
    print(color("Sources used:", CYAN), ", ".join(enabled))
    if brute:
        print(color("Brute mode:", CYAN), f"enabled (wordlist: {wordlist_path})")
    if use_asn_ip:
        print(color("amass ASN/IP:", CYAN), f"ASNs={asn_list or 'none'} CIDRs={ip_ranges or 'none'}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)
