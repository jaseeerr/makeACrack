makeAcrack – Recon Automation Suite

makeAcrack is a modular recon pipeline designed to help you slip through cracks in security like a pro.
It automates early-stage recon on domains, subdomains, and services, combining classic OSINT, DNS enumeration, and service fingerprinting into a streamlined workflow.

✨ Features

Automated Recon Flow → ./run guides you step by step.

scan1.py → Whois + DNS enumeration (A, MX, NS, SOA, CNAME, TXT, AXFR, reverse DNS).

scan2.py → Subdomain discovery via amass (CT logs, passive DNS, ASN, brute force).

scan2a.py → Service classification via httpx (active vs inactive, headers, TLS certs, favicons).

Results saved neatly into timestamped folders under results/.

⚡ Installation

Make sure you’re on Kali Linux or another Debian-based distro.

🔹 System packages
sudo apt update
sudo apt install -y python3 python3-pip whois dnsutils amass golang

🔹 ProjectDiscovery tools
# Install httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# (Optional) Install nuclei for vuln scanning
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin

🔹 Python libraries
pip install rich

🚀 Usage

Just run the entry script:

./run


It will ask for a domain.

Then guide you through:

DNS & Whois recon (scan1)

Subdomain enumeration (scan2)

Service detection (scan2a)

Results are saved in results/<domain>/<timestamp>/.

🧩 Example Workflow
./run
enter: domain.com


Output files:

whois.txt, dig_A.txt, dig_MX.txt, …

subdomains.txt (cleaned)

active_subdomains.txt / inactive_subdomains.txt

⚠️ Disclaimer

This project is for educational and authorized security testing only.
Running these scans on systems without permission is illegal.
The authors take no responsibility for misuse.

🏴‍☠️ Why makeAcrack?

Because the best hackers know:

Recon wins fights before the first payload is fired.

Attackers don’t “hack in” — they slip through cracks you didn’t even know were there.

With makeAcrack, you get a simple but powerful toolkit to automate recon, so you can focus on exploiting the fun parts.
