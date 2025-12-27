---

A collection of **battle-tested scripts, automation wrappers, and one-liners** designed for Red Teaming engagements, CTFs, and Bug Bounty operations.

These tools are built for **speed, modularity, and piping**. No bloat, just raw functionality to integrate into your existing recon pipelines.

## 📂 Utilities

### 1. `crtsh_enum.py`

A robust Python extractor for **Certificate Transparency logs** (crt.sh).

* **Features:**
* Handles JSON parsing errors and Timeouts (common with crt.sh).
* Auto-cleans wildcards (`*.target.com` -> `target.com`).
* Deduplicates results automatically.
* Outputs clean lists ready for piping.



### 2. `mass_crawl.sh`

An automated "Search & Destroy" pipeline wrapper.

* **Workflow:** `Raw Domains` -> `HTTPX Filter` -> `Feroxbuster Recursive Scan`.
* **Features:**
* **Smart Filtering:** Uses `httpx` to discard dead domains before attacking.
* **Structured Output:** Organizes findings by directory (`scans_DATE/domain/`).
* **Protocol Handling:** Auto-detects HTTP/HTTPS and follows redirects.



---

## ⚡ Prerequisites

To use the bash wrappers, ensure you have the following tools installed and in your `$PATH`:

```bash
# Essential Go tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Rust tools (Feroxbuster)
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
sudo mv feroxbuster /usr/bin/

# Python deps
pip3 install requests

```

---

## 🚀 Usage

### Passive Recon (Certificate Enumeration)

Extract subdomains from crt.sh and save them to a file:

```bash
python3 crtsh_enum.py tesla.com > raw_subs.txt

```

### Active Recon & Crawling

Feed the raw list into the mass crawler. The script will filter alive hosts and start directory busting:

```bash
chmod +x mass_crawl.sh
./mass_crawl.sh raw_subs.txt

```

**Custom Wordlist:**

```bash
./mass_crawl.sh raw_subs.txt /usr/share/wordlists/dirb/big.txt

```

---

## ⚠️ Disclaimer

**Educational and Ethical Use Only.**
These scripts are intended for authorized security auditing, Red Teaming engagements, and educational purposes. The author is not responsible for any misuse or damage caused by these tools. **Do not scan targets you do not have explicit permission to test.**

---

## 🤝 Contributing

Got a better one-liner? Found a bug?

1. Fork the repo.
2. Create a branch (`git checkout -b feature/better-recon`).
3. Commit your changes.
4. Open a Pull Request.

---

