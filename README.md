# grabIOC

> A Lightweight Threat Intel & IOC Extraction Toolkit 🕵️‍  
> Developed by [Ali J](https://github.com/tekn1nja69)

---

## 🚀 Overview

`grabIOC` is a lightweight, CLI-based tool built for security analysts, DFIR professionals, and threat hunters. It extracts, enriches, and correlates IOCs (Indicators of Compromise) from files, PCAPs, URLs, IPs, and live system processes — all from a terminal interface.

---

## 🎯 Features

-  **IOC Extraction**: IPs, URLs, Hashes, and Emails from text and PCAPs
-  **Threat Intel Integration**: VirusTotal, AbuseIPDB, IPinfo, APIVoid, MISP, OTX
-  **YARA Rule Support**: Match suspicious binaries against compiled YARA rules
-  **Live Process Analysis**: With YAML-configurable detection patterns
-  **Sigma Rule Matching**: Identify suspicious log entries via Sigma
-  **Export Support**: JSON/CSV output for reporting and sharing
-  **Webhook Alerts**: Send alerts to Discord/Slack via simple flag
-  **System Scanning**: Scan entire directories or target files
-  **CLI-Friendly**: Built for automation, supports multiple OS

---

## ⚙️ Installation

```bash
git clone https://github.com/tekn1nja69/grabioc.git
cd grabioc
pip install -r requirements.txt
```

Then set up your `.env` file:

```bash
cp .env.proto .env
```

Add your API keys inside `.env`.

---

## 🔐 .env Format

```env
ABUSEIPDB_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
IPINFO_KEY=your_key_here
CRIMINALIP_KEY=your_key_here
APIVOID_KEY=your_key_here
MISP_URL=https://your.misp.instance
MISP_KEY=your_key_here
OTX_KEY=your_key_here
```

---

## 🧪 Usage Examples

### Extract IOCs from a file
```bash
python grabioc.py --file suspicious.txt
```

### Analyze a URL
```bash
python grabioc.py --url http://malicious.site
```

### Analyze an IP address
```bash
python grabioc.py --ip 8.8.8.8
```

### Scan system directories
```bash
python grabioc.py --scan ~/Downloads /tmp --export result.json
```

### Scan running processes (YAML-based rules)
```bash
python grabioc.py --scan-procs --process-config process_config.yaml
```

### Use YARA or Sigma rules
```bash
python grabioc.py --file suspicious.log --yara rules/
python grabioc.py --file log.txt --sigma rules/
```

### Export IOCs to CSV
```bash
python grabioc.py --file file.txt --csv output.csv
```

### Enable verbose logging
```bash
python grabioc.py --file file.txt --verbose
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE)

---------------------------------------------------------------------
For educational and research purposes only. Use responsibly.