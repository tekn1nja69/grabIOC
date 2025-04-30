# grabIOC - Release Notes

## v1.2 – Alerting & Threat Hunting Enhancements
**Released:** April 2025

### Updates and Bug Fixes:
- ✅ **Telegram Bot alert support** via `.env` or CLI
- ✅ **Unified `send_alert()` function** for Discord & Telegram
- ✅ **Shortened CLI arguments**:
  - `-a` for alert triggering
  - `-m` for selecting alert mode (`webhook` or `telegram`)
- ✅ Enhanced **process scanner**:
  - Parent-child process tracking (`ppid`)
  - Command-line analysis for suspicious encoded payloads
  - VT hash lookup + malware engine count
  - Scoring-based verdicts for smarter triage
- ✅ Refactored `ThreatHunter` class:
  - Cleaner MISP and OTX context fetching
  - Improved logging and exception handling
  - Configurable result limits

### ⚙️ Improvements:
- 🌐 Webhook alerts now fall back to `.env` if `--alert` is not supplied
- 🧪 IOC detection and context results cleaned for readability
- 🔒 `.env` config centralized for better secret/API management

---

## v1.0 – Initial Public Release
### Features:
- IOC extraction from text, logs, and PCAP files
- Threat intelligence lookups via:
  - VirusTotal
  - AbuseIPDB
  - IPinfo
  - APIVoid
  - OTX & MISP
- YARA rule scanning
- Sigma rule matching
- System-wide IOC scans with directory support
- Configurable process analysis using YAML
- Export to JSON/CSV
- Discord/Webhook alerting
- Verbose logging and error tracking
- Cross-platform support (Linux, macOS, Windows)

---

### 🧩 Known Limitations:
- Sigma matching is keyword-based only (no real-time log backend yet)
- Webhook notifications are still plain-text (no rich embeds yet)
- No GUI (CLI-only)



