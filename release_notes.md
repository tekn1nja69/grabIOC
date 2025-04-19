# grabIOC - Release Notes

## v1.0 - Initial Public Release 

 Features:
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

 Known Limitations:
- Sigma matching is keyword-based only (no real-time log backend yet)
- Webhook notifications are basic
- No GUI (CLI-only)

 Released: April 2025

