#!/usr/bin/env python3

import argparse
import os
import re
import csv
import json
import requests
import ipaddress
import time
import base64
import sys
import hashlib
import psutil
import yaml
from typing import Dict, List, Optional
from dotenv import load_dotenv
from colorama import Fore, Style, init
import logging
from requests.exceptions import RequestException
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend

init(autoreset=True)

def validate_config(warn_only: bool = True) -> bool:
    """Validate essential configuration before execution"""
    required_configs = [
        ("VIRUSTOTAL_KEY", "VirusTotal API"),
        ("ABUSEIPDB_KEY", "AbuseIPDB API"),
        ("MISP_URL", "MISP Instance URL"),
        ("MISP_KEY", "MISP API Key")
    ]

    missing = []
    for var, name in required_configs:
        if not os.getenv(var):
            missing.append(name)

    if missing:
        print(f"
{Fore.RED}[!] Missing critical configurations:{Style.RESET_ALL}")
        for name in missing:
            print(f"  - {name}")
        print(f"{Fore.YELLOW}Some features may not work properly without them.{Style.RESET_ALL}")

        if not warn_only:
            print(f"
{Fore.RED}Exiting due to incomplete configuration.{Style.RESET_ALL}")
            return False

    return True



REQUIRED_LIBS = ['pymisp', 'OTXv2', 'pyshark', 'psutil', 'yara-python', 'pyyaml', 'sigma']

# Dependency check block
missing = []

try:
    from pymisp import ExpandedPyMISP
except ImportError:
    missing.append("pymisp")

try:
    from OTXv2 import OTXv2
except ImportError:
    missing.append("OTXv2")

try:
    import pyshark
except ImportError:
    missing.append("pyshark")

try:
    import psutil  # psutil is also used later for process scanning
except ImportError:
    missing.append("psutil")

try:
    import yara
except ImportError:
    missing.append("yara-python")

try:
    import yaml
except ImportError:
    missing.append("pyyaml")

if missing:
    print(f"\n{Fore.RED}ERROR: Missing dependencies - {', '.join(missing)}")
    print(f"{Fore.YELLOW}Install with: pip install {' '.join(missing)}{Style.RESET_ALL}\n")
    sys.exit(1)

load_dotenv()

# API Key Checks
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
IPINFO_KEY = os.getenv("IPINFO_KEY")
CRIMINALIP_KEY = os.getenv("CRIMINALIP_KEY")
APIVOID_KEY = os.getenv("APIVOID_KEY")
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
OTX_KEY = os.getenv("OTX_KEY")

# Validate Critical API Keys
if not VIRUSTOTAL_KEY:
    print(f"{Fore.YELLOW}Warning: VirusTotal API key missing - hash/IP/url analysis limited{Style.RESET_ALL}")

if not ABUSEIPDB_KEY:
    print(f"{Fore.YELLOW}Warning: AbuseIPDB API key missing - IP reputation checks limited{Style.RESET_ALL}")
if not OTX_KEY:
    print(f"{Fore.YELLOW}Warning: OTX API key missing - AlienVault threat intelligence disabled{Style.RESET_ALL}")
if not MISP_KEY or not MISP_URL:
    print(f"{Fore.YELLOW}Warning: MISP configuration incomplete - local threat intel disabled{Style.RESET_ALL}")



# ======== Rate Limiter ========
class RateLimiter:
    def __init__(self, max_calls=10, period=1):
        self.max_calls = max_calls
        self.period = period
        self.timestamps = []

    def wait(self):
        now = time.time()
        self.timestamps = [t for t in self.timestamps if t > now - self.period]
        
        if len(self.timestamps) >= self.max_calls:
            sleep_time = self.period - (now - self.timestamps[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        self.timestamps.append(time.time())

GLOBAL_RATE_LIMITER = RateLimiter(max_calls=15, period=5)
# ====================================
# ========== YARA Utilities============

def print_yara_matches(matches: List[yara.Match], file_path: str = None):
    """Print YARA matches in a standardized format"""
    if not matches:
        return
    
    header = f"=== YARA Matches {'in ' + file_path if file_path else ''} ==="
    print(f"\n{Fore.RED}{header}{Style.RESET_ALL}")
    
    for match in matches[:5]:  # Show first 5 matches
        print(f"{Fore.YELLOW}Rule: {match.rule}{Style.RESET_ALL}")
        if match.meta.get('description'):
            print(f"  Description: {match.meta['description']}")
        if match.meta.get('author'):
            print(f"  Author: {match.meta['author']}")
        if match.tags:
            print(f"  Tags: {', '.join(match.tags)}")
    
    if len(matches) > 5:
        print(f"{Fore.CYAN}  [...] ({len(matches)-5} more matches not shown){Style.RESET_ALL}")

def export_yara_matches(matches: List[yara.Match], export_path: str):
    """Export YARA matches to JSON file"""
    try:
        with open(export_path, "w") as yf:
            json.dump([{
                "rule": match.rule,
                "tags": list(match.tags),
                "meta": match.meta,
                "strings": [str(s) for s in match.strings]
            } for match in matches], yf, indent=2)
        print(f"{Fore.GREEN}[+] YARA matches exported to {export_path}{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to export YARA matches: {e}{Style.RESET_ALL}")
        return False

# ==========System Scanning ==========
def scan_system(paths: List[str], yara_rules: Optional[yara.Rules] = None, args=None):
    """Scan specified system paths for IOCs (with optional YARA rules)"""
    print(f"\n{Fore.CYAN}[+] Starting system scan on: {', '.join(paths)}{Style.RESET_ALL}")
    
    # Notify if YARA is enabled
    if yara_rules:
        print(f"{Fore.GREEN}[+] YARA scanning enabled{Style.RESET_ALL}")
    
    # File scanning
    total_iocs = 0
    for path in paths:
        if not os.path.exists(path):
            print(f"{Fore.RED}[-] Path not found: {path}{Style.RESET_ALL}")
            continue
            
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Skip large files (>25MB)
                    if os.path.getsize(file_path) > 25 * 1024 * 1024:
                        continue
                        
                    # Traditional IOC Extraction
                    if iocs := extract_iocs_from_file(file_path):
                        print(f"\n{Fore.MAGENTA}=== IOCs in {file_path} ==={Style.RESET_ALL}")
                        for ioc_type, values in iocs.items():
                            print(f"{Fore.YELLOW}{ioc_type} ({len(values)}):{Style.RESET_ALL}")
                            for v in values[:5]:  # Show first 5 matches
                                print(f"  - {v}")
                        total_iocs += sum(len(v) for v in iocs.values())
                    
                    # YARA Scanning (if rules provided)
                    if yara_rules:
                       if yara_matches := scan_with_yara(file_path, yara_rules):
                         print_yara_matches(yara_matches, file_path)  
                         total_iocs += len(yara_matches)
                        
                except Exception as e:
                    log_event(f"Error scanning {file_path}: {str(e)}", "ERROR")

#======Threat Hunting Funtionality=============
class ThreatHunter:
    def __init__(self):
        self.sources_available = []

        try:
            self.misp = self._init_misp()
            if self.misp:
                log_event("MISP initialized successfully", "INFO")
                self.sources_available.append("MISP")
            else:
                log_event("MISP not configured", "WARNING")
        except Exception as e:
            log_event(f"MISP init exception: {str(e)}", "ERROR")
            self.misp = None

        try:
            self.otx = OTXv2(OTX_KEY) if OTX_KEY else None
            if self.otx:
                log_event("OTX initialized successfully", "INFO")
                self.sources_available.append("OTX")
            else:
                log_event("OTX key missing or not initialized", "WARNING")
        except Exception as e:
            log_event(f"OTX init failed: {str(e)}", "ERROR")
            self.otx = None

    def _init_misp(self):
        if MISP_URL and MISP_KEY:
            try:
                ssl_verify = os.getenv("MISP_SSL_VERIFY", "True").lower() == "true"
                return ExpandedPyMISP(MISP_URL, MISP_KEY, ssl=ssl_verify)
            except Exception as e:
                log_event(f"MISP init failed: {str(e)}", "ERROR")
        return None

    def get_ioc_context(self, ioc: str, ioc_type: str) -> Dict[str, List]:
        context = {"misp_events": [], "otx_pulses": []}
        ioc_type = ioc_type.lower()

        if self.misp:
            try:
                GLOBAL_RATE_LIMITER.wait()
                result = self.misp.search("attributes", value=ioc)
                context["misp_events"] = result.get("response", [])
                log_event(f"MISP returned {len(context['misp_events'])} events for IOC {ioc}", "INFO")
            except Exception as e:
                log_event(f"MISP query failed: {str(e)}", "ERROR")

        if self.otx:
            try:
                GLOBAL_RATE_LIMITER.wait()
                otx_data = self.otx.get_indicator_details_full(ioc_type, ioc)
                context["otx_pulses"] = otx_data.get("pulse_info", {}).get("pulses", [])
                log_event(f"OTX returned {len(context['otx_pulses'])} pulses for IOC {ioc}", "INFO")
            except Exception as e:
                log_event(f"OTX query failed: {str(e)}", "ERROR")

        return context

    def generate_correlation_report(self, context: dict, limit: int = 3) -> str:
        report = []
        if context["misp_events"]:
            report.append(f"{Fore.CYAN}\n[MISP Threat Intelligence]{Style.RESET_ALL}")
            for event in context["misp_events"][:limit]:
                info = event["Event"].get("info", "No description")
                if len(info) > 50:
                    info = info[:50] + "..."
                report.append(f"- {info} (ID: {event['Event']['id']})")

        if context["otx_pulses"]:
            report.append(f"{Fore.CYAN}\n[AlienVault OTX Findings]{Style.RESET_ALL}")
            for pulse in context["otx_pulses"][:limit]:
                report.append(f"- {pulse.get('name', 'Unnamed Pulse')}")
                if pulse.get("tags"):
                    report.append(f"  Tags: {', '.join(pulse['tags'])}")

        return "\n".join(report) if report else "No Threat Intel Found"

def log_event(message: str, level: str = "INFO"):
    if level == "INFO":
        logging.info(message)
    elif level == "ERROR":
        logging.error(message)
    elif level == "WARNING":
        logging.warning(message)
    elif level == "DEBUG":
        logging.debug(message)

def load_process_config(config_path: str = "process_config.yaml") -> dict:
    """Load process analysis rules from YAML"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"{Fore.RED}Error loading config: {e}{Style.RESET_ALL}")
        return {
            'process_rules': {
                'name_patterns': [],
                'path_patterns': [],
                'trusted_ports': [80, 443, 53, 22],
                'vt_api_key': None
            }
        }

def check_suspicious_processes(args=None) -> List[dict]:
    """
    Enhanced process analysis with:
    - name_patterns (regex list)
    - path_patterns (regex list)
    - trusted_ports (int list)
    - cmdline analysis
    - parent process tracing
    - VT hash lookup (optional)
    """
    config_path = getattr(args, "process_config", None) or "process_config.yaml"
    rules = load_process_config(config_path).get("process_rules", {})

    suspicious = []
    seen_pids = set()

    for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "cmdline", "connections"]):
        try:
        if proc.pid < 0 or proc.pid in seen_pids:
            continue
        if not proc.info.get("name") or not isinstance(proc.info["name"], str):
            continue
            if proc.pid in seen_pids:
                continue
            seen_pids.add(proc.pid)
            info = proc.info
            verdict = {"process": info, "reasons": [], "vt_result": None, "score": 0}

            # === Name checks
            for pat in rules.get("name_patterns", []):
                if re.search(pat, info.get("name", ""), re.IGNORECASE):
                    verdict["reasons"].append(f"Name matches '{pat}'")
                    verdict["score"] += 1

            # === Path checks
            exe = info.get("exe") or ""
            for pat in rules.get("path_patterns", []):
                if exe and re.search(pat, exe, re.IGNORECASE):
                    verdict["reasons"].append(f"Path matches '{pat}'")
                    verdict["score"] += 1

            # === Port listening checks
            for conn in info.get("connections", []):
                if conn.status == "LISTEN":
                    port = conn.laddr.port
                    if port not in rules.get("trusted_ports", []):
                        verdict["reasons"].append(f"LISTEN on port {port}")
                        verdict["score"] += 1

            # === Command-line inspection
            cmdline = " ".join(info.get("cmdline") or [])
            if re.search(r"(?:-e|Invoke|FromBase64|EncodedCommand|cmd|powershell|certutil)", cmdline, re.IGNORECASE):
                verdict["reasons"].append("Suspicious command line args")
                verdict["score"] += 1

            # === Parent process tracing
            try:
                parent = psutil.Process(info.get("ppid"))
                verdict["process"]["parent_name"] = parent.name()
                if parent.name().lower() in ["notepad.exe", "explorer.exe"]:
                    verdict["reasons"].append(f"Suspicious parent: {parent.name()}")
                    verdict["score"] += 1
            except Exception:
                pass

            # === VirusTotal lookup
            vt_key = rules.get("vt_api_key")
            if vt_key and exe and os.path.isfile(exe):
                try:
                    with open(exe, "rb") as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                    GLOBAL_RATE_LIMITER.wait()
                    resp = requests.get(
                        f"https://www.virustotal.com/api/v3/files/{sha256}",
                        headers={"x-apikey": vt_key},
                        timeout=10
                    )
                    if resp.status_code == 200:
                        verdict["vt_result"] = resp.json().get("data", {})
                        stats = verdict["vt_result"].get("attributes", {}).get("last_analysis_stats", {})
                        if stats.get("malicious", 0) > 0:
                            verdict["reasons"].append(f"VT flagged: {stats.get('malicious')} engines")
                            verdict["score"] += 2
                except Exception as e:
                    log_event(f"VT lookup failed: {e}", "ERROR")

            # === If scored suspicious
            if verdict["score"] > 0:
                suspicious.append(verdict)

        except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
            continue

    return suspicious

def print_banner():
    banner = f"""{Fore.GREEN}

***************** Initializing grabIOC ******************
---------------------------------------------------------
 ██████╗ ██████╗  █████╗ ██████╗     ██╗ ██████╗  ██████╗
██╔════╝ ██╔══██╗██╔══██╗██╔══██╗    ██║██╔═══██╗██╔════╝
██║  ███╗██████╔╝███████║██████╔╝    ██║██║   ██║██║
██║   ██║██╔══██╗██╔══██║██╔══██╗    ██║██║   ██║██║
╚██████╔╝██║  ██║██║  ██║██████╔╝    ██║╚██████╔╝╚██████╗
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝     ╚═╝ ╚═════╝  ╚═════╝
---------------------------------------------------------
*********************************************************
 
[ grabIOC v1.1 ]  A Lightweight Threat Intel Scanner
----------------------------------------------------
  [>] IOC Extraction | File • PCAP • URL • IP
  [>] YARA & Sigma Rule Detection
  [>] Process & Dir Hunt Mode
  [>] API Intel: VirusTotal, AbuseIPDB, OTX, MISP
  [>] Webhook Alerts | JSON & CSV Exports

[+] Author : Ali J [linkedin.com/in/ali01010101/] 
[!] Use responsibly. Logging Enabled. 
----------------------------------------------------
{Style.RESET_ALL}"""
    print(banner)

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_internal_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False

#==========IOC Pattens==================
def extract_iocs_from_file(file_path: str) -> Dict[str, List[str]]:
    ioc_patterns = {
        "IP Address": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "URL": r'\bhttps?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[^\s]*)?\b',
        "Email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b',
        "MD5": r'\b[a-fA-F0-9]{32}\b',
        "SHA1": r'\b[a-fA-F0-9]{40}\b',
        "SHA256": r'\b[a-fA-F0-9]{64}\b',
        "Domain": r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        "Windows Path": r'\b[a-zA-Z]:\\\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\b',
    }
    extracted = {}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            for ioc_type, pattern in ioc_patterns.items():

                 raw_matches = re.findall(pattern, content)
                 
                 if ioc_type == "IP Address":
                     matches = {ip for ip in raw_matches if is_valid_ip(ip)}
                 else:
                     matches = set(raw_matches)
    
                 if matches:
                     extracted[ioc_type] = list(matches)

#=============================

        log_event(f"Extracted {sum(len(v) for v in extracted.values())} IOCs from {file_path}", "INFO")
        return extracted
    except FileNotFoundError:
        log_event(f"File not found: {file_path}", "ERROR")
        return {}
    except Exception as e:
        log_event(f"Error reading file {file_path}: {str(e)}", "ERROR")
        return {}

def extract_iocs_from_pcap(pcap_file: str) -> Dict[str, List[str]]:
    if not pyshark:
        print(f"{Fore.RED}[-] pyshark or TShark is not available.{Style.RESET_ALL}")
        log_event("pyshark/TShark unavailable for pcap analysis", "ERROR")
        return {}

    print(f"\n{Fore.CYAN}[+] Processing pcap file: {pcap_file}{Style.RESET_ALL}\n")
    iocs = {"IP": set(), "URL": set(), "Domain": set(), "User-Agent": set()}

    try:
        with pyshark.FileCapture(pcap_file, display_filter='tcp') as capture:
            capture.set_parameter("max_packets", 10000)
            
            for pkt in capture:
                try:
                    if hasattr(pkt, 'ip'):
                        for field in ['src', 'dst']:
                            ip = getattr(pkt.ip, field, None)
                            if ip and is_valid_ip(ip):
                                iocs["IP"].add(ip)
                    
                    if 'http' in pkt:
                        http = pkt.http
                        if hasattr(http, 'host') and hasattr(http, 'request_uri'):
                            proto = "https" if 'ssl' in pkt else "http"
                            url = f"{proto}://{http.host}{http.request_uri}"
                            iocs["URL"].add(url)
                        if hasattr(http, 'user_agent'):
                            iocs["User-Agent"].add(http.user_agent)
                    
                    if 'dns' in pkt and hasattr(pkt.dns, 'qry_name'):
                        iocs["Domain"].add(pkt.dns.qry_name)
                        
                except AttributeError:
                    continue

        # Convert sets to lists for consistent return type
        return {k: list(v) for k, v in iocs.items()}

    except FileNotFoundError:
        log_event(f"PCAP file not found: {pcap_file}", "ERROR")
    except Exception as e:
        log_event(f"PCAP processing failed: {str(e)}", "ERROR")
    
    return {}

def compile_yara_rules(yara_dir: str) -> Optional[yara.Rules]:
    """Compile YARA rules from a directory with validation"""
    if not yara_dir or not os.path.isdir(yara_dir):
        log_event(f"Invalid YARA rules directory: {yara_dir}", "ERROR")
        return None
    
    try:
        valid_rules = {}
        problematic_rules = []
        
        for root, _, files in os.walk(yara_dir):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    rule_path = os.path.join(root, file)
                    try:
                        yara.compile(filepath=rule_path)
                        valid_rules[file] = rule_path
                    except yara.Error as e:
                        problem = f"Rule {file}: {str(e)}"
                        problematic_rules.append(problem)
                        log_event(problem, "WARNING")
        
        if problematic_rules:
            print(f"{Fore.YELLOW}[!] {len(problematic_rules)} YARA rules skipped due to errors:{Style.RESET_ALL}")
            for problem in problematic_rules[:3]:
                print(f"  - {problem}")
            if len(problematic_rules) > 3:
                print(f"  [...] ({len(problematic_rules)-3} more not shown)")
        
        if not valid_rules:
            log_event("No valid YARA rules found", "ERROR")
            return None
            
        return yara.compile(filepaths=valid_rules)
        
    except yara.Error as e:
        log_event(f"YARA fatal error: {str(e)}", "ERROR")
        return None

def scan_with_yara(file_path: str, yara_rules: yara.Rules) -> List[Dict]:
    """Scan a file with compiled YARA rules"""
    matches = []
    try:
        if os.path.getsize(file_path) > 25 * 1024 * 1024:  # Skip large files
            return matches
            
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        matches = yara_rules.match(data=file_data)
        return matches
    except Exception as e:
        log_event(f"YARA scan failed for {file_path}: {str(e)}", "ERROR")
        return []



def load_sigma_rules(sigma_dir: str) -> List[SigmaRule]:
    if not sigma_dir or not os.path.isdir(sigma_dir):
        log_event(f"Invalid Sigma rule directory: {sigma_dir}", "ERROR")
        return []
    rules = []
    for root, _, files in os.walk(sigma_dir):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                try:
                    with open(os.path.join(root, file), "r") as rule_file:
                        content = rule_file.read()
                        collection = SigmaCollection.from_yaml(content)
                        rules.extend(collection.rules)
                except Exception as e:
                    log_event(f"Error loading Sigma rule {file}: {e}", "ERROR")
    log_event(f"Loaded {len(rules)} Sigma rules", "INFO")
    return rules

def apply_sigma_rules(log_lines: List[str], sigma_rules: List[SigmaRule]):
    """Apply Sigma rules to log content with proper detection"""
    print(f"\n{Fore.CYAN}[+] Applying {len(sigma_rules)} Sigma rules{Style.RESET_ALL}")
    matches = []
    
    for rule in sigma_rules:
        try:
            backend = SplunkBackend()
            detection = backend.convert_rule(rule)
            
            for line in log_lines:
                if all(
                    keyword.lower() in line.lower() 
                    for keyword in detection.keywords
                ):
                    matches.append({
                        'rule': rule.title,
                        'id': rule.id,
                        'description': rule.description,
                        'severity': rule.level.name if rule.level else 'unknown'
                    })
                    break
                    
        except Exception as e:
            log_event(f"Sigma rule '{rule.title}' error: {str(e)}", "ERROR")
    
    return matches

def send_alert(message: str, mode: str = "webhook", webhook_url: str = None):
    """
    Send alerts to Discord-style webhook or Telegram Bot.
    Prioritize CLI-supplied webhook_url, then fall back to .env for both modes.
    """
    if mode == "webhook":
        url = webhook_url or os.getenv("WEBHOOK_URL")
        if not url:
            print(f"{Fore.YELLOW}[!] Webhook URL not provided or missing from .env{Style.RESET_ALL}")
            return

        if not url.startswith("http"):
            print(f"{Fore.RED}[-] Invalid webhook URL{Style.RESET_ALL}")
            return

        payload = {
            "content": message,
            "username": "grabIOC Alert",
            "avatar_url": "https://i.imgur.com/4M34hi2.png"
        }
        try:
            response = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
            if response.status_code in [200, 204]:
                print(f"{Fore.GREEN}[+] Webhook alert sent successfully{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Webhook error: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Webhook failed: {str(e)}{Style.RESET_ALL}")

    elif mode == "telegram":
        bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")

        if not bot_token or not chat_id:
            print(f"{Fore.YELLOW}[!] Telegram Bot Token or Chat ID missing from .env{Style.RESET_ALL}")
            return

        tg_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message
        }
        try:
            response = requests.post(tg_url, json=payload, timeout=10)
            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Telegram alert sent successfully{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Telegram alert error: {response.status_code} - {response.text}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Telegram alert failed: {str(e)}{Style.RESET_ALL}")

    else:
        print(f"{Fore.RED}[-] Unsupported alert mode: {mode}{Style.RESET_ALL}")


def make_api_request(url: str, headers: dict, params: Optional[dict] = None, retries: int = 3):
    for attempt in range(retries):
        try:
            GLOBAL_RATE_LIMITER.wait()  
            response = requests.get(url, headers=headers, params=params, timeout=15)
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            log_event(f"API attempt {attempt+1} failed: {str(e)}", "WARNING")
            time.sleep(2 ** attempt)
    return None

def analyze_ip(ip: str):
    print(f"\n{Fore.CYAN}Analyzing IP: {ip}{Style.RESET_ALL}")
    
    if not is_valid_ip(ip):
        print(f"{Fore.RED}[-] Invalid IP address{Style.RESET_ALL}")
        return
    
    if is_internal_ip(ip):
        print(f"{Fore.YELLOW}[!] {ip} is private/internal - skipping analysis{Style.RESET_ALL}")
        return

    if not ABUSEIPDB_KEY:
        print(f"{Fore.YELLOW}[!] AbuseIPDB key missing. Skipping AbuseIPDB lookup.{Style.RESET_ALL}")
    if not IPINFO_KEY:
        print(f"{Fore.YELLOW}[!] IPinfo key missing. Skipping IPinfo lookup.{Style.RESET_ALL}")

    hunter = ThreatHunter()
    threat_context = hunter.get_ioc_context(ip, "IPv4")

    results = {
        "AbuseIPDB": make_api_request(
            "https://api.abuseipdb.com/api/v2/check",
            {"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            {"ipAddress": ip, "maxAgeInDays": "90"}
        ),
        "VirusTotal": make_api_request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            {"x-apikey": VIRUSTOTAL_KEY}
        ),
        "IPinfo": make_api_request(
            f"https://ipinfo.io/{ip}/json",
            {"Authorization": f"Bearer {IPINFO_KEY}"}
        )
    }

    print(f"\n{Fore.MAGENTA}=== Analysis Results ==={Style.RESET_ALL}")
    if results["AbuseIPDB"]:
        score = results["AbuseIPDB"].get('data', {}).get('abuseConfidenceScore', 'N/A')
        print(f"{Fore.RED}AbuseIPDB Score: {score}{Style.RESET_ALL}")
    
    if results["VirusTotal"]:
        stats = results["VirusTotal"].get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        print(f"{Fore.BLUE}VirusTotal Malicious: {stats.get('malicious', 0)}{Style.RESET_ALL}")
    
    if results["IPinfo"]:
        print(f"{Fore.GREEN}IPinfo: {results['IPinfo'].get('org', 'N/A')} in {results['IPinfo'].get('country', 'N/A')}{Style.RESET_ALL}")

    print(f"\n{Fore.MAGENTA}=== Threat Hunting Report ==={Style.RESET_ALL}")
    print(hunter.generate_correlation_report(threat_context))

    print(f"{Fore.YELLOW}\n[+] Analysis Complete{Style.RESET_ALL}")

def analyze_url(url: str):
    print(f"\n{Fore.CYAN}Analyzing URL: {url}{Style.RESET_ALL}")
    
    hunter = ThreatHunter()
    threat_context = hunter.get_ioc_context(url, "url")

    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    results = {
        "VirusTotal": make_api_request(
            f"https://www.virustotal.com/api/v3/urls/{encoded}",
            {"x-apikey": VIRUSTOTAL_KEY}
        ),
        "APIVoid": make_api_request(
            f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={APIVOID_KEY}&url={url}",
            {}
        )
    }

    print(f"\n{Fore.MAGENTA}=== Analysis Results ==={Style.RESET_ALL}")
    if results["VirusTotal"]:
        stats = results["VirusTotal"].get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        print(f"{Fore.BLUE}VirusTotal Malicious: {stats.get('malicious', 0)}{Style.RESET_ALL}")
    
    if results["APIVoid"]:
        rep = results["APIVoid"].get('data', {}).get('reputation', 'N/A')
        print(f"{Fore.GREEN}APIVoid Reputation: {rep}{Style.RESET_ALL}")

    print(f"\n{Fore.MAGENTA}=== Threat Hunting Report ==={Style.RESET_ALL}")
    print(hunter.generate_correlation_report(threat_context))

    print(f"{Fore.YELLOW}\n[+] Analysis Complete{Style.RESET_ALL}")

#===========Main====================================
def main():
    parser = argparse.ArgumentParser(description="grabIOC v1.1 - Lightweight Threat & IOC Analyzer")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Analyze file for IOCs")
    group.add_argument("-p", "--pcap", help="Analyze pcap file")
    group.add_argument("-i", "--ip", help="Analyze IP reputation")
    group.add_argument("-u", "--url", help="Analyze URL reputation")
    group.add_argument("-s", "--scan", nargs='+', help="Scan system/directories for IOCs")
    group.add_argument("--scan-procs", action="store_true", help="Scan running processes for suspicious indicators only")
    group.add_argument("--hash", help="Generate hashes (MD5, SHA1, SHA256) of a file")
    group.add_argument("--list-yara", action="store_true", help="List compiled YARA rules")

    # Optional modifiers and extras
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--export", help="Export extracted IOCs to a JSON file")
    parser.add_argument("--csv", help="Export extracted IOCs to a CSV file")
    parser.add_argument("-a", "--alert", help="Send alert (Discord/TG)")
    parser.add_argument("-m", "--mode", choices=["webhook", "telegram"], default="webhook", help="Alert mode")
    parser.add_argument("--yara", help="Directory containing YARA rules")
    parser.add_argument("--export-yara", help="Export YARA match results to JSON file")
    parser.add_argument("--sigma", help="Directory containing Sigma rules")
    parser.add_argument("--process-config", help="Path to YAML file with process_rules")
    

    args = parser.parse_args()

    # Warn-only config validation
    validate_config(warn_only=True)
    
    if args.list_yara:
        rules = compile_yara_rules(args.yara)
        if not rules:
            print(f"{Fore.RED}[-] No YARA rules compiled{Style.RESET_ALL}")
            sys.exit(1)
        print(f"{Fore.GREEN}[+] YARA rules compiled successfully{Style.RESET_ALL}")
        sys.exit(0)

    # Logging Configuration
    logging.basicConfig(
        filename='grabioc.log',
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filemode='a'  
    )

    print_banner()

    # Initialize YARA rules if specified
    yara_rules = None
    if args.yara:
        yara_rules = compile_yara_rules(args.yara)
        if not yara_rules:
            print(f"{Fore.RED}[-] Failed to compile YARA rules{Style.RESET_ALL}")
            sys.exit(1)

    
    # Apply Sigma rules to file if provided
    if args.sigma and args.file:
        if not os.path.isfile(args.file):
            print(f"{Fore.RED}[-] File not found for Sigma scan: {args.file}{Style.RESET_ALL}")
        else:
            sigma_rules = load_sigma_rules(args.sigma)
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                log_lines = f.readlines()
            sigma_matches = apply_sigma_rules(log_lines, sigma_rules)
            if sigma_matches:
                 print(f"\n{Fore.MAGENTA}=== Sigma Rule Matches ==={Style.RESET_ALL}")
                 for match in sigma_matches:
                      print(f"  - {Fore.RED}{match['rule']}{Style.RESET_ALL}")
                      print(f"    ID: {match['id']} | Severity: {match['severity']}")
                      if match['description']:
                          print(f"    Description: {match['description'][:100]}...")
            else:
                print(f"{Fore.GREEN}[+] No Sigma rule matches found{Style.RESET_ALL}")

    if args.scan:
        scan_system(args.scan, yara_rules, args)  # Passing YARA rules to scanner

    elif args.scan_procs:
        print(f"\n{Fore.CYAN}[+] Analyzing running processes{Style.RESET_ALL}")
        suspicious = check_suspicious_processes(args)
        if suspicious:
            print(f"{Fore.RED}=== Suspicious Processes Found ==={Style.RESET_ALL}")
            for v in suspicious:
                p = v["process"]
                print(f"\n{Fore.YELLOW}PID {p['pid']}: {p['name']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN} Path: {p.get('exe','<unknown>')}{Style.RESET_ALL}")
                print(f"{Fore.RED} Reasons:{Style.RESET_ALL}")
                for r in v["reasons"]:
                    print(f"  - {r}")
                if v["vt_result"]:
                    stats = v["vt_result"].get("attributes", {}).get("last_analysis_stats", {})
                    print(f"{Fore.GREEN} VT flagged: {stats.get('malicious',0)}/90 engines{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] No suspicious processes detected{Style.RESET_ALL}")

    elif args.file:
        file_ext = os.path.splitext(args.file)[1].lower()
        if file_ext not in [".txt", ".log", ".csv"]:
            print(f"{Fore.YELLOW}[!] Warning: {file_ext} files may not be supported fully.{Style.RESET_ALL}")
        
        if iocs := extract_iocs_from_file(args.file):
            print(f"\n{Fore.MAGENTA}=== Extracted IOCs ==={Style.RESET_ALL}")
            for ioc_type, values in iocs.items():
                print(f"\n{Fore.YELLOW}{ioc_type} ({len(values)}):{Style.RESET_ALL}")
                for v in values:
                    print(f"  - {v}")

            if args.csv:
                try:
                    with open(args.csv, "w", newline="") as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(["IOC Type", "Value"])
                        for ioc_type, values in iocs.items():
                            for val in values:
                                writer.writerow([ioc_type, val])
                    print(f"\n{Fore.GREEN}[+] IOCs exported to CSV: {args.csv}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Failed to export to CSV: {e}{Style.RESET_ALL}")

            send_alert(
                  message=f"grabIOC found {sum(len(v) for v in iocs.values())} IOCs in {args.file}",
                  mode=args.mode,
                  webhook_url=args.alert
            )

            if args.export:
                try:
                    with open(args.export, "w") as out_file:
                        json.dump(iocs, out_file, indent=2)
                    print(f"\n{Fore.GREEN}[+] IOCs exported to {args.export}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Failed to export IOCs: {e}{Style.RESET_ALL}")

        if yara_rules:
            if yara_matches := scan_with_yara(args.file, yara_rules):
                print_yara_matches(yara_matches, args.file)
                if args.export_yara:
                    export_yara_matches(yara_matches, args.export_yara)

    elif args.pcap:
        extract_iocs_from_pcap(args.pcap)

    elif args.ip:
        analyze_ip(args.ip)

    elif args.url:
        analyze_url(args.url)

    elif args.hash:
        file_path = args.hash
        if not os.path.isfile(file_path):
            print(f"{Fore.RED}[-] File not found: {file_path}{Style.RESET_ALL}")
        else:
            with open(file_path, "rb") as f:
                data = f.read()
            print(f"\n{Fore.CYAN}=== Hashes for {file_path} ==={Style.RESET_ALL}")
            print(f"{Fore.YELLOW}MD5   : {hashlib.md5(data).hexdigest()}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}SHA1  : {hashlib.sha1(data).hexdigest()}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}SHA256: {hashlib.sha256(data).hexdigest()}{Style.RESET_ALL}")

    else:
        print(f"{Fore.RED}Error: No valid input provided{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
