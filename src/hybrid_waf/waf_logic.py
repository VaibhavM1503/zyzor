
import re
import time
import json
import logging
import os
from datetime import datetime

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure Logging
logging.basicConfig(filename='logs/waf_system.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class WAFAttackLog:
    STATS_FILE = 'logs/attack_stats.json'

    @staticmethod
    def log_attack(client_ip, attack_type, payload):
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": client_ip,
            "type": attack_type,
            "payload": payload[:50] + "..." if len(payload) > 50 else payload
        }
        
        data = WAFAttackLog.get_stats()
        data["total_threats"] += 1
        data["recent_logs"].insert(0, entry)
        data["recent_logs"] = data["recent_logs"][:20]
        
        with open(WAFAttackLog.STATS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
            
    @staticmethod
    def increment_request_count():
        data = WAFAttackLog.get_stats()
        data["total_requests"] += 1
        with open(WAFAttackLog.STATS_FILE, 'w') as f:
            json.dump(data, f, indent=4)

    @staticmethod
    def get_stats():
        if not os.path.exists(WAFAttackLog.STATS_FILE):
            return {"total_requests": 0, "total_threats": 0, "recent_logs": []}
        try:
            with open(WAFAttackLog.STATS_FILE, 'r') as f:
                return json.load(f)
        except:
             return {"total_requests": 0, "total_threats": 0, "recent_logs": []}

class TrafficControl:
    request_history = {}
    BLACKLIST = ["bad.actor.ip"]

    @staticmethod
    def check_ip(client_ip):
        if client_ip in TrafficControl.BLACKLIST:
            return False, "IP Blacklisted"

        now = time.time()
        history = TrafficControl.request_history.get(client_ip, [])
        valid_history = [t for t in history if now - t < 60]
        
        if len(valid_history) >= 60:
            return False, "Rate Limit Exceeded"
        
        valid_history.append(now)
        TrafficControl.request_history[client_ip] = valid_history
        return True, "Allowed"

class VulnerabilityScanner:
    """
    Standard & Advanced Vulnerability Detection
    """
    
    PATTERNS = {
        # Standard
        "SQL Injection": {
            "regex": [
                r"(?i)(\b(OR|AND)\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
                r"(?i)\bUNION\s+SELECT\b",
                r"(?i)\/\*.*\*\/",
                r"(?i)--",
                r"(?i)sleep\((\d+)\)"
            ],
            "desc": "Malicious SQL query detected.",
            "cwe": "CWE-89",
            "impact": "Data theft, authentication bypass.",
            "remediation": "Use parameterized queries (Prepared Statements). Sanitize inputs."
        },
        "Cross-Site Scripting (XSS)": {
            "regex": [
                r"(?si)<script.*?>",
                r"(?i)javascript:",
                r"(?i)onerror\s*=",
                r"(?i)onload\s*=",
                r"(?i)alert\("
            ],
            "desc": "Malicious script tag or event handler detected.",
            "cwe": "CWE-79",
            "impact": "Session hijacking, malicious redirects.",
            "remediation": "Encode/Escape output context-specifically (HTML entities, URL encoding)."
        },
        "CSRF": {
            "regex": [], 
            # Logic check: Missing CSRF token in POST body heuristic
            "custom_check": "check_csrf_heuristics",
            "desc": "Potential CSRF attempt (missing anti-csrf token).",
            "cwe": "CWE-352",
            "impact": "Unauthorized actions on behalf of authenticated user.",
            "remediation": "Implement Anti-CSRF tokens (SameSite cookies, custom headers)."
        },
        "Access Control (IDOR)": {
            "regex": [
                r"(?i)\b(id|user_id|account_id|doc_id|order_id|customer_id)\s*=\s*\d+" 
            ],
            "desc": "Direct Object Reference pattern detected.",
            "cwe": "CWE-639",
            "impact": "Unauthorized access to other user's data.",
            "remediation": "Use indirect object references (session-based) or strict access control checks."
        },
        "Clickjacking": {
             # Logic: Detect if X-Frame-Options is referenced or needed
             "regex": [],
             "custom_check": "check_clickjacking_heuristics",
             "desc": "Missing X-Frame-Options or CSP frame-ancestors.",
             "cwe": "CWE-1021",
             "impact": "UI Redressing, tricking users into clicking hidden elements.",
             "remediation": "Set 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors \'none\''."
        },
        "DOM Vulnerability": {
            "regex": [
                r"(?i)(location\.hash|document\.write|innerHTML)\s*="
            ],
            "desc": "Unsafe DOM manipulation detected.",
            "cwe": "CWE-79",
            "impact": "Client-side XSS.",
            "remediation": "Avoid innerHTML. Use textContent or DOMPurify."
        },

        # Advanced & Modern
        "SSRF": {
            "regex": [
                r"(?i)(TARGET|url|uri|webhook)\s*=\s*http:\/\/(localhost|127\.0\.0\.1|169\.254\.169\.254|internal)"
            ],
            "desc": "Suspicious internal URL Detected.",
            "cwe": "CWE-918",
            "impact": "Access to internal services/cloud metadata.",
            "remediation": "Whitelist allowed domains. Disable HTTP redirections."
        },
        "Web Cache Poisoning": {
             "regex": [
                 r"(?i)X-Forwarded-Host:",
                 r"(?i)X-Host:",
             ],
             "desc": "Suspicious Cache-Key headers detected.",
             "cwe": "CWE-444",
             "impact": "Serving malicious content to other users via cache.",
             "remediation": "Disable unkeyed inputs in cache keys (e.g., X-Forwarded-Host)."
        },
        "HTTP Request Smuggling": {
            "regex": [],
            "custom_check": "check_smuggling_heuristics",
            "desc": "Conflicting Transfer-Encoding and Content-Length headers.",
            "cwe": "CWE-444",
            "impact": "Bypass security controls, cache poisoning.",
            "remediation": "Reject requests with both TE and CL headers. Prefer HTTP/2."
        },
        "Insecure Deserialization / RCE": {
             "regex": [
                 r"(?i)(rO0AB|aced0005|pyobject|pickle)", # Base64 signatures for Java/Python serialization
                 r"(?i)\%\{\(#", # OGNL expression start (Struts2)
                 r"(?i)\@java\.lang\.", # Java static method call in OGNL
                 r"(?i)ognl\.OgnlContext" # OGNL Context reference
             ],
             "desc": "Serialized object or Remote Code Execution (RCE) attempt detected.",
             "cwe": "CWE-502",
             "impact": "Remote Code Execution (RCE).",
             "remediation": "Do not accept serialized objects from untrusted sources. Update vulnerable frameworks (e.g. Struts2)."
        },
        "Web LLM Attack": {
            "regex": [
                r"(?i)\b(ignore\s+(\w+\s+)?previous\s+instructions|ignore\s+system\s+prompt|dan\s+mode|do\s+anything\s+now|system\s+prompt|uncensored|act\s+as\s+a\s+developer)\b"
            ],
            "desc": "Prompt Injection / Jailbreak attempt detected.",
            "cwe": "CWE-LLM01",
            "impact": "Model manipulation, policy bypass.",
            "remediation": "Input validation, rigorous prompt engineering, separate context layers."
        },
        "Host Header Attack": {
            # Typically logic, but if "Host" header is present in body or strange place
            "regex": [],
             "custom_check": "check_host_header_heuristics",
             "desc": "Malicious Host Header injection.",
             "cwe": "CWE-74",
             "impact": "Password reset poisoning, cache poisoning.",
             "remediation": "Validate Host header against whitelist of allowed domains."
        }
    }

    @staticmethod
    def scan(payload_text):
        """
        Scans the text (which can be a raw request string) for all patterns.
        """
        # 1. Regex Checks
        for attack_name, info in VulnerabilityScanner.PATTERNS.items():
            for pattern in info.get("regex", []):
                match = re.search(pattern, payload_text)
                if match:
                    return {
                        "allowed": False,
                        "type": attack_name,
                        "match": match.group(0),
                        "info": info
                    }

        # 2. Custom Heuristics Checks
        # HTTP Request Smuggling
        if "Content-Length" in payload_text and "Transfer-Encoding" in payload_text:
             info = VulnerabilityScanner.PATTERNS["HTTP Request Smuggling"]
             return {"allowed": False, "type": "HTTP Request Smuggling", "match": "Content-Length & Transfer-Encoding", "info": info}

        # CSRF Heuristic (Very simple: matches "POST" but no typical token names)
        # Only if it looks like a HTTP POST
        if "POST " in payload_text and not re.search(r"(?i)(csrf|token|xsrf)", payload_text):
             # Blocking potential CSRF
             info = VulnerabilityScanner.PATTERNS["CSRF"]
             return {"allowed": False, "type": "CSRF", "match": "Missing CSRF Token in POST", "info": info}

        # Host Header Attack Heuristic
        # Detects X-Original-Host or if Host header is manipulated to be "evil" (demo purpose)
        if "X-Original-Host" in payload_text:
             info = VulnerabilityScanner.PATTERNS["Host Header Attack"]
             return {"allowed": False, "type": "Host Header Attack", "match": "X-Original-Host Header Detected", "info": info}
        
        # Check for Host: evil... pattern as per user example
        if re.search(r"(?i)Host:\s*evil", payload_text):
             info = VulnerabilityScanner.PATTERNS["Host Header Attack"]
             return {"allowed": False, "type": "Host Header Attack", "match": "Malicious Host Header", "info": info}


        return {"allowed": True}


class WAFEngine:
    """Main Engine Class combining all modules"""
    
    @staticmethod
    def inspect_request(client_ip, raw_input):
        # Log every request attempt count
        WAFAttackLog.increment_request_count()

        # Step 1: Traffic Control
        allowed, reason = TrafficControl.check_ip(client_ip)
        if not allowed:
            WAFAttackLog.log_attack(client_ip, "Traffic Control", reason)
            return {
                "status": "blocked", 
                "message": reason, 
                "analysis": {
                    "parsed_view": {"raw": raw_input},
                    "flaw_highlight": reason,
                    "cwe_info": {"name": "Rate Limit", "id": "CWE-000"},
                    "remediation": "Slow down requests.",
                    "ai_explanation": "Traffic control rejected this IP due to excessive rate.",
                    "location": "Gateway",
                    "impact": "Denial of Service"
                }
            }

        # Step 2: Vulnerability Detection
        result = VulnerabilityScanner.scan(raw_input)
        
        if not result["allowed"]:
            attack_type = result["type"]
            info = result["info"]
            match_str = result["match"]
            
            WAFAttackLog.log_attack(client_ip, attack_type, f"{info['desc']} Match: {match_str}")
            
            return {
                "status": "blocked",
                "message": f"Blocked: {attack_type}",
                "analysis": {
                    "parsed_view": {"raw": raw_input},
                    "flaw_highlight": match_str,
                    "cwe_info": {
                        "name": attack_type,
                        "id": info["cwe"],
                        "owasp": "Unknown" # can add if needed
                    },
                    "remediation": info["remediation"],
                    "ai_explanation": f"The system detected a pattern indicative of {attack_type}. {info['desc']}",
                    "location": "Application Layer",
                    "impact": info["impact"]
                }
            }

        # Step 3: Valid Request
        return {
            "status": "valid", 
            "message": "Request is Safe", 
            "analysis": {
                "parsed_view": {"raw": raw_input},
                "flaw_highlight": "",
                "cwe_info": {},
                "remediation": "",
                "ai_explanation": "No known patterns detected.",
                "location": "",
                "impact": ""
            }
        }

    @staticmethod
    def get_dashboard_stats():
        return WAFAttackLog.get_stats()
