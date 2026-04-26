
import re
import time
import json
import logging
import os
from datetime import datetime
import logging_loki
from dotenv import load_dotenv

load_dotenv()

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure Logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

if logger.hasHandlers():
    logger.handlers.clear()

LOKI_URL = os.getenv("GRAFANA_LOKI_URL")
LOKI_USER = os.getenv("GRAFANA_LOKI_USER")
LOKI_PASSWORD = os.getenv("GRAFANA_LOKI_PASSWORD")

if LOKI_URL and LOKI_USER and LOKI_PASSWORD:
    loki_handler = logging_loki.LokiHandler(
        url=LOKI_URL,
        tags={"application": "cogniwas-waf"},
        auth=(LOKI_USER, LOKI_PASSWORD),
        version="1",
    )
    loki_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(loki_handler)
else:
    file_handler = logging.FileHandler('logs/waf_system.log')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

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
        "Command Injection": {
            "regex": [
                r"(?i)(;|\||`|&&)\s*(ls|cat|whoami|echo|ping|wget|curl)\b"
            ],
            "desc": "Malicious OS command execution attempt.",
            "cwe": "CWE-78",
            "impact": "Full system compromise, remote code execution.",
            "remediation": "Avoid constructing commands from user input. Use safe API alternatives."
        },
        "NoSQL Injection": {
            "regex": [
                r"(?i)(\$gt|\$ne|\$where|\$regex)\s*:"
            ],
            "desc": "Malicious NoSQL query parameter manipulation.",
            "cwe": "CWE-943",
            "impact": "Data theft, bypass authentication in NoSQL DBs.",
            "remediation": "Sanitize inputs and use parameterized NoSQL queries."
        },
        "Web LLM Attack": {
            "regex": [
                r"(?i)\b(ignore\s+(\w+\s+)?previous\s+instructions|ignore\s+system\s+prompt|dan\s+mode|do\s+anything\s+now|system\s+prompt|uncensored|act\s+as\s+a\s+developer)\b"
            ],
            "desc": "Prompt Injection / Jailbreak attempt detected.",
            "cwe": "CWE-LLM01",
            "impact": "Model manipulation, policy bypass.",
            "remediation": "Input validation, rigorous prompt engineering, separate context layers."
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

        return {"allowed": True}


class WAFEngine:
    """Main Engine Class combining all modules"""
    
    @staticmethod
    def inspect_request(client_ip, raw_input):
        from src.hybrid_waf.utils.threat_explainer import explainer
        
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

        raw_lower = raw_input.lower()

        # Step 2: Local Common Payload DB Check (O(1) Speed Bypass)
        local_db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "common_payloads.json")
        try:
            if not os.path.exists(local_db_path):
                 local_db_path = "common_payloads.json"
            with open(local_db_path, "r") as f:
                 common_db = json.load(f)
                 
            for attack_cat, signatures in common_db.items():
                 for sig in signatures:
                      if sig.lower() in raw_lower:
                           # Block immediately, no AI call needed
                           ai_exp = f"System identified a known standard {attack_cat} signature locally without API check."
                           
                           WAFAttackLog.log_attack(client_ip, attack_cat, sig)
                           return {
                               "status": "blocked",
                               "message": f"Blocked: {attack_cat}",
                               "analysis": {
                                   "parsed_view": {"raw": raw_input},
                                   "flaw_highlight": sig,
                                   "cwe_info": {
                                       "name": attack_cat,
                                       "id": "Local-DB-Classified",
                                       "owasp": "Unknown" 
                                   },
                                   "remediation": f"Validate inputs against {attack_cat} patterns locally.",
                                   "ai_explanation": ai_exp,
                                   "location": "Local Signature Matcher",
                                   "impact": "Common payload execution attempt."
                               }
                           }
        except Exception as e:
            logging.error(f"Local DB Load Exception: {e}")

        # Step 2.5: Local Machine Learning (Random Forest) Check
        from src.hybrid_waf.utils.request_utils import parse_raw_request
        from src.hybrid_waf.utils.preprocessor import extract_features
        from src.hybrid_waf.utils.ml_checker import check_ml_prediction
        
        try:
            parsed = parse_raw_request(raw_input)
            features = extract_features(parsed.get('uri', ''), parsed.get('uri', ''), parsed.get('body', ''))
            
            
            ml_pred = check_ml_prediction(features)
            
            # Step 3: Use AI (ThreatExplainer) for Zero-Day Verification & Exact Highlighting
            ai_result = explainer.explain(raw_input)
            attack_type = ai_result.get("attack_type", "suspicious").strip()
            
            # If Model flagged OR AI flagged, treat as Zero-Day / Novel threat
            if ml_pred == 1 or attack_type != "Safe":
                # Ensure we have a string flag
                final_attack_type = attack_type if attack_type != "Safe" else "ML Detected"
                
                # The AI generated 'flaw' parameter should contain the exact sub-string of raw_input
                flaw = ai_result.get("flaw", "")
                if not flaw or flaw not in raw_input:
                    # Fallback intelligently: Highlight the body payload or URI instead of HTTP Headers
                    parsed_req = parse_raw_request(raw_input)
                    if parsed_req.get('body') and len(parsed_req['body']) > 2:
                        flaw = parsed_req['body'].strip()
                    else:
                        uri_val = parsed_req.get('uri', '')
                        flaw = uri_val if uri_val != "/" else raw_input.split('\n')[0]
                
                # SELF-LEARNING MECHANISM: Log features to DB and Retrain Model async
                from src.hybrid_waf.utils.database import log_request_data
                from src.hybrid_waf.utils.trainer import retrain_model
                import threading
                
                # Log the confirmed malicious features directly to the SQLite DB
                log_request_data(features, 1) # 1 = Malicious
                
                # Fire and forget background retrain thread
                threading.Thread(target=retrain_model, daemon=True).start()
                
                WAFAttackLog.log_attack(client_ip, final_attack_type, flaw)
                return {
                    "status": "blocked",
                    "message": f"Blocked: {final_attack_type}",
                    "analysis": {
                        "parsed_view": {"raw": raw_input},
                        "flaw_highlight": flaw, # Exact string pinpointed by Groq logic
                        "cwe_info": {
                            "name": final_attack_type,
                            "id": "AI-ZeroDay-Self-Learning",
                            "owasp": "Unknown" 
                        },
                        "remediation": ai_result.get("remediation", "Review payload properties."),
                        "ai_explanation": ai_result.get("text", "Our AI identified a novel/obfuscated threat syntax."),
                        "location": ai_result.get("location", "Application Payload"),
                        "impact": ai_result.get("impact", "Potential zero-day exploitation.")
                    }
                }
                
        except Exception as e:
            logging.error(f"ML / DB Processing Exception: {e}")
            
        # If we got here, neither ML nor AI found a threat. 
        # Optionally log safe features to DB as 0 for balanced training
        try:
             parsed = parse_raw_request(raw_input)
             features = extract_features(parsed.get('uri', ''), parsed.get('uri', ''), parsed.get('body', ''))
             from src.hybrid_waf.utils.database import log_request_data
             log_request_data(features, 0)
        except Exception:
             pass

        # Step 4: Valid/Clean Hybrid Request if Local is clean AND AI returned 'Safe'
        return {
            "status": "valid", 
            "message": "Request is Safe", 
            "analysis": {
                "parsed_view": {"raw": raw_input},
                "flaw_highlight": "",
                "cwe_info": {},
                "remediation": "",
                "ai_explanation": "Both Local DB and Zero-Day AI scan detected no actionable vulnerabilities.",
                "location": "",
                "impact": ""
            }
        }

    @staticmethod
    def get_dashboard_stats():
        stats = WAFAttackLog.get_stats()
        # Try to attach ML accuracy stats if available
        ml_stats_path = os.path.join(os.path.dirname(__file__), 'models/ml_stats.json')
        if os.path.exists(ml_stats_path):
            try:
                with open(ml_stats_path, 'r') as f:
                    stats['ml_stats'] = json.load(f)
            except Exception as e:
                logging.error(f"Error loading ML stats: {e}")
        return stats

