import re
from src.hybrid_waf.utils.database import get_patterns

def check_signature(user_input: str):
    """
    Checks if the user request matches malicious or obfuscation patterns.
    Returns:
        - "malicious" if it's an attack
        - "obfuscated" if it looks suspicious
        - "valid" if nothing is detected
    """
    user_input = " ".join(user_input.split())  # Normalize input
    
    # Fetch patterns from database
    malicious_patterns = get_patterns("malicious")
    obfuscation_patterns = get_patterns("obfuscated")
    
    for pattern in malicious_patterns:
        try:
            match = re.search(pattern, user_input, re.IGNORECASE)
            if match:
                # Identify Attack Type and CWE based on pattern keyword (heuristic mapping)
                attack_type = "Malicious Payload"
                cwe_id = "CWE-20" # Improper Input Validation (Generic)
                
                matched_str = match.group(0).lower()
                
                if any(x in matched_str for x in ['union', 'select', 'drop', 'insert', 'update', '1=1', '--', 'sleep(', 'benchmark(', 'waitfor', 'declare']):
                    attack_type = "SQL Injection"
                    cwe_id = "CWE-89"
                    owasp_tag = "A03:2021 – Injection"
                elif any(x in matched_str for x in ['<script', 'alert', 'img src', 'iframe', 'javascript:', 'onerror', 'onload', 'eval', 'document.cookie']):
                    attack_type = "Cross-Site Scripting (XSS)"
                    cwe_id = "CWE-79"
                    owasp_tag = "A03:2021 – Injection"
                elif any(x in matched_str for x in ['/etc/passwd', '../', 'boot.ini', 'win.ini', '..\\']):
                    attack_type = "Path Traversal"
                    cwe_id = "CWE-22"
                    owasp_tag = "A01:2021 – Broken Access Control"
                elif any(x in matched_str for x in ['exec', 'cmd', 'system(', 'bash', 'whoami', 'net user']) or (any(x in matched_str for x in ['&&', '||', ';', '|']) and len(matched_str) < 50):
                    attack_type = "Command Injection"
                    cwe_id = "CWE-78"
                    owasp_tag = "A03:2021 – Injection"
                elif any(x in matched_str for x in ['$gt', '$ne', '$where', 'this.']):
                    attack_type = "NoSQL Injection"
                    cwe_id = "CWE-943"
                    owasp_tag = "A03:2021 – Injection"
                elif any(x in matched_str for x in ['*(', '*)']):
                    attack_type = "LDAP Injection"
                    cwe_id = "CWE-90"
                    owasp_tag = "A03:2021 – Injection"

                return {
                    "status": "malicious",
                    "matched_part": match.group(0),
                    "attack_type": attack_type,
                    "cwe_id": cwe_id,
                    "owasp_tag": owasp_tag
                }
        except re.error:
            continue
    
    for pattern in obfuscation_patterns:
        try:
            match = re.search(pattern, user_input, re.IGNORECASE)
            if match:
                return {
                    "status": "obfuscated",
                    "matched_part": match.group(0),
                    "attack_type": "Obfuscation Attempt",
                    "cwe_id": "CWE-116", # Improper Encoding or Escaping of Output
                    "owasp_tag": "A04:2021 – Insecure Design"
                }
        except re.error:
            continue

    return {
        "status": "valid",
        "matched_part": None,
        "attack_type": None,
        "cwe_id": None,
        "owasp_tag": None
    }

