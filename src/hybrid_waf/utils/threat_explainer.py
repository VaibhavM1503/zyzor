import logging
import os

# Configure logger
logger = logging.getLogger('threat_explainer')
logger.setLevel(logging.INFO)

class ThreatExplainer:
    def __init__(self, api_key=None):
        # Using provided key as default if not passed or in env
        self.api_key = api_key or os.getenv("AI_API_KEY") or "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"
        self.client = None
        
        if self.api_key:
            logger.info("ThreatExplainer initialized with API Key.")
        else:
            logger.warning("ThreatExplainer initialized WITHOUT API Key. Using rule-based fallback.")

    def explain(self, payload: str, attack_type: str = "suspicious") -> dict:
        """
        Generates a natural language explanation, flaw isolation, remediation, location, and impact analysis.
        Returns: { 'text': str, 'flaw': str, 'remediation': str, 'location': str, 'impact': str }
        """
        if self.client:
            return self._call_llm(payload)
        else:
            return self._heuristic_explain(payload, attack_type)

    def _call_llm(self, payload: str) -> dict:
        """
        Calls OpenRouter API to get a real AI explanation, flaw isolation, remediation, location, and impact.
        """
        try:
            import requests
            import json
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:5000",
                "X-Title": "Hybrid WAF"
            }
            
            # Using a lightweight, fast model
            data = {
                "model": "mistralai/mistral-7b-instruct:free", 
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Analyze the malicious HTTP payload. Return a JSON object with five keys: 'text' (1 sentence explanation), 'flaw' (the exact malicious substring), 'remediation' (High-level fix description, NO code examples), 'location' (Target component, e.g., 'Backend (Database)' or 'Frontend (Templates)'), and 'impact' (1 sentence on what damage this could cause). Do not include any other text."
                    },
                    {
                        "role": "user",
                        "content": payload
                    }
                ],
                "response_format": {"type": "json_object"}
            }
            
            response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, data=json.dumps(data), timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                if "choices" in result and len(result["choices"]) > 0:
                    content = result["choices"][0]["message"]["content"]
                    try:
                        return json.loads(content)
                    except json.JSONDecodeError:
                        logger.warning("LLM did not return valid JSON. Using raw content.")
                        return {
                            "text": content, 
                            "flaw": payload[:50] + "...",
                            "remediation": "Review code for input validation vulnerabilities.",
                            "location": "Backend/Frontend",
                            "impact": "Potential security breach or data loss."
                        }
            
            logger.error(f"LLM API Error: {response.status_code} - {response.text}")
            return self._heuristic_explain(payload, "Malicious Anomaly (Fallback)")
            
        except Exception as e:
            logger.error(f"Failed to call LLM: {e}")
            return self._heuristic_explain(payload, "Malicious Anomaly (Fallback)")

    def _heuristic_explain(self, payload: str, attack_type: str) -> dict:
        """
        Fallback logic to generate explanations, isolate flaws, and provide remediation/impact.
        """
        payload_lower = payload.lower()
        
        if "select" in payload_lower and "union" in payload_lower:
             return {
                 "text": "AI Analysis: Detected a highly probable SQL Injection attack using 'UNION SELECT'.",
                 "flaw": "UNION SELECT",
                 "remediation": "Fix: Use parameterized queries (Prepared Statements).",
                 "location": "Backend (Database Layer)",
                 "impact": "Attackers could view, modify, or delete sensitive database records."
             }
        
        if "<script>" in payload_lower or "alert(" in payload_lower:
            match = "<script>" if "<script>" in payload_lower else "alert("
            return {
                "text": "AI Analysis: Identified a Cross-Site Scripting (XSS) attempt.",
                "flaw": match,
                "remediation": "Fix: Sanitize user input and use Content Security Policy (CSP).",
                "location": "Frontend (Template Rendering)",
                "impact": "Attackers could execute malicious scripts in users' browsers, stealing cookies or session tokens."
            }
            
        if "or 1=1" in payload_lower or "'='" in payload_lower:
             match = "or 1=1" if "or 1=1" in payload_lower else "'='"
             return {
                 "text": "AI Analysis: Detected a tautology-based SQL Injection attempt.",
                 "flaw": match,
                 "remediation": "Fix: Use ORM or Prepared Statements.",
                 "location": "Backend (Authentication)",
                 "impact": "Authentication bypass allowing unauthorized access to the application."
             }

        if "../" in payload_lower or "/etc/passwd" in payload_lower:
             match = "../" if "../" in payload_lower else "/etc/passwd"
             return {
                 "text": "AI Analysis: Detected a Directory Traversal attack.",
                 "flaw": match,
                 "remediation": "Fix: Validate file paths and avoid direct file access.",
                 "location": "Backend (Filesystem API)",
                 "impact": "Unauthorized access to sensitive server files (e.g., config files, passwords)."
             }

        return {
            "text": f"AI Analysis: The request was flagged as {attack_type} due to anomalous patterns.",
            "flaw": payload,  
            "remediation": "Implement strict input validation and WAF rules.",
            "location": "Backend (Input Validation)",
            "impact": "Potential exploitation of zero-day vulnerabilities or logic flaws."
        }

    def _detect_intent(self, payload):
        # A helper for the mock LLM function
        if "drop" in payload.lower(): return "Data Destruction"
        if "select" in payload.lower(): return "Data Exfiltration"
        return "Security Bypass"

# Singleton instance
explainer = ThreatExplainer()
