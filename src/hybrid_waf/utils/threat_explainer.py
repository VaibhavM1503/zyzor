import logging
import os
import json
from groq import Groq

# Configure logger
logger = logging.getLogger('threat_explainer')
logger.setLevel(logging.INFO)

class ThreatExplainer:
    def __init__(self, api_key=None):
        # Using provided key as default if not passed or in env
        self.api_key = api_key or os.getenv("GROQ_API_KEY") 
        self.client = None
        
        # New limited 5 attacks constraint
        self.attack_types = ['SQLi', 'XSS', 'WebLLM', 'Command Injection', 'NoSQL Injection']
        
        if self.api_key:
            try:
                self.client = Groq(api_key=self.api_key)
                logger.info("ThreatExplainer initialized with Groq API Key.")
            except Exception as e:
                logger.error(f"Failed to initialize Groq client: {e}")
                self.client = None
        else:
            logger.warning("ThreatExplainer initialized WITHOUT API Key. Using rule-based fallback.")

    def explain(self, payload: str) -> dict:
        """
        Generates a natural language explanation, flaw isolation, remediation, location, impact, and attack_type.
        Returns: { 'attack_type': str, 'text': str, 'flaw': str, 'remediation': str, 'location': str, 'impact': str }
        """
        if self.client:
            return self._call_llm(payload)
        else:
            return self._heuristic_explain(payload)

    def _call_llm(self, payload: str) -> dict:
        """
        Calls Groq API to get a real AI explanation, flaw isolation, remediation, location, impact, and strictly mapped attack_type.
        """
        try:
            # First, check if input payload is small enough (arbitrary length to avoid abuse)
            if len(payload) > 2000:
                 return self._heuristic_explain(payload, "Payload Too Large")
            
            system_content = (
                "You are an advanced cybersecurity expert analyzing a raw HTTP payload for Zero-Day attacks or logic flaws. "
                "Respond ONLY with a valid JSON object containing exactly these six keys:\n"
                "- 'attack_type': Look for anomalies. If the payload is malicious and fits exactly one of these five categories: " + ", ".join(f'"{t}"' for t in self.attack_types) + ", then output that name exactly. "
                "If the payload is incredibly obfuscated, nonsensical, or statistically anomalous (high entropy, weird encoding sequences) without matching a core category, classify it as 'suspicious'. "
                "If the payload is completely benign and safe, output 'Safe'.\n"
                "- 'text': 1 concise sentence explaining the zero-day mechanism or anomaly.\n"
                "- 'flaw': YOUR MOST IMPORTANT TASK. You MUST extract the EXACT specific malicious substring or parameter keyword from the user's raw input that triggered the detection. We will use this to highlight the raw request. Keep it exact and concise.\n"
                "- 'remediation': High-level fix description, NO code examples.\n"
                "- 'location': Target component, e.g., 'Backend (Database)' or 'Frontend (Templates)'.\n"
                "- 'impact': 1 sentence on what damage this could cause.\n"
                "Do not include markdown formatting or any other text before or after the JSON."
            )
            
            # Use Groq Client for chat completion using Llama 3 8b model
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": system_content
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this payload:\n{payload}"
                    }
                ],
                model="llama3-8b-8192",
                temperature=0.0, # Complete deterministic output for precise matching
                max_tokens=256,
            )
            
            content = chat_completion.choices[0].message.content
            
            # Clean possible markdown block
            if content.startswith("```json"):
                content = content.replace("```json\n", "")
                content = content.replace("\n```", "")
            elif content.startswith("```"):
                content = content.replace("```\n", "")
                content = content.replace("\n```", "")
                
            try:
                result = json.loads(content)
                # Validate that all required keys are present
                required_keys = ['attack_type', 'text', 'flaw', 'remediation', 'location', 'impact']
                if all(key in result for key in required_keys):
                     # Validate attack_type fits rules
                     if result['attack_type'] not in self.attack_types and result['attack_type'] not in ['suspicious', 'Safe']:
                         logger.warning(f"Groq hallucinated an unknown zero-day tag: {result['attack_type']}, forcing 'suspicious'")
                         result['attack_type'] = "suspicious" # Force suspicious rule 
                     return result
                else:
                     logger.warning(f"Groq API returned JSON but missing keys: {result}")
                     return self._heuristic_explain(payload)
                
            except json.JSONDecodeError:
                logger.warning(f"Groq API did not return valid JSON. Content: {content}")
                return self._heuristic_explain(payload, "Fallback (Parse Error)")
            
        except Exception as e:
            logger.error(f"Failed to call Groq API: {e}")
            return self._heuristic_explain(payload)

    def _heuristic_explain(self, payload: str, force_type: str = None) -> dict:
        """
        Fallback logic to generate explanations, isolate flaws, and provide remediation/impact.
        """
        return {
            "attack_type": force_type or "Safe", # Generic fallback to Safe
            "text": "AI/Local fallback: The request was flagged due to anomalous patterns.",
            "flaw": payload[:50],  
            "remediation": "Implement strict input validation and WAF rules.",
            "location": "Backend (Input Validation)",
            "impact": "Potential exploitation of zero-day vulnerabilities or logic flaws."
        }

# Singleton instance
explainer = ThreatExplainer()

