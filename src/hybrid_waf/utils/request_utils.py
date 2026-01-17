import re
import urllib.parse
import base64
import binascii
import logging

logger = logging.getLogger('smart_processor')
logger.setLevel(logging.INFO)

def recursive_decode(text: str) -> str:
    """
    Recursively decodes URL encoding, Hex, and Base64 until the text stabilizes.
    This catches 'obfuscation layers' like %2541 (Double URL encoded 'A').
    """
    if not text:
        return ""
    
    current_text = text
    iterations = 0
    max_iterations = 10 # Prevent infinite loops
    
    while iterations < max_iterations:
        previous_text = current_text
        
        # 1. URL Decode
        try:
            decoded = urllib.parse.unquote(current_text)
            if decoded != current_text:
                current_text = decoded
                continue # If we successfully decoded, loop again to check for more layers
        except Exception:
            pass
            
        # 2. Base64 Decode
        # Only try if it looks like Base64 (len % 4 == 0, valid chars) and isn't too short
        if len(current_text) > 4 and len(current_text) % 4 == 0:
            try:
                # Add padding if needed (though %4 check handles most)
                decoded_bytes = base64.b64decode(current_text, validate=True)
                # Ensure it decodes to readable text, otherwise keep original (binary payloads)
                decoded_str = decoded_bytes.decode('utf-8')
                if decoded_str != current_text and len(decoded_str) > 2:
                    current_text = decoded_str
                    continue
            except Exception:
                pass
        
        # 3. Hex Decode (e.g., \x41 or 414243)
        # Regex for \xNN format
        if "\\x" in current_text:
            try:
                def hex_repl(match):
                    return chr(int(match.group(1), 16))
                decoded = re.sub(r'\\x([0-9a-fA-F]{2})', hex_repl, current_text)
                if decoded != current_text:
                    current_text = decoded
                    continue
            except Exception:
                pass

        # If no changes in this iteration, we are done
        if current_text == previous_text:
            break
            
        iterations += 1
        
    return current_text

def parse_raw_request(raw_text: str) -> dict:
    """
    Parses a Raw HTTP Request dump into structured components.
    Supported inputs:
    - Full Raw HTTP dump (POST / HTTP/1.1 ...)
    - Just a URL
    - Just a payload
    """
    raw_text = raw_text.strip()
    result = {
        "method": "GET", # Default
        "uri": "/",
        "version": "HTTP/1.1",
        "headers": {},
        "body": "",
        "raw": raw_text
    }
    
    lines = raw_text.splitlines()
    if not lines:
        return result
        
    # Attempt to parse Request Line (Method URI Version)
    request_line_match = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+(HTTP/\d\.\d)?', lines[0].upper())
    
    if request_line_match:
        result["method"] = request_line_match.group(1)
        # URI might be path + query
        full_uri = request_line_match.group(2)
        result["uri"] = full_uri
        if request_line_match.group(3):
            result["version"] = request_line_match.group(3)
            
        # Parse Headers (lines 1 until empty line)
        body_start_index = -1
        for i in range(1, len(lines)):
            line = lines[i].strip()
            if not line: # Empty line denotes end of headers
                body_start_index = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                result["headers"][key.strip()] = value.strip()
        
        # Parse Body
        if body_start_index != -1 and body_start_index < len(lines):
            result["body"] = "\n".join(lines[body_start_index:])
            
    else:
        # Fallback: Treat as simple payload/URI or just body
        # If it looks like a path (starts with /), treat as URI
        if raw_text.startswith('/'):
             result["uri"] = raw_text
        else:
            # Treat strictly as input payload (e.g. user just pasted "UNION SELECT...")
            # We put this in 'body' or 'uri' query params depending on context, 
            # but for WAF checking we usually check WHOLE request.
            # Let's put it in body for consistency if it's not a URI.
            result["method"] = "UNKNOWN"
            result["body"] = raw_text

    return result
