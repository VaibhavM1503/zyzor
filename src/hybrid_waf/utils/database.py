import sqlite3
import os
import logging

# Configure logger
logger = logging.getLogger('waf_database')
logger.setLevel(logging.INFO)
# Ensure handlers are set up (usually done in main app, but safe to add null handler)
logger.addHandler(logging.NullHandler())

DB_PATH = "waf_patterns.db"

# Hardcoded patterns for seeding
INITIAL_MALICIOUS_PATTERNS = [
    r"(?:\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bupdate\b).*?\bfrom\b",  # SQL Injection
    r"(\bscript\b|<script>)",  # XSS Attack
    r"(\balert\b|\bconsole\.log\b)",  # JavaScript-based attacks
    r"(?:--)|(/\*.*?\*/)|(#.*?\n)",  # Comment-based SQL Injection
    # Additional SQL Injection Signatures
    r"(?i)union\s+select", r"(?i)drop\s+table", r"(?i)or\s+1=1", r"--", 
    r"' or '1'='1", r"1' or '1'='1", r"1' or 1=1--", r"(?i)admin'--", r"#",
    r"/\*.*\*/", r"' and '1'='1", r"' and sleep\(", r"(?i)or\s+sleep\(",
    r"'; drop table users;--", r"'; exec xp_cmdshell\(", r"(?i)or\s+1=1--", 
    r"(?i)waitfor\s+delay", r"(?i)select\s+\*", r"';shutdown --", 
    r"' union all select", r"' and benchmark\(", r"' having 1=1--", 
    r"' and ascii\(", r"' group by columnnames having 1=1--", 
    r"' and extractvalue\(", r"(?i)or\s+'a'='a", r"(?i)1 or 1=1", 
    r"(?i)order by \d+", r"convert\(int,", r"(?i)select username", 
    r"(?i)select password", r"'; waitfor delay '0:0:10'--", 
    r"' OR '1'='1'--", r"(?i)select\s+@@version", r"(?i)select\s+@@datadir", 
    r"(?i)select\s+load_file", r"(?i)select\s+user\(\)", 
    r"(?i)select\s+database\(\)", r"\" OR \"1\"=\"1", r"\' OR \'1\'=\'1",
    # Additional XSS Signatures
    r"(?i)<script>", r"(?i)<img src=", r"(?i)onerror=", r"(?i)alert\(", 
    r"(?i)document\.cookie", r"javascript:", r"(?i)<iframe>", r"(?i)<svg>", 
    r"(?i)onmouseover=", r"(?i)onload=", r"(?i)eval\(", r"settimeout\(", 
    r"setinterval\(", r"(?i)innerhtml=", r"(?i)srcdoc=", 
    r"(?i)<link rel=stylesheet href=", r"fetch\(", r"xhr\.open\(", 
    r"window\.location=", r"self\.location=", r"(?i)prompt\(", 
    r"constructor\.constructor\(", r"String\.fromCharCode\(", r"&#x", 
    r"&lt;script&gt;", r"(?i)<body onload=", r"onfocus=", r"onblur=", 
    r"onclick=", r"onkeydown=", r"onkeyup=", r"src=javascript:", 
    r"data:text/html;base64", r"(?i)<embed>", r"(?i)confirm\(",
    # Additional HTML Injection Signatures
    r"(?i)<div>", r"(?i)<span>", r"(?i)<input", r"(?i)<form", 
    r"(?i)<body", r"(?i)<html", r"(?i)<a href=", r"(?i)<p>", 
    r"(?i)<button>", r"</", r"(?i)<table>", r"(?i)<meta>", r"(?i)<object>", 
    r"(?i)<style>", r"(?i)<textarea>", r"(?i)<fieldset>", 
    r"(?i)<label>", r"(?i)<iframe src=", r"(?i)value=", 
    r"(?i)name=", r"(?i)action=", r"(?i)placeholder=", 
    r"(?i)<marquee>", r"(?i)<select>", r"(?i)<option>", r"(?i)<audio>", 
    r"(?i)<video>", r"(?i)<source>", r"(?i)<track>",
    # Additional CSRF Signatures
    r"fetch\(", r"xhr\.open\(", r"xmlhttprequest", r"(?i)<form action=", 
    r"cross-site", r"token=", r"access_token=", r"xsrf-token", 
    r"csrf-token", r"application/x-www-form-urlencoded", 
    r"submitform\(", r"credentials=", r"(?i)<input type=hidden", 
    r"Authorization: Bearer", r"(?i)<form method=",
    # Additional SSRF Signatures
    r"file://", r"gopher://", r"ftp://", r"http://127.0.0.1", 
    r"http://localhost", r"169.254.", r"internal", 
    r"metadata.google.internal", r"aws", r"azure", 
    r"kubernetes.default.svc", r"169.254.169.254", r"127.0.0.53", 
    r"metadata\.", r"0x7f000001", r"0:0:0:0:0:ffff:7f00:1", 
    r"169.254.169.254/latest/meta-data/", r"file:/etc/passwd", 
    r"file:/c:/windows/system32/", r"http://0x7f000001", 
    r"localhost:8080", r"127.0.0.1:3306", r"http://10.", 
    r"http://192.168."
]

INITIAL_OBFUSCATION_PATTERNS = [
    r"(%[0-9A-Fa-f]{2})+",  # URL encoding
    r"(\\x[0-9A-Fa-f]{2})+",  # Hex encoding
    r"(\bchar\b|\bconcat\b|\bsubstr\b)",  # SQL obfuscation functions
    r"(\bbase64_decode\b|\bbase64_encode\b)",  # Base64 encoding
    r"(\\u[0-9A-Fa-f]{4})+",  # Unicode escape sequences
    r"(\bfromCharCode\b)",  # JavaScript obfuscation
    r"(\bROT13\b)",  # ROT13 encoding
    r"(\bdecodeURIComponent\b|\bencodeURIComponent\b)",  # URI encoding
    r"(\bhexToInt\b|\bcharCodeAt\b)",  # Character conversion tricks
    r"(\\bXOR\\b|\bXOR\b)",  # XOR encoding
    r"(\bmd5\b|\bsha1\b|\bsha256\b)",  # Hash-based obfuscation
    r"(\bblind_sql\b|\btime_delay\b)",  # Blind SQL injection techniques
    r"(\bcase when\b|\bcase\b|\bthen\b)",  # SQL CASE obfuscation
    r"(?:--)|(/\*.*?\*/)|(#.*?\n)",  # Comment-based SQL obfuscation
]

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Always ensure table exists
    conn = get_db_connection()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL,
                type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(pattern, type)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS training_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                features TEXT NOT NULL,
                label INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attack_type TEXT,
                owasp_tag TEXT,
                ip TEXT
            )
        ''')
        conn.commit()
        # Always attempt to seed (idempotent due to INSERT OR IGNORE)
        seed_db(conn)
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
    finally:
        conn.close()

def seed_db(conn):
    logger.info("Ensuring database is seeded with initial patterns...")
    cursor = conn.cursor()
    
    malicious_data = [(p, 'malicious') for p in INITIAL_MALICIOUS_PATTERNS]
    obfuscation_data = [(p, 'obfuscated') for p in INITIAL_OBFUSCATION_PATTERNS]
    
    try:
        # Use INSERT OR IGNORE to add missing patterns without errors
        cursor.executemany('INSERT OR IGNORE INTO patterns (pattern, type) VALUES (?, ?)', malicious_data + obfuscation_data)
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Error seeding database: {e}")


def get_patterns(pattern_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        rows = cursor.execute('SELECT pattern FROM patterns WHERE type = ?', (pattern_type,)).fetchall()
        conn.close()
        return [row['pattern'] for row in rows]
    except Exception as e:
        logger.error(f"Error fetching patterns: {e}")
        return []

def add_pattern(pattern, pattern_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO patterns (pattern, type) VALUES (?, ?)', (pattern, pattern_type))
        conn.commit()
        conn.close()
        logger.info(f"Added new pattern: {pattern} ({pattern_type})")
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"Pattern already exists: {pattern}")
        return False
    except Exception as e:
        logger.error(f"Error adding pattern: {e}")
        return False

def log_request_data(features, label):
    """
    Logs request features and the determined label (1=malicious, 0=valid) 
    to the database for future model retraining.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # features is a list, convert to string for simple storage or individual columns.
        # Storing as string representation for simplicity in this MVP.
        # In a production DB, you'd want separate columns.
        features_str = str(features) 
        cursor.execute('INSERT INTO training_data (features, label) VALUES (?, ?)', (features_str, label))
        conn.commit()
        conn.close()
        # logger.info(f"Logged training data: {label}") # Optional: verbose logging
        return True
    except Exception as e:
        logger.error(f"Error logging training data: {e}")
        return False

def get_training_data():
    """
    Fetches all logged training data for model retraining.
    Returns a list of tuples (features_list, label).
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        rows = cursor.execute('SELECT features, label FROM training_data').fetchall()
        conn.close()
        
        data = []
        for row in rows:
            # excessive safety: eval is dangerous if DB is compromised, but okay for internal MVP
            # ideally use json.loads if features stored as json
            import ast
            features = ast.literal_eval(row['features']) 
            label = row['label']
            data.append((features, label))
        return data
    except Exception as e:
        logger.error(f"Error fetching training data: {e}")
        return []

def log_attack(attack_type, owasp_tag, ip):
    """
    Logs an attack event to the database.
    """
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO attack_logs (attack_type, owasp_tag, ip) VALUES (?, ?, ?)', 
                     (attack_type, owasp_tag, ip))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error logging attack: {e}")

def get_attack_stats():
    """
    Returns the count of attacks grouped by OWASP tag.
    Returns: list of dicts like [{'name': 'SQL Injection', 'value': 10}, ...]
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        rows = cursor.execute('''
            SELECT owasp_tag, COUNT(*) as count 
            FROM attack_logs 
            WHERE owasp_tag IS NOT NULL 
            GROUP BY owasp_tag
        ''').fetchall()
        conn.close()
        return [{"name": row['owasp_tag'], "value": row['count']} for row in rows]
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return []


# Initialize on module load (simple approach for this script)
init_db()
