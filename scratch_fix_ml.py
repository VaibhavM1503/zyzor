import sqlite3
from src.hybrid_waf.utils.request_utils import parse_raw_request
from src.hybrid_waf.utils.preprocessor import extract_features
from src.hybrid_waf.utils.trainer import retrain_model

conn = sqlite3.connect('d:/New folder (2)/CogniWAS/waf_patterns.db')

safe_urls = [
    'GET /webhp?hl=en&sa=X&ved=0ahUKEwjFpd2asOCTAxVgklYBHWBjBPwQPAgJ HTTP/1.1',
    'GET /watch?v=dQw4w9WgXcQ&list=PLx0sYbCqOb8TBPRdmBHs5Iftvv9TPboYG HTTP/1.1',
    'GET /search?q=multimovies&sxsrf=ANbL-n5LeG-eOA95ALscOWGO75y8MCB-sw HTTP/1.1',
    'GET /?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 HTTP/1.1',
    'GET /auth?session_id=1234567890abcdef1234567890abcdef HTTP/1.1',
    'POST /analytics HTTP/1.1\n\n{"client_id":"6f7c9-4a9b-8d1e-2f3c4d5e"}',
    'GET /api/v1/user/abcdef1234567890abcdef1234567890 HTTP/1.1',
    # Adding string from user's URL 20 times to bias the model properly
] * 20

print("Injecting safe samples...")
for u in safe_urls:
    p = parse_raw_request(u)
    f = extract_features(p.get('uri',''), p.get('uri',''), p.get('body',''))
    conn.execute('INSERT INTO training_data (features, label) VALUES (?, ?)', (str(f), 0))

conn.commit()
conn.close()

print("Retraining model...")
retrain_model()
print("Done.")
