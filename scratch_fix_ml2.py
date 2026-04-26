import sqlite3
from src.hybrid_waf.utils.request_utils import parse_raw_request
from src.hybrid_waf.utils.preprocessor import extract_features
from src.hybrid_waf.utils.trainer import retrain_model

conn = sqlite3.connect('d:/New folder (2)/CogniWAS/waf_patterns.db')

# A large variety of raw, LONG URLs that are safe
safe_urls = [
    'https://www.google.com/search?q=hello&hl=en&sxsrf=ANbL-n5Ht0Ty7DZWM_ALq5kzpYRPKEQ1hw%3A1775724223587',
    'https://www.google.com/webhp?hl=en&sa=X&ved=0ahUKEwjFpd2asOCTAxVgklYBHWBjBPwQPAgJ',
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLx0sYbCqOb8TBPRdmBHs5Iftvv9TPboYG',
    'https://github.com/microsoft/vscode/issues/123456?q=is%3Aissue+is%3Aopen+label%3A%22bug%22',
    'https://www.amazon.com/dp/B08F7PTF53/ref=sspa_dk_detail_0?pd_rd_i=B08F7PTF53&pd_rd_w=1a2b3&pf_rd_p=4a3b2c1d&pd_rd_wg=x1y2z&pf_rd_r=A1B2C3D4E5F6&pd_rd_r=g7h8i9j0',
    'https://auth.google.com/oauth2/v2.0/authorize?client_id=1234567890.apps.googleusercontent.com&redirect_uri=https://example.com/oauth2callback&response_type=code&scope=openid%20email%20profile&state=security_token%3D138r5719ru3e1%26url%3Dhttps://oauth2.example.com/token'
] * 10

print("Injecting safe long URL samples...")
for u in safe_urls:
    p = parse_raw_request(u)
    f = extract_features(p.get('uri',''), p.get('uri',''), p.get('body',''))
    conn.execute('INSERT INTO training_data (features, label) VALUES (?, ?)', (str(f), 0))

conn.commit()
conn.close()

print("Retraining model...")
retrain_model()
print("Done.")
