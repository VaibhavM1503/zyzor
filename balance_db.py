import sqlite3
from src.hybrid_waf.utils.database import log_request_data
from src.hybrid_waf.utils.preprocessor import extract_features
from src.hybrid_waf.utils.trainer import retrain_model

safe_texts = [
    'GET /home HTTP/1.1\nHost: example.com', 
    'GET /about HTTP/1.1\nHost: test.com', 
    'POST /login HTTP/1.1\n\n{"user":"admin","pass":"pass123"}', 
    'GET /css/style.css HTTP/1.1\n', 
    'GET /js/app.js HTTP/1.1\n', 
    'GET /api/data?id=123 HTTP/1.1\n', 
    'POST /contact HTTP/1.1\n\nname=John&msg=hello'
] * 20

for t in safe_texts:
    features = extract_features(t, t, t)
    log_request_data(features, 0)

retrain_model()
print("Balanced ML Dataset and Retrained Model!")
