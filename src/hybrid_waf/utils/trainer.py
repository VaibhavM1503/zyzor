import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from src.hybrid_waf.utils.database import get_training_data
import logging

# Configure logger
logger = logging.getLogger('waf_trainer')
logger.setLevel(logging.INFO)
logger.addHandler(logging.NullHandler())

MODEL_PATH = os.path.join(os.getcwd(), 'src/hybrid_waf/models/ml_model.pkl')

def retrain_model():
    """
    Fetches training data from the database and retrains the model.
    """
    logger.info("Starting model retraining process...")
    
    # 1. Fetch data
    data = get_training_data()
    if not data:
        logger.warning("No training data found. Skipping retraining.")
        return False, "No training data available."

    try:
        # 2. Prepare dataset
        X = [item[0] for item in data]
        y = [item[1] for item in data]
        
        # 3. Train Model
        # Using RandomForest as it's robust and generally performs well
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X, y)
        
        # 4. Save Model
        # Ensure directory exists
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(clf, MODEL_PATH)
        
        logger.info(f"Model successfully retrained with {len(data)} samples and saved to {MODEL_PATH}")
        return True, f"Model retrained with {len(data)} samples."
        
    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        return False, str(e)

if __name__ == "__main__":
    # For manual testing
    success, msg = retrain_model()
    print(msg)
