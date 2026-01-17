import os
import joblib
import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from src.hybrid_waf.utils.database import get_training_data

# Configure logger
logger = logging.getLogger('model_trainer')
logger.setLevel(logging.INFO)
channel = logging.StreamHandler()
channel.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(channel)

MODEL_PATH = "src/hybrid_waf/models/ml_model.pkl"

def train_model():
    logger.info("Starting model retraining process...")
    
    # 1. Fetch Data
    data = get_training_data()
    if not data:
        logger.warning("No training data found in database. Aborting retraining.")
        return False

    logger.info(f"Loaded {len(data)} training samples from database.")

    # 2. Prepare features and labels
    X = [d[0] for d in data] # Features
    y = [d[1] for d in data] # Labels
    
    # 3. Train Model (Using Random Forest as a robust default)
    # in a real scenario, we might want to split train/test to verify accuracy before saving
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    
    logger.info("Model trained successfully.")

    # 4. Save Model
    try:
        joblib.dump(clf, MODEL_PATH)
        logger.info(f"New model saved to {MODEL_PATH}")
        return True
    except Exception as e:
        logger.error(f"Failed to save model: {e}")
        return False

if __name__ == "__main__":
    train_model()
