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
        
        # 3. Train Model with splits
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score
        import json

        # Split 80/20 train/test
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Using RandomForest as it's robust and generally performs well
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)
        
        # Calculate Efficiency (Accuracy)
        predictions = clf.predict(X_test)
        accuracy = accuracy_score(y_test, predictions) * 100
        
        # 4. Save Model and Stats
        # Ensure directory exists
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(clf, MODEL_PATH)

        # Save ML specs
        stats_path = os.path.join(os.path.dirname(MODEL_PATH), 'ml_stats.json')
        with open(stats_path, 'w') as f:
            json.dump({"accuracy": round(accuracy, 2), "total_samples": len(data)}, f)
        
        logger.info(f"Model successfully retrained with {len(data)} samples. Accuracy: {accuracy:.2f}%")
        return True, f"Model retrained. Accuracy: {accuracy:.2f}%"
        
    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        return False, str(e)

if __name__ == "__main__":
    # For manual testing
    success, msg = retrain_model()
    print(msg)
