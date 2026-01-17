import os
import joblib

# Construct the path to the ML model relative to this file
# Construct the path to the ML model relative to this file
# Global variable to hold the model
ml_model = None

def load_model():
    global ml_model
    try:
        # Construct the path relative to this file
        model_path = os.path.join(os.path.dirname(__file__), "../models/ml_model.pkl")
        ml_model = joblib.load(model_path)
    except Exception as e:
        print(f"Error loading ML model: {e}")
        ml_model = None

# Initial load
load_model()

def reload_model():
    """Force reloads the model from disk."""
    load_model()

def check_ml_prediction(features: list) -> int:
    """
    Takes a list of eight features and returns the ML prediction.
    Assumes the model outputs 1 for malicious and 0 for valid.
    """
    if ml_model is None:
        return 0 # Fail open if model missing
    prediction = ml_model.predict([features])[0]  # Pass as a 2D array
    return prediction
