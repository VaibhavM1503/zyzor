from flask import Flask, send_from_directory
from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp  # Import proxy Blueprint
import threading
import time

app = Flask(__name__)

# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)


def run_self_check():
    """Runs the verification suite after a short delay."""
    time.sleep(2) # Wait for Flask to start
    print("\n[AUTO-VERIFICATION] Starting self-check sequence...\n")
    try:
        import verify_features
        verify_features.run_tests()
    except Exception as e:
        print(f"Verification failed: {e}")
    print("\n[AUTO-VERIFICATION] Self-check complete. Server is ready.\n")

if __name__ == '__main__':
    # Start verification in a background thread
    threading.Thread(target=run_self_check, daemon=True).start()
    app.run(debug=True, use_reloader=False)
