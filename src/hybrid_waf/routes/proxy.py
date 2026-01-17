from flask import Blueprint, request, jsonify
from src.hybrid_waf.waf_logic import WAFEngine

proxy_bp = Blueprint('proxy', __name__)

@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    """
    Main entry point for the WAF.
    Receives user input (raw request), sends to WAFEngine, returns JSON.
    """
    data = request.get_json()
    raw_input = data.get("user_request", "")
    
    # Get client IP (simulated or real)
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # Use the new Engine
    response_data = WAFEngine.inspect_request(client_ip, raw_input)
    
    # Return 200 OK so the frontend Javascript can process the JSON payload
    # Even if blocked, we return 200 http status so the UI logic runs.
    return jsonify(response_data), 200

@proxy_bp.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Returns the live stats for the dashboard.
    """
    stats = WAFEngine.get_dashboard_stats()
    return jsonify(stats)
