"""
Internal routes including health check and newcodes WebSocket endpoint.
"""
from flask import Blueprint, jsonify

internal_bp = Blueprint('internal', __name__, url_prefix='/internal')


@internal_bp.route('/health')
def internal_health():
    """Internal health check endpoint for UptimeRobot monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'code-server',
        'internal': True
    }), 200



