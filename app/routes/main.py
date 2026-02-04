"""
Main API routes (no HTML rendering).
"""
from pathlib import Path

from flask import Blueprint, Response, jsonify, request, send_from_directory

from app.utils.decoy import generate_decoy_response

main_bp = Blueprint('main', __name__)


@main_bp.route('/health')
def health():
    """Health check endpoint for UptimeRobot monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'code-server'
    }), 200


@main_bp.route('/relay')
def relay():
    """Bypass CSP restrictions."""
    # Get the target URL from query parameters
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({'error': 'Missing url parameter'}), 400
    
    try:
        import requests
        response = requests.get(target_url, timeout=10)
        return Response(
            response.content,
            status=response.status_code,
            headers={'Content-Type': response.headers.get('Content-Type', 'text/html')}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Decoy routes (intentionally added, no real purpose)
@main_bp.route('/')
def index():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/dashboard')
def dashboard():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/admin')
def admin():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/api')
def api_index():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/status')
def status():
    """Decoy route."""
    return generate_decoy_response()


@main_bp.route('/test')
def test_page():
    """Serve the Socket.IO test HTML page."""
    tests_dir = Path(__file__).parent.parent.parent / 'tests'
    return send_from_directory(str(tests_dir), 'socket_test.html')


@main_bp.route('/sse-test')
def sse_test_page():
    """Serve the SSE /embed-stream test HTML page."""
    tests_dir = Path(__file__).parent.parent.parent / 'tests'
    return send_from_directory(str(tests_dir), 'sse_test.html')


@main_bp.route('/load-test')
def load_test_page():
    """Serve the SSE load test HTML page."""
    tests_dir = Path(__file__).parent.parent.parent / 'tests'
    return send_from_directory(str(tests_dir), 'load_test_sse.html')



