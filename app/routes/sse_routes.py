"""
SSE (Server-Sent Events) routes for embed-stream functionality.
"""
import hmac
import hashlib
import json
import queue
import time
import logging
from typing import Optional
from urllib.parse import urlparse

from flask import Blueprint, Response, request, jsonify
from app.config import Config
from app.services import get_user_auth_service, user_service
from app.sse_manager import sse_manager
from app.utils.validators import extract_username

# Configure logger
logger = logging.getLogger(__name__)

sse_bp = Blueprint('sse', __name__)

def _resolve_user_for_sse(user: str) -> Optional[dict]:
    """
    Resolve user with clean priority flow:
    1) Local cache (pinned only)
    2) Redis
    3) Quick DB lookup (with timeout) which will backfill Redis
    """
    logger.info(f"Resolving user for SSE: {user}")
    normalized = extract_username({"username": user})
    if not normalized:
        logger.warning(f"Failed to extract username from: {user}")
        return None
    
    # Normalize to lowercase for consistent lookups
    normalized = normalized.lower()
    logger.debug(f"Normalized username: {normalized}")

    # Priority 1: local cache (pinned users only)
    cached = user_service._get_from_cache(normalized)
    if cached and cached.get("user_id"):
        logger.info(f"User {normalized} found in local cache (pinned)")
        return cached

    auth_service = get_user_auth_service()
    if not auth_service:
        logger.error("UserAuthService not available")
        return None

    # Priority 2: Redis
    if auth_service.is_available():
        try:
            logger.debug(f"Checking Redis for user: {normalized}")
            user_record = auth_service.verify_username(normalized)
            if user_record and user_record.get("user_id"):
                logger.info(f"User {normalized} found in Redis")
                return user_record
        except Exception as e:
            logger.error(f"Error checking Redis for {normalized}: {e}")
            pass
    else:
        logger.warning("Redis is not available, skipping Redis lookup")

    # Priority 3: quick DB lookup (backfills Redis)
    # Increased timeout to 1s for Render DB latency
    try:
        logger.info(f"Attempting synchronous DB lookup for {normalized}")
        user_record = auth_service.lookup_user_sync(normalized, timeout=4.0)
        if user_record and user_record.get("user_id"):
            logger.info(f"User {normalized} found in DB")
            return user_record
        else:
            logger.warning(f"User {normalized} not found in DB lookup")
    except Exception as e:
        logger.error(f"Error in DB lookup for {normalized}: {e}")
        pass

    logger.warning(f"Could not resolve user: {normalized}")
    return None


def generate_iframe_token(user: str, expiry_minutes: int = 15) -> str:
    """Generate HMAC-signed token for iframe session."""
    if not Config.WS_SECRET:
        raise ValueError("WS_SECRET not configured")
    
    expiry = int(time.time()) + (expiry_minutes * 60)
    payload = f"{user}:{expiry}"
    
    signature = hmac.new(
        Config.WS_SECRET.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return f"{payload}:{signature}"


def validate_iframe_token(token: str, user: str) -> bool:
    """Validate HMAC-signed iframe token."""
    if not Config.WS_SECRET:
        return False
    
    try:
        parts = token.split(':')
        if len(parts) != 3:
            return False
        
        user_part, expiry_str, signature = parts
        expiry = int(expiry_str)
        
        # Check user matches
        if user_part != user:
            return False
        
        # Check expiry
        if time.time() > expiry:
            return False
        
        # Verify signature
        payload = f"{user_part}:{expiry_str}"
        expected_signature = hmac.new(
            Config.WS_SECRET.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    except (ValueError, IndexError):
        return False


def extract_parent_origin(request) -> Optional[str]:
    """Extract parent origin from request headers."""
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    
    candidate_origin = None
    if origin:
        candidate_origin = origin
    elif referer:
        try:
            parsed = urlparse(referer)
            if parsed.scheme and parsed.netloc:
                candidate_origin = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass
    
    return candidate_origin


def is_origin_allowed(origin: str) -> bool:
    """Check if origin is in allowed list."""
    if not origin:
        return False
    return origin in Config.ALLOWED_ORIGINS


@sse_bp.route('/embed-stream')
def embed_stream():
    """Hidden iframe endpoint for cross-origin SSE streaming."""
    user = request.args.get('user')
    nonce = request.args.get('nonce')
    
    logger.info(f"GET /embed-stream called - user: {user}, nonce: {nonce}")
    
    if not user:
        logger.warning("GET /embed-stream: user parameter missing")
        return jsonify({'error': 'user parameter required'}), 400
    
    if not nonce or len(nonce) < 8:
        logger.warning(f"GET /embed-stream: invalid nonce: {nonce}")
        return jsonify({'error': 'Valid nonce required (minimum 8 characters)'}), 400
    
    # Validate username
    user_record = _resolve_user_for_sse(user)
    if not user_record or not user_record.get('user_id'):
        logger.warning(f"GET /embed-stream: Unknown username {user}")
        return jsonify({'error': 'Unknown username'}), 403
    
    logger.info(f"GET /embed-stream: User {user} validated successfully (ID: {user_record.get('user_id')})")
    
    # Generate signed token
    try:
        iframe_token = generate_iframe_token(user, expiry_minutes=15)
    except ValueError:
        logger.error("GET /embed-stream: Server configuration error (WS_SECRET)")
        return jsonify({'error': 'Server configuration error'}), 500
    
    # Validate origin
    parent_origin = extract_parent_origin(request)
    logger.debug(f"GET /embed-stream: Extracted parent origin: {parent_origin}")
    
    # If no origin found, check if request is from same server (localhost/development)
    if not parent_origin:
        # Allow same-origin requests (for development/testing)
        host = request.host
        if host.startswith('localhost') or host.startswith('127.0.0.1'):
            parent_origin = f"http://{host}"
            logger.info(f"GET /embed-stream: Allowing same-origin request from {host}")
        else:
            logger.warning(f"GET /embed-stream: Unauthorized origin - no origin found and not localhost")
            return jsonify({'error': 'Unauthorized origin - iframe access only'}), 403
    
    # Check if origin is allowed
    if not is_origin_allowed(parent_origin):
        logger.warning(f"GET /embed-stream: Unauthorized origin: {parent_origin}")
        return jsonify({'error': 'Unauthorized origin - iframe access only'}), 403
    
    logger.info(f"GET /embed-stream: Origin {parent_origin} authorized")
    
    # HTML content with SSE connection
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SSE Relay</title>
    <meta charset="utf-8">
    <style>
        body {{ margin: 0; padding: 0; background: transparent; }}
        #status {{ font-family: monospace; font-size: 10px; color: #666; padding: 2px; }}
    </style>
</head>
<body>
    <div id="status">Connecting...</div>
    <script>
        // SSE connection variables
        let eventSource = null;
        let reconnectAttempts = 0;
        let maxReconnectAttempts = 5;
        let reconnectDelay = 2000;
        const parentOrigin = '{parent_origin}';
        const messageNonce = '{nonce}';

        // Notify parent that iframe is ready
        if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'iframe_ready',
                nonce: messageNonce,
                timestamp: Date.now()
            }}, parentOrigin);
        }}

        // Initialize SSE connection
        function connectSSE() {{
            const sseUrl = `/events?user={user}&token={iframe_token}`;

            if (eventSource) {{
                eventSource.close();
            }}

            try {{
                eventSource = new EventSource(sseUrl);
                document.getElementById('status').textContent = 'Connecting to SSE...';

                eventSource.onopen = function(event) {{
                    document.getElementById('status').textContent = 'Connected';
                    reconnectAttempts = 0;
                    reconnectDelay = 2000;

                    // Notify parent that connection is established
                    if (window.parent && window.parent !== window) {{
                        window.parent.postMessage({{
                            type: 'iframe_sse_connected',
                            nonce: messageNonce,
                            timestamp: Date.now()
                        }}, parentOrigin);
                    }}
                }};

                eventSource.onmessage = function(event) {{
                    try {{
                        const data = JSON.parse(event.data);

                        // Handle ping messages
                        if (data.type === 'ping' && data.connection_id) {{
                            // Send pong response
                            fetch(`/sse-pong?connection_id=${{data.connection_id}}&token={iframe_token}`, {{
                                method: 'POST',
                                headers: {{ 'Content-Type': 'application/json' }}
                            }}).then(() => {{
                                // Track successful pong
                                if (window.parent && window.parent !== window) {{
                                    window.parent.postMessage({{
                                        type: 'iframe_pong_success',
                                        nonce: messageNonce,
                                        timestamp: Date.now()
                                    }}, parentOrigin);
                                }}
                            }}).catch(() => {{
                                // Silent failure
                            }});
                        }}

                        // Forward all messages to parent window
                        if (window.parent && window.parent !== window) {{
                            window.parent.postMessage({{
                                type: 'iframe_sse_message',
                                data: data,
                                nonce: messageNonce,
                                timestamp: Date.now()
                            }}, parentOrigin);
                        }}

                        // Update status
                        if (data.type === 'connected') {{
                            document.getElementById('status').textContent = 'SSE Ready';
                        }} else if (data.type === 'ping') {{
                            document.getElementById('status').textContent = 'Connected (ping)';
                        }} else {{
                            document.getElementById('status').textContent = 'Message received';
                        }}

                    }} catch (e) {{
                        // Error parsing message
                    }}
                }};

                eventSource.onerror = function(event) {{
                    document.getElementById('status').textContent = 'Connection error';

                    // Check error status
                    fetch(sseUrl, {{ method: 'HEAD' }}).then(response => {{
                        const errorDetails = {{
                            type: 'iframe_sse_error',
                            attempt: reconnectAttempts,
                            maxAttempts: maxReconnectAttempts,
                            nonce: messageNonce,
                            timestamp: Date.now()
                        }};

                        if (response.status === 401) {{
                            errorDetails.error = 'Unauthorized - Invalid token';
                        }} else if (response.status === 403) {{
                            errorDetails.error = 'Forbidden - Unknown user';
                        }} else if (response.status === 402) {{
                            errorDetails.error = 'Payment Required - Insufficient credits';
                        }}

                        // Notify parent of error
                        if (window.parent && window.parent !== window) {{
                            window.parent.postMessage(errorDetails, parentOrigin);
                        }}
                    }}).catch(() => {{
                        // Fallback error
                        if (window.parent && window.parent !== window) {{
                            window.parent.postMessage({{
                                type: 'iframe_sse_error',
                                attempt: reconnectAttempts,
                                maxAttempts: maxReconnectAttempts,
                                nonce: messageNonce,
                                timestamp: Date.now()
                            }}, parentOrigin);
                        }}
                    }});

                    // Auto-reconnect with backoff
                    if (reconnectAttempts < maxReconnectAttempts) {{
                        reconnectAttempts++;
                        setTimeout(() => {{
                            connectSSE();
                        }}, reconnectDelay);
                        reconnectDelay = Math.min(reconnectDelay * 1.5, 30000);
                    }} else {{
                        // Max attempts reached
                        if (window.parent && window.parent !== window) {{
                            window.parent.postMessage({{
                                type: 'iframe_sse_failed',
                                nonce: messageNonce,
                                timestamp: Date.now()
                            }}, parentOrigin);
                        }}
                    }}
                }};

            }} catch (error) {{
                document.getElementById('status').textContent = 'Connection failed';

                if (window.parent && window.parent !== window) {{
                    window.parent.postMessage({{
                        type: 'iframe_sse_failed',
                        error: error.message,
                        nonce: messageNonce,
                        timestamp: Date.now()
                    }}, parentOrigin);
                }}
            }}
        }}

        // Start connection
        connectSSE();
    </script>
</body>
</html>"""
    
    return Response(html_content, mimetype='text/html')


@sse_bp.route('/events')
def stream_events():
    """Server-Sent Events endpoint for real-time code streaming."""
    user = request.args.get('user')
    token = request.args.get('token')
    
    logger.info(f"GET /events called - user: {user}")
    
    if not user or not token:
        logger.warning("GET /events: user or token missing")
        return jsonify({'error': 'user and token parameters required'}), 400
    
    # Validate token
    if not validate_iframe_token(token, user):
        logger.warning(f"GET /events: Invalid or expired token for user {user}")
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    # Validate username
    user_record = _resolve_user_for_sse(user)
    if not user_record or not user_record.get('user_id'):
        logger.warning(f"GET /events: Unknown username {user} during event stream initialization")
        return jsonify({'error': 'Unknown username'}), 403
    
    # Generate unique connection ID (username + timestamp + random suffix)
    import random
    import string
    random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    connection_id = f"{user}_{int(time.time())}_{random_suffix}"
    
    logger.info(f"GET /events: Creating connection {connection_id} for user {user}")
    
    # Add connection to manager
    try:
        sse_manager.add_connection(user, connection_id)
        logger.info(f"GET /events: Connection {connection_id} added to sse_manager")
    except Exception as e:
        logger.error(f"GET /events: Failed to add connection to sse_manager: {e}")
        return jsonify({'error': 'Internal server error'}), 500
    
    def event_generator():
        try:
            # Send initial connection event
            initial_message = {
                'type': 'connected',
                'message': 'SSE stream connected',
                'username': user,
                'timestamp': int(time.time()),
                'connection_id': connection_id
            }
            yield f"data: {json.dumps(initial_message)}\n\n"
            
            # Get message queue for this specific connection
            message_queue = sse_manager.get_message_queue(connection_id)
            if not message_queue:
                logger.error(f"SSE Generator: Failed to initialize message queue for {connection_id}")
                yield f"data: {json.dumps({'type': 'error', 'message': 'Failed to initialize message queue'})}\n\n"
                return
            
            logger.info(f"SSE Generator: Started for {connection_id}")
            
            last_ping_sent = time.time()
            last_keepalive_sent = time.time()
            SSE_PING_INTERVAL = 10.0  # 10 seconds
            KEEPALIVE_INTERVAL = 15.0  # 15 seconds
            
            while True:
                try:
                    # Try to get message with timeout
                    try:
                        message = message_queue.get(timeout=5.0)
                        # Send the message
                        yield f"data: {json.dumps(message)}\n\n"
                        message_queue.task_done()
                    except queue.Empty:
                        # Timeout - send ping/keepalive
                        current_time = time.time()
                        
                        # Send ping every 10 seconds
                        if current_time - last_ping_sent > SSE_PING_INTERVAL:
                            ping_message = {
                                'type': 'ping',
                                'timestamp': int(current_time),
                                'connection_id': connection_id
                            }
                            yield f"data: {json.dumps(ping_message)}\n\n"
                            last_ping_sent = current_time
                            
                            # Update ping tracking
                            if connection_id in sse_manager.connection_health:
                                sse_manager.connection_health[connection_id]['last_ping'] = current_time
                                sse_manager.connection_health[connection_id]['ping_count'] += 1
                        
                        # Send keepalive comment every 15 seconds
                        if current_time - last_keepalive_sent > KEEPALIVE_INTERVAL:
                            yield ": SSE keepalive\n\n"
                            last_keepalive_sent = current_time
                
                except Exception as e:
                    logger.error(f"SSE Generator: Error in message processing for {connection_id}: {e}")
                    break
        
        finally:
            # Clean up connection
            logger.info(f"SSE Generator: Cleaning up connection {connection_id}")
            sse_manager.remove_connection(user, connection_id)
    
    return Response(
        event_generator(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Cache-Control'
        }
    )


@sse_bp.route('/sse-pong', methods=['POST'])
def sse_pong():
    """Handle SSE heartbeat pong response."""
    connection_id = request.args.get('connection_id')
    token = request.args.get('token')
    
    if not connection_id or not token:
        return jsonify({'error': 'connection_id and token required'}), 400
    
    # Extract user from connection_id (format: user_timestamp_random)
    try:
        user_from_connection = connection_id.split('_')[0]
    except Exception:
        return jsonify({'error': 'Invalid connection_id'}), 400
    
    # Validate token matches the connection's user
    if not validate_iframe_token(token, user_from_connection):
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    # Ensure the connection exists and belongs to this user
    connection_owner = sse_manager.get_connection_username(connection_id)
    if not connection_owner:
        return jsonify({'error': 'Unknown connection_id'}), 404
    
    if connection_owner != user_from_connection:
        return jsonify({'error': 'Token/user mismatch'}), 403
    
    # Enforce per-connection rate limiting (1 pong / 10 seconds)
    allowed, retry_after = sse_manager.update_pong(connection_id, rate_limit_seconds=10.0)
    if not allowed:
        response = jsonify({
            'error': 'Rate limit exceeded',
            'detail': 'Only one pong is allowed every 10 seconds'
        })
        response.status_code = 429
        response.headers['Retry-After'] = f"{int(retry_after) if retry_after else 10}"
        return response
    
    return jsonify({'status': 'pong_received'}), 200
