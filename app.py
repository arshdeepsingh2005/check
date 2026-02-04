"""
Development entry point (proxies to wsgi app).
"""
from wsgi import app

if __name__ == "__main__":
    from app import socketio

    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

