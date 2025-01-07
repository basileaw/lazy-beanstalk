from flask import Flask, render_template_string, request
import subprocess
import signal
import sys
import os

app = Flask(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>Quote Guessing Game</title></head>
<body><iframe id="terminal" src="http://{host}:7681/" style="width:100%;height:100vh;border:none"></iframe></body>
</html>"""

# Store the ttyd process globally
ttyd_process = None

def start_ttyd():
    """Start the ttyd process"""
    global ttyd_process
    ttyd_process = subprocess.Popen(
        ['ttyd', '--writable', '-p', '7681', 'python', 'client.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def cleanup(signum, frame):
    """Cleanup function to terminate ttyd process on shutdown"""
    if ttyd_process:
        ttyd_process.terminate()
        ttyd_process.wait()
    sys.exit(0)

@app.route('/')
def index():
    try:
        host = request.headers.get('Host', '').split(':')[0]
        app.logger.info(f'Using host: {host}')
        return HTML_TEMPLATE.format(host=host)
    except Exception as e:
        app.logger.error(f'Error: {str(e)}')
        return str(e), 500

if __name__ == '__main__':
    # Register signal handlers for cleanup
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    # Start ttyd process
    start_ttyd()
    
    try:
        app.run(host='0.0.0.0', port=5000)
    finally:
        # Ensure cleanup happens even if Flask crashes
        cleanup(None, None)