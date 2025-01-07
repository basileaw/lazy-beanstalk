from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import subprocess
import signal
import sys
import os
import uvicorn

app = FastAPI()
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
        ['ttyd', '--writable', '-p', '7681', 'python', 'application/main.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def cleanup(signum=None, frame=None):
    """Cleanup function to terminate ttyd process on shutdown"""
    if ttyd_process:
        ttyd_process.terminate()
        ttyd_process.wait()
    sys.exit(0)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    try:
        host = request.headers.get('host', '').split(':')[0]
        print(f'Using host: {host}')  # FastAPI equivalent of app.logger.info
        return HTML_TEMPLATE.format(host=host)
    except Exception as e:
        print(f'Error: {str(e)}')  # FastAPI equivalent of app.logger.error
        return str(e)

if __name__ == '__main__':
    # Register signal handlers for cleanup
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Start ttyd process
    start_ttyd()

    try:
        uvicorn.run(app, host="0.0.0.0", port=5000)
    finally:
        # Ensure cleanup happens even if FastAPI crashes
        cleanup()