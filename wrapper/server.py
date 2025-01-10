from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import subprocess
import signal
import sys
import os
import uvicorn
import logging

# Get the uvicorn logger
logger = logging.getLogger("uvicorn")

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

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    try:
        host = request.headers.get('host', '').split(':')[0]
        logger.info(f'Using host: {host}')
        return HTML_TEMPLATE.format(host=host)
    except Exception as e:
        logger.error(f'Error in index route: {str(e)}')
        return str(e)

if __name__ == '__main__':
    # Register signal handlers for cleanup and start ttyd process
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    start_ttyd()

    # Check for the environment variable to decide if watchfiles should be enabled
    is_container = os.getenv('IS_CONTAINER', 'false').lower() == 'true'

    try:
        uvicorn_args = {
            "app": "server:app",
            "host": "0.0.0.0",
            "port": 5000
        }

        if not is_container:
            # Enable watchfiles in local development
            uvicorn_args["reload"] = True
            uvicorn_args["reload_dirs"] = ["./"]

        uvicorn.run(**uvicorn_args)
    finally:
        # Ensure cleanup happens even if FastAPI crashes
        cleanup()
