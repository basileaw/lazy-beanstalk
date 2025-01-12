import os
import sys
import json
import signal
import uvicorn
import logging
import subprocess
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logger = logging.getLogger("uvicorn")

# Store the ttyd process globally
ttyd_process = None

# At the top with other imports and constants
TERMINAL_THEME = {
    "background": "black"  # Single source of truth for the color
}

def start_ttyd():
    """Start the ttyd process"""
    global ttyd_process
    if ttyd_process:  # Kill existing process if it exists
        ttyd_process.terminate()
        ttyd_process.wait()
    ttyd_process = subprocess.Popen(
        ['ttyd',
         '--writable',
         '-p', '7681',
         '-t', f'theme={json.dumps(TERMINAL_THEME)}',  # Use the config
         'python',
         'application/main.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def cleanup(signum=None, frame=None):
    """Cleanup function to terminate ttyd process on shutdown"""
    global ttyd_process
    if ttyd_process:
        logger.info("Cleaning up ttyd process...")
        ttyd_process.terminate()
        ttyd_process.wait()
        ttyd_process = None
    sys.exit(0) if signum else None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    start_ttyd()
    yield
    # Shutdown
    cleanup()

app = FastAPI(lifespan=lifespan)
SERVER_ROOT = Path(__file__).parent
templates = Jinja2Templates(directory=str(SERVER_ROOT / "static"))
app.mount("/static", StaticFiles(directory=str(SERVER_ROOT / "static")), name="static")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    try:
        host = request.headers.get('host', '').split(':')[0]
        logger.info(f'Using host: {host}')
        return templates.TemplateResponse(
            "index.html", 
            {
                "request": request, 
                "host": host,
                "background_color": TERMINAL_THEME["background"]
            }
        )
    except Exception as e:
        logger.error(f'Error in index route: {str(e)}')
        return str(e)

if __name__ == '__main__':
    # Register signal handlers for cleanup
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

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