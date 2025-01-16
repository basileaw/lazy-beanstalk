import os
import sys
import signal
import uvicorn
import logging
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from modules import TTYDManager

logger = logging.getLogger("uvicorn")

# Initialize the TTYDManager
ttyd_manager = TTYDManager()

# Create the FastAPI app with the TTYDManager's lifespan
app = FastAPI(lifespan=ttyd_manager.lifespan)

SERVER_ROOT = Path(__file__).parent
templates = Jinja2Templates(directory=str(SERVER_ROOT / "static"))
app.mount("/static", StaticFiles(directory=str(SERVER_ROOT / "static")), name="static")

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "ttyd_running": ttyd_manager.is_running
    }

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    try:
        is_container = os.getenv('IS_CONTAINER', 'false').lower() == 'true'
        host = request.headers.get('host', '').split(':')[0]
        logger.info(f'Using host: {host}')
        
        # If we're in a container, use the nginx proxy path
        ttyd_path = "/ttyd/" if is_container else f"http://{host}:7681/"
        
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "host": host,
                "ttyd_path": ttyd_path,
                "background_color": ttyd_manager.theme["background"]
            }
        )
    except Exception as e:
        logger.error(f'Error in index route: {str(e)}')
        return str(e)

if __name__ == '__main__':
    # Register signal handlers for cleanup
    signal.signal(signal.SIGINT, lambda s, f: (ttyd_manager.stop(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: (ttyd_manager.stop(), sys.exit(0)))
    
    # Check for the environment variable to decide if watchfiles should be enabled
    is_container = os.getenv('IS_CONTAINER', 'false').lower() == 'true'
    
    try:
        uvicorn_args = {
            "app": "server:app",
            "host": "0.0.0.0",
            "port": 5000
        }
        if not is_container:
            uvicorn_args["reload"] = True
            uvicorn_args["reload_dirs"] = ["./"]
        
        uvicorn.run(**uvicorn_args)
    finally:
        ttyd_manager.stop()