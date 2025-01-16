# backend/server.py
import os
import sys
import signal
import uvicorn
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from modules.ttyd_manager import TTYDManager
from modules.proxy import ProxyManager, setup_proxy_routes

logger = logging.getLogger("uvicorn")

# Initialize managers
ttyd_manager = TTYDManager()
proxy_manager = ProxyManager(target_host="127.0.0.1", target_port=7681)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Coordinated lifespan management for all components"""
    async with ttyd_manager.lifespan(app):
        try:
            yield
        finally:
            await proxy_manager.cleanup()

# Create the FastAPI app
app = FastAPI(lifespan=lifespan)

# Setup paths
PROJECT_ROOT = Path(__file__).parent.parent
STATIC_DIR = PROJECT_ROOT / "frontend" / "static"
templates = Jinja2Templates(directory=str(STATIC_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Setup proxy routes
setup_proxy_routes(app, proxy_manager)

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "ttyd_running": ttyd_manager.is_running
    }

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
                "ttyd_path": "/ttyd/",  # Always use the proxy path
                "background_color": ttyd_manager.theme["background"]
            }
        )
    except Exception as e:
        logger.error(f'Error in index route: {str(e)}')
        return str(e)

if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGINT, lambda s, f: (ttyd_manager.stop(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: (ttyd_manager.stop(), sys.exit(0)))

    # Development mode detection
    is_container = os.getenv('IS_CONTAINER', 'false').lower() == 'true'

    try:
        # Determine port based on environment
        port = int(os.getenv('PORT', '80' if is_container else '5000'))
        logger.info(f"Starting server on port {port}")

        uvicorn_args = {
            "app": "server:app",
            "host": "0.0.0.0",
            "port": port
        }

        if not is_container:
            uvicorn_args["reload"] = True
            uvicorn_args["reload_dirs"] = ["./"]

        uvicorn.run(**uvicorn_args)
    finally:
        ttyd_manager.stop()