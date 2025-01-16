# backend/modules/proxy.py
import logging
import asyncio
import httpx
import json
import websockets
from fastapi import FastAPI, Request, WebSocket, HTTPException
from fastapi.responses import Response, StreamingResponse
from typing import Optional, AsyncGenerator
from urllib.parse import urljoin

logger = logging.getLogger("uvicorn")

class ProxyManager:
    """Generic proxy manager for both HTTP and WebSocket connections"""
    def __init__(self, target_host: str, target_port: int):
        self.target_url = f"http://{target_host}:{target_port}"
        self.ws_url = f"ws://{target_host}:{target_port}/ws"
        self._client = None

    @property
    def http_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                follow_redirects=True
            )
        return self._client

    async def cleanup(self):
        """Cleanup resources"""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _stream_response(self, response: httpx.Response) -> AsyncGenerator[bytes, None]:
        """Stream response content with proper error handling"""
        try:
            async for chunk in response.aiter_bytes():
                yield chunk
        except httpx.HTTPError as e:
            logger.error(f"Error streaming response: {e}")
        finally:
            await response.aclose()

    async def proxy_http(self, request: Request, strip_prefix: str = "") -> Response:
        """Proxy HTTP requests to target service"""
        # Strip prefix from path if specified
        path = request.url.path
        if strip_prefix and path.startswith(strip_prefix):
            path = path.replace(strip_prefix, "", 1) or "/"
        
        url = urljoin(self.target_url, path)
        
        # Prepare headers, removing host
        headers = dict(request.headers)
        headers.pop("host", None)
        
        try:
            # Handle source map requests early
            if path.endswith('.map'):
                # Create a complete source map with minimal content
                source_map = {
                    "version": 3,
                    "file": path.split('/')[-1].replace('.map', ''),
                    "sourceRoot": "",
                    "sources": ["source.js"],  # Provide at least one source
                    "sourcesContent": ["// Source code unavailable"],  # Provide content for the source
                    "names": [],
                    "mappings": ";;;;;;;",  # Minimal valid mapping
                    "x_google_ignoreList": [0]  # Hint to Chrome DevTools to ignore this
                }
                return Response(
                    content=json.dumps(source_map),
                    media_type='application/json; charset=utf-8',
                    headers={
                        'Access-Control-Allow-Origin': '*',
                        'SourceMap': 'null',  # Tell browser not to look for nested source maps
                        'X-SourceMap': 'null'
                    }
                )

            # Get raw body content
            body = await request.body()
            
            # Forward the request
            response = await self.http_client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body
            )
            
            # Create response headers, filtering out problematic ones
            response_headers = dict(response.headers)
            for header in ['content-encoding', 'content-length', 'transfer-encoding']:
                response_headers.pop(header, None)
            
            return StreamingResponse(
                self._stream_response(response),
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get('content-type')
            )
            
        except httpx.RequestError as e:
            logger.error(f"Error proxying request: {e}")
            raise HTTPException(status_code=502, detail="Failed to proxy request")

    async def proxy_websocket(self, websocket: WebSocket, subprotocols: Optional[list] = None) -> None:
        """Handle WebSocket connections"""
        try:
            # Accept the WebSocket connection with specified subprotocols
            if subprotocols:
                await websocket.accept(subprotocol=subprotocols[0])
            else:
                await websocket.accept()
            
            # Connect to target WebSocket
            async with websockets.connect(
                self.ws_url,
                subprotocols=subprotocols or [],
                ping_interval=None,
                close_timeout=5
            ) as target_ws:
                # Create tasks for bidirectional communication
                async def forward_to_target():
                    try:
                        while True:
                            try:
                                data = await websocket.receive_bytes()
                                await target_ws.send(data)
                            except Exception as e:
                                if not isinstance(e, asyncio.CancelledError):
                                    logger.debug(f"Error forwarding to target: {e}")
                                break
                    finally:
                        logger.debug("Forward to target task ending")

                async def forward_to_client():
                    try:
                        while True:
                            try:
                                data = await target_ws.recv()
                                if isinstance(data, str):
                                    await websocket.send_text(data)
                                else:
                                    await websocket.send_bytes(data)
                            except Exception as e:
                                if not isinstance(e, asyncio.CancelledError):
                                    logger.debug(f"Error forwarding to client: {e}")
                                break
                    finally:
                        logger.debug("Forward to client task ending")

                # Run both forwarding tasks concurrently
                tasks = [
                    asyncio.create_task(forward_to_target()),
                    asyncio.create_task(forward_to_client())
                ]
                
                try:
                    done, pending = await asyncio.wait(
                        tasks,
                        return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    # Ensure all tasks are cleaned up
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass
                    
        except websockets.exceptions.WebSocketException as e:
            logger.error(f"WebSocket error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in WebSocket proxy: {e}")
        finally:
            try:
                await websocket.close()
            except Exception:
                pass

def setup_proxy_routes(
    app: FastAPI,
    proxy: ProxyManager,
    prefix: str = "/ttyd",
    ws_path: str = "/ws"
):
    """Add proxy routes to the FastAPI application"""
    
    @app.websocket(f"{prefix}{ws_path}")
    async def proxy_ws(websocket: WebSocket):
        await proxy.proxy_websocket(websocket, subprotocols=['tty'])
    
    @app.api_route(f"{prefix}{{path:path}}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"])
    async def proxy_http(request: Request, path: str):
        return await proxy.proxy_http(request, strip_prefix=prefix)