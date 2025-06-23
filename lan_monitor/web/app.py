"""
Web application module for LAN Monitor.

This module provides a FastAPI web application for the LAN Monitor dashboard.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

from lan_monitor.config import config
from lan_monitor.tracker import device_tracker
from lan_monitor.scanner import network_scanner

# Configure logging
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="LAN Monitor",
    description="Network device monitoring dashboard",
    version="0.1.0"
)

# Get the templates directory
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Get the static files directory
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    # Add cache control headers to prevent caching of static files
    app.mount("/static", StaticFiles(directory=str(static_dir), html=True, check_dir=True), name="static")

# Add middleware to set cache control headers
@app.middleware("http")
async def add_cache_control_headers(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Set up authentication
auth_enabled = config.get("web", "auth_enabled", False)
auth_username = config.get("web", "username", "admin")
auth_password = config.get("web", "password", "admin")

# Only use HTTPBasic if auth is enabled
security = HTTPBasic(auto_error=False)


def get_current_user(credentials: Optional[HTTPBasicCredentials] = Depends(security)):
    """
    Validate user credentials.
    
    Args:
        credentials: HTTP basic auth credentials
        
    Returns:
        Username if credentials are valid
        
    Raises:
        HTTPException: If credentials are invalid
    """
    if not auth_enabled:
        return "guest"
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    correct_username = secrets.compare_digest(credentials.username, auth_username)
    correct_password = secrets.compare_digest(credentials.password, auth_password)
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return credentials.username


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, username: str = Depends(get_current_user)):
    """
    Render the dashboard index page.
    
    Args:
        request: FastAPI request object
        username: Authenticated username
        
    Returns:
        HTML response
    """
    # Get online devices
    devices = device_tracker.get_online_devices()
    
    # Get network information
    network_info = network_scanner.get_local_network_info()
    
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "devices": devices,
            "network_info": network_info,
            "username": username,
            "title": "LAN Monitor - Dashboard"
        }
    )


@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, username: str = Depends(get_current_user)):
    """
    Render the devices page.
    
    Args:
        request: FastAPI request object
        username: Authenticated username
        
    Returns:
        HTML response
    """
    # Get all devices
    devices = device_tracker.get_all_devices()
    
    return templates.TemplateResponse(
        "devices.html",
        {
            "request": request,
            "devices": devices,
            "username": username,
            "title": "LAN Monitor - All Devices"
        }
    )


@app.get("/device/{mac_address}", response_class=HTMLResponse)
async def device_details(
    request: Request,
    mac_address: str,
    username: str = Depends(get_current_user)
):
    """
    Render the device details page.
    
    Args:
        request: FastAPI request object
        mac_address: MAC address of the device
        username: Authenticated username
        
    Returns:
        HTML response
    """
    # Get device details
    device = device_tracker.get_device_details(mac_address)
    
    if not device:
        return RedirectResponse(url="/devices")
    
    return templates.TemplateResponse(
        "device_details.html",
        {
            "request": request,
            "device": device,
            "username": username,
            "title": f"LAN Monitor - Device {mac_address}"
        }
    )


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, username: str = Depends(get_current_user)):
    """
    Render the history page.
    
    Args:
        request: FastAPI request object
        username: Authenticated username
        
    Returns:
        HTML response
    """
    # Get all devices for the dropdown
    devices = device_tracker.get_all_devices()
    
    return templates.TemplateResponse(
        "history.html",
        {
            "request": request,
            "devices": devices,
            "username": username,
            "title": "LAN Monitor - History"
        }
    )


# API endpoints for AJAX requests

@app.get("/api/devices")
async def api_devices(username: str = Depends(get_current_user)):
    """
    Get all devices.
    
    Args:
        username: Authenticated username
        
    Returns:
        JSON response with devices
    """
    return device_tracker.get_all_devices()


@app.get("/api/devices/online")
async def api_online_devices(username: str = Depends(get_current_user)):
    """
    Get online devices.
    
    Args:
        username: Authenticated username
        
    Returns:
        JSON response with online devices
    """
    return device_tracker.get_online_devices()


@app.get("/api/device/{mac_address}")
async def api_device_details(mac_address: str, username: str = Depends(get_current_user)):
    """
    Get device details.
    
    Args:
        mac_address: MAC address of the device
        username: Authenticated username
        
    Returns:
        JSON response with device details
    """
    device = device_tracker.get_device_details(mac_address)
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return device


@app.get("/api/network")
async def api_network_info(username: str = Depends(get_current_user)):
    """
    Get network information.
    
    Args:
        username: Authenticated username
        
    Returns:
        JSON response with network information
    """
    return network_scanner.get_local_network_info()
