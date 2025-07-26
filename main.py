from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os
import httpx
import json
from datetime import datetime, timedelta
import jwt
import hashlib
import logging
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Axie Studio Backend API",
    description="Multi-tenant backend for Axie Studio platform",
    version="1.0.0"
)

# Add cache-busting middleware
@app.middleware("http")
async def add_cache_headers(request: Request, call_next):
    response = await call_next(request)
    # NO CACHE - Force fresh content on every request
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Cache-Bust"] = str(int(datetime.utcnow().timestamp()))
    return response

# CORS Configuration - Updated for builder.axiestudio.se
ALLOWED_ORIGINS_RAW = os.getenv("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_RAW.split(",")]
print(f"🔧 CORS ALLOWED_ORIGINS_RAW: {ALLOWED_ORIGINS_RAW}")  # Debug log
print(f"🔧 CORS ALLOWED_ORIGINS: {ALLOWED_ORIGINS}")  # Debug log

# Add explicit origins for production
PRODUCTION_ORIGINS = [
    "https://builder.axiestudio.se",
    "https://axiestudio.se",
    "https://axiestudio.com",
    "https://axie-studio-frontend-70mryh85x-swdgs-projects.vercel.app"
]

# Combine environment origins with production origins
ALL_ORIGINS = list(set(ALLOWED_ORIGINS + PRODUCTION_ORIGINS))
print(f"🔧 CORS ALL_ORIGINS: {ALL_ORIGINS}")  # Debug log

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALL_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
AXIE_STUDIO_BACKEND_URL = os.getenv("AXIE_STUDIO_BACKEND_URL", "https://langflow-tv34o.ondigitalocean.app")
SECRET_KEY = os.getenv("SECRET_KEY", "axie-studio-secret-key-2024")
JWT_SECRET = os.getenv("JWT_SECRET", "axie-studio-jwt-secret-2024")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "stefan@axiestudio.se")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "STEfanjohn!12")

# Security
security = HTTPBearer()

# Models
class User(BaseModel):
    id: Optional[str] = None
    username: str
    email: str
    password: Optional[str] = None
    is_active: bool = True
    is_superuser: bool = False
    tenant_id: Optional[str] = None
    created_at: Optional[datetime] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class TenantConfig(BaseModel):
    id: str
    name: str
    domain: str
    custom_domain: Optional[str] = None
    white_label_enabled: bool = False
    features: Dict[str, Any] = {}

class WhiteLabelCustomization(BaseModel):
    logo: Optional[str] = None
    primary_color: Optional[str] = "#1f2937"
    secondary_color: Optional[str] = "#3b82f6"
    company_name: Optional[str] = "Axie Studio"
    custom_footer: Optional[str] = None
    hide_axie_branding: bool = False

# In-memory storage (replace with database in production)
users_db = {}
tenants_db = {
    "default": {
        "id": "default",
        "name": "Axie Studio",
        "domain": "axiestudio.com",
        "white_label_enabled": True,
        "features": {"admin_panel": True, "bulk_users": True}
    }
}
customizations_db = {
    "default": {
        "logo": "https://www.axiestudio.se/logo.jpg",
        "primary_color": "#1f2937",
        "secondary_color": "#3b82f6",
        "company_name": "Axie Studio",
        "hide_axie_branding": False
    }
}

# Helper Functions
def get_tenant_from_domain(host: str = Header(None)) -> str:
    """Extract tenant ID from domain"""
    if not host:
        return "default"
    
    # Handle subdomains (client01.axiestudio.com)
    if ".axiestudio.com" in host:
        subdomain = host.split(".axiestudio.com")[0]
        if subdomain and subdomain != "axiestudio":
            return subdomain
    
    # Handle custom domains
    for tenant_id, tenant in tenants_db.items():
        if tenant.get("custom_domain") == host:
            return tenant_id
    
    return "default"

def create_jwt_token(user_data: dict) -> str:
    """Create JWT token for user"""
    payload = {
        "user_id": user_data["id"],
        "username": user_data["username"],
        "tenant_id": user_data["tenant_id"],
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str) -> dict:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Health Check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test Axie Studio Backend connection
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{AXIE_STUDIO_BACKEND_URL}/health")
            backend_status = "healthy" if response.status_code == 200 else "unhealthy"
    except:
        backend_status = "unreachable"

    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "backend_status": backend_status,
        "backend_url": AXIE_STUDIO_BACKEND_URL
    }

# Missing Frontend Compatibility Endpoints
@app.get("/api/v1/users/whoami")
async def whoami(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user info (frontend compatibility)"""
    try:
        payload = verify_jwt_token(credentials.credentials)

        if payload["username"] == "admin":
            return {
                "id": "admin",
                "username": "admin",
                "email": "admin@axiestudio.se",
                "is_active": True,
                "is_superuser": True,
                "tenant_id": payload["tenant_id"]
            }

        # Find user in database
        user_key = f"{payload['tenant_id']}:{payload['username']}"
        if user_key in users_db:
            user = users_db[user_key]
            return {k: v for k, v in user.items() if k != "password"}

        raise HTTPException(status_code=404, detail="User not found")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/api/v1/auto_login")
async def auto_login():
    """Auto login endpoint (frontend compatibility)"""
    return {"auto_login": False, "message": "Auto login disabled"}

@app.get("/api/v1/variables/")
async def get_variables():
    """Get variables (frontend compatibility)"""
    return {"variables": [], "total": 0}

@app.get("/api/v1/flows/basic_examples/")
async def get_basic_examples():
    """Get basic examples (frontend compatibility)"""
    return {"flows": [], "total": 0}

@app.get("/api/v1/config")
async def get_config():
    """Get configuration (frontend compatibility)"""
    return {
        "version": "1.0.0",
        "frontend_timeout": 60000,
        "auto_saving": True,
        "health_check_max_retries": 3
    }

@app.get("/api/v1/version")
async def get_version():
    """Get version (frontend compatibility)"""
    return {"version": "1.0.0", "package": "axie-studio"}

@app.get("/api/v1/projects/")
async def get_projects():
    """Get projects (frontend compatibility)"""
    return {"projects": [], "total": 0}

@app.get("/api/v1/store/tags")
async def get_store_tags():
    """Get store tags (frontend compatibility)"""
    return {"tags": [], "total": 0}

# Additional missing endpoints that frontend calls
@app.get("/api/v1/api_key/")
async def get_api_keys():
    """Get API keys (frontend compatibility)"""
    return {"api_keys": [], "total": 0}

@app.get("/api/v1/files/")
async def get_files():
    """Get files (frontend compatibility)"""
    return {"files": [], "total": 0}

@app.get("/api/v1/monitor/transactions")
async def get_transactions():
    """Get transactions (frontend compatibility)"""
    return {"transactions": [], "total": 0}

@app.get("/api/v1/monitor/messages")
async def get_messages():
    """Get messages (frontend compatibility)"""
    return {"messages": [], "total": 0}

@app.get("/api/v1/monitor/builds")
async def get_builds():
    """Get builds (frontend compatibility)"""
    return {"builds": [], "total": 0}

@app.get("/api/v1/all")
async def get_all_components():
    """Get all components (frontend compatibility)"""
    return {"components": {}, "total": 0}

@app.get("/api/v1/custom_component")
async def get_custom_components():
    """Get custom components (frontend compatibility)"""
    return {"components": [], "total": 0}

@app.get("/api/v1/validate")
async def validate():
    """Validate endpoint (frontend compatibility)"""
    return {"valid": True}

@app.get("/api/v1/build")
async def build():
    """Build endpoint (frontend compatibility)"""
    return {"status": "success"}

@app.get("/api/v1/starter-projects")
async def get_starter_projects():
    """Get starter projects (frontend compatibility)"""
    return {"projects": [], "total": 0}

@app.get("/api/v1/sidebar_categories")
async def get_sidebar_categories():
    """Get sidebar categories (frontend compatibility)"""
    return {"categories": [], "total": 0}

@app.get("/api/v1/voice")
async def get_voice():
    """Get voice (frontend compatibility)"""
    return {"voice": [], "total": 0}

@app.get("/api/v1/mcp/project")
async def get_mcp_project():
    """Get MCP project (frontend compatibility)"""
    return {"project": {}, "total": 0}

@app.get("/api/v1/mcp/servers")
async def get_mcp_servers():
    """Get MCP servers (frontend compatibility)"""
    return {"servers": [], "total": 0}

@app.get("/health_check")
async def health_check_alt():
    """Alternative health check endpoint"""
    return await health_check()

@app.get("/api/v1/debug/admin")
async def debug_admin_credentials():
    """Debug endpoint to check admin credentials configuration"""
    return {
        "admin_email": ADMIN_EMAIL,
        "admin_password_set": bool(ADMIN_PASSWORD),
        "admin_password_length": len(ADMIN_PASSWORD) if ADMIN_PASSWORD else 0,
        "admin_password_first_3": ADMIN_PASSWORD[:3] if ADMIN_PASSWORD else "",
        "admin_password_last_3": ADMIN_PASSWORD[-3:] if ADMIN_PASSWORD else "",
        "valid_usernames": ["admin", ADMIN_EMAIL],
        "commit_version": "8dc75d0",
        "deployment_time": "2025-07-26T02:40:37Z"
    }

# Additional missing authentication and POST endpoints
@app.post("/api/v1/login")
async def login_alt(
    request: Request,
    tenant_id: str = Depends(get_tenant_from_domain)
):
    """Alternative login endpoint (frontend compatibility) - handles both JSON and form-encoded"""
    try:
        content_type = request.headers.get("content-type", "")

        if "application/x-www-form-urlencoded" in content_type:
            # Handle form-encoded data (like the frontend sends)
            form_data = await request.form()
            username = form_data.get("username")
            password = form_data.get("password")
        else:
            # Handle JSON data
            json_data = await request.json()
            username = json_data.get("username")
            password = json_data.get("password")

        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")

        logger.info(f"Login attempt for user: {username} in tenant: {tenant_id}")
        logger.info(f"DEBUG: username='{username}', ADMIN_EMAIL='{ADMIN_EMAIL}', password_length={len(password)}")
        logger.info(f"DEBUG: username in valid list: {username in ['admin', ADMIN_EMAIL]}")
        logger.info(f"DEBUG: password matches: {password == ADMIN_PASSWORD}")

        # Check admin credentials (accept both "admin" and admin email)
        if (username in ["admin", ADMIN_EMAIL]) and password == ADMIN_PASSWORD:
            admin_user = {
                "id": "admin",
                "username": "admin",
                "email": ADMIN_EMAIL,
                "is_superuser": True,
                "tenant_id": tenant_id
            }
            token = create_jwt_token(admin_user)
            return {
                "access_token": token,
                "token_type": "bearer",
                "user": admin_user
            }

        # Check regular users
        user_key = f"{tenant_id}:{username}"
        if user_key in users_db:
            user = users_db[user_key]
            if user["password"] == password and user["is_active"]:
                token = create_jwt_token(user)
                return {
                    "access_token": token,
                    "token_type": "bearer",
                    "user": {k: v for k, v in user.items() if k != "password"}
                }

        raise HTTPException(status_code=401, detail="Invalid credentials")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid login request")

@app.post("/api/v1/logout")
async def logout():
    """Logout endpoint (frontend compatibility)"""
    return {"message": "Logged out successfully"}

@app.post("/api/v1/refresh")
async def refresh_token():
    """Refresh token endpoint (frontend compatibility)"""
    return {"message": "Token refresh not implemented"}

@app.post("/api/v1/api_key/store")
async def store_api_key(api_key_data: dict):
    """Store API key (frontend compatibility)"""
    return {"message": "API key stored", "status": "success"}

@app.post("/api/v1/store/users/likes/{component_id}")
async def like_component(component_id: str):
    """Like component (frontend compatibility)"""
    return {"message": f"Component {component_id} liked", "status": "success"}

@app.post("/api/v1/flows/")
async def create_flow(flow_data: dict):
    """Create flow (frontend compatibility)"""
    return {"message": "Flow created", "id": "flow_1", "status": "success"}

@app.post("/api/v1/variables/")
async def create_variable(variable_data: dict):
    """Create variable (frontend compatibility)"""
    return {"message": "Variable created", "id": "var_1", "status": "success"}

@app.post("/api/v1/custom_component")
async def validate_custom_component(component_data: dict):
    """Validate custom component (frontend compatibility)"""
    return {"valid": True, "message": "Component is valid"}

@app.get("/api/v1/components")
async def get_components():
    """Get components (frontend compatibility)"""
    return {"components": [], "total": 0}

@app.get("/api/v1/flows/public_flow")
async def get_public_flow():
    """Get public flow (frontend compatibility)"""
    return {"flow": {}, "status": "success"}

# Authentication Endpoints
@app.post("/api/v1/auth/login")
async def login(login_data: LoginRequest, tenant_id: str = Depends(get_tenant_from_domain)):
    """User login endpoint"""
    logger.info(f"Login attempt for user: {login_data.username} in tenant: {tenant_id}")
    
    # Check admin credentials (accept both "admin" and admin email)
    if (login_data.username in ["admin", ADMIN_EMAIL]) and login_data.password == ADMIN_PASSWORD:
        admin_user = {
            "id": "admin",
            "username": "admin",
            "email": ADMIN_EMAIL,
            "is_superuser": True,
            "tenant_id": tenant_id
        }
        token = create_jwt_token(admin_user)
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": admin_user
        }
    
    # Check regular users
    user_key = f"{tenant_id}:{login_data.username}"
    if user_key in users_db:
        user = users_db[user_key]
        if user["password"] == login_data.password and user["is_active"]:
            token = create_jwt_token(user)
            return {
                "access_token": token,
                "token_type": "bearer",
                "user": {k: v for k, v in user.items() if k != "password"}
            }
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/v1/auth/me")
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user info"""
    payload = verify_jwt_token(credentials.credentials)
    
    if payload["username"] == "admin":
        return {
            "id": "admin",
            "username": "admin",
            "email": ADMIN_EMAIL,
            "is_superuser": True,
            "tenant_id": payload["tenant_id"]
        }
    
    user_key = f"{payload['tenant_id']}:{payload['username']}"
    if user_key in users_db:
        user = users_db[user_key]
        return {k: v for k, v in user.items() if k != "password"}
    
    raise HTTPException(status_code=404, detail="User not found")

# User Management Endpoints
@app.post("/api/v1/users")
async def create_user(user: User, tenant_id: str = Depends(get_tenant_from_domain)):
    """Create a new user in the tenant"""
    user_id = f"user_{len(users_db) + 1}"
    user_key = f"{tenant_id}:{user.username}"
    
    if user_key in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    user_data = {
        "id": user_id,
        "username": user.username,
        "email": user.email,
        "password": user.password or "password123",
        "is_active": user.is_active,
        "is_superuser": user.is_superuser,
        "tenant_id": tenant_id,
        "created_at": datetime.utcnow()
    }
    
    users_db[user_key] = user_data
    logger.info(f"Created user: {user.username} in tenant: {tenant_id}")
    
    return {"message": "User created", "user": {k: v for k, v in user_data.items() if k != "password"}}

@app.get("/api/v1/users")
async def list_users(tenant_id: str = Depends(get_tenant_from_domain)):
    """List users for the current tenant"""
    tenant_users = []
    for user_key, user_data in users_db.items():
        if user_data["tenant_id"] == tenant_id:
            tenant_users.append({k: v for k, v in user_data.items() if k != "password"})
    
    return {"users": tenant_users, "tenant_id": tenant_id, "total": len(tenant_users)}

@app.post("/api/v1/users/bulk")
async def create_bulk_users(users: List[User], tenant_id: str = Depends(get_tenant_from_domain)):
    """Create multiple users at once"""
    created_users = []
    errors = []
    
    for user in users:
        try:
            user_id = f"user_{len(users_db) + len(created_users) + 1}"
            user_key = f"{tenant_id}:{user.username}"
            
            if user_key in users_db:
                errors.append(f"User {user.username} already exists")
                continue
            
            user_data = {
                "id": user_id,
                "username": user.username,
                "email": user.email,
                "password": user.password or "password123",
                "is_active": user.is_active,
                "is_superuser": user.is_superuser,
                "tenant_id": tenant_id,
                "created_at": datetime.utcnow()
            }
            
            users_db[user_key] = user_data
            created_users.append({k: v for k, v in user_data.items() if k != "password"})
            
        except Exception as e:
            errors.append(f"Error creating user {user.username}: {str(e)}")
    
    logger.info(f"Bulk created {len(created_users)} users in tenant: {tenant_id}")
    
    return {
        "message": f"Created {len(created_users)} users",
        "created": len(created_users),
        "errors": errors,
        "users": created_users,
        "tenant_id": tenant_id
    }

# User Authentication Helper
async def get_authenticated_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get authenticated user from JWT token"""
    payload = verify_jwt_token(credentials.credentials)

    if payload["username"] == "admin":
        return {
            "id": "admin",
            "username": "admin",
            "email": ADMIN_EMAIL,
            "is_superuser": True,
            "tenant_id": payload["tenant_id"]
        }

    user_key = f"{payload['tenant_id']}:{payload['username']}"
    if user_key in users_db:
        user = users_db[user_key]
        return {k: v for k, v in user.items() if k != "password"}

    raise HTTPException(status_code=404, detail="User not found")

# Axie Studio Backend Proxy Endpoints with User Isolation
@app.api_route("/api/v1/backend/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_to_backend(
    request: Request,
    path: str,
    tenant_id: str = Depends(get_tenant_from_domain),
    current_user: dict = Depends(get_authenticated_user)
):
    """Proxy requests to Axie Studio Backend with user and tenant isolation"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get request body
            body = await request.body()

            # Forward headers (excluding host)
            headers = dict(request.headers)
            headers.pop("host", None)

            # Add user and tenant context headers
            headers["X-Tenant-ID"] = tenant_id
            headers["X-User-ID"] = current_user["id"]
            headers["X-Username"] = current_user["username"]
            headers["X-Is-Superuser"] = str(current_user.get("is_superuser", False))

            # Construct Backend URL
            backend_endpoint = f"{AXIE_STUDIO_BACKEND_URL}/api/v1/{path}"
            if request.query_params:
                backend_endpoint += f"?{request.query_params}"

            logger.info(f"Proxying {request.method} {path} to Axie Studio Backend for user: {current_user['username']} in tenant: {tenant_id}")

            # Forward request to Backend
            response = await client.request(
                method=request.method,
                url=backend_endpoint,
                headers=headers,
                content=body,
                params=request.query_params
            )

            # Return response
            return JSONResponse(
                content=response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text,
                status_code=response.status_code,
                headers=dict(response.headers)
            )

    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Backend request timeout")
    except httpx.RequestError as e:
        logger.error(f"Backend proxy error: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Backend connection error: {str(e)}")
    except Exception as e:
        logger.error(f"Backend proxy unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Proxy error: {str(e)}")

# Axie Studio Backend Direct Endpoints (for frontend compatibility)
@app.get("/api/v1/flows")
@app.get("/api/v1/flows/")
async def get_flows(
    request: Request,
    tenant_id: str = Depends(get_tenant_from_domain),
    current_user: dict = Depends(get_authenticated_user),
    get_all: bool = False,
    header_flows: bool = False
):
    """Get flows from Axie Studio Backend for authenticated user"""
    try:
        # For now, return empty flows list with proper structure
        return {
            "flows": [],
            "total": 0,
            "get_all": get_all,
            "header_flows": header_flows,
            "user": current_user["username"],
            "tenant": tenant_id
        }
    except Exception as e:
        logger.error(f"Get flows error: {str(e)}")
        return {"flows": [], "total": 0}

@app.post("/api/v1/flows/{flow_id}/run")
async def run_flow(
    flow_id: str,
    request: Request,
    tenant_id: str = Depends(get_tenant_from_domain),
    current_user: dict = Depends(get_authenticated_user)
):
    """Run a flow in Axie Studio Backend for authenticated user"""
    body = await request.body()
    async with httpx.AsyncClient() as client:
        headers = {
            "Content-Type": "application/json",
            "X-Tenant-ID": tenant_id,
            "X-User-ID": current_user["id"],
            "X-Username": current_user["username"]
        }
        response = await client.post(
            f"{AXIE_STUDIO_BACKEND_URL}/api/v1/flows/{flow_id}/run",
            content=body,
            headers=headers
        )
        return response.json()

# Admin Endpoints
@app.get("/api/v1/admin/stats")
async def get_admin_stats():
    """Get platform statistics"""
    total_users = len(users_db)
    active_users = len([u for u in users_db.values() if u["is_active"]])
    total_tenants = len(tenants_db)
    white_label_enabled = len([t for t in tenants_db.values() if t.get("white_label_enabled", False)])

    return {
        "total_tenants": total_tenants,
        "total_users": total_users,
        "active_users": active_users,
        "white_label_enabled": white_label_enabled,
        "backend_url": AXIE_STUDIO_BACKEND_URL,
        "backend_status": "connected"
    }

# Admin User Management Endpoints
@app.get("/api/v1/admin/users")
async def admin_get_all_users(
    tenant_id: str = Depends(get_tenant_from_domain),
    current_user: dict = Depends(get_authenticated_user)
):
    """Get all users for admin (requires superuser privileges)"""
    if not current_user.get("is_superuser", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Get all users for the current tenant
    tenant_users = []
    for user_key, user_data in users_db.items():
        if user_data["tenant_id"] == tenant_id:
            user_info = {k: v for k, v in user_data.items() if k != "password"}
            user_info["workspace_id"] = f"workspace_{user_data['id']}"  # Generate workspace ID
            tenant_users.append(user_info)

    return {
        "users": tenant_users,
        "tenant_id": tenant_id,
        "total": len(tenant_users)
    }

@app.post("/api/v1/admin/users")
async def admin_create_user(
    user: User,
    tenant_id: str = Depends(get_tenant_from_domain),
    current_user: dict = Depends(get_authenticated_user)
):
    """Create a new user (admin only)"""
    if not current_user.get("is_superuser", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Generate unique user ID with proper format
    import uuid
    user_id = f"user_{uuid.uuid4().hex[:8]}"
    user_key = f"{tenant_id}:{user.username}"

    if user_key in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Create user with proper workspace isolation
    user_data = {
        "id": user_id,
        "username": user.username,
        "email": user.email,
        "password": user.password or f"temp_{uuid.uuid4().hex[:8]}",
        "is_active": user.is_active,
        "is_superuser": user.is_superuser,
        "tenant_id": tenant_id,
        "workspace_id": f"workspace_{user_id}",
        "created_at": datetime.utcnow(),
        "created_by": current_user["username"]
    }

    users_db[user_key] = user_data
    logger.info(f"Admin {current_user['username']} created user: {user.username} in tenant: {tenant_id}")

    # Return user info without password
    user_response = {k: v for k, v in user_data.items() if k != "password"}
    return {
        "message": "User created successfully",
        "user": user_response
    }

@app.put("/api/v1/admin/users/{user_id}")
async def admin_update_user(
    user_id: str,
    user_update: dict,
    tenant_id: str = Depends(get_tenant_from_domain),
    current_user: dict = Depends(get_authenticated_user)
):
    """Update user (admin only)"""
    if not current_user.get("is_superuser", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Find user by ID in the tenant
    user_key = None
    user_data = None
    for key, data in users_db.items():
        if data["id"] == user_id and data["tenant_id"] == tenant_id:
            user_key = key
            user_data = data
            break

    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    # Update allowed fields
    allowed_fields = ["is_active", "is_superuser", "email", "password"]
    for field, value in user_update.items():
        if field in allowed_fields:
            user_data[field] = value

    user_data["updated_at"] = datetime.utcnow()
    user_data["updated_by"] = current_user["username"]

    users_db[user_key] = user_data
    logger.info(f"Admin {current_user['username']} updated user: {user_data['username']} in tenant: {tenant_id}")

    # Return updated user info without password
    user_response = {k: v for k, v in user_data.items() if k != "password"}
    return {
        "message": "User updated successfully",
        "user": user_response
    }

@app.delete("/api/v1/admin/users/{user_id}")
async def admin_delete_user(
    user_id: str,
    tenant_id: str = Depends(get_tenant_from_domain),
    current_user: dict = Depends(get_authenticated_user)
):
    """Delete user (admin only)"""
    if not current_user.get("is_superuser", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Find and remove user by ID in the tenant
    user_key = None
    user_data = None
    for key, data in users_db.items():
        if data["id"] == user_id and data["tenant_id"] == tenant_id:
            user_key = key
            user_data = data
            break

    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent admin from deleting themselves
    if user_data["username"] == current_user["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    # Remove user from database
    del users_db[user_key]
    logger.info(f"Admin {current_user['username']} deleted user: {user_data['username']} in tenant: {tenant_id}")

    return {
        "message": f"User {user_data['username']} deleted successfully"
    }

@app.patch("/api/v1/admin/users/{user_id}/toggle-status")
async def admin_toggle_user_status(
    user_id: str,
    tenant_id: str = Depends(get_tenant_from_domain),
    current_user: dict = Depends(get_authenticated_user)
):
    """Toggle user active status (pause/unpause) - admin only"""
    if not current_user.get("is_superuser", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    # Find user by ID in the tenant
    user_key = None
    user_data = None
    for key, data in users_db.items():
        if data["id"] == user_id and data["tenant_id"] == tenant_id:
            user_key = key
            user_data = data
            break

    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    # Toggle active status
    user_data["is_active"] = not user_data["is_active"]
    user_data["updated_at"] = datetime.utcnow()
    user_data["updated_by"] = current_user["username"]

    users_db[user_key] = user_data

    status = "activated" if user_data["is_active"] else "paused"
    logger.info(f"Admin {current_user['username']} {status} user: {user_data['username']} in tenant: {tenant_id}")

    # Return updated user info without password
    user_response = {k: v for k, v in user_data.items() if k != "password"}
    return {
        "message": f"User {user_data['username']} {status} successfully",
        "user": user_response
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
