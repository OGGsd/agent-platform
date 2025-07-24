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

# CORS Configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
LANGFLOW_URL = os.getenv("LANGFLOW_URL", "https://langflow-tv34o.ondigitalocean.app")
SECRET_KEY = os.getenv("SECRET_KEY", "axie-studio-secret-key-2024")
JWT_SECRET = os.getenv("JWT_SECRET", "axie-studio-jwt-secret-2024")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "stefan@axiestudio.se")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

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
        # Test Langflow connection
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{LANGFLOW_URL}/health")
            langflow_status = "healthy" if response.status_code == 200 else "unhealthy"
    except:
        langflow_status = "unreachable"
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "langflow_status": langflow_status,
        "langflow_url": LANGFLOW_URL
    }

# Authentication Endpoints
@app.post("/api/v1/auth/login")
async def login(login_data: LoginRequest, tenant_id: str = Depends(get_tenant_from_domain)):
    """User login endpoint"""
    logger.info(f"Login attempt for user: {login_data.username} in tenant: {tenant_id}")
    
    # Check admin credentials
    if login_data.username == "admin" and login_data.password == ADMIN_PASSWORD:
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

# Langflow Proxy Endpoints
@app.api_route("/api/v1/langflow/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_to_langflow(request: Request, path: str, tenant_id: str = Depends(get_tenant_from_domain)):
    """Proxy requests to Langflow with tenant context"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get request body
            body = await request.body()

            # Forward headers (excluding host)
            headers = dict(request.headers)
            headers.pop("host", None)
            headers["X-Tenant-ID"] = tenant_id

            # Construct Langflow URL
            langflow_endpoint = f"{LANGFLOW_URL}/api/v1/{path}"
            if request.query_params:
                langflow_endpoint += f"?{request.query_params}"

            logger.info(f"Proxying {request.method} {path} to Langflow for tenant: {tenant_id}")

            # Forward request to Langflow
            response = await client.request(
                method=request.method,
                url=langflow_endpoint,
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
        raise HTTPException(status_code=504, detail="Langflow request timeout")
    except httpx.RequestError as e:
        logger.error(f"Langflow proxy error: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Langflow connection error: {str(e)}")
    except Exception as e:
        logger.error(f"Langflow proxy unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Proxy error: {str(e)}")

# Langflow Direct Endpoints (for frontend compatibility)
@app.get("/api/v1/flows")
async def get_flows(tenant_id: str = Depends(get_tenant_from_domain)):
    """Get flows from Langflow"""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{LANGFLOW_URL}/api/v1/flows")
        return response.json()

@app.post("/api/v1/flows/{flow_id}/run")
async def run_flow(flow_id: str, request: Request, tenant_id: str = Depends(get_tenant_from_domain)):
    """Run a flow in Langflow"""
    body = await request.body()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{LANGFLOW_URL}/api/v1/flows/{flow_id}/run",
            content=body,
            headers={"Content-Type": "application/json", "X-Tenant-ID": tenant_id}
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
        "langflow_url": LANGFLOW_URL,
        "langflow_status": "connected"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
