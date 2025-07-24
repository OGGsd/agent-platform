# Axie Studio Backend API

Multi-tenant backend API for the Axie Studio platform.

## Features

- **Multi-tenant Architecture**: Support for multiple clients with domain-based routing
- **User Management**: Create, list, and manage users per tenant
- **Authentication**: JWT-based authentication with admin and user roles
- **Langflow Integration**: Proxy to existing Langflow instance
- **White-label Support**: Customizable branding per tenant
- **Bulk Operations**: Mass user creation and management

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - User login
- `GET /api/v1/auth/me` - Get current user info

### User Management
- `POST /api/v1/users` - Create single user
- `GET /api/v1/users` - List users for tenant
- `POST /api/v1/users/bulk` - Create multiple users

### Health Check
- `GET /health` - Health check with Langflow status

## Environment Variables

```bash
LANGFLOW_URL=https://langflow-tv34o.ondigitalocean.app
SECRET_KEY=your-secret-key
JWT_SECRET=your-jwt-secret
ALLOWED_ORIGINS=https://your-frontend.vercel.app
ADMIN_EMAIL=admin@axiestudio.se
ADMIN_PASSWORD=your-admin-password
```

## Deployment

### Digital Ocean App Platform

1. Connect this repository to Digital Ocean App Platform
2. Use the `.do/app.yaml` configuration
3. Set environment variables in the dashboard
4. Deploy!

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your values

# Run the application
python main.py
```

## Admin Access

- Username: `admin`
- Password: Set via `ADMIN_PASSWORD` environment variable
- Default: `AxieStudio2024!`

## Multi-tenant Routing

The API automatically detects tenant from the `Host` header:

- `axiestudio.com` → `default` tenant
- `client01.axiestudio.com` → `client01` tenant
- Custom domains can be configured per tenant

## Integration

This backend is designed to work with:
- **Frontend**: Axie Studio React application on Vercel
- **AI Engine**: Existing Langflow instance at `langflow-tv34o.ondigitalocean.app`

## Architecture

```
Frontend (Vercel) → Backend (Digital Ocean) → Langflow (Existing)
```

Built with FastAPI, designed for production deployment on Digital Ocean App Platform.
