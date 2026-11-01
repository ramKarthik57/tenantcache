"""FastAPI Target Application for Multi-Tenant Lab."""

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel
from typing import Optional, Dict, Any
from lab.application.database import lab_db
from src.tenantcache.models import Role, Visibility

app = FastAPI(
    title="TenantCache Multi-Tenant Lab Target",
    description="Intentionally configurable multi-tenant enterprise API for cache isolation security research.",
    version="1.0.0"
)


class RevocationRequest(BaseModel):
    resource_id: str
    user_id: str


def authenticate_principal(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Authenticates caller and extracts tenant & user identity from cryptographic Bearer token."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header"
        )
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme; Bearer token required"
        )
    token = authorization.split("Bearer ")[1].strip()
    user_info = lab_db.get_user_by_token(token)
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or revoked security token"
        )
    return user_info


@app.get("/healthz")
def health_check():
    return {"status": "ok", "app": "TenantCache Multi-Tenant Lab Target"}


@app.post("/api/v1/lab/reset")
def reset_lab_state():
    lab_db.reset()
    return {"status": "reset_successful", "message": "Database and fixtures restored to seed state"}


@app.post("/api/v1/admin/revoke-access")
def revoke_user_access(
    req: RevocationRequest,
    authorization: Optional[str] = Header(None)
):
    principal = authenticate_principal(authorization)
    if principal["role"] != Role.ADMIN.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required for access revocation")
    
    lab_db.revoke_user_access(req.resource_id, req.user_id)
    return {
        "status": "revoked",
        "resource_id": req.resource_id,
        "revoked_user_id": req.user_id
    }


@app.get("/api/v1/public/docs/{doc_id}")
def get_public_document(doc_id: str, response: Response):
    """Public guidelines and terms endpoint - legitimately shared across tenants."""
    res = next((r for r in lab_db.simulator.resources.values() if r.visibility == Visibility.PUBLIC and doc_id in r.endpoint_path), None)
    if not res:
        res = lab_db.get_resource("res_pub_guideline")
    if not res:
        raise HTTPException(status_code=404, detail="Document not found")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return res.payload


@app.get("/api/v1/tenant/dashboard")
def get_tenant_dashboard(
    response: Response,
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """Tenant dashboard endpoint: confidential per tenant."""
    principal = authenticate_principal(authorization)
    tenant_id = principal["tenant_id"]

    res_id = f"res_{tenant_id.replace('tenant_', '')}_dashboard"
    res = lab_db.get_resource(res_id)
    if not res:
        # Fallback search by tenant
        res = next((r for r in lab_db.simulator.resources.values() if r.tenant_id == tenant_id and "dashboard" in r.id), None)
    
    if not res:
        raise HTTPException(status_code=404, detail=f"No dashboard for tenant {tenant_id}")
    
    # Origin policy: authenticated endpoints should be private, but intermediate caches might misinterpret
    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.get("/api/v1/tenant/invoices/{invoice_id}")
def get_tenant_invoice(
    invoice_id: str,
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """Tenant invoices endpoint."""
    principal = authenticate_principal(authorization)
    tenant_id = principal["tenant_id"]

    res = next((r for r in lab_db.simulator.resources.values() if invoice_id in r.endpoint_path), None)
    if not res:
        raise HTTPException(status_code=404, detail="Invoice not found")
    
    # Cross-tenant check at origin:
    if res.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Invoice belongs to another tenant")

    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.get("/api/v1/user/profile")
def get_user_profile(
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """User private profile."""
    principal = authenticate_principal(authorization)
    user_id = principal["user_id"]
    res_id = f"res_{principal['username']}_profile"
    res = lab_db.get_resource(res_id)
    if not res:
        raise HTTPException(status_code=404, detail="Profile not found")

    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.get("/api/v1/admin/audit-logs")
def get_admin_audit_logs(
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """Admin only audit logs."""
    principal = authenticate_principal(authorization)
    if principal["role"] != Role.ADMIN.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Admin role required")

    res_id = f"res_{principal['tenant_id'].replace('tenant_', '')}_admin_logs"
    res = lab_db.get_resource(res_id)
    if not res or res.tenant_id != principal["tenant_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Tenant mismatch")

    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.get("/api/v1/shared/projects/{proj_id}")
def get_shared_project(
    proj_id: str,
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """Shared project endpoint with dynamic access control and revocation."""
    principal = authenticate_principal(authorization)
    res = next((r for r in lab_db.simulator.resources.values() if proj_id in r.endpoint_path), None)
    if not res:
        raise HTTPException(status_code=404, detail="Project not found")

    # Verify tenant isolation
    if res.tenant_id != principal["tenant_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Cross-tenant project access prohibited")

    # Verify user revocation or membership
    if principal["user_id"] in res.is_revoked_for or principal["user_id"] not in res.allowed_user_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: User access to this project has been revoked")

    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload
