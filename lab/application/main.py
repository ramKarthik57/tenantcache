"""FastAPI Target Application for Multi-Tenant Lab."""

import posixpath
import urllib.parse
from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel
from typing import Optional, Dict, Any, Tuple
from lab.application.database import lab_db
from tenantcache.models import Role, Visibility

app = FastAPI(
    title="TenantCache Multi-Tenant Lab Target",
    description="Intentionally configurable multi-tenant enterprise API for cache isolation security research.",
    version="1.1.0"
)


class RevocationRequest(BaseModel):
    resource_id: str
    user_id: str


def authenticate_principal(authorization: Optional[str]) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
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


def evaluate_request_authorization(
    clean_path: str,
    method: str,
    principal: Optional[Dict[str, Any]]
) -> Tuple[bool, int, str, Optional[Any]]:
    """Authoritative shared authorization policy engine.
    Synchronously evaluated by BOTH origin route handlers and the Nginx auth_request subrequest verifier.
    Enforces exact route, method, role, and current resource-existence ACL verification.
    Fails closed (401, 403, 404, or 405) for any unauthorized, unmapped, or missing/deleted resource.
    """
    m = method.upper()

    # 1. Reject disallowed HTTP methods
    if m in ("TRACE", "CONNECT"):
        return (False, status.HTTP_403_FORBIDDEN, f"Method '{m}' strictly forbidden", None)

    # 2. Public Endpoints
    if clean_path == "/healthz":
        if m not in ("GET", "HEAD"):
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on /healthz", None)
        return (True, 200, "public", None)

    if clean_path.startswith("/api/v1/public/docs/"):
        if m not in ("GET", "HEAD"):
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on public docs", None)
        doc_id = clean_path.removeprefix("/api/v1/public/docs/")
        # Exact matching: reject empty or multi-segment/partial path components
        if not doc_id or "/" in doc_id:
            return (False, status.HTTP_403_FORBIDDEN, "Invalid document identifier; denied by policy", None)
        # Find exact resource matching this exact endpoint path
        res = next((r for r in lab_db.simulator.resources.values() if r.visibility == Visibility.PUBLIC and r.endpoint_path == clean_path), None)
        if not res:
            return (False, status.HTTP_403_FORBIDDEN, f"Public document '{doc_id}' not found; denied by policy", None)
        return (True, 200, "public", res)

    # All non-public endpoints require an authenticated principal
    if not principal:
        return (False, status.HTTP_401_UNAUTHORIZED, "Bearer token required", None)

    tenant_id = principal["tenant_id"]
    user_id = principal["user_id"]
    username = principal.get("username", "")
    role = principal["role"]

    # 3. User Private Profile
    if clean_path == "/api/v1/user/profile":
        if m not in ("GET", "HEAD"):
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on /user/profile", None)
        res_id = f"res_{username}_profile"
        res = lab_db.get_resource(res_id)
        if not res or res.endpoint_path != clean_path:
            return (False, status.HTTP_404_NOT_FOUND, "Profile not found", None)
        if user_id not in res.allowed_user_ids or res.owner_id != user_id or res.tenant_id != tenant_id:
            return (False, status.HTTP_403_FORBIDDEN, "Access denied: profile owner mismatch", None)
        return (True, 200, "authorized", res)

    # 4. Tenant Dashboard (Exact Canonical Resource ID Resolution - No Fallback)
    if clean_path == "/api/v1/tenant/dashboard":
        if m not in ("GET", "HEAD"):
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on /tenant/dashboard", None)
        if tenant_id not in [t.id for t in lab_db.simulator.tenants.values()]:
            return (False, status.HTTP_403_FORBIDDEN, "Unknown or evicted tenant membership", None)
        res_id = f"res_{tenant_id.replace('tenant_', '')}_dashboard"
        res = lab_db.get_resource(res_id)
        if not res or res.endpoint_path != clean_path:
            return (False, status.HTTP_404_NOT_FOUND, f"No dashboard for tenant {tenant_id}", None)
        if res.tenant_id != tenant_id:
            return (False, status.HTTP_403_FORBIDDEN, "Tenant mismatch", None)
        return (True, 200, "authorized", res)

    # 5. Tenant Reports
    if clean_path == "/api/v1/tenant/reports":
        if m not in ("GET", "HEAD"):
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on /tenant/reports", None)
        if tenant_id not in [t.id for t in lab_db.simulator.tenants.values()]:
            return (False, status.HTTP_403_FORBIDDEN, "Unknown or evicted tenant membership", None)
        return (True, 200, "authorized", None)

    # 6. Admin Audit Logs
    if clean_path == "/api/v1/admin/audit-logs":
        if m not in ("GET", "HEAD"):
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on /admin/audit-logs", None)
        if role != Role.ADMIN.value:
            return (False, status.HTTP_403_FORBIDDEN, "Admin role required", None)
        res_id = f"res_{tenant_id.replace('tenant_', '')}_admin_logs"
        res = lab_db.get_resource(res_id)
        if not res or res.endpoint_path != clean_path:
            return (False, status.HTTP_404_NOT_FOUND, f"No audit logs for tenant {tenant_id}", None)
        if res.tenant_id != tenant_id:
            return (False, status.HTTP_403_FORBIDDEN, "Access denied: Tenant mismatch", None)
        return (True, 200, "authorized", res)

    # 7. Tenant Invoices (Exact Resource Matching)
    if clean_path.startswith("/api/v1/tenant/invoices/"):
        if m not in ("GET", "HEAD"):
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on invoices", None)
        invoice_id = clean_path.removeprefix("/api/v1/tenant/invoices/")
        if not invoice_id or "/" in invoice_id:
            return (False, status.HTTP_404_NOT_FOUND, "Invalid invoice identifier", None)
        res = next((r for r in lab_db.simulator.resources.values() if r.endpoint_path == clean_path), None)
        if not res:
            return (False, status.HTTP_404_NOT_FOUND, "Invoice not found", None)
        if res.tenant_id != tenant_id:
            return (False, status.HTTP_403_FORBIDDEN, "Cross-tenant invoice access forbidden", None)
        return (True, 200, "authorized", res)

    # 8. Shared Projects (Exact Resource Matching)
    if clean_path.startswith("/api/v1/shared/projects/"):
        if m not in ("GET", "HEAD"):
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on projects", None)
        proj_id = clean_path.removeprefix("/api/v1/shared/projects/")
        if not proj_id or "/" in proj_id:
            return (False, status.HTTP_404_NOT_FOUND, "Invalid project identifier", None)
        res = next((r for r in lab_db.simulator.resources.values() if r.endpoint_path == clean_path), None)
        if not res:
            return (False, status.HTTP_404_NOT_FOUND, "Project not found", None)
        if res.tenant_id != tenant_id:
            return (False, status.HTTP_403_FORBIDDEN, "Cross-tenant access forbidden", None)
        if user_id in res.is_revoked_for or user_id not in res.allowed_user_ids:
            return (False, status.HTTP_403_FORBIDDEN, "Access revoked", None)
        return (True, 200, "authorized", res)

    # 9. Admin Mutation POST Endpoints
    admin_post_routes = (
        "/api/v1/admin/revoke-access",
        "/api/v1/admin/revoke-token",
        "/api/v1/admin/expire-token",
        "/api/v1/admin/downgrade-role",
        "/api/v1/admin/evict-tenant-member",
        "/api/v1/admin/delete-resource"
    )
    if clean_path in admin_post_routes:
        if m != "POST":
            return (False, status.HTTP_405_METHOD_NOT_ALLOWED, f"Method '{m}' not allowed on mutation endpoint", None)
        if role != Role.ADMIN.value:
            return (False, status.HTTP_403_FORBIDDEN, "Admin role required", None)
        return (True, 200, "authorized", None)

    # STRICT FAIL-CLOSED (DENY BY DEFAULT): Any unmapped, non-existent, or undeclared route
    return (False, status.HTTP_403_FORBIDDEN, f"Route '{clean_path}' not declared in authoritative policy registry", None)


@app.api_route("/api/v1/auth/verify", methods=["GET", "HEAD"])
def verify_authorization(
    request: Request,
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """Authorization verification subrequest endpoint for Nginx auth_request module.
    Evaluates current token validity, tenant affiliation, role permissions, exact routes,
    and authoritative resource existence via evaluate_request_authorization.
    Fails closed (401 or 403) for any unauthorized, unmapped, or missing/deleted resource.
    """
    orig_method = request.headers.get("x-original-method", request.method).upper()
    raw_uri = request.headers.get("x-original-uri") or request.query_params.get("uri") or ""
    raw_path = raw_uri.split("?")[0]
    clean_path = posixpath.normpath(urllib.parse.unquote(raw_path))

    # Authenticate token if provided
    principal = None
    if authorization:
        principal = authenticate_principal(authorization)

    allowed, code, reason, _ = evaluate_request_authorization(clean_path, orig_method, principal)
    if not allowed:
        # Nginx ngx_http_auth_request_module expects 401 for unauthorized or 403 for forbidden.
        # Any other code (such as 404 or 405) causes Nginx to return 500 Internal Server Error.
        auth_code = status.HTTP_401_UNAUTHORIZED if code == status.HTTP_401_UNAUTHORIZED else status.HTTP_403_FORBIDDEN
        raise HTTPException(status_code=auth_code, detail=reason)

    if principal:
        response.headers["X-Auth-Tenant-ID"] = principal["tenant_id"]
        response.headers["X-Auth-User-ID"] = principal["user_id"]
        return {"status": "authorized", "tenant_id": principal["tenant_id"], "user_id": principal["user_id"]}
    else:
        response.headers["X-Auth-Tenant-ID"] = "public"
        response.headers["X-Auth-User-ID"] = "public"
        return {"status": "authorized", "scope": "public"}


@app.api_route("/healthz", methods=["GET", "HEAD"])
def health_check(request: Request):
    allowed, code, detail, _ = evaluate_request_authorization("/healthz", request.method, None)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    return {"status": "ok", "app": "TenantCache Multi-Tenant Lab Target"}


@app.post("/api/v1/lab/reset")
def reset_lab_state(
    request: Request,
    x_test_control: Optional[str] = Header(None, alias="X-TenantCache-Test-Control")
):
    """Isolated test harness control endpoint.
    Strictly forbidden unless called with the internal test control authorization header.
    Never exposed through the user-facing proxy verifier.
    """
    if x_test_control != "TC_LOCAL_TEST_CONTROL":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Lab reset restricted to authorized local test harness"
        )
    lab_db.reset()
    return {"status": "reset_successful", "message": "Database and fixtures restored to seed state"}


class TokenRevocationRequest(BaseModel):
    token: str


@app.post("/api/v1/admin/revoke-token")
def revoke_user_token(
    req: TokenRevocationRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    principal = authenticate_principal(authorization)
    allowed, code, detail, _ = evaluate_request_authorization("/api/v1/admin/revoke-token", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    lab_db.revoked_tokens.add(req.token)
    return {"status": "token_revoked", "token": req.token}


@app.post("/api/v1/admin/revoke-access")
def revoke_user_access(
    req: RevocationRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    principal = authenticate_principal(authorization)
    allowed, code, detail, _ = evaluate_request_authorization("/api/v1/admin/revoke-access", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    
    lab_db.revoke_user_access(req.resource_id, req.user_id)
    return {
        "status": "revoked",
        "resource_id": req.resource_id,
        "revoked_user_id": req.user_id
    }


class RoleUpdateRequest(BaseModel):
    user_id: str
    new_role: str


class EvictMemberRequest(BaseModel):
    user_id: str


class DeleteResourceRequest(BaseModel):
    resource_id: str


@app.post("/api/v1/admin/expire-token")
def expire_user_token(
    req: TokenRevocationRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    principal = authenticate_principal(authorization)
    allowed, code, detail, _ = evaluate_request_authorization("/api/v1/admin/expire-token", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    lab_db.expire_token(req.token)
    return {"status": "token_expired", "token": req.token}


@app.post("/api/v1/admin/downgrade-role")
def downgrade_user_role(
    req: RoleUpdateRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    principal = authenticate_principal(authorization)
    allowed, code, detail, _ = evaluate_request_authorization("/api/v1/admin/downgrade-role", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    new_r = Role(req.new_role)
    lab_db.update_role(req.user_id, new_r)
    return {"status": "role_updated", "user_id": req.user_id, "new_role": req.new_role}


@app.post("/api/v1/admin/evict-tenant-member")
def evict_tenant_member(
    req: EvictMemberRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    principal = authenticate_principal(authorization)
    allowed, code, detail, _ = evaluate_request_authorization("/api/v1/admin/evict-tenant-member", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    lab_db.remove_tenant_member(req.user_id)
    return {"status": "member_evicted", "user_id": req.user_id}


@app.post("/api/v1/admin/delete-resource")
def delete_application_resource(
    req: DeleteResourceRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    principal = authenticate_principal(authorization)
    allowed, code, detail, _ = evaluate_request_authorization("/api/v1/admin/delete-resource", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    lab_db.delete_resource(req.resource_id)
    return {"status": "resource_deleted", "resource_id": req.resource_id}


@app.api_route("/api/v1/public/docs/{doc_id}", methods=["GET", "HEAD"])
def get_public_document(doc_id: str, request: Request, response: Response):
    """Public guidelines and terms endpoint - legitimately shared across tenants."""
    clean_path = f"/api/v1/public/docs/{doc_id}"
    allowed, code, detail, res = evaluate_request_authorization(clean_path, request.method, None)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    response.headers["Cache-Control"] = "public, max-age=3600"
    return res.payload


@app.api_route("/api/v1/tenant/dashboard", methods=["GET", "HEAD"])
def get_tenant_dashboard(
    request: Request,
    response: Response,
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """Tenant dashboard endpoint: confidential per tenant."""
    principal = authenticate_principal(authorization)
    allowed, code, detail, res = evaluate_request_authorization("/api/v1/tenant/dashboard", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)
    
    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.api_route("/api/v1/tenant/invoices/{invoice_id}", methods=["GET", "HEAD"])
def get_tenant_invoice(
    invoice_id: str,
    request: Request,
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """Tenant invoices endpoint."""
    principal = authenticate_principal(authorization)
    clean_path = f"/api/v1/tenant/invoices/{invoice_id}"
    allowed, code, detail, res = evaluate_request_authorization(clean_path, request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)

    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.api_route("/api/v1/user/profile", methods=["GET", "HEAD"])
def get_user_profile(
    request: Request,
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """User private profile."""
    principal = authenticate_principal(authorization)
    allowed, code, detail, res = evaluate_request_authorization("/api/v1/user/profile", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)

    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.api_route("/api/v1/admin/audit-logs", methods=["GET", "HEAD"])
def get_admin_audit_logs(
    request: Request,
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """Admin only audit logs."""
    principal = authenticate_principal(authorization)
    allowed, code, detail, res = evaluate_request_authorization("/api/v1/admin/audit-logs", request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)

    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.api_route("/api/v1/shared/projects/{proj_id}", methods=["GET", "HEAD"])
def get_shared_project(
    proj_id: str,
    request: Request,
    response: Response,
    authorization: Optional[str] = Header(None)
):
    """Shared project endpoint with dynamic access control and revocation."""
    principal = authenticate_principal(authorization)
    clean_path = f"/api/v1/shared/projects/{proj_id}"
    allowed, code, detail, res = evaluate_request_authorization(clean_path, request.method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)

    response.headers["Cache-Control"] = "private, max-age=300"
    return res.payload


@app.api_route("/api/v1/tenant/reports", methods=["GET", "HEAD"])
def get_tenant_report(
    scope: str = "summary",
    request: Request = None,
    response: Response = None,
    authorization: Optional[str] = Header(None)
):
    """Query-sensitive endpoint where the response representation and confidentiality level
    genuinely diverge based on query parameters.
    """
    principal = authenticate_principal(authorization)
    method = request.method if request else "GET"
    allowed, code, detail, _ = evaluate_request_authorization("/api/v1/tenant/reports", method, principal)
    if not allowed:
        raise HTTPException(status_code=code, detail=detail)

    tenant_id = principal["tenant_id"]
    scope_canary = f"TC_REPORT_{tenant_id.upper()}_{scope.upper()}_{principal['username'].upper()}"

    if response:
        response.headers["Cache-Control"] = "private, max-age=300"

    return {
        "tenant_id": tenant_id,
        "requested_scope": scope,
        "report_canary": scope_canary,
        "payload": f"Confidential {scope} report data for {tenant_id}"
    }
