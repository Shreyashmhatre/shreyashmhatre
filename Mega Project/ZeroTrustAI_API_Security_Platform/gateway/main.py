import asyncio
import contextlib
import json
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from common.auth import check_password, hash_password, issue_token, verify_token
from common.config import Settings
from gateway.detection import AnomalyEngine, evaluate
from gateway.features import extract_features
from gateway.state import MemoryState, RedisState
from gateway.storage import EventStore

logger = logging.getLogger("zerotrustai")
ASSETS = Path(__file__).parent.parent / "dashboard"
HOP_HEADERS = {
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class Release(BaseModel):
    identity: str = Field(min_length=1, max_length=150)


def safe_path(path: str) -> str:
    """Keep audit logs useful without storing user IDs or arbitrary URL secrets."""
    if path in {"/health", "/auth/login", "/products", "/orders", "/admin/users"}:
        return path
    if path.startswith("/orders/"):
        return "/orders/{id}"
    return "/[other]"


async def bounded_body(request: Request, maximum: int) -> bytes:
    result = bytearray()
    async for chunk in request.stream():
        result.extend(chunk)
        if len(result) > maximum:
            raise HTTPException(413, "Request body too large")
    return bytes(result)


def create_app(settings: Settings | None = None, upstream_transport=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        cfg = settings or Settings()
        if cfg.database_url.startswith("sqlite"):
            Path("data").mkdir(exist_ok=True)
        app.state.cfg = cfg
        app.state.store = EventStore(cfg.database_url)
        await app.state.store.start()
        app.state.state = RedisState(cfg.redis_url) if cfg.redis_url else MemoryState()
        if cfg.redis_url:
            await app.state.state.redis.ping()
        else:
            logger.warning("Memory state enabled: use ONE gateway worker only")
        app.state.model = await asyncio.to_thread(AnomalyEngine, cfg.model_path)
        app.state.admin_hash = await asyncio.to_thread(
            hash_password, cfg.admin_password.get_secret_value()
        )
        app.state.client = httpx.AsyncClient(
            transport=upstream_transport,
            timeout=httpx.Timeout(10, connect=2),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

        async def housekeeping():
            while True:
                try:
                    await app.state.store.prune(cfg.event_retention_days)
                except Exception:
                    logger.exception("Event retention cleanup failed")
                await asyncio.sleep(3600)

        cleanup = asyncio.create_task(housekeeping())
        try:
            yield
        finally:
            cleanup.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleanup
            await app.state.client.aclose()
            await app.state.state.close()
            await app.state.store.close()

    app = FastAPI(title="ZeroTrustAI Security Gateway", lifespan=lifespan)
    app.mount("/assets", StaticFiles(directory=ASSETS), name="assets")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # Applies also to admin authentication, before JSON parsing.
        if not request.url.path.startswith("/proxy/") and request.method in {
            "POST",
            "PUT",
            "PATCH",
        }:
            try:
                body = await bounded_body(request, 8192)
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
            request._body = body
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path == "/" or request.url.path.startswith("/assets/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        return response

    def admin(request: Request):
        claims = verify_token(
            request.headers.get("authorization"),
            request.app.state.cfg.jwt_secret.get_secret_value(),
            "zerotrust-admin",
        )
        if claims["role"] != "admin":
            raise HTTPException(403, "Administrator access required")
        return claims

    async def audit(event: dict):
        await app.state.store.append(event)

    @app.get("/")
    async def dashboard():
        return FileResponse(ASSETS / "index.html")

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "gateway"}

    @app.post("/api/admin/login")
    async def login(body: Credentials, request: Request):
        key = "admin-login:" + (request.client.host if request.client else "unknown")
        try:
            window = await app.state.state.observe(key, "/api/admin/login", 10)
        except Exception as exc:
            raise HTTPException(503, "Security state unavailable") from exc
        if window.count > 10:
            raise HTTPException(429, "Login rate limit exceeded", headers={"Retry-After": "60"})
        valid = await asyncio.to_thread(check_password, body.password, app.state.admin_hash)
        valid_user = secrets.compare_digest(
            body.username.encode(), app.state.cfg.admin_username.encode()
        )
        if not valid or not valid_user:
            raise HTTPException(401, "Invalid credentials")
        return {
            "access_token": issue_token(
                app.state.cfg.jwt_secret.get_secret_value(),
                body.username,
                "admin",
                "zerotrust-admin",
            ),
            "token_type": "bearer",
            "expires_in": 900,
        }

    @app.get("/api/summary", dependencies=[Depends(admin)])
    async def summary():
        result = await app.state.store.summary()
        result["model"] = app.state.model.info()
        result["state_backend"] = "redis" if app.state.cfg.redis_url else "memory-single-worker"
        result["step_up_mfa"] = "not-implemented"
        return result

    @app.get("/api/events", dependencies=[Depends(admin)])
    async def recent_events(limit: int = Query(default=100, ge=1, le=500)):
        return await app.state.store.recent(limit)

    @app.get("/api/quarantines", dependencies=[Depends(admin)])
    async def quarantines():
        return await app.state.state.list_quarantines()

    @app.post("/api/quarantines/release")
    async def release(body: Release, user: dict = Depends(admin)):
        await audit(
            {
                "id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "method": "POST",
                "path": "/api/quarantines/release",
                "identity": user["sub"],
                "action": "admin_release",
                "risk_score": 0,
                "status_code": 200,
                "inspection_ms": 0,
                "total_ms": 0,
                "reasons": ["manual_release", body.identity],
                "features": [],
            }
        )
        await app.state.state.release(body.identity)
        return {"released": body.identity}

    @app.get("/api/stream", dependencies=[Depends(admin)])
    async def stream(request: Request, user: dict = Depends(admin)):
        async def generate():
            while not await request.is_disconnected() and time.time() < user["exp"]:
                payload = await app.state.store.summary()
                yield f"event: summary\ndata: {json.dumps(payload)}\n\n"
                await asyncio.sleep(2)

        return StreamingResponse(
            generate(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
        )

    @app.api_route(
        "/proxy/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    )
    async def proxy(request: Request, path: str):
        start = time.perf_counter()
        cfg = app.state.cfg
        event_id = str(uuid.uuid4())
        peer = request.client.host if request.client else "unknown"
        identity = f"ip:{peer}"
        clean_path = "/" + path
        features: list[float] = []
        score, action, reasons = 0, "allow", ["within_policy"]
        inspection_ms = 0.0
        claims = None
        observed = False

        async def finish(response: Response):
            elapsed = (time.perf_counter() - start) * 1000
            try:
                if observed:
                    await app.state.state.record_status(identity, response.status_code)
                await audit(
                    {
                        "id": event_id,
                        "timestamp": time.time(),
                        "method": request.method,
                        "path": safe_path(clean_path),
                        "identity": identity,
                        "action": action,
                        "risk_score": score,
                        "status_code": response.status_code,
                        "inspection_ms": round(inspection_ms or elapsed, 3),
                        "total_ms": round(elapsed, 3),
                        "reasons": reasons,
                        "features": features,
                    }
                )
            except Exception:
                logger.exception("Security state or audit persistence unavailable")
                return JSONResponse(
                    {"detail": "Security audit unavailable", "request_id": event_id},
                    status_code=503,
                )
            response.headers["X-Request-ID"] = event_id
            return response

        try:
            if len(request.scope["query_string"]) + len(path) > 8192:
                raise HTTPException(414, "Request URL too long")
            if "\\" in path or any(p in {".", ".."} for p in path.split("/")) or "//" in path:
                raise HTTPException(400, "Invalid proxy path")
            body = await bounded_body(request, cfg.max_body_bytes)
            public = (request.method, clean_path) in {("POST", "/auth/login"), ("GET", "/health")}
            if not public:
                try:
                    claims = verify_token(
                        request.headers.get("authorization"),
                        cfg.jwt_secret.get_secret_value(),
                        "demo-api",
                    )
                    identity = "user:" + claims["sub"]
                except HTTPException:
                    window = await app.state.state.observe(identity, clean_path, 15)
                    observed = True
                    if window.count > 15:
                        raise HTTPException(429, "Authentication rate limit exceeded") from None
                    raise
            if await app.state.state.quarantined(identity):
                score, action, reasons = 95, "block", ["active_quarantine"]
                return await finish(
                    JSONResponse({"detail": "Identity temporarily quarantined"}, 403)
                )
            limit = (
                min(cfg.requests_per_minute, 10)
                if clean_path == "/auth/login"
                else cfg.requests_per_minute
            )
            window = await app.state.state.observe(identity, clean_path, limit)
            observed = True
            features = extract_features(
                request.method,
                clean_path,
                request.url.query,
                body,
                dict(request.headers),
                window,
                claims,
            )
            anomaly = await asyncio.to_thread(app.state.model.score, features)
            score, action, reasons = evaluate(features, anomaly, limit)
            inspection_ms = (time.perf_counter() - start) * 1000
            if action == "block":
                await app.state.state.quarantine(identity, cfg.quarantine_seconds)
                return await finish(
                    JSONResponse({"detail": "Request blocked by security policy"}, 403)
                )
            if action == "throttle":
                return await finish(
                    JSONResponse(
                        {"detail": "Rate limit exceeded"}, 429, headers={"Retry-After": "60"}
                    )
                )
            connection_headers = {
                h.strip().lower() for h in request.headers.get("connection", "").split(",")
            }
            headers = {
                k: v
                for k, v in request.headers.items()
                if k.lower() not in HOP_HEADERS | connection_headers | {"accept-encoding"}
            }
            headers["accept-encoding"] = "identity"
            headers["x-request-id"] = event_id
            target = httpx.URL(cfg.upstream_url + quote(clean_path, safe="/-._~"))
            target = target.copy_with(query=request.scope["query_string"] or None)
            async with app.state.client.stream(
                request.method, target, headers=headers, content=body
            ) as upstream:
                content = bytearray()
                async for chunk in upstream.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > 2 * 1024 * 1024:
                        raise HTTPException(502, "Upstream response exceeded safety limit")
                if upstream.status_code in {401, 403}:
                    score, action = 90, "deny"
                    reasons = [
                        "backend_authentication_denied"
                        if upstream.status_code == 401
                        else "backend_authorization_denied"
                    ]
                response_hops = {
                    h.strip().lower() for h in upstream.headers.get("connection", "").split(",")
                }
                response_headers = {
                    k: v
                    for k, v in upstream.headers.items()
                    if k.lower()
                    not in HOP_HEADERS | response_hops | {"content-encoding", "set-cookie"}
                }
                response = Response(bytes(content), upstream.status_code, headers=response_headers)
            return await finish(response)
        except HTTPException as exc:
            action, reasons = "deny", [str(exc.detail)]
            score = 90 if exc.status_code in {401, 403} else 50
            return await finish(
                JSONResponse({"detail": exc.detail}, exc.status_code, headers=exc.headers)
            )
        except httpx.HTTPError:
            action, reasons = "error", ["upstream_unavailable"]
            return await finish(JSONResponse({"detail": "Upstream unavailable"}, 502))
        except Exception:
            logger.exception("Security inspection failed")
            action, reasons = "error", ["security_dependency_unavailable"]
            return await finish(JSONResponse({"detail": "Security inspection unavailable"}, 503))

    return app


app = create_app()
