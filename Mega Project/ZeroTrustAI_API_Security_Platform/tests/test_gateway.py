import asyncio
import time

import httpx
import jwt

from common.auth import ISSUER, issue_token
from gateway.main import create_app
from tests.conftest import admin_login, demo_login


async def test_dashboard_and_security_headers(system):
    client, _ = system
    response = await client.get("/")
    assert response.status_code == 200
    assert "Your API. Under watch." in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert (await client.get("/assets/app.js")).status_code == 200


async def test_authentication_and_audience_boundaries(system, settings):
    client, _ = system
    assert (await client.get("/proxy/orders")).status_code == 401
    auth = await demo_login(client, settings)
    assert (await client.get("/proxy/products", headers=auth)).status_code == 200
    assert (await client.get("/api/events", headers=auth)).status_code == 401
    admin = await admin_login(client, settings)
    assert (await client.get("/proxy/orders", headers=admin)).status_code == 401
    operator = await demo_login(client, settings, "operator")
    assert (await client.get("/api/events", headers=operator)).status_code == 401
    assert (await client.get("/api/events")).status_code == 401


async def test_expired_wrong_issuer_and_forged_tokens(system, settings):
    client, _ = system
    for issuer, expiry, secret in [
        (ISSUER, time.time() - 1, settings.jwt_secret.get_secret_value()),
        ("wrong-issuer", time.time() + 100, settings.jwt_secret.get_secret_value()),
        (ISSUER, time.time() + 100, "wrong-secret" * 4),
    ]:
        token = jwt.encode(
            {
                "sub": "alice",
                "role": "user",
                "iss": issuer,
                "aud": "demo-api",
                "iat": time.time() - 100,
                "exp": expiry,
                "jti": "test",
            },
            secret,
            algorithm="HS256",
        )
        assert (
            await client.get("/proxy/orders", headers={"Authorization": "Bearer " + token})
        ).status_code == 401


async def test_bola_and_role_enforcement_are_logged(system, settings):
    client, _ = system
    auth = await demo_login(client, settings)
    assert (await client.get("/proxy/orders/1", headers=auth)).status_code == 200
    assert (await client.get("/proxy/orders/2", headers=auth)).status_code == 403
    assert (await client.get("/proxy/admin/users", headers=auth)).status_code == 403
    admin = await admin_login(client, settings)
    rows = (await client.get("/api/events", headers=admin)).json()
    denied = [r for r in rows if r["action"] == "deny"]
    assert len(denied) == 2
    assert all("backend_authorization_denied" in r["reasons"] for r in denied)
    assert "/orders/{id}" in [r["path"] for r in denied]
    operator = await demo_login(client, settings, "operator")
    assert (await client.get("/proxy/admin/users", headers=operator)).status_code == 200


async def test_rate_limit_quarantine_and_audited_release(system, settings):
    client, _ = system
    auth = await demo_login(client, settings)
    statuses = []
    for _ in range(22):
        response = await client.get("/proxy/products", headers=auth)
        statuses.append(response.status_code)
        if response.status_code == 429:
            assert response.headers["retry-after"] == "60"
    assert statuses[:10] == [200] * 10
    assert 429 in statuses and statuses[-1] == 403
    admin = await admin_login(client, settings)
    items = (await client.get("/api/quarantines", headers=admin)).json()
    assert items[0]["identity"] == "user:alice"
    assert (
        await client.post("/api/quarantines/release", json={"identity": "user:alice"})
    ).status_code == 401
    assert (
        await client.post(
            "/api/quarantines/release", json={"identity": "user:alice"}, headers=admin
        )
    ).status_code == 200
    assert (await client.get("/api/quarantines", headers=admin)).json() == []
    rows = (await client.get("/api/events", headers=admin)).json()
    assert any(r["action"] == "admin_release" for r in rows)


async def test_tokens_and_forwarded_ip_cannot_reset_identity_window(system, settings):
    client, _ = system
    for i in range(11):
        token = issue_token(settings.jwt_secret.get_secret_value(), "alice", "user", "demo-api")
        response = await client.get(
            "/proxy/products",
            headers={
                "Authorization": "Bearer " + token,
                "X-Forwarded-For": f"10.0.0.{i}",
            },
        )
    assert response.status_code == 429


async def test_body_limit_and_path_validation(system, settings):
    client, _ = system
    response = await client.post("/proxy/auth/login", content=b"x" * (settings.max_body_bytes + 1))
    assert response.status_code == 413
    response = await client.post("/api/admin/login", content=b"x" * 9000)
    assert response.status_code == 413
    auth = await demo_login(client, settings)
    assert (await client.get("/proxy/%2e%2e/health", headers=auth)).status_code == 400
    assert (await client.get("/proxy/%5cother", headers=auth)).status_code == 400


async def test_redaction_features_and_summary(system, settings):
    client, _ = system
    auth = await demo_login(client, settings)
    await client.get("/proxy/products?secret=do-not-persist", headers=auth)
    admin = await admin_login(client, settings)
    response = await client.get("/api/events", headers=admin)
    assert "do-not-persist" not in response.text
    assert settings.demo_password.get_secret_value() not in response.text
    assert auth["Authorization"] not in response.text
    assert all(len(row["features"]) == 18 for row in response.json())
    summary = (await client.get("/api/summary", headers=admin)).json()
    assert summary["requests"] == 2
    assert summary["model"]["mode"] == "rules-only"
    assert summary["step_up_mfa"] == "not-implemented"


async def test_login_limits_and_unicode_username(system, settings):
    client, _ = system
    for _ in range(10):
        response = await client.post(
            "/api/admin/login", json={"username": "未知", "password": "bad"}
        )
        assert response.status_code == 401
    assert (
        await client.post("/api/admin/login", json={"username": "admin", "password": "bad"})
    ).status_code == 429


async def test_upstream_failure_and_no_open_proxy(settings):
    targets = []

    async def broken(request):
        targets.append(str(request.url))
        raise httpx.ConnectError("offline")

    gateway = create_app(settings, httpx.MockTransport(broken))
    async with gateway.router.lifespan_context(gateway):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway), base_url="http://test"
        ) as client:
            token = issue_token(settings.jwt_secret.get_secret_value(), "alice", "user", "demo-api")
            response = await client.get(
                "/proxy/https://external.example/orders",
                headers={"Authorization": "Bearer " + token},
            )
            assert response.status_code == 400
            response = await client.get(
                "/proxy/products", headers={"Authorization": "Bearer " + token}
            )
            assert response.status_code == 502
            assert targets == ["http://demo.test/products"]


async def test_security_state_failure_does_not_forward(system, settings, monkeypatch):
    client, gateway = system
    auth = await demo_login(client, settings)

    async def unavailable(*args):
        raise RuntimeError("simulated Redis failure")

    monkeypatch.setattr(gateway.state.state, "observe", unavailable)
    response = await client.get("/proxy/products", headers=auth)
    assert response.status_code == 503


async def test_concurrent_rate_limit_is_atomic(system, settings):
    client, _ = system
    auth = await demo_login(client, settings)
    responses = await asyncio.gather(
        *[client.get("/proxy/products", headers=auth) for _ in range(15)]
    )
    assert sum(r.status_code == 200 for r in responses) == 10
    assert sum(r.status_code == 429 for r in responses) == 5
