import httpx
import pytest
import pytest_asyncio

from common.config import Settings
from demo_api.main import create_app as create_demo
from gateway.main import create_app


@pytest.fixture
def settings(tmp_path):
    return Settings(
        _env_file=None,
        jwt_secret="test-secret-" + "a" * 40,
        admin_password="test-admin-password",
        demo_password="test-demo-password",
        database_url=f"sqlite+aiosqlite:///{tmp_path}/events.db",
        model_path=str(tmp_path / "absent.joblib"),
        requests_per_minute=10,
        redis_url="",
        upstream_url="http://demo.test",
    )


@pytest_asyncio.fixture
async def system(settings):
    backend = create_demo(settings)
    gateway = create_app(settings, httpx.ASGITransport(app=backend))
    async with backend.router.lifespan_context(backend), gateway.router.lifespan_context(gateway):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway), base_url="http://test"
        ) as client:
            yield client, gateway


async def demo_login(client, settings, username="alice"):
    response = await client.post(
        "/proxy/auth/login",
        json={
            "username": username,
            "password": settings.demo_password.get_secret_value(),
        },
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


async def admin_login(client, settings):
    response = await client.post(
        "/api/admin/login",
        json={
            "username": "admin",
            "password": settings.admin_password.get_secret_value(),
        },
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}
