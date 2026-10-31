import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from common.auth import check_password, hash_password, issue_token, verify_token
from common.config import Settings


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings or Settings()
        app.state.password_hash = await asyncio.to_thread(
            hash_password, app.state.settings.demo_password.get_secret_value()
        )
        yield

    app = FastAPI(title="ZeroTrustAI Demo API", lifespan=lifespan)
    orders = {
        1: {"id": 1, "owner": "alice", "product": "Sensor kit", "total": 1200},
        2: {"id": 2, "owner": "bob", "product": "Network adapter", "total": 800},
        3: {"id": 3, "owner": "alice", "product": "Microcontroller", "total": 650},
    }

    def identity(request: Request):
        return verify_token(
            request.headers.get("authorization"),
            request.app.state.settings.jwt_secret.get_secret_value(),
            "demo-api",
        )

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "demo-api"}

    @app.post("/auth/login")
    async def login(body: Login, request: Request):
        valid = await asyncio.to_thread(
            check_password, body.password, request.app.state.password_hash
        )
        if not valid or body.username not in {"alice", "bob", "operator"}:
            raise HTTPException(401, "Invalid credentials")
        role = "admin" if body.username == "operator" else "user"
        return {
            "access_token": issue_token(
                request.app.state.settings.jwt_secret.get_secret_value(),
                body.username,
                role,
                "demo-api",
            ),
            "token_type": "bearer",
            "expires_in": 900,
        }

    @app.get("/products")
    async def products(user: dict = Depends(identity)):
        return [{"id": 1, "name": "Sensor kit"}, {"id": 2, "name": "Network adapter"}]

    @app.get("/orders")
    async def list_orders(user: dict = Depends(identity)):
        return [o for o in orders.values() if o["owner"] == user["sub"] or user["role"] == "admin"]

    @app.get("/orders/{order_id}")
    async def get_order(order_id: int, user: dict = Depends(identity)):
        order = orders.get(order_id)
        if not order:
            raise HTTPException(404, "Order not found")
        if order["owner"] != user["sub"] and user["role"] != "admin":
            raise HTTPException(403, "Object access denied")
        return order

    @app.get("/admin/users")
    async def users(user: dict = Depends(identity)):
        if user["role"] != "admin":
            raise HTTPException(403, "Administrator role required")
        return [{"username": name} for name in ["alice", "bob", "operator"]]

    return app


app = create_app()
