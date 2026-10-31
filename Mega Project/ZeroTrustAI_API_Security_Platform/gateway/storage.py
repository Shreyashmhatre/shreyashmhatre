import json
import time

from sqlalchemy import Column, Float, Integer, MetaData, String, Table, Text, delete, func, select
from sqlalchemy.ext.asyncio import create_async_engine

metadata = MetaData()
events = Table(
    "events",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("timestamp", Float, index=True, nullable=False),
    Column("method", String(16)),
    Column("path", String(300)),
    Column("identity", String(150)),
    Column("action", String(30), index=True),
    Column("risk_score", Integer),
    Column("status_code", Integer),
    Column("inspection_ms", Float),
    Column("total_ms", Float),
    Column("reasons", Text),
    Column("features", Text),
)


class EventStore:
    def __init__(self, url: str):
        self.engine = create_async_engine(url)

    async def start(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def append(self, event: dict):
        row = {
            **event,
            "reasons": json.dumps(event["reasons"]),
            "features": json.dumps(event.get("features", [])),
        }
        async with self.engine.begin() as conn:
            await conn.execute(events.insert().values(**row))

    async def recent(self, limit: int = 100):
        async with self.engine.connect() as conn:
            rows = (
                (
                    await conn.execute(
                        select(events).order_by(events.c.timestamp.desc()).limit(limit)
                    )
                )
                .mappings()
                .all()
            )
        return [
            {**r, "reasons": json.loads(r["reasons"]), "features": json.loads(r["features"])}
            for r in rows
        ]

    async def summary(self):
        cutoff = time.time() - 3600
        async with self.engine.connect() as conn:
            rows = (
                (
                    await conn.execute(
                        select(
                            events.c.action,
                            func.count().label("count"),
                            func.avg(events.c.inspection_ms).label("avg_inspection_ms"),
                        )
                        .where(events.c.timestamp > cutoff, events.c.action != "admin_release")
                        .group_by(events.c.action)
                    )
                )
                .mappings()
                .all()
            )
        counts = {r["action"]: r["count"] for r in rows}
        total = sum(counts.values())
        mean = sum(r["avg_inspection_ms"] * r["count"] for r in rows) / max(total, 1)
        return {
            "requests": total,
            "actions": counts,
            "avg_inspection_ms": round(mean, 3),
            "window_seconds": 3600,
        }

    async def prune(self, retention_days: int):
        async with self.engine.begin() as conn:
            await conn.execute(
                delete(events).where(events.c.timestamp < time.time() - retention_days * 86400)
            )

    async def close(self):
        await self.engine.dispose()
