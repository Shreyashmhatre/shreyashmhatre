import math
import time
from collections import Counter
from urllib.parse import parse_qsl

from gateway.state import Window

FEATURE_NAMES = [
    "path_length",
    "path_depth",
    "query_length",
    "parameter_count",
    "body_bytes",
    "body_entropy",
    "header_count",
    "header_bytes",
    "is_post",
    "is_write",
    "requests_60s",
    "unique_paths_60s",
    "interarrival_ms",
    "recent_error_ratio",
    "recent_auth_failures",
    "token_age_seconds",
    "is_json",
    "special_char_ratio",
]
SCHEMA_VERSION = 1


def entropy(body: bytes) -> float:
    if not body:
        return 0.0
    return -sum((n / len(body)) * math.log2(n / len(body)) for n in Counter(body).values())


def extract_features(
    method: str,
    path: str,
    query: str,
    body: bytes,
    headers: dict,
    window: Window,
    claims: dict | None,
) -> list[float]:
    safe = {k: v for k, v in headers.items() if k.lower() not in {"authorization", "cookie"}}
    text = path + query
    return [
        len(path),
        len([p for p in path.split("/") if p]),
        len(query),
        len(parse_qsl(query, keep_blank_values=True)),
        len(body),
        entropy(body),
        len(safe),
        sum(len(k) + len(v) for k, v in safe.items()),
        int(method == "POST"),
        int(method in {"POST", "PUT", "PATCH", "DELETE"}),
        window.count,
        window.unique_paths,
        min(window.delta_ms, 60000),
        window.error_ratio,
        window.auth_failures,
        max(0, time.time() - claims["iat"]) if claims else 0,
        int("application/json" in headers.get("content-type", "")),
        sum(not c.isalnum() and c not in "/_-= &" for c in text) / max(1, len(text)),
    ]
