import json
import math

import pytest
from pydantic import ValidationError

from common.config import Settings
from gateway.detection import AnomalyEngine, evaluate
from gateway.features import FEATURE_NAMES, entropy
from gateway.state import MemoryState
from ml.train import synthetic_benign, train


def test_entropy():
    assert entropy(b"") == 0
    assert entropy(b"aaaaaaaa") == 0
    assert math.isclose(entropy(b"abcd"), 2)


def test_model_training_roundtrip(tmp_path):
    artifact = str(tmp_path / "model.joblib")
    report_path = str(tmp_path / "report.json")
    report = train(None, artifact, report_path)
    engine = AnomalyEngine(artifact)
    assert engine.info()["loaded"]
    assert engine.info()["training_source"] == "synthetic-local-demo-only"
    assert len(FEATURE_NAMES) == 18
    assert 0 <= engine.score(synthetic_benign(1)[0].tolist()) <= 1
    assert json.loads((tmp_path / "report.json").read_text()) == report


def test_ml_alone_does_not_override_authorization_or_auto_block():
    features = synthetic_benign(1)[0].tolist()
    features[10] = 1
    score, action, _ = evaluate(features, 1, 60)
    assert score == 35 and action == "allow"
    features[10] = 61
    assert evaluate(features, 0, 60)[1] == "throttle"
    features[10] = 121
    assert evaluate(features, 0, 60)[1] == "block"


async def test_memory_window_and_quarantine_expiry(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("gateway.state.time.time", lambda: now[0])
    state = MemoryState(capacity=1)
    assert (await state.observe("alice", "/orders", 60)).count == 1
    await state.record_status("alice", 401)
    window = await state.observe("alice", "/products", 60)
    assert window.auth_failures == 1 and window.error_ratio == 1
    assert window.unique_paths == 2
    with pytest.raises(RuntimeError):
        await state.observe("bob", "/orders", 60)
    await state.quarantine("alice", 5)
    assert await state.quarantined("alice")
    now[0] += 61
    assert not await state.quarantined("alice")
    assert (await state.observe("bob", "/orders", 60)).count == 1


def test_reject_insecure_configuration():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret="short", admin_password="short", demo_password="short")
