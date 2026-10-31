from pathlib import Path

import joblib
import numpy as np

from gateway.features import FEATURE_NAMES, SCHEMA_VERSION


class AnomalyEngine:
    def __init__(self, path: str):
        self.artifact = None
        if Path(path).is_file():
            # Joblib can execute code: load ONLY artifacts trained by this installation.
            artifact = joblib.load(path)
            if artifact["features"] != FEATURE_NAMES or artifact["schema"] != SCHEMA_VERSION:
                raise ValueError("Model feature schema does not match gateway")
            self.artifact = artifact

    def score(self, features: list[float]) -> float:
        if self.artifact is None:
            return 0.0
        raw = -float(self.artifact["model"].score_samples(np.array([features]))[0])
        threshold = self.artifact["threshold"]
        width = max(0.02, threshold - self.artifact["median"])
        return float(np.clip((raw - threshold) / width, 0, 1))

    def info(self):
        if self.artifact is None:
            return {"loaded": False, "mode": "rules-only", "version": None}
        return {
            "loaded": True,
            "mode": "rules+isolation-forest",
            "version": self.artifact["version"],
            "training_source": self.artifact["source"],
        }


def evaluate(features: list[float], anomaly: float, limit: int) -> tuple[int, str, list[str]]:
    values = dict(zip(FEATURE_NAMES, features, strict=True))
    score = round(35 * anomaly)
    reasons = ["ml_anomaly"] if anomaly > 0 else []
    count = values["requests_60s"]
    if count > limit * 2:
        return 90, "block", [*reasons, "sustained_rate_abuse"]
    if count > limit:
        return max(score, 65), "throttle", [*reasons, "rate_limit_exceeded"]
    if values["recent_auth_failures"] >= 5:
        score += 40
        reasons.append("repeated_authentication_failures")
    if values["unique_paths_60s"] > 20:
        score += 35
        reasons.append("resource_enumeration")
    if values["query_length"] > 2000 or values["parameter_count"] > 40:
        score += 35
        reasons.append("unusual_query_shape")
    score = min(score, 100)
    if score >= 71:
        return score, "block", reasons
    if score >= 31 and count > limit // 2:
        return score, "throttle", reasons
    # No simulated MFA: medium risk is observed or rate limited in this release.
    return score, "allow", reasons or ["within_policy"]
