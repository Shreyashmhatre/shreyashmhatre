import stat
from pathlib import Path

from scripts import init_env


def test_secret_initialization_is_private_and_non_destructive(tmp_path, monkeypatch):
    template = Path(__file__).resolve().parent.parent / ".env.example"
    (tmp_path / ".env.example").write_text(template.read_text())
    monkeypatch.setattr(init_env, "ROOT", tmp_path)
    init_env.main()
    env = tmp_path / ".env"
    original = env.read_text()
    assert "replace-with-" not in original
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    init_env.main()
    assert env.read_text() == original
