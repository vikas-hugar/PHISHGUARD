import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


@pytest.mark.skipif(not app.ENABLE_DEEP_LEARNING, reason="CNN artifacts unavailable")
def test_cnn_input_alignment():
    for url in ("https://example.org", "https://example.org/" + "a" * app.MAX_LEN):
        tokens = app.tokenizer.texts_to_sequences([url])[0][:app.MAX_LEN]
        expected = tokens + [0] * (app.MAX_LEN - len(tokens))
        assert app.preprocess_url(url)[0].tolist() == expected


def test_failed_transformer_is_excluded_from_quick_scan(monkeypatch):
    monkeypatch.setattr(app, "validate_ssrf", lambda url: {"safe": True})
    monkeypatch.setattr(app, "check_reachability", lambda url: {
        "reachable": True, "status": "REACHABLE", "http_status": 200,
    })
    monkeypatch.setattr(app, "roberta_model", Mock())
    monkeypatch.setattr(app, "roberta_tokenizer", Mock(side_effect=ValueError("tokenization failed")))
    response = app.app.test_client().post("/predict", json={
        "url": "https://example.org/article", "scan_mode": "quick",
    })
    assert response.status_code == 200
    result = response.get_json()
    assert result["roberta_score"] is None
    assert result["roberta"]["executed"] is False
    assert result["roberta"]["error"] == "tokenization failed"
