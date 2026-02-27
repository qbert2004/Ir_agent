"""Tests for ML attack detector."""

from app.services.ml_detector import MLAttackDetector


def test_detector_init():
    detector = MLAttackDetector(threshold=0.5)
    assert detector.threshold == 0.5
    assert isinstance(detector.suspicious_keywords, list)


def test_heuristic_malicious():
    detector = MLAttackDetector(threshold=0.3)
    event = {
        "event_id": 4688,
        "process_name": "powershell.exe",
        "command_line": "powershell -enc SGVsbG8= invoke-mimikatz -bypass hidden",
        "parent_image": "cmd.exe",
        "channel": "Security",
    }
    is_mal, confidence, reason = detector.predict(event)
    assert is_mal is True
    assert confidence > 0.3
    assert "Heuristic" in reason or "ML" in reason


def test_heuristic_benign(benign_event):
    detector = MLAttackDetector(threshold=0.5)
    is_mal, confidence, reason = detector.predict(benign_event)
    assert is_mal is False
    assert confidence < 0.5


def test_suspicious_keywords():
    detector = MLAttackDetector(threshold=0.3)
    event = {
        "event_id": 4688,
        "process_name": "powershell.exe",
        "command_line": "powershell -enc SGVsbG8= -bypass hidden downloadstring",
        "channel": "Security",
    }
    is_mal, confidence, reason = detector.predict(event)
    assert is_mal is True
    assert confidence > 0.5


def test_empty_event():
    detector = MLAttackDetector(threshold=0.5)
    is_mal, confidence, reason = detector.predict({})
    assert isinstance(is_mal, bool)
    assert 0.0 <= confidence <= 1.0


def test_get_stats():
    detector = MLAttackDetector(threshold=0.5)
    stats = detector.get_stats()
    assert "model_loaded" in stats
    assert "threshold" in stats
