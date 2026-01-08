# test_detection.py
"""Quick tests to verify detection scoring works."""
import sys
sys.path.insert(0, '.')

from detection.state import DetectionState
from detection.scoring import score_event, guess_attack_type
from detection.analytics import severity, leaderboard

def test_endpoint_weights():
    state = DetectionState()
    ip_state = state.get_ip("1.2.3.4")
    
    # Admin probe should score 25
    event = {"path": "/admin", "method": "GET", "ip": "1.2.3.4"}
    delta, tags, guess, _ = score_event(event, ip_state)
    assert delta >= 25, f"Admin should score >=25, got {delta}"
    assert "admin-probe" in tags
    print(f"✓ /admin scores {delta} with tags {tags}")

def test_sqli_detection():
    state = DetectionState()
    ip_state = state.get_ip("5.6.7.8")
    
    event = {
        "path": "/login",
        "method": "POST",
        "ip": "5.6.7.8",
        "body": {"username": "admin' OR 1=1 --", "password": "x"}
    }
    delta, tags, guess, reasons = score_event(event, ip_state)
    assert "sqli" in tags, f"Should detect SQLi, got tags: {tags}"
    assert delta >= 35, f"SQLi + login should score >=35, got {delta}"
    print(f"✓ SQLi detected: score={delta}, tags={tags}")

def test_rce_detection():
    state = DetectionState()
    ip_state = state.get_ip("10.0.0.1")
    
    event = {
        "path": "/api/exec",
        "method": "GET",
        "ip": "10.0.0.1",
        "query_params": {"cmd": "whoami"}
    }
    delta, tags, guess, _ = score_event(event, ip_state)
    assert "rce-attempt" in tags, f"Should detect RCE, got: {tags}"
    print(f"✓ RCE detected: score={delta}, guess={guess}")

def test_severity_thresholds():
    assert severity(0) == "info"
    assert severity(59) == "info"
    assert severity(60) == "warn"
    assert severity(99) == "warn"
    assert severity(100) == "critical"
    assert severity(500) == "critical"
    print("✓ Severity thresholds correct")

def test_leaderboard():
    state = DetectionState()
    
    # Create some attackers with different scores
    for i, (ip, score) in enumerate([
        ("192.168.1.1", 150),
        ("192.168.1.2", 75),
        ("192.168.1.3", 30),
    ]):
        st = state.get_ip(ip)
        st.score = score
        st.attack_type_guess = "test"
    
    board = leaderboard(state, limit=10)
    assert len(board) == 3
    assert board[0]["ip"] == "192.168.1.1"  # Highest score first
    assert board[0]["severity"] == "critical"
    assert board[1]["severity"] == "warn"
    assert board[2]["severity"] == "info"
    print(f"✓ Leaderboard sorted correctly: {[r['ip'] for r in board]}")

def test_attack_type_guess():
    # RCE should take priority
    assert guess_attack_type(["sqli", "rce-attempt"]) == "rce"
    # SSRF next
    assert guess_attack_type(["sqli", "ssrf"]) == "ssrf"
    # Scanner detection
    assert guess_attack_type(["path-sweep", "admin-probe"]) == "automated-scan"
    print("✓ Attack type guessing works")

if __name__ == "__main__":
    print("Running detection tests...\n")
    test_endpoint_weights()
    test_sqli_detection()
    test_rce_detection()
    test_severity_thresholds()
    test_leaderboard()
    test_attack_type_guess()
    print("\n✅ All tests passed!")