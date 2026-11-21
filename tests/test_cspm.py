from pathlib import Path
from cspm_audit import scan_tf


def test_vulnerable_vs_hardened():
    root = Path(__file__).parent.parent
    before = scan_tf(root / "terraform/vulnerable/main.tf")
    after = scan_tf(root / "terraform/hardened/main.tf")
    assert all(r["status"] == "FAIL" for r in before)
    assert all(r["status"] == "PASS" for r in after)
