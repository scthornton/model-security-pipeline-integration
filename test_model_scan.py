#!/usr/bin/env python3
"""
Unit tests for model_scan.py
Tests validation logic without requiring API client
"""
import os
import sys
import tempfile
from unittest.mock import patch, MagicMock

# Mock the model_security_client import before importing model_scan
sys.modules['model_security_client'] = MagicMock()
sys.modules['model_security_client.api'] = MagicMock()

# Now we can import model_scan functions
from model_scan import (
    validate_model_uri,
    get_severity_thresholds,
    serialize_scan_results,
    ALLOWED_OUTCOMES,
    DEFAULT_FAIL_SEVERITIES
)


def test_validate_model_uri():
    """Test model URI validation logic."""
    print("Testing model URI validation...")

    # Test HTTPS URL (should pass)
    try:
        result = validate_model_uri("https://huggingface.co/bert-base-uncased")
        assert result == "https://huggingface.co/bert-base-uncased"
        print("  ✅ HTTPS URL validation passed")
    except Exception as e:
        print(f"  ❌ HTTPS URL validation failed: {e}")
        return False

    # Test HTTP URL (should fail)
    try:
        result = validate_model_uri("http://example.com/model.bin")
        print(f"  ❌ HTTP URL should have been rejected but got: {result}")
        return False
    except ValueError as e:
        if "HTTP URLs are not allowed" in str(e):
            print("  ✅ HTTP URL correctly rejected")
        else:
            print(f"  ❌ Wrong error message: {e}")
            return False

    # Test local file (create temp file)
    with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = validate_model_uri(tmp_path)
        assert result.startswith("file://")
        assert tmp_path in result
        print("  ✅ Local file validation passed")
    finally:
        os.unlink(tmp_path)

    # Test non-existent local file (should fail)
    try:
        result = validate_model_uri("/nonexistent/model.bin")
        print(f"  ❌ Nonexistent file should have been rejected but got: {result}")
        return False
    except ValueError as e:
        if "not found" in str(e):
            print("  ✅ Nonexistent file correctly rejected")
        else:
            print(f"  ❌ Wrong error message: {e}")
            return False

    return True


def test_severity_thresholds():
    """Test severity threshold parsing."""
    print("\nTesting severity threshold parsing...")

    # Test default
    with patch.dict(os.environ, {}, clear=False):
        if 'FAIL_ON_SEVERITY' in os.environ:
            del os.environ['FAIL_ON_SEVERITY']
        severities = get_severity_thresholds()
        assert severities == {"CRITICAL", "HIGH"}
        print("  ✅ Default severity thresholds correct")

    # Test custom single severity
    with patch.dict(os.environ, {'FAIL_ON_SEVERITY': 'CRITICAL'}, clear=False):
        severities = get_severity_thresholds()
        assert severities == {"CRITICAL"}
        print("  ✅ Custom single severity correct")

    # Test custom multiple severities
    with patch.dict(os.environ, {'FAIL_ON_SEVERITY': 'CRITICAL,HIGH,MEDIUM'}, clear=False):
        severities = get_severity_thresholds()
        assert severities == {"CRITICAL", "HIGH", "MEDIUM"}
        print("  ✅ Custom multiple severities correct")

    # Test case insensitivity
    with patch.dict(os.environ, {'FAIL_ON_SEVERITY': 'critical,HIGH,Medium'}, clear=False):
        severities = get_severity_thresholds()
        assert severities == {"CRITICAL", "HIGH", "MEDIUM"}
        print("  ✅ Case insensitive parsing correct")

    # Test invalid severity (should be filtered out)
    with patch.dict(os.environ, {'FAIL_ON_SEVERITY': 'CRITICAL,INVALID,HIGH'}, clear=False):
        severities = get_severity_thresholds()
        assert severities == {"CRITICAL", "HIGH"}
        print("  ✅ Invalid severity correctly filtered")

    return True


def test_serialize_scan_results():
    """Test result serialization with different SDK versions."""
    print("\nTesting scan result serialization...")

    # Test with Pydantic v2 model_dump()
    mock_result = MagicMock()
    mock_result.model_dump.return_value = {"status": "pass", "findings": []}
    data = serialize_scan_results(mock_result)
    assert data == {"status": "pass", "findings": []}
    print("  ✅ Pydantic v2 model_dump() serialization passed")

    # Test with Pydantic v1 dict()
    mock_result = MagicMock()
    mock_result.model_dump.side_effect = AttributeError()
    mock_result.dict.return_value = {"status": "pass", "findings": []}
    data = serialize_scan_results(mock_result)
    assert data == {"status": "pass", "findings": []}
    print("  ✅ Pydantic v1 dict() serialization passed")

    # Test with plain __dict__
    mock_result = MagicMock()
    mock_result.model_dump.side_effect = AttributeError()
    mock_result.dict.side_effect = AttributeError()
    mock_result.__dict__ = {"status": "pass", "findings": []}
    data = serialize_scan_results(mock_result)
    assert data == {"status": "pass", "findings": []}
    print("  ✅ Plain __dict__ serialization passed")

    return True


def test_constants():
    """Test that constants are properly defined."""
    print("\nTesting constants...")

    assert ALLOWED_OUTCOMES == {"PASS", "CLEAN", "SUCCESS"}
    print(f"  ✅ ALLOWED_OUTCOMES: {ALLOWED_OUTCOMES}")

    assert DEFAULT_FAIL_SEVERITIES == "CRITICAL,HIGH"
    print(f"  ✅ DEFAULT_FAIL_SEVERITIES: {DEFAULT_FAIL_SEVERITIES}")

    return True


def run_all_tests():
    """Run all tests and report results."""
    print("=" * 60)
    print("Model Scan Script Tests")
    print("=" * 60)

    tests = [
        ("Constants", test_constants),
        ("Model URI Validation", test_validate_model_uri),
        ("Severity Thresholds", test_severity_thresholds),
        ("Result Serialization", test_serialize_scan_results),
    ]

    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print(f"\n  💥 {name} crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    total = len(results)
    passed = sum(1 for _, result in results if result)
    failed = total - passed

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")

    print(f"\nTotal: {passed}/{total} passed")

    if failed > 0:
        print(f"\n❌ {failed} test(s) failed")
        sys.exit(1)
    else:
        print("\n✅ All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    run_all_tests()
