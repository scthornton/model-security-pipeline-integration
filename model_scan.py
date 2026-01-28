#!/usr/bin/env python3
"""
Prisma AIRS Model Security Scanner
Production-grade CI/CD integration for AI/ML model security scanning.
"""
import os
import sys
import argparse
import json
from typing import Dict, Any, Set
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from model_security_client.api import ModelSecurityAPIClient

# Constants for policy enforcement
ALLOWED_OUTCOMES: Set[str] = {"PASS", "CLEAN", "SUCCESS"}
DEFAULT_FAIL_SEVERITIES: str = "CRITICAL,HIGH"

# Exit codes
EXIT_SUCCESS = 0
EXIT_SECURITY_VIOLATION = 1
EXIT_ERROR = 2


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for model path and security group ID."""
    parser = argparse.ArgumentParser(
        description="Prisma AIRS Model Security Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan Hugging Face model
  python model_scan.py --model-path https://huggingface.co/bert-base-uncased --security-group-id <uuid>

  # Scan local model file
  python model_scan.py --model-path ./models/my_model.safetensors --security-group-id <uuid>

  # Custom severity thresholds (via environment)
  export FAIL_ON_SEVERITY="CRITICAL,HIGH,MEDIUM"
  python model_scan.py --model-path <path> --security-group-id <uuid>
        """
    )

    parser.add_argument(
        "--model-path",
        required=True,
        help="Path to model artifact (local file path or HTTPS URL)"
    )

    parser.add_argument(
        "--security-group-id",
        required=True,
        help="UUID of the Prisma AIRS security group"
    )

    return parser.parse_args()


def validate_model_uri(model_path: str) -> str:
    """
    Validates and converts model path to proper URI format.

    Args:
        model_path: Raw model path from user input

    Returns:
        Properly formatted model URI

    Raises:
        ValueError: If model_path uses insecure HTTP or invalid format
    """
    # Remote URL validation
    if model_path.startswith("https://"):
        print(f"   Target: Remote URL ({model_path})")
        return model_path

    # Reject insecure HTTP - prevents downgrade attacks
    if model_path.startswith("http://"):
        raise ValueError(
            "HTTP URLs are not allowed for security reasons. "
            "Use HTTPS instead (Hugging Face models are HTTPS-only)."
        )

    # Local file path - convert to file:// URI
    abs_path = os.path.abspath(model_path)
    if not os.path.exists(abs_path):
        raise ValueError(f"Local model file not found: {abs_path}")

    print(f"   Target: Local File ({abs_path})")
    return f"file://{abs_path}"


def get_severity_thresholds() -> Set[str]:
    """
    Retrieves severity thresholds from environment or uses defaults.

    Returns:
        Set of severity levels that trigger pipeline failure
    """
    severity_str = os.getenv("FAIL_ON_SEVERITY", DEFAULT_FAIL_SEVERITIES)
    severities = {s.strip().upper() for s in severity_str.split(",")}

    # Validate severity levels
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    invalid = severities - valid_severities
    if invalid:
        print(f"⚠️  Warning: Invalid severity levels ignored: {invalid}")
        severities = severities & valid_severities

    print(f"   Fail on Severities: {', '.join(sorted(severities))}")
    return severities


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type((ConnectionError, TimeoutError)),
    reraise=True
)
def perform_scan_with_retry(
    client: ModelSecurityAPIClient,
    security_group_id: str,
    model_uri: str
) -> Any:
    """
    Performs model scan with automatic retry on transient failures.

    Args:
        client: Initialized ModelSecurityAPIClient
        security_group_id: Security group UUID
        model_uri: Model URI (file:// or https://)

    Returns:
        Scan result object from API

    Raises:
        ConnectionError, TimeoutError: On persistent network failures (after retries)
    """
    print("   Initiating scan (with automatic retry on transient failures)...")
    return client.scan(
        security_group_uuid=security_group_id,
        model_uri=model_uri
    )


def serialize_scan_results(result: Any) -> Dict[str, Any]:
    """
    Safely converts scan result object to dictionary.

    Args:
        result: Scan result object from API

    Returns:
        Dictionary representation of scan results
    """
    try:
        # Try Pydantic v2 model_dump() first
        return result.model_dump()
    except AttributeError:
        try:
            # Fall back to Pydantic v1 dict()
            return result.dict()
        except AttributeError:
            # Last resort: direct __dict__ access
            return result.__dict__


def save_scan_report(data_dict: Dict[str, Any], filename: str = "model_scan_report.json") -> None:
    """
    Saves scan results as JSON artifact for CI/CD retention.

    Args:
        data_dict: Scan results as dictionary
        filename: Output filename
    """
    with open(filename, 'w') as f:
        json.dump(data_dict, f, indent=4, default=str)
    print(f"   Report saved to '{filename}'")


def evaluate_scan_outcome(
    result: Any,
    data_dict: Dict[str, Any],
    fail_severities: Set[str]
) -> bool:
    """
    Evaluates scan results against security policy.

    Args:
        result: Raw scan result object
        data_dict: Serialized scan results
        fail_severities: Set of severity levels that trigger failure

    Returns:
        True if policy violated (should fail), False if passed
    """
    policy_violated = False

    # Check 1: Validate high-level scan outcome
    outcome_str = str(result.eval_outcome).upper()
    print(f"\n🏁 Scan Status: {outcome_str}")

    if outcome_str not in ALLOWED_OUTCOMES:
        print(f"⚠️  VIOLATION: Outcome '{outcome_str}' not in allowed set: {ALLOWED_OUTCOMES}")
        policy_violated = True

    # Check 2: Deep inspection of individual findings
    findings = data_dict.get("findings", [])
    if findings:
        print(f"\n🔍 Detailed Findings ({len(findings)} total):")

        violation_count = 0
        for finding in findings:
            severity = str(finding.get('severity', 'UNKNOWN')).upper()
            category = finding.get('category', 'Generic')
            description = finding.get('description', 'No description')

            # Check if this severity level should trigger failure
            triggers_failure = severity in fail_severities
            marker = "❌" if triggers_failure else "ℹ️"

            print(f"   {marker} [{severity}] {category}")
            if triggers_failure:
                print(f"      └─ {description[:100]}{'...' if len(description) > 100 else ''}")
                policy_violated = True
                violation_count += 1

        if violation_count > 0:
            print(f"\n⚠️  Found {violation_count} finding(s) matching failure criteria")
    else:
        print("\n✅ No security findings detected")

    return policy_violated


def run_model_scan(model_path: str, security_group_id: str) -> int:
    """
    Main orchestration function for model security scanning.

    Args:
        model_path: Path to model (local or remote)
        security_group_id: Security group UUID

    Returns:
        Exit code (0=success, 1=security violation, 2=error)
    """
    try:
        # Initialize configuration
        base_url = os.getenv(
            "MODEL_SECURITY_API_ENDPOINT",
            "https://api.sase.paloaltonetworks.com/aims"
        )
        fail_severities = get_severity_thresholds()

        print(f"🚀 Initializing Prisma AIRS Scanner")
        print(f"   Endpoint: {base_url}")
        print(f"   Profile UUID: {security_group_id}")

        # Validate and prepare model URI
        final_model_uri = validate_model_uri(model_path)

        # Initialize API client
        client = ModelSecurityAPIClient(base_url=base_url)

        # Perform scan with automatic retry
        result = perform_scan_with_retry(client, security_group_id, final_model_uri)

        # Serialize and save results
        data_dict = serialize_scan_results(result)
        save_scan_report(data_dict)

        # Evaluate against security policy
        policy_violated = evaluate_scan_outcome(result, data_dict, fail_severities)

        # Determine final status
        if policy_violated:
            print("\n⛔ SCAN FAILED: Security violations detected")
            print("   Pipeline halted to prevent deployment of vulnerable model")
            print("   Review 'model_scan_report.json' artifact for detailed findings")
            return EXIT_SECURITY_VIOLATION
        else:
            print("\n✅ SCAN PASSED: Model meets security requirements")
            print("   No violations found - safe to proceed with deployment")
            return EXIT_SUCCESS

    except ValueError as e:
        # Configuration or validation errors
        print(f"\n❌ CONFIGURATION ERROR: {e}")
        print("   Fix the error and retry the scan")
        return EXIT_ERROR

    except Exception as e:
        # Unexpected errors (API failures, network issues, etc.)
        print(f"\n💥 CRITICAL ERROR: {e}")
        print("   Check connectivity, credentials, and API endpoint")

        # Print full traceback for debugging
        import traceback
        traceback.print_exc()

        return EXIT_ERROR


def main() -> None:
    """Entry point for CLI execution."""
    args = parse_arguments()
    exit_code = run_model_scan(args.model_path, args.security_group_id)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
