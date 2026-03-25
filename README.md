# Prisma AIRS Model Security CI/CD Pipeline

Production-ready GitHub Actions workflow for automated AI/ML model security scanning using Palo Alto Networks Prisma AIRS (AI Runtime Security).

## What This Does

This pipeline scans AI models for security vulnerabilities **before deployment**, implementing MLSecOps best practices to prevent:

- **Backdoor Detection**: Identifies hidden triggers that cause malicious behavior
- **Trojan Analysis**: Detects neural network trojans and poisoned weights
- **Model Poisoning**: Validates model integrity against data poisoning attacks
- **Adversarial Robustness**: Tests resistance to adversarial examples
- **Supply Chain Security**: Verifies model provenance and integrity

**Policy Enforcement**: Models with security violations automatically fail the pipeline - preventing deployment of compromised models.

## Quick Start

### 1. Configure GitHub Secrets and Variables

**Required Secrets** (Settings → Secrets and variables → Actions → Secrets):
- `MODEL_SECURITY_CLIENT_SECRET` - Your Prisma AIRS OAuth2 client secret

**Required Variables** (Settings → Secrets and variables → Actions → Variables):
- `MODEL_SECURITY_CLIENT_ID` - Your Prisma AIRS OAuth2 client ID
- `TSG_ID` - Your Tenant Service Group ID
- `MODEL_SECURITY_API_ENDPOINT` - API endpoint (default: `https://api.sase.paloaltonetworks.com/aims`)

### 2. Run the Workflow

1. Go to **Actions** tab in your repository
2. Select **"Prisma AIRS Model Security Scan"**
3. Click **"Run workflow"**
4. Enter required inputs:
   - **Model URL**: Hugging Face model URL (e.g., `https://huggingface.co/bert-base-uncased`)
   - **Security Profile ID**: Your Prisma AIRS security group UUID
   - **Fail on Severity** (optional): Comma-separated severity levels that trigger failure (default: `CRITICAL,HIGH`)
5. Click **"Run workflow"**

### 3. Review Results

- **Green check**: Model passed all security checks
- **Red X**: Security violations detected - check the scan report artifact
- **Scan Report**: Download from workflow artifacts (`model-scan-report`)

## Configuration Options

### Workflow Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `model_url` | Yes | - | Hugging Face model URL |
| `security_profile_id` | Yes | - | Prisma AIRS security group UUID |
| `fail_on_severity` | No | `CRITICAL,HIGH` | Severities that trigger pipeline failure |

### Environment Variables

Override defaults by setting these as GitHub Variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_SECURITY_API_ENDPOINT` | `https://api.sase.paloaltonetworks.com/aims` | Prisma AIRS API endpoint |
| `MODEL_SECURITY_TOKEN_ENDPOINT` | `https://auth.apps.paloaltonetworks.com/oauth2/access_token` | OAuth2 token endpoint |

## Security Policy

### Default Enforcement

By default, the pipeline **fails** if the scan finds:
- **CRITICAL** severity findings
- **HIGH** severity findings
- Scan outcome is not `PASS`, `CLEAN`, or `SUCCESS`

### Custom Severity Thresholds

Configure per-environment thresholds using the `fail_on_severity` input:

**Production** (strict):
```yaml
fail_on_severity: CRITICAL,HIGH,MEDIUM
```

**Staging** (moderate):
```yaml
fail_on_severity: CRITICAL,HIGH
```

**Development** (permissive):
```yaml
fail_on_severity: CRITICAL
```

### Defense-in-Depth

The pipeline uses two-layer validation:
1. **Primary**: Validates scan outcome status
2. **Secondary**: Deep inspection of individual findings by severity

Both checks must pass for deployment to proceed.

## How to Interpret Results

### Scan Outcomes

| Outcome | Meaning | Pipeline Result |
|---------|---------|-----------------|
| `PASS` / `CLEAN` / `SUCCESS` | No violations found | ✅ Passes |
| `BLOCKED` | Security policy violation | ❌ Fails |
| `WARNING` | Suspicious patterns detected | ❌ Fails |
| `FAILURE` | Scan error or critical issue | ❌ Fails |

### Finding Severities

| Severity | Description | Default Action |
|----------|-------------|----------------|
| **CRITICAL** | Confirmed exploit or backdoor | Fail |
| **HIGH** | Serious security risk | Fail |
| **MEDIUM** | Moderate security concern | Pass (configurable) |
| **LOW** | Minor issue or best practice violation | Pass |
| **INFO** | Informational finding | Pass |

### Scan Report Artifacts

Download the `model-scan-report.json` artifact to see:
- Detailed finding descriptions
- Severity classifications
- Affected model components
- Remediation recommendations

## Troubleshooting

### Authentication Failures

**Error**: `Failed to obtain SCM access token`

**Causes**:
- Invalid `MODEL_SECURITY_CLIENT_ID` or `MODEL_SECURITY_CLIENT_SECRET`
- Incorrect `TSG_ID`
- Network connectivity issues

**Fix**:
1. Verify credentials in Prisma AIRS console
2. Confirm TSG ID matches your tenant
3. Check repository secrets are set correctly

### PyPI Installation Failures

**Error**: `Failed to retrieve PyPI URL`

**Causes**:
- SCM authentication failed
- API endpoint misconfigured

**Fix**:
1. Verify `MODEL_SECURITY_API_ENDPOINT` is set correctly
2. Check SCM token has proper permissions
3. Review `getPYPIurl.sh` output for detailed errors

### Scan Timeouts

**Error**: Workflow exceeds 30-minute timeout

**Causes**:
- Large model files
- Network latency to Hugging Face
- API rate limiting

**Fix**:
1. Use smaller models for testing
2. Contact Palo Alto Networks support for rate limit increases
3. Consider local model scanning instead of remote URLs

### False Positives

**Issue**: Legitimate model flagged as malicious

**Resolution**:
1. Review scan report details
2. Adjust security profile thresholds in Prisma AIRS console
3. Use `fail_on_severity` to temporarily allow MEDIUM/LOW findings
4. Contact PANW support with scan ID for investigation

## Local Development

### Testing the Scan Script

```bash
# Install dependencies
pip install model-security-client tenacity

# Set environment variables
export MODEL_SECURITY_CLIENT_ID="your-client-id"
export MODEL_SECURITY_CLIENT_SECRET="your-client-secret"
export TSG_ID="your-tsg-id"
export MODEL_SECURITY_API_ENDPOINT="https://api.sase.paloaltonetworks.com/aims"
export MODEL_SECURITY_TOKEN_ENDPOINT="https://auth.apps.paloaltonetworks.com/oauth2/access_token"

# Run scan
python model_scan.py \
  --model-path "https://huggingface.co/bert-base-uncased" \
  --security-group-id "your-security-group-uuid" \
  --fail-on-severity "CRITICAL,HIGH"
```

### Testing PyPI Authentication

```bash
# Make script executable
chmod +x getPYPIurl.sh

# Get PyPI URL
./getPYPIurl.sh
```

## Architecture

### Pipeline Stages

1. **Install** - Authenticate to private PyPI and install `model-security-client`
2. **Scan** - Download model, perform security analysis, validate findings
3. **Artifact** - Save scan report for audit trail (runs even on failure)

### Security Design

- **Ephemeral Credentials**: PyPI URLs generated on-demand, never stored
- **Fail-Safe Defaults**: Only explicitly safe outcomes allowed
- **Exit Code Enforcement**: Violations return exit code 1, blocking deployment
- **Artifact Retention**: Scan reports saved for compliance audits
- **HTTPS-Only**: Rejects insecure HTTP model URLs

## Best Practices

### Pre-Commit Scanning

Add this workflow as a required status check for pull requests:

```yaml
on:
  pull_request:
    paths:
      - 'models/**'
      - 'requirements.txt'
```

### Multi-Environment Strategy

Create separate security profiles for each environment:
- **Development**: Permissive (CRITICAL only)
- **Staging**: Moderate (CRITICAL + HIGH)
- **Production**: Strict (CRITICAL + HIGH + MEDIUM)

### Incident Response

When a scan fails:
1. Download the scan report artifact
2. Identify the specific findings
3. Determine if it's a true positive or false positive
4. If true positive: quarantine the model, investigate source
5. If false positive: adjust security profile, create exception

## Support

- **Documentation**: [Prisma AIRS Documentation](https://docs.paloaltonetworks.com/)
- **Issues**: Report bugs or feature requests in this repository
- **Enterprise Support**: Contact Palo Alto Networks support with your TSG ID

## License

This repository is provided as a reference implementation. Modify as needed for your organization's requirements.

---

**Security Note**: This pipeline only prevents deployment of flagged models. Implement runtime monitoring with Prisma AIRS for defense-in-depth protection against zero-day model attacks.

---

## Contact

**Scott Thornton** — AI Security Researcher

- Website: [perfecxion.ai](https://perfecxion.ai/)
- Email: [scott@perfecxion.ai](mailto:scott@perfecxion.ai)
- LinkedIn: [linkedin.com/in/scthornton](https://www.linkedin.com/in/scthornton)
- ORCID: [0009-0008-0491-0032](https://orcid.org/0009-0008-0491-0032)
- GitHub: [@scthornton](https://github.com/scthornton)

**Security Issues**: Please report via [SECURITY.md](SECURITY.md)
