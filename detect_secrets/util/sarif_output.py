"""SARIF 2.1.0 output formatter for detect-secrets.

Converts detect-secrets scan results to SARIF format for integration
with GitHub Code Scanning, GitLab SAST, Azure DevOps, and other
CI platforms that consume SARIF.

This is a utility module, not a plugin detector.

Usage:
    from detect_secrets.util.sarif_output import to_sarif
    sarif = to_sarif(baseline_data, tool_name="detect-secrets-fork")
"""
import json
from datetime import datetime, timezone


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def to_sarif(baseline: dict, tool_name: str = "detect-secrets-fork",
             tool_version: str = "1.5.0") -> dict:
    """Convert detect-secrets baseline JSON to SARIF 2.1.0 format."""
    results_sarif = []
    rules = {}  # dedup rule definitions by secret_type

    for filename, secrets in baseline.get("results", {}).items():
        for secret in secrets:
            secret_type = secret.get("type", "unknown")
            line = secret.get("line_number", 1)

            # Create rule if not exists
            rule_id = secret_type.replace(" ", "_").lower()
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": secret_type,
                    "shortDescription": {"text": f"Detected: {secret_type}"},
                    "defaultConfiguration": {"level": "error"},
                }

            # Create result
            results_sarif.append({
                "ruleId": rule_id,
                "message": {"text": f"Potential {secret_type} detected"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": filename},
                        "region": {"startLine": line}
                    }
                }],
                "level": "error",
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "rules": list(rules.values()),
                }
            },
            "results": results_sarif,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }


def baseline_to_sarif_file(baseline_path: str, output_path: str = None,
                           tool_name: str = "detect-secrets-fork") -> str:
    """Read a baseline and write SARIF file. Returns output path."""
    with open(baseline_path) as f:
        baseline = json.load(f)

    sarif = to_sarif(baseline, tool_name=tool_name)

    if not output_path:
        output_path = baseline_path.replace(".json", ".sarif").replace(".baseline", ".sarif")
        if output_path == baseline_path:
            output_path = baseline_path + ".sarif"

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)

    return output_path
