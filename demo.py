#!/usr/bin/env python3
"""
Quick demo: scan any directory and show findings with confidence scores.

Usage:
    python demo.py /path/to/scan
    python demo.py .                    # scan current directory
    python demo.py --example            # scan built-in test cases
"""
import sys
import json
import os

def run_demo(target_path=None, example=False):
    from detect_secrets.core.scan import scan_file
    from detect_secrets.settings import default_settings
    from detect_secrets.plugins.confidence import get_confidence, get_contextual_confidence

    if example:
        # Create temporary test file
        import tempfile
        test_content = '''# Example: secrets that detect-secrets-enhanced finds
ANTHROPIC_KEY = "sk-ant-api03-abc123def456ghi789jkl012mno345pqr678"
HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz0123456789ab"
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
VAULT_TOKEN = "hvs.CAESIGxyz789abc123def456ghi"
FIREBASE_KEY = "AIzaSyBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"
DATABASE_URL = "postgresql://admin:SecretPass123@db.example.com:5432/prod"
'''
        fd, target_path = tempfile.mkstemp(suffix='.py')
        with os.fdopen(fd, 'w') as f:
            f.write(test_content)

    if not target_path:
        print("Usage: python demo.py /path/to/scan  OR  python demo.py --example")
        sys.exit(1)

    print(f"\n🔍 detect-secrets-enhanced — scanning: {target_path}")
    print("=" * 60)

    total_files = 0
    all_secrets = []

    with default_settings():
        if os.path.isfile(target_path):
            files = [target_path]
        else:
            files = []
            for root, dirs, fnames in os.walk(target_path):
                dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv', 'venv')]
                for fn in fnames:
                    if fn.endswith(('.py', '.js', '.ts', '.json', '.yaml', '.yml', '.env', '.cfg', '.ini', '.tf', '.hcl')):
                        files.append(os.path.join(root, fn))

        for fp in files:
            total_files += 1
            try:
                secrets = list(scan_file(fp))
                all_secrets.extend([(fp, s) for s in secrets])
            except Exception:
                pass

    if not all_secrets:
        print(f"\n✅ Clean! Scanned {total_files} files, no secrets found.")
        return

    # Sort by confidence
    all_secrets.sort(key=lambda x: get_confidence(x[1].type), reverse=True)

    # Display with confidence coloring
    high = [(fp, s) for fp, s in all_secrets if get_contextual_confidence(s.type, fp) >= 0.8]
    medium = [(fp, s) for fp, s in all_secrets if 0.4 <= get_contextual_confidence(s.type, fp) < 0.8]
    low = [(fp, s) for fp, s in all_secrets if get_contextual_confidence(s.type, fp) < 0.4]

    if high:
        print(f"\n🔴 HIGH CONFIDENCE ({len(high)} findings) — almost certainly real secrets:")
        for fp, s in high:
            rel_path = os.path.relpath(fp, target_path) if os.path.isdir(target_path) else os.path.basename(fp)
            print(f"   {get_contextual_confidence(s.type, fp):.0%} | {s.type:30} | {rel_path}:{s.line_number}")

    if medium:
        print(f"\n🟡 MEDIUM CONFIDENCE ({len(medium)} findings) — review recommended:")
        for fp, s in medium:
            rel_path = os.path.relpath(fp, target_path) if os.path.isdir(target_path) else os.path.basename(fp)
            print(f"   {get_contextual_confidence(s.type, fp):.0%} | {s.type:30} | {rel_path}:{s.line_number}")

    if low:
        print(f"\n⚪ LOW CONFIDENCE ({len(low)} findings) — likely false positives:")
        for fp, s in low[:5]:
            rel_path = os.path.relpath(fp, target_path) if os.path.isdir(target_path) else os.path.basename(fp)
            print(f"   {get_contextual_confidence(s.type, fp):.0%} | {s.type:30} | {rel_path}:{s.line_number}")
        if len(low) > 5:
            print(f"   ... and {len(low) - 5} more low-confidence findings")

    print(f"\n📊 Summary: {len(all_secrets)} findings in {total_files} files")
    print(f"   🔴 {len(high)} high  🟡 {len(medium)} medium  ⚪ {len(low)} low confidence")
    print(f"   Use --min-confidence 0.5 to hide likely false positives")

    if example:
        os.unlink(target_path)

if __name__ == '__main__':
    if '--example' in sys.argv:
        run_demo(example=True)
    elif len(sys.argv) > 1:
        run_demo(sys.argv[1])
    else:
        run_demo()
