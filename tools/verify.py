# -*- coding: utf-8 -*-
"""
Lang-to-English evidence manifest verifier.
Usage:  python tools/verify.py [logs_dir]
Checks that every file listed in each manifest_*.json is unmodified
(SHA-256 match). Exit code 0 = all good, 1 = any mismatch/missing file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ids_tool.evidence import sha256_file  # noqa: E402


def verify_manifest(manifest_path: Path):
    ok = True
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    print(f"\n[manifest] {manifest_path}")
    for entry in data.get("files", []):
        f = Path(entry["file"])
        if not f.exists():
            print(f"  MISSING  {f}")
            ok = False
            continue
        digest = sha256_file(f)
        if digest == entry.get("sha256"):
            print(f"  OK       {f.name}  ({f.stat().st_size} bytes)")
        else:
            print(f"  TAMPERED {f}")
            ok = False
    return ok


def main():
    logs_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs")
    if not logs_dir.exists():
        print(f"logs dir not found: {logs_dir}")
        return 1
    manifests = sorted(logs_dir.glob("manifest_*.json"))
    if not manifests:
        print(f"no manifests in {logs_dir} - run a session first")
        return 1
    ok = all(verify_manifest(m) for m in manifests)
    print("\nRESULT:", "ALL VERIFIED" if ok else "VERIFICATION FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
