#!/usr/bin/env python3
"""Sync public/ clients into the Worker-embedded fallbacks in src/worker.ts.

The Worker serves /desktop, /mobile and /client/*.js itself when no Pages
assets binding is configured, by embedding those files as JS string literals
(desktopFallbackHtml, mobileFallbackHtml, desktopJs, mobileJs). This script is
the ONLY supported way to update those literals — hand-editing them drifts,
and it has bitten us before.

Usage:
  python3 scripts/sync-fallbacks.py          # rewrite src/worker.ts in place
  python3 scripts/sync-fallbacks.py --check  # exit 1 if worker.ts is stale (CI)

Run it after every change to public/desktop.html, public/mobile.html,
public/client/desktop.js or public/client/mobile.js, then commit the result.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAPPING = {
    "desktopFallbackHtml": "public/desktop.html",
    "mobileFallbackHtml": "public/mobile.html",
    "desktopJs": "public/client/desktop.js",
    "mobileJs": "public/client/mobile.js",
}


def js_string(path: Path) -> str:
    return json.dumps(path.read_text(encoding="utf-8"), ensure_ascii=True)


def main() -> int:
    check_only = "--check" in sys.argv
    worker = ROOT / "src" / "worker.ts"
    src = worker.read_text(encoding="utf-8")
    stale: list[str] = []
    for fn, rel in MAPPING.items():
        lit = js_string(ROOT / rel)
        pat = re.compile(
            r"(async function " + fn + r"\(\): Promise<string> \{\n  return ).*?(\n\})",
            re.DOTALL,
        )
        m = pat.search(src)
        if not m:
            print(f"ERROR: fallback function {fn} not found in src/worker.ts")
            return 2
        if m.group(1) + lit + m.group(2) != m.group(0):
            stale.append(f"{fn} <- {rel}")
            src = pat.sub(lambda mm: mm.group(1) + lit + mm.group(2), src, count=1)
    if check_only:
        if stale:
            print("STALE worker fallbacks (run python3 scripts/sync-fallbacks.py):")
            for s in stale:
                print(f"  - {s}")
            return 1
        print("worker fallbacks in sync")
        return 0
    if stale:
        worker.write_text(src, encoding="utf-8")
        print("synced:")
        for s in stale:
            print(f"  - {s}")
    else:
        print("already in sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
