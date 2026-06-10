#!/usr/bin/env python3
"""
DockSec scanner worker — runs INSIDE the dedicated Python 3.12 venv.

Why this exists: the `docksec` package requires Python >= 3.12, but the Hermes
agent runs on Python 3.11. The two cannot share an interpreter, so the scanner
is isolated here and invoked as a subprocess by ``docksec_tool.py`` (which runs
under Hermes' 3.11 venv and never imports docksec).

Contract:
    Invoked as:
        <3.12-venv-python> docksec_worker.py \
            [--image IMAGE] [--dockerfile PATH] [--severity "CRITICAL,HIGH"]

    Emits a single JSON object on stdout (all docksec console chatter is
    redirected to stderr so stdout stays clean):

        {
          "ok": true,
          "json_data": [ {VulnerabilityID, Severity, PkgName, ...}, ... ],
          "dockerfile_scan": {"success": bool, "output": str|None, "skipped": bool},
          "timestamp": "YYYY-MM-DD HH:MM:SS",
          "cached": bool
        }

    On failure:
        {"ok": false, "error": "..."}

Exit code is 0 whenever a JSON object was emitted (including ok=false), so the
caller always parses stdout rather than guessing from the exit status.
"""

import argparse
import contextlib
import json
import os
import sys


def _run(image_name, dockerfile_path, severity):
    # Imported here (not at module top) so an import error is reported as JSON.
    from docksec.docker_scanner import DockerSecurityScanner

    results_dir = os.path.expanduser(
        os.getenv("DOCKSEC_RESULTS_DIR", "~/.hermes/docksec/results")
    )
    os.makedirs(results_dir, exist_ok=True)

    scanner = DockerSecurityScanner(
        dockerfile_path=dockerfile_path,
        image_name=image_name,
        results_dir=results_dir,
        scan_only=True,        # disables docksec's LangChain init
        skip_ai_scoring=True,  # disables docksec's LLM scoring
    )

    # Determine cache-hit BEFORE scanning. docksec returns the inner results dict
    # on a cache hit without flagging it, so the only reliable signal is whether
    # an entry already exists in its cache. (Blueprint read results["cached"],
    # which docksec never sets — this is the corrected detection.)
    cached = bool(
        getattr(scanner, "use_cache", False)
        and image_name
        and scanner.cache.get(image_name)
    )

    if image_name and not dockerfile_path:
        results = scanner.run_image_only_scan(severity)
    else:
        results = scanner.run_full_scan(severity)

    return {
        "ok": True,
        "json_data": results.get("json_data", []),
        "dockerfile_scan": results.get("dockerfile_scan", {}),
        "timestamp": results.get("timestamp"),
        "cached": cached,
    }


def main():
    parser = argparse.ArgumentParser(description="DockSec scanner worker (py3.12)")
    parser.add_argument("--image", default=None)
    parser.add_argument("--dockerfile", default=None)
    parser.add_argument("--severity", default="CRITICAL,HIGH")
    args = parser.parse_args()

    if not args.image and not args.dockerfile:
        print(json.dumps({"ok": False, "error": "no image or dockerfile provided"}))
        return

    try:
        # docksec prints progress to stdout; send all of that to stderr so the
        # only thing on real stdout is our final JSON line.
        with contextlib.redirect_stdout(sys.stderr):
            payload = _run(args.image, args.dockerfile, args.severity)
    except Exception as e:  # noqa: BLE001 — surface any failure as JSON
        payload = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
