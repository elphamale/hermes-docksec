"""
DockSec tool for the Hermes agent.

Runs DockSec's scanner layer (Trivy + Hadolint) and optionally calls any
OpenAI-compatible LLM endpoint for AI-powered remediation recommendations.

Two-interpreter architecture
----------------------------
The ``docksec`` PyPI package requires Python >= 3.12, but Hermes runs on
Python 3.11. They cannot share an interpreter, so the scanner lives in a
dedicated 3.12 venv and is invoked as a subprocess (``docksec_worker.py``).
This module runs under Hermes' 3.11 venv and NEVER imports docksec — it only
shells out to the worker, then does scoring / LLM calls / formatting in pure
Python (``openai`` is available in the Hermes venv).

Configuration via env vars:
    DOCKSEC_LLM_BASE_URL    OpenAI-compatible endpoint base URL (e.g. https://app.manifest.build/v1)
    DOCKSEC_LLM_API_KEY     API key for the endpoint (any non-empty string for keyless routers)
    DOCKSEC_LLM_MODEL       Model name/alias to request (default: "auto")
    DOCKSEC_RESULTS_DIR     Where to store scan results (default: ~/.hermes/docksec/results)
    DOCKSEC_WORKER_PYTHON   Path to the 3.12 venv python that has docksec installed
    DOCKSEC_WORKER_SCRIPT   Path to docksec_worker.py (default: sibling of this file)
    DOCKSEC_WORKER_TIMEOUT  Seconds before the scan subprocess is killed (default: 600)
    DOCKSEC_EXTRA_PATH      Extra dirs prepended to the worker's PATH so it can find
                            trivy/hadolint (default: ~/.local/bin)

If DOCKSEC_LLM_BASE_URL is unset, the tool operates in scan-only mode:
scanner output and local scoring still work; AI recommendations return None.

Compatible with: Manifest, LiteLLM, OpenRouter, OpenAI, Ollama, and any other
OpenAI-compatible proxy.
"""

import asyncio
import json
import os
from collections import defaultdict

# ── Severity (plain strings — Trivy emits these; we must NOT import docksec
#    here, it isn't importable under Python 3.11) ────────────────────────────
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
UNKNOWN = "UNKNOWN"

SEVERITY_WEIGHTS = {CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1}


# ── Config ────────────────────────────────────────────────────────────────────

RESULTS_DIR = os.path.expanduser(
    os.getenv("DOCKSEC_RESULTS_DIR", "~/.hermes/docksec/results")
)

_LLM_BASE_URL = os.getenv("DOCKSEC_LLM_BASE_URL", "").rstrip("/")
_LLM_API_KEY = os.getenv("DOCKSEC_LLM_API_KEY", "unused")
_LLM_MODEL = os.getenv("DOCKSEC_LLM_MODEL", "auto")
_LLM_ENABLED = bool(_LLM_BASE_URL)

_WORKER_SCRIPT = os.getenv("DOCKSEC_WORKER_SCRIPT") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "docksec_worker.py"
)


def _default_worker_python() -> str:
    """Prefer an explicit env var, then a venv next to the worker, then python3."""
    explicit = os.getenv("DOCKSEC_WORKER_PYTHON")
    if explicit:
        return explicit
    sibling = os.path.join(os.path.dirname(_WORKER_SCRIPT), "venv", "bin", "python")
    if os.path.exists(sibling):
        return sibling
    return "python3"


_WORKER_PYTHON = _default_worker_python()
_WORKER_TIMEOUT = int(os.getenv("DOCKSEC_WORKER_TIMEOUT", "600"))
_EXTRA_PATH = os.path.expanduser(os.getenv("DOCKSEC_EXTRA_PATH", "~/.local/bin"))


# ── Endpoint probe (used during install) ──────────────────────────────────────

def probe_llm_endpoint() -> dict:
    """
    Check whether the configured LLM endpoint is reachable and functional.

    Returns:
        {"ok": True,  "url": str, "model": str}   on success
        {"ok": False, "url": str, "error": str}   on failure
        {"ok": None,  "url": None, "reason": str} if DOCKSEC_LLM_BASE_URL is unset
    """
    if not _LLM_ENABLED:
        return {
            "ok": None,
            "url": None,
            "reason": "DOCKSEC_LLM_BASE_URL not set — tool will run in scan-only mode",
        }

    import urllib.error
    import urllib.request

    # Step 1: reachability — probe /models (lightweight, no tokens).
    models_url = _LLM_BASE_URL + "/models"
    try:
        with urllib.request.urlopen(models_url, timeout=5):
            pass
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403):
            # 401/403 = auth required but server is up — that's fine.
            return {"ok": False, "url": _LLM_BASE_URL, "error": f"/models returned HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "url": _LLM_BASE_URL, "error": f"Endpoint unreachable: {e}"}

    # Step 2: live completion round-trip (minimal tokens).
    try:
        from openai import OpenAI

        client = OpenAI(base_url=_LLM_BASE_URL, api_key=_LLM_API_KEY)
        resp = client.chat.completions.create(
            model=_LLM_MODEL,
            max_tokens=5,
            messages=[{"role": "user", "content": "ping"}],
        )
        return {"ok": True, "url": _LLM_BASE_URL, "model": resp.model or _LLM_MODEL}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "url": _LLM_BASE_URL, "error": f"Completion failed: {e}"}


# ── Local scoring (no LLM) ────────────────────────────────────────────────────

def _score_locally(vulns: list, dockerfile_clean: bool) -> int:
    """
    Mirror DockSec's SecurityScoreCalculator weights without its LLM dependency.
    Vulns 50% | Dockerfile quality 30% | Config 20% (stubbed at 100 for now).
    """
    if not vulns:
        vuln_score = 100
    else:
        penalty = sum(SEVERITY_WEIGHTS.get(v.get("Severity", ""), 0) for v in vulns)
        vuln_score = max(0, 100 - min(penalty, 100))

    dockerfile_score = 100 if dockerfile_clean else 60
    config_score = 100  # extend later with Docker Scout config analysis

    return round(vuln_score * 0.5 + dockerfile_score * 0.3 + config_score * 0.2)


def _score_label(score: int) -> str:
    if score >= 90:
        return "EXCELLENT"
    if score >= 70:
        return "GOOD"
    if score >= 50:
        return "FAIR"
    return "POOR"


# ── LLM recommendations ───────────────────────────────────────────────────────

def _get_ai_recommendations(vulns: list, dockerfile_issues):
    """
    Call the configured LLM endpoint for remediation recommendations.
    Sends CRITICAL+HIGH only, capped at 5 entries to control token usage.
    Returns None when there is nothing to recommend, or an error string on failure.
    """
    if not _LLM_ENABLED:
        return None

    top = [v for v in vulns if v.get("Severity") in (CRITICAL, HIGH)][:5]
    if not top:
        return None

    vuln_summary = json.dumps(
        [
            {
                "id": v.get("VulnerabilityID"),
                "pkg": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "title": (v.get("Title") or "")[:80],
                "severity": v.get("Severity"),
            }
            for v in top
        ],
        indent=2,
    )

    prompt = (
        "You are a container security expert. "
        "Given the following Docker image vulnerabilities, provide 3-5 specific, "
        "actionable remediation steps. Be concise. Highest severity first. "
        "Numbered list only, no preamble.\n\n"
        f"Vulnerabilities:\n{vuln_summary}\n\n"
        f"Dockerfile issues: {dockerfile_issues or 'None'}"
    )

    try:
        from openai import OpenAI

        client = OpenAI(base_url=_LLM_BASE_URL, api_key=_LLM_API_KEY)
        resp = client.chat.completions.create(
            model=_LLM_MODEL,
            # Generous budget: routers may resolve "auto" to a reasoning model
            # (e.g. deepseek) that spends tokens on hidden reasoning before any
            # visible content. Too small a cap returns empty content.
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        msg = resp.choices[0].message
        content = (msg.content or "").strip()
        if not content:
            # Reasoning models surface the answer in reasoning_content when the
            # token budget is exhausted before the final content channel.
            content = (getattr(msg, "reasoning_content", "") or "").strip()
        return content or "[AI recommendations unavailable: model returned no content]"
    except Exception as e:  # noqa: BLE001
        return f"[AI recommendations unavailable: {e}]"


# ── Scanner subprocess bridge ─────────────────────────────────────────────────

async def _run_worker(image_name, dockerfile_path, severity) -> dict:
    """Invoke the 3.12 docksec worker and parse its JSON. Raises on hard failure."""
    cmd = [_WORKER_PYTHON, _WORKER_SCRIPT, "--severity", severity]
    if image_name:
        cmd += ["--image", image_name]
    if dockerfile_path:
        cmd += ["--dockerfile", dockerfile_path]

    env = dict(os.environ)
    env["DOCKSEC_RESULTS_DIR"] = RESULTS_DIR
    # Ensure the worker can find trivy/hadolint even under a stripped PATH.
    if _EXTRA_PATH:
        env["PATH"] = _EXTRA_PATH + os.pathsep + env.get("PATH", "")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=_WORKER_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"docksec scan timed out after {_WORKER_TIMEOUT}s")

    out = out.decode("utf-8", "replace").strip()
    if not out:
        tail = err.decode("utf-8", "replace")[-500:]
        raise RuntimeError(f"docksec worker produced no output. stderr tail:\n{tail}")

    try:
        payload = json.loads(out.splitlines()[-1])
    except json.JSONDecodeError as e:
        raise RuntimeError(f"could not parse worker output: {e}\nraw: {out[:500]}")

    if not payload.get("ok"):
        raise RuntimeError(payload.get("error", "unknown worker error"))
    return payload


# ── Main tool function ────────────────────────────────────────────────────────

async def scan_docker_image(
    image_name: str = None,
    dockerfile_path: str = None,
    severity: str = "CRITICAL,HIGH",
    include_ai_recommendations: bool = False,
) -> dict:
    """
    Hermes tool: scan a Docker image and/or Dockerfile for security issues.

    Args:
        image_name:                  e.g. "hermes-api:latest" or "nginx:alpine"
        dockerfile_path:             absolute path to Dockerfile (optional)
        severity:                    comma-separated Trivy severity filter
        include_ai_recommendations:  if True, call the configured LLM endpoint
                                     for remediation text. Silently skipped if
                                     DOCKSEC_LLM_BASE_URL is unset.

    Returns dict with:
        score, score_label, critical, high, medium, low,
        top_issues, dockerfile_issues, recommendations,
        raw_vulns, cached, timestamp, llm_enabled
        (or {"error": "..."} if the scan itself failed)
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)

    try:
        payload = await _run_worker(image_name, dockerfile_path, severity)
    except Exception as e:  # noqa: BLE001 — degrade gracefully for the agent
        return {"error": str(e), "llm_enabled": _LLM_ENABLED}

    vulns = payload.get("json_data") or []
    dockerfile_scan = payload.get("dockerfile_scan") or {}
    dockerfile_clean = dockerfile_scan.get("success", True)
    dockerfile_issues = dockerfile_scan.get("output")
    # docksec emits a "Skipped - ..." sentinel for the dockerfile slot on
    # image-only scans; treat that as "no dockerfile findings" rather than noise.
    if dockerfile_scan.get("skipped") or (
        isinstance(dockerfile_issues, str) and dockerfile_issues.startswith("Skipped")
    ):
        dockerfile_issues = None

    counts = defaultdict(int)
    for v in vulns:
        counts[v.get("Severity", UNKNOWN)] += 1

    score = _score_locally(vulns, dockerfile_clean)

    top_issues = [
        {
            "id": v.get("VulnerabilityID"),
            "pkg": v.get("PkgName"),
            "version": v.get("InstalledVersion"),
            "title": (v.get("Title") or "")[:80],
            "severity": v.get("Severity"),
            "cvss": v.get("CVSS"),
        }
        for v in vulns
        if v.get("Severity") in (CRITICAL, HIGH)
    ][:5]

    recommendations = None
    if include_ai_recommendations:
        recommendations = _get_ai_recommendations(vulns, dockerfile_issues)

    return {
        "score": score,
        "score_label": _score_label(score),
        "critical": counts.get(CRITICAL, 0),
        "high": counts.get(HIGH, 0),
        "medium": counts.get(MEDIUM, 0),
        "low": counts.get(LOW, 0),
        "top_issues": top_issues,
        "dockerfile_issues": dockerfile_issues,
        "recommendations": recommendations,
        "raw_vulns": vulns,
        "cached": payload.get("cached", False),
        "timestamp": payload.get("timestamp"),
        "llm_enabled": _LLM_ENABLED,
    }


# ── Telegram formatter ────────────────────────────────────────────────────────

def format_for_telegram(result: dict, target: str) -> str:
    if result.get("error"):
        return f"🔴 *DocSec: {target}*\nScan failed: `{result['error'][:300]}`"

    score = result["score"]
    label = result["score_label"]
    emoji = {"EXCELLENT": "🟢", "GOOD": "🟡", "FAIR": "🟠", "POOR": "🔴"}.get(label, "⚪")

    lines = [
        f"{emoji} *DocSec: {target}*",
        f"Score: `{score}/100` — {label}",
        f"🔴 {result['critical']}  🟠 {result['high']}  🟡 {result['medium']}  ⚪ {result['low']}",
    ]

    if result["top_issues"]:
        lines.append("\n*Top Issues:*")
        for i in result["top_issues"][:3]:
            lines.append(f"• [{i['severity']}] `{i['id']}` — {i['pkg']} {i['version']}")
            if i.get("title"):
                lines.append(f"  _{i['title'][:60]}_")

    if result.get("dockerfile_issues"):
        lines.append("\n*Dockerfile:*")
        lines.append(f"`{result['dockerfile_issues'][:300]}`")

    if result.get("recommendations"):
        lines.append("\n*Recommendations:*")
        lines.append(result["recommendations"][:600])

    if result.get("cached"):
        lines.append(f"\n_⚡ Cached — {result['timestamp']}_")

    if not result.get("llm_enabled"):
        lines.append("\n_ℹ️ AI recommendations disabled (DOCKSEC\\_LLM\\_BASE\\_URL not set)_")

    return "\n".join(lines)


# ── Hermes registration ───────────────────────────────────────────────────────
# When this module is imported inside the Hermes agent, the call to
# ``registry.register(...)`` below self-registers the tool. Hermes' auto-discovery
# (tools/registry.py: discover_builtin_tools) only imports modules that contain a
# *top-level* ``registry.register(...)`` statement, so that call must live at
# module scope — NOT nested in a try/except.
#
# To keep this same file usable as a standalone library (where ``tools.registry``
# doesn't exist), we fall back to a no-op ``_NullRegistry`` shim. The top-level
# ``registry.register(...)`` then either registers for real (Hermes) or does
# nothing (standalone), while remaining AST-discoverable in both cases.
import shutil

try:
    from tools.registry import registry, tool_result
except ImportError:  # standalone use — provide harmless shims
    class _NullRegistry:
        def register(self, *args, **kwargs):
            return None

    registry = _NullRegistry()

    def tool_result(data=None, **kwargs):
        return json.dumps(data if data is not None else kwargs)


_SCAN_DOCKER_SCHEMA = {
    "name": "scan_docker",
    "description": (
        "Scan a Docker image or Dockerfile for security vulnerabilities "
        "(Trivy + Hadolint). Returns a 0-100 security score, CVE severity "
        "counts, and the top issues. The image must already be present "
        "locally (it is not pulled automatically). Set "
        "include_ai_recommendations=true for LLM-powered remediation advice "
        "(requires DOCKSEC_LLM_BASE_URL to be configured)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "image_name": {
                "type": "string",
                "description": "Docker image name, e.g. 'nginx:alpine'. Must exist locally.",
            },
            "dockerfile_path": {
                "type": "string",
                "description": "Absolute path to a Dockerfile to lint (optional).",
            },
            "severity": {
                "type": "string",
                "description": "Comma-separated Trivy severity filter. Default 'CRITICAL,HIGH'.",
            },
            "include_ai_recommendations": {
                "type": "boolean",
                "description": "Add AI remediation suggestions via the configured LLM endpoint.",
            },
        },
        "required": [],
    },
}


def _check_docksec_available() -> bool:
    """Tool is available only when Docker and the 3.12 worker python exist."""
    if not shutil.which("docker"):
        return False
    return _WORKER_PYTHON == "python3" or os.path.exists(_WORKER_PYTHON)


async def _scan_docker_handler(args, **kwargs):
    result = await scan_docker_image(
        image_name=args.get("image_name"),
        dockerfile_path=args.get("dockerfile_path"),
        severity=args.get("severity") or "CRITICAL,HIGH",
        include_ai_recommendations=bool(args.get("include_ai_recommendations", False)),
    )
    return tool_result(result)


registry.register(
    name="scan_docker",
    toolset="docksec",
    schema=_SCAN_DOCKER_SCHEMA,
    handler=_scan_docker_handler,
    check_fn=_check_docksec_available,
    requires_env=[],
    is_async=True,
    description="Scan a Docker image/Dockerfile for security vulnerabilities",
    emoji="🛡️",
)

