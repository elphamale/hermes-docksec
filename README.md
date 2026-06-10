# hermes-docksec

A Hermes/agent integration wrapper for container security scanning.

It runs [DockSec](https://github.com/OWASP/DockSec)'s scanner layer (Trivy +
Hadolint) and returns a compact, agent-friendly result: a 0–100 security score,
CVE severity counts, the top issues, and — optionally — AI-powered remediation
advice from any OpenAI-compatible LLM endpoint.

> Built on top of [DockSec](https://github.com/OWASP/DockSec) by OWASP.

This is **not** a fork of DockSec. It uses `docksec` as a PyPI dependency the
same way it uses `openai`. DockSec's own LangChain/LLM machinery is bypassed —
we reuse only its Trivy/Hadolint scanner orchestration and route AI analysis
through a configurable endpoint instead.

## Architecture: two interpreters

The `docksec` package requires **Python ≥ 3.12**, but Hermes runs on **Python
3.11**. They cannot share an interpreter, so the tool is split:

```
Hermes agent (Python 3.11)
  └─ docksec_tool.py          ← no docksec import; pure stdlib + openai
        │  asyncio subprocess
        ▼
  docksec_worker.py (Python 3.12 venv, has docksec)
        ├─► Trivy   (subprocess) ── CVE JSON
        └─► Hadolint(subprocess) ── Dockerfile lint
        ▼  emits one JSON line on stdout
  docksec_tool.py  → local scoring → optional LLM recommendations → result dict
```

`docksec_tool.py` shells out to the worker with `asyncio.create_subprocess_exec`,
parses its JSON, computes the score locally (mirroring DockSec's weights: vulns
50% / Dockerfile 30% / config 20%), and optionally calls the configured LLM for
remediation steps. If the LLM endpoint is unset, it runs in **scan-only mode**.

## Files

| File | Runs under | Purpose |
|---|---|---|
| `docksec_tool.py`   | Hermes' 3.11 venv | Agent tool: subprocess bridge, scoring, LLM, formatting |
| `docksec_worker.py` | dedicated 3.12 venv | Imports docksec, runs the scan, emits JSON |
| `.env.example`      | — | Env var reference for all backends |
| `requirements.txt`  | — | `docksec` (3.12 venv) + `openai` (Hermes venv) |

## Setup

```bash
# 1) Scanner backends (static binaries; no sudo needed)
mkdir -p ~/.local/bin
curl -fsSL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
     -o ~/.local/bin/hadolint && chmod +x ~/.local/bin/hadolint
TRIVY_VER=$(curl -fsSL https://api.github.com/repos/aquasecurity/trivy/releases/latest \
            | grep -oP '"tag_name":\s*"v\K[0-9.]+' | head -1)
curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-64bit.tar.gz" \
     | tar xz -C ~/.local/bin trivy

# 2) Dedicated 3.12 venv for the worker (docksec needs >=3.12)
uv venv --python 3.12 ~/.hermes/docksec/venv
VIRTUAL_ENV=~/.hermes/docksec/venv uv pip install docksec openai
cp docksec_worker.py ~/.hermes/docksec/docksec_worker.py

# 3) openai in the environment that runs docksec_tool.py (e.g. Hermes venv)
#    (Hermes already ships openai.)

# 4) Configure env (see .env.example)
cp .env.example .env   # then edit
```

> **Heads-up on `docksec`'s own installer:** `python -m docksec.setup_external_tools`
> tries to write Trivy/Hadolint to `/usr/local/bin` via `sudo apt-get`, which
> fails in non-root / non-interactive environments. The static-binary commands
> in step 1 install to `~/.local/bin` without sudo.

## Backend compatibility

`DOCKSEC_LLM_BASE_URL` accepts any OpenAI-compatible endpoint:

| Setup | `DOCKSEC_LLM_BASE_URL` | `DOCKSEC_LLM_API_KEY` | `DOCKSEC_LLM_MODEL` |
|---|---|---|---|
| Manifest router (hosted) | `https://app.manifest.build/v1` | `mnfst_...` | `auto` |
| LiteLLM proxy | `http://localhost:4000/v1` | your litellm key | model alias |
| OpenRouter | `https://openrouter.ai/api/v1` | `sk-or-...` | `anthropic/claude-sonnet-4-6` |
| OpenAI direct | `https://api.openai.com/v1` | `sk-...` | `gpt-4o` |
| Ollama (local) | `http://localhost:11434/v1` | `ollama` | `llama3.1` |

> A locally self-hosted `manifestdotbuild/manifest` web app (commonly on
> `:2099`) is a **dashboard, not an LLM endpoint** — its `/v1/chat/completions`
> returns 404. Use the hosted router URL above or another provider.

If `DOCKSEC_LLM_BASE_URL` is unset, AI recommendations are silently skipped and
everything else still works.

## Usage

```python
import asyncio
from docksec_tool import scan_docker_image, format_for_telegram

result = asyncio.run(scan_docker_image(
    image_name="nginx:alpine",
    severity="CRITICAL,HIGH",
    include_ai_recommendations=True,   # requires DOCKSEC_LLM_BASE_URL
))
print(format_for_telegram(result, "nginx:alpine"))
```

`scan_docker_image(...)` returns a dict:

```
score, score_label, critical, high, medium, low,
top_issues, dockerfile_issues, recommendations,
raw_vulns, cached, timestamp, llm_enabled
```

(or `{"error": "..."}` if the scan subprocess failed).

`probe_llm_endpoint()` checks reachability + a live completion round-trip; use
it during setup to confirm the endpoint before wiring the tool into an agent.

## Credit

Built on top of [DockSec](https://github.com/OWASP/DockSec) by OWASP. DockSec is
the upstream scanner this wrapper depends on; see their repository for the
scanner internals and license.
