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

## Prerequisites

This tool depends on external (non-Python) components. Trivy and Hadolint are
standalone binaries — they are **not** pip packages and cannot live in
`requirements.txt`; install them as system dependencies before setup.

| Dependency | Min version | Why |
|---|---|---|
| **Docker** | any | Trivy scans local images via the Docker daemon; the daemon must be running and the target image present locally (the tool does not pull it). |
| **Python 3.12 + [uv](https://docs.astral.sh/uv/)** | 3.12 | `docksec` requires Python ≥ 3.12; the worker runs in its own 3.12 venv. |
| **[Trivy](https://github.com/aquasecurity/trivy)** | 0.71 | CVE scanning. |
| **[Hadolint](https://github.com/hadolint/hadolint)** | 2.14 | Dockerfile linting. |

### Installing Trivy + Hadolint

Neither tool is in the default Debian/Ubuntu repositories. Pick whichever path
fits your environment.

**Via a package manager (needs root):**

```bash
snap install trivy                       # Trivy
brew install trivy hadolint              # both (macOS / Linuxbrew)
nix profile install nixpkgs#trivy nixpkgs#hadolint   # both, via Nix
# Trivy also has an official Aquasec apt repo — see
# https://trivy.dev/latest/getting-started/installation/
```

**No-root fallback — pinned, checksum-verified binaries into `~/.local/bin`:**

```bash
mkdir -p ~/.local/bin && cd "$(mktemp -d)"

# Hadolint
HADOLINT_VERSION=2.14.0
curl -fsSL -o hadolint \
  "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64"
curl -fsSL -o hadolint.sha256 \
  "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64.sha256"
echo "$(cut -d' ' -f1 hadolint.sha256)  hadolint" | sha256sum -c -
install -m 0755 hadolint ~/.local/bin/hadolint

# Trivy
TRIVY_VERSION=0.71.0
curl -fsSL -O \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
curl -fsSL -O \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"
grep "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -
tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C ~/.local/bin trivy
```

Make sure `~/.local/bin` is on your `PATH` (or point `DOCKSEC_EXTRA_PATH` at it).

> **Don't use `docksec`'s own installer.** `python -m docksec.setup_external_tools`
> writes Trivy/Hadolint to `/usr/local/bin` via `sudo apt-get`, which fails in
> non-root / non-interactive environments (and Trivy isn't in the default apt
> repos anyway). Use one of the methods above instead.

## Setup

With the [prerequisites](#prerequisites) in place:

```bash
# 1) Install dependencies — dedicated 3.12 venv for the worker (docksec needs >=3.12)
uv venv --python 3.12 ~/.hermes/docksec/venv
VIRTUAL_ENV=~/.hermes/docksec/venv uv pip install docksec openai
cp docksec_worker.py ~/.hermes/docksec/docksec_worker.py

# 2) Ensure `openai` is available to whatever runs docksec_tool.py
#    (e.g. the Hermes venv — Hermes already ships openai).

# 3) Configure env (see .env.example)
cp .env.example .env   # then edit
```

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
