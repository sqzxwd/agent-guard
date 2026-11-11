<div align="center">

# 🛡️ AgentGuard
### AI Agent Firewall & Cost Guard

**A lightweight local proxy that protects your wallet and secrets from runaway AI agents.**

[![Python 3.14+](https://img.shields.io/badge/python-3.14+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-17%2F17%20passed-brightgreen.svg)]()

</div>

---

## 💥 The Problem

Autonomous coding agents (**Google Antigravity**, **Cursor**, **Claude Code**, **AutoGPT**, etc.) operate in continuous feedback loops. When facing elusive syntax errors, missing packages, or hallucinated APIs, agents can easily fall into **infinite death loops**:
- Repeating the exact same failing terminal command dozens of times.
- Burning through hundreds of thousands of tokens and exhausting your API balances in minutes.
- Inadvertently leaking `.env` files, production credentials, AWS keys, and database connection strings into upstream LLM context and telemetry logs.

---

## ⚡ The Solution

**AgentGuard** sits transparently between your AI agents and upstream LLM providers (e.g. `localhost:8085`):

1. **🔁 Loop Killer**: Computes deterministic SHA-256 signatures of tool calls, compiler tracebacks, and repeating queries. The moment an agent repeats the same failing action or error **3 times in a row**, AgentGuard terminates the loop with HTTP `429 Too Many Requests`, immediately saving your tokens.
2. **🔒 In-Flight Secret Redactor**: Strips OpenAI, Anthropic, Google AI, AWS, JWT, and `.env` credentials from outgoing payloads, replacing them with `[REDACTED_SECRET_X]`. 
3. **🌊 Bidirectional SSE Stream Restoration**: Dynamically re-injects redacted secrets back into incoming Server-Sent Events (SSE) and JSON responses so your agent workflow continues without disruption.
4. **📊 Rich Terminal Dashboard**: Live terminal UI displaying active filters, upstream health, and real-time counters of killed loops and redacted secrets.

---

## 🏗️ Architecture

```text
┌────────────────────────┐
│       AI Agent         │
│ (Antigravity, Cursor,  │
│  Claude Code, CrewAI)  │
└────────────────────────┘
            │
            │  1. POST /v1/chat/completions (with sensitive prompts/tool calls)
            ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   🛡️  AgentGuard (localhost:8085)                      │
├────────────────────────────────────────────────────────────────────────┤
│  ⚡ Loop Killer:                                                       │
│     Computes tool call & error hashes. 3x repeat? -> HTTP 429 Kill!    │
│                                                                        │
│  🔒 Secret Redactor:                                                   │
│     OpenAI (sk-*), Anthropic (sk-ant-*), Google AI, AWS, JWT, .env     │
│     Replaces raw secrets -> [REDACTED_SECRET_X]                        │
└────────────────────────────────────────────────────────────────────────┘
            │
            │  2. Forward sanitized payload ([REDACTED_...])
            ▼
┌────────────────────────┐
│      Upstream LLM      │
│ (OpenAI, Anthropic,    │
│  or self-hosted LLM)   │
└────────────────────────┘
            │
            │  3. Raw SSE / JSON chunks containing [REDACTED_SECRET_X]
            ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   🛡️  AgentGuard (localhost:8085)                      │
├────────────────────────────────────────────────────────────────────────┤
│  🌊 Dynamic Stream Restorer:                                           │
│     Reconstructs split tokens across chunk boundaries and restores     │
│     [REDACTED_SECRET_X] -> original secret on the fly                  │
└────────────────────────────────────────────────────────────────────────┘
            │
            │  4. Fully restored response stream
            ▼
┌────────────────────────┐
│       AI Agent         │
└────────────────────────┘
```

---

## 🚀 Quickstart

### 1. Clone & Set Up

```bash
# Clone the repository
git clone https://github.com/your-username/agent-guard.git
cd agent-guard

# Create and activate virtual environment (requires Python 3.14+)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies in editable mode
pip install -e .
```

### 2. Launch AgentGuard

```bash
# Start proxy on default port 8085 proxying to OpenAI
python3 -m src.cli start

# Or using custom upstream and port:
python3 -m src.cli start --port 8085 --upstream https://api.openai.com
```

You will see the **Rich Terminal Dashboard**:

```text
╭─────────────────── 🛡️  AgentGuard Firewall & Loop Killer ────────────────────╮
│                                                                              │
│   Proxy Address  http://127.0.0.1:8085                                       │
│    Upstream API  https://api.openai.com                                      │
│          Status  ONLINE (Listening for /v1/chat/completions)                 │
│                                                                              │
│  Active Filters  1. SecretRedactor ACTIVE                                    │
│                     └─ OpenAI (sk-*), Anthropic (sk-ant-*), Google AI, AWS,  │
│                  JWT, .env (KEY=VALUE)                                       │
│                  2. LoopDetector   ACTIVE                                    │
│                     └─ 3x Consecutive Tool Calls, Repeating                  │
│                  Terminal/Compiler Errors, Cycling Requests                  │
│                                                                              │
│    Live Metrics  • Loops Killed    : 0                                       │
│                  • Secrets Masked  : 0                                       │
│                  • Total Requests  : 0                                       │
│                                                                              │
╰──────────────────────────── Press CTRL+C to stop ────────────────────────────╯
```

### 3. Connect Your Agent

Simply point your agent's API base URL to `http://localhost:8085/v1`:

#### In Environment Variables
```bash
export OPENAI_BASE_URL="http://localhost:8085/v1"
```

#### In Cursor / IDE Agent Settings
- **Base URL**: `http://localhost:8085/v1`

#### In Python (OpenAI SDK)
```python
from openai import OpenAI

# Agent connects through the local firewall
client = OpenAI(
    base_url="http://localhost:8085/v1",
    api_key="your-api-key",
)

# Even if prompt contains sensitive credentials:
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Debug this script: AWS_KEY=AKIAIOSFODNN7EXAMPLE"}
    ],
    stream=True,
)

# Secrets are stripped before hitting OpenAI, and restored in the stream
for chunk in response:
    print(chunk.choices[0].delta.content or "", end="")
```

---

## 🧪 Testing

AgentGuard has a comprehensive test suite covering all filtering, loop detection, and proxy streaming scenarios:

```bash
pytest -v
```

```text
============================= test session starts ==============================
collected 17 items

tests/test_guard.py::test_redact_openai_key PASSED                       [  5%]
tests/test_guard.py::test_redact_anthropic_key PASSED                    [ 11%]
tests/test_guard.py::test_redact_google_ai_key PASSED                    [ 17%]
tests/test_guard.py::test_redact_aws_keys PASSED                         [ 23%]
tests/test_guard.py::test_redact_jwt_token PASSED                        [ 29%]
tests/test_guard.py::test_redact_env_format PASSED                       [ 35%]
tests/test_guard.py::test_redact_multiple_and_repeated_secrets PASSED    [ 41%]
tests/test_guard.py::test_sanitize_object PASSED                         [ 47%]
tests/test_guard.py::test_loop_detector_tool_calls_loop_3_consecutive PASSED [ 52%]
tests/test_guard.py::test_loop_detector_tool_calls_no_loop_when_args_differ PASSED [ 58%]
tests/test_guard.py::test_loop_detector_repeated_terminal_errors PASSED  [ 64%]
tests/test_guard.py::test_loop_detector_repeated_user_prompts PASSED     [ 70%]
tests/test_guard.py::test_loop_detector_healthy_flow PASSED              [ 76%]
tests/test_guard.py::test_proxy_loop_killer_triggers_429 PASSED          [ 82%]
tests/test_guard.py::test_proxy_non_streaming_secret_redaction_and_restoration PASSED [ 88%]
tests/test_guard.py::test_proxy_streaming_sse_restoration[asyncio] PASSED [ 94%]
tests/test_guard.py::test_proxy_health_and_stats PASSED                  [100%]

======================== 17 passed, 1 warning in 0.15s =========================
```

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.
