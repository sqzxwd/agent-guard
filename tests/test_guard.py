"""Tests for agent-guard: SecretRedactor, LoopDetector, and FastAPI Proxy."""

from __future__ import annotations

import json
from typing import AsyncIterator

from fastapi.testclient import TestClient
import httpx
import pytest

from src.filters.loop_detector import LoopDetector
from src.filters.redactor import SecretRedactor
from src.proxy import app, state


# ============================================================================
# 1. Tests for SecretRedactor
# ============================================================================

def test_redact_openai_key():
    redactor = SecretRedactor()
    raw = "My OpenAI key is sk-proj-1234567890abcdef1234567890abcdef."
    sanitized, mapping = redactor.sanitize(raw)

    assert "sk-proj-" not in sanitized
    assert "[REDACTED_SECRET_1]" in sanitized
    assert mapping["[REDACTED_SECRET_1]"] == "sk-proj-1234567890abcdef1234567890abcdef"

    restored = redactor.restore(sanitized, mapping)
    assert restored == raw


def test_redact_anthropic_key():
    redactor = SecretRedactor()
    raw = "Bearer sk-ant-api03-abcdef12345678901234567890"
    sanitized, mapping = redactor.sanitize(raw)

    assert "sk-ant-" not in sanitized
    assert "[REDACTED_SECRET_1]" in sanitized
    assert mapping["[REDACTED_SECRET_1]"] == "sk-ant-api03-abcdef12345678901234567890"

    restored = redactor.restore(sanitized, mapping)
    assert restored == raw


def test_redact_google_ai_key():
    redactor = SecretRedactor()
    raw = "Google API Key: AIzaSyD1234567890123456789012345678901"
    sanitized, mapping = redactor.sanitize(raw)

    assert "AIza" not in sanitized
    assert "[REDACTED_SECRET_1]" in sanitized
    assert mapping["[REDACTED_SECRET_1]"] == "AIzaSyD1234567890123456789012345678901"

    restored = redactor.restore(sanitized, mapping)
    assert restored == raw


def test_redact_aws_keys():
    redactor = SecretRedactor()
    raw = "Access: AKIAIOSFODNN7EXAMPLE and aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    sanitized, mapping = redactor.sanitize(raw)

    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in sanitized
    assert len(mapping) == 2

    restored = redactor.restore(sanitized, mapping)
    assert restored == raw


def test_redact_jwt_token():
    redactor = SecretRedactor()
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    raw = f"Authorization: Bearer {token}"
    sanitized, mapping = redactor.sanitize(raw)

    assert token not in sanitized
    assert "[REDACTED_SECRET_1]" in sanitized
    assert mapping["[REDACTED_SECRET_1]"] == token

    restored = redactor.restore(sanitized, mapping)
    assert restored == raw


def test_redact_env_format():
    redactor = SecretRedactor()
    env_content = (
        "DB_PASS=super_secret_database_password_999\n"
        'export API_TOKEN="ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
        "EMPTY_KEY=\n"
    )
    sanitized, mapping = redactor.sanitize(env_content)

    assert "super_secret_database_password_999" not in sanitized
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in sanitized
    assert "DB_PASS=[REDACTED_SECRET_" in sanitized
    assert 'export API_TOKEN="[REDACTED_SECRET_' in sanitized

    restored = redactor.restore(sanitized, mapping)
    assert restored == env_content


def test_redact_multiple_and_repeated_secrets():
    redactor = SecretRedactor()
    key1 = "sk-proj-1111111111111111111111111111"
    key2 = "AIzaSyD9999999999999999999999999999999"
    raw = f"Key1: {key1}, Key2: {key2}, Repeat Key1: {key1}"

    sanitized, mapping = redactor.sanitize(raw)
    assert key1 not in sanitized
    assert key2 not in sanitized
    # Same secret gets the same token
    assert sanitized.count("[REDACTED_SECRET_1]") == 2
    assert sanitized.count("[REDACTED_SECRET_2]") == 1

    restored = redactor.restore(sanitized, mapping)
    assert restored == raw


def test_sanitize_object():
    redactor = SecretRedactor()
    data = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {
                "role": "user",
                "content": "Here is my key sk-proj-1234567890abcdef1234567890abcdef",
            },
        ],
    }

    sanitized, mapping = redactor.sanitize_object(data)
    assert "[REDACTED_SECRET_1]" in sanitized["messages"][1]["content"]
    assert "sk-proj-" not in sanitized["messages"][1]["content"]
    assert len(mapping) == 1


# ============================================================================
# 2. Tests for LoopDetector
# ============================================================================

def test_loop_detector_tool_calls_loop_3_consecutive():
    detector = LoopDetector(max_repeats=3)
    tool_call = {
        "role": "assistant",
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "run_terminal", "arguments": '{"command": "pytest"}'},
            }
        ],
    }

    # 1st call -> False
    assert detector.check_loop([tool_call]) is False
    # 2nd consecutive -> False
    assert detector.check_loop([tool_call, tool_call]) is False
    # 3rd consecutive -> True (Loop detected!)
    assert detector.check_loop([tool_call, tool_call, tool_call]) is True
    assert detector.loops_detected == 1


def test_loop_detector_tool_calls_no_loop_when_args_differ():
    detector = LoopDetector(max_repeats=3)
    tc1 = {
        "role": "assistant",
        "tool_calls": [
            {"type": "function", "function": {"name": "run", "arguments": '{"cmd": "ls"}'}}
        ],
    }
    tc2 = {
        "role": "assistant",
        "tool_calls": [
            {"type": "function", "function": {"name": "run", "arguments": '{"cmd": "pwd"}'}}
        ],
    }
    tc3 = {
        "role": "assistant",
        "tool_calls": [
            {"type": "function", "function": {"name": "run", "arguments": '{"cmd": "whoami"}'}}
        ],
    }
    assert detector.check_loop([tc1, tc2, tc3]) is False
    assert detector.loops_detected == 0


def test_loop_detector_repeated_terminal_errors():
    detector = LoopDetector(max_repeats=3)
    error_msg = {
        "role": "tool",
        "content": "SyntaxError: invalid syntax in file.py at line 14: unexpected EOF",
    }

    messages = [
        {"role": "user", "content": "fix this error"},
        error_msg,
        {"role": "assistant", "content": "trying to fix"},
        error_msg,
        {"role": "assistant", "content": "trying again"},
        error_msg,
    ]

    assert detector.check_loop(messages) is True
    assert detector.loops_detected == 1


def test_loop_detector_repeated_user_prompts():
    detector = LoopDetector(max_repeats=3)
    user_msg = {"role": "user", "content": "Please retry step 1"}
    messages = [
        user_msg,
        {"role": "assistant", "content": "step 1 failed"},
        user_msg,
        {"role": "assistant", "content": "step 1 failed again"},
        user_msg,
    ]
    assert detector.check_loop(messages) is True
    assert detector.loops_detected == 1


def test_loop_detector_healthy_flow():
    detector = LoopDetector(max_repeats=3)
    messages = [
        {"role": "system", "content": "You are an assistant."},
        {"role": "user", "content": "List files"},
        {
            "role": "assistant",
            "tool_calls": [
                {"type": "function", "function": {"name": "ls", "arguments": "{}"}}
            ],
        },
        {"role": "tool", "content": "file1.txt file2.txt"},
        {"role": "assistant", "content": "Found 2 files."},
    ]
    assert detector.check_loop(messages) is False


# ============================================================================
# 3. Tests for Proxy /v1/chat/completions (TestClient / AsyncClient)
# ============================================================================

@pytest.fixture(autouse=True)
def reset_proxy_state():
    """Reset global proxy state between test runs."""
    state.loop_detector.reset()
    state.requests_total = 0
    state.secrets_redacted_total = 0
    state.upstream_url = "http://mock-upstream"


def test_proxy_loop_killer_triggers_429():
    tool_call = {
        "role": "assistant",
        "tool_calls": [
            {
                "type": "function",
                "function": {"name": "bash", "arguments": '{"cmd": "make test"}'},
            }
        ],
    }

    payload = {
        "model": "gpt-4o",
        "messages": [tool_call, tool_call, tool_call],
    }

    client = TestClient(app)
    response = client.post("/v1/chat/completions", json=payload)

    assert response.status_code == 429
    assert response.json() == {
        "error": "AgentGuard: loop detected, request killed to save tokens"
    }
    assert state.loops_killed == 1


def test_proxy_non_streaming_secret_redaction_and_restoration():
    secret_key = "sk-proj-123456789012345678901234567890"
    user_prompt = f"Use this token: {secret_key}"

    # Mock upstream handler to verify masking before upstream and echo back masked token
    def mock_upstream_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        # Upstream must NOT receive the raw secret!
        assert secret_key not in json.dumps(body)
        assert "[REDACTED_SECRET_1]" in json.dumps(body)

        # Upstream responds referencing the masked token
        resp_data = {
            "id": "chatcmpl-123",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Acknowledged token [REDACTED_SECRET_1] successfully.",
                    }
                }
            ],
        }
        return httpx.Response(200, json=resp_data)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_upstream_handler))
    state.client = mock_client

    client = TestClient(app)
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": user_prompt}],
        "stream": False,
    }

    response = client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 200

    resp_json = response.json()
    reply_content = resp_json["choices"][0]["message"]["content"]
    # The client response must have the secret restored!
    assert secret_key in reply_content
    assert "[REDACTED_SECRET_1]" not in reply_content
    assert reply_content == f"Acknowledged token {secret_key} successfully."


@pytest.mark.anyio
async def test_proxy_streaming_sse_restoration():
    secret_key = "sk-ant-api03-abcdef12345678901234567890"

    # Async generator stream where the masked token is split across chunks
    class AsyncSSEStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            # Chunk 1: partial token
            yield b'data: {"choices":[{"delta":{"content":"Secret is [REDACTED_"}}]}\n\n'
            # Chunk 2: completing the token
            yield b'data: {"choices":[{"delta":{"content":"SECRET_1]!"}}]}\n\n'
            # Chunk 3: end of stream
            yield b"data: [DONE]\n\n"

        async def aclose(self) -> None:
            pass

    def mock_stream_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert secret_key not in json.dumps(body)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=AsyncSSEStream(),
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_stream_handler))
    state.client = mock_client

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        req_payload = {
            "model": "claude-3-5-sonnet",
            "messages": [{"role": "user", "content": f"My Anthropic key is {secret_key}"}],
            "stream": True,
        }
        resp = await ac.post("/v1/chat/completions", json=req_payload)
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]

        full_stream_text = resp.text
        # The secret must be restored in the SSE stream
        assert secret_key in full_stream_text
        assert "[REDACTED_SECRET_1]" not in full_stream_text


def test_proxy_health_and_stats():
    client = TestClient(app)
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    stats_resp = client.get("/stats")
    assert stats_resp.status_code == 200
    data = stats_resp.json()
    assert "active_filters" in data
    assert "SecretRedactor" in data["active_filters"]
    assert "LoopDetector" in data["active_filters"]
