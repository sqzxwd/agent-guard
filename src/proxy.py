"""Proxy firewall application for agent-guard.

Proxies /v1/chat/completions requests, intercepts infinite loops,
masks secrets before sending to upstream, and restores secrets on response.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import json
import os
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
import httpx

from src.filters.loop_detector import LoopDetector
from src.filters.redactor import SecretRedactor


class ProxyState:
    """Shared state for proxy statistics and configuration."""

    def __init__(self, upstream_url: str = "https://api.openai.com") -> None:
        self.upstream_url: str = upstream_url
        self.redactor: SecretRedactor = SecretRedactor()
        self.loop_detector: LoopDetector = LoopDetector(max_repeats=3)
        self.client: httpx.AsyncClient | None = None
        self.requests_total: int = 0
        self.secrets_redacted_total: int = 0

    @property
    def loops_killed(self) -> int:
        return self.loop_detector.loops_detected


# Global state instance
state = ProxyState(upstream_url=os.getenv("UPSTREAM_URL", "https://api.openai.com"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan to manage httpx.AsyncClient."""
    if state.client is None:
        state.client = httpx.AsyncClient(timeout=60.0)
    yield
    if state.client is not None:
        await state.client.aclose()


app = FastAPI(
    title="agent-guard",
    description="Local lightweight proxy-firewall for AI agents",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check() -> dict[str, Any]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "upstream": state.upstream_url,
        "loops_killed": state.loops_killed,
        "secrets_redacted": state.secrets_redacted_total,
        "requests_total": state.requests_total,
    }


@app.get("/stats")
async def stats() -> dict[str, Any]:
    """Detailed statistics endpoint."""
    return {
        "upstream_url": state.upstream_url,
        "active_filters": ["SecretRedactor", "LoopDetector"],
        "loop_threshold": state.loop_detector.max_repeats,
        "loops_killed": state.loops_killed,
        "secrets_redacted": state.secrets_redacted_total,
        "requests_total": state.requests_total,
    }


def _clean_headers(headers: dict[str, str]) -> dict[str, str]:
    """Filter out hop-by-hop headers for forwarding to upstream."""
    excluded = {"host", "content-length", "content-encoding", "connection"}
    return {k: v for k, v in headers.items() if k.lower() not in excluded}


async def _stream_and_restore(
    upstream_resp: httpx.Response,
    mapping: dict[str, str],
) -> AsyncGenerator[str, None]:
    """Stream upstream response chunks, restoring redacted secrets in-flight.

    Handles:
    1. Direct token replacement in whole chunks.
    2. TCP stream buffering across partial chunk boundaries.
    3. SSE delta-level token splitting where an LLM emits a token across multiple SSE events.
    """
    buffer = ""
    pending_delta_prefix = ""

    try:
        async for chunk in upstream_resp.aiter_text():
            if not mapping:
                yield chunk
                continue

            buffer += chunk

            # Process complete SSE events delimited by double newline
            while "\n\n" in buffer:
                event_str, buffer = buffer.split("\n\n", 1)
                event_stripped = event_str.strip()

                if not event_stripped:
                    yield "\n\n"
                    continue

                if event_stripped == "data: [DONE]":
                    yield f"{event_str}\n\n"
                    continue

                # First try direct string replacement of complete tokens
                for token in sorted(mapping.keys(), key=len, reverse=True):
                    if token in event_str:
                        event_str = event_str.replace(token, mapping[token])

                # Check if this is an SSE JSON event with delta.content
                if event_stripped.startswith("data: "):
                    payload_raw = event_stripped[6:].strip()
                    try:
                        payload = json.loads(payload_raw)
                        choices = payload.get("choices", [])
                        if choices and isinstance(choices, list):
                            delta = choices[0].get("delta", {})
                            if (
                                isinstance(delta, dict)
                                and "content" in delta
                                and isinstance(delta["content"], str)
                            ):
                                content = delta["content"]
                                if pending_delta_prefix:
                                    content = pending_delta_prefix + content
                                    pending_delta_prefix = ""

                                # Check complete tokens
                                for token in sorted(mapping.keys(), key=len, reverse=True):
                                    if token in content:
                                        content = content.replace(token, mapping[token])

                                # Check partial token prefix at end of content
                                for token in mapping:
                                    for k in range(len(token) - 1, 0, -1):
                                        pref = token[:k]
                                        if content.endswith(pref):
                                            pending_delta_prefix = pref
                                            content = content[:-k]
                                            break
                                    if pending_delta_prefix:
                                        break

                                delta["content"] = content
                                event_str = f"data: {json.dumps(payload)}"
                    except Exception:
                        pass

                yield f"{event_str}\n\n"

        # End of stream: flush any leftover buffer or pending prefix
        if buffer or pending_delta_prefix:
            tail = buffer
            if pending_delta_prefix:
                tail = pending_delta_prefix + tail
            for token in sorted(mapping.keys(), key=len, reverse=True):
                tail = tail.replace(token, mapping[token])
            if tail:
                yield tail
    finally:
        await upstream_resp.aclose()


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    """Proxy OpenAI chat completions with loop killing and secret redacting."""
    state.requests_total += 1

    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    messages = body.get("messages", [])
    if isinstance(messages, list):
        # 1. Loop detection
        if state.loop_detector.check_loop(messages):
            return JSONResponse(
                status_code=429,
                content={"error": "AgentGuard: loop detected, request killed to save tokens"},
            )

    # 2. Secret redaction before sending to upstream
    sanitized_body, mapping = state.redactor.sanitize_object(body)
    if mapping:
        state.secrets_redacted_total += len(mapping)

    # Prepare upstream URL and headers
    upstream_target = f"{state.upstream_url.rstrip('/')}/v1/chat/completions"
    headers = _clean_headers(dict(request.headers))

    is_stream = bool(sanitized_body.get("stream", False))

    client = state.client
    if client is None:
        client = httpx.AsyncClient(timeout=60.0)

    try:
        req = client.build_request(
            method="POST",
            url=upstream_target,
            json=sanitized_body,
            headers=headers,
        )

        if is_stream:
            upstream_resp = await client.send(req, stream=True)
            if upstream_resp.status_code >= 400:
                err_body = await upstream_resp.aread()
                await upstream_resp.aclose()
                return Response(
                    content=err_body,
                    status_code=upstream_resp.status_code,
                    media_type="application/json",
                )

            return StreamingResponse(
                _stream_and_restore(upstream_resp, mapping),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                },
            )
        else:
            upstream_resp = await client.send(req)
            resp_text = upstream_resp.text

            # Restore any redacted tokens in the response
            if mapping:
                resp_text = state.redactor.restore(resp_text, mapping)

            content_type = upstream_resp.headers.get("content-type", "application/json")
            return Response(
                content=resp_text.encode("utf-8"),
                status_code=upstream_resp.status_code,
                media_type=content_type,
            )

    except httpx.RequestError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": "Upstream connection error", "detail": str(exc)},
        )
