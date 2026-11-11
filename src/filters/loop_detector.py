"""Loop detector module for agent-guard.

Detects repetitive tool calls, repeating compilation/terminal errors, and cycling requests
to kill agent infinite loops and prevent token waste.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


class LoopDetector:
    """Detects infinite loops in AI agent conversations.

    Identifies:
    1. Consecutive identical tool calls (same function and arguments).
    2. Consecutive identical compiler/terminal/tool error outputs.
    3. Consecutive identical user queries or assistant responses.

    Kills the loop when the same request, tool call, or error repeats `max_repeats` times in a row (default: 3).
    """

    ERROR_KEYWORDS = (
        "error",
        "exception",
        "traceback",
        "syntaxerror",
        "typeerror",
        "valueerror",
        "nameerror",
        "failed",
        "failure",
        "fatal",
        "command not found",
        "exit status",
        "exit code",
        "compilation error",
    )

    def __init__(self, max_repeats: int = 3) -> None:
        self.max_repeats: int = max_repeats
        self.loops_detected: int = 0
        self._request_history: list[str] = []

    def _normalize_string(self, text: str) -> str:
        """Normalize string by removing volatile memory addresses and collapsing whitespace."""
        # Replace memory addresses like 0x7fa1234b with placeholder
        text = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", text)
        return " ".join(text.strip().lower().split())

    def _hash_tool_call(self, call: dict[str, Any]) -> str:
        """Compute deterministic SHA-256 hash of a tool call."""
        fn = call.get("function") if isinstance(call.get("function"), dict) else {}
        name = fn.get("name", "") or call.get("name", "")
        args = fn.get("arguments", "") or call.get("arguments", "")

        # Canonicalize JSON arguments if possible
        if isinstance(args, dict):
            canon_args = json.dumps(args, sort_keys=True)
        elif isinstance(args, str):
            try:
                parsed = json.loads(args)
                canon_args = json.dumps(parsed, sort_keys=True)
            except Exception:
                canon_args = self._normalize_string(args)
        else:
            canon_args = str(args)

        payload = f"tool:{name}:{canon_args}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _hash_error_or_output(self, text: str) -> str:
        """Compute deterministic SHA-256 hash of error or tool output."""
        normalized = self._normalize_string(text)
        payload = f"error:{normalized}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _hash_message_content(self, role: str, content: Any) -> str:
        """Compute deterministic SHA-256 hash of a message's content."""
        if isinstance(content, str):
            norm_content = self._normalize_string(content)
        elif isinstance(content, list):
            norm_content = self._normalize_string(json.dumps(content, sort_keys=True))
        else:
            norm_content = str(content)
        payload = f"msg:{role}:{norm_content}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _has_consecutive_repeats(self, hashes: list[str]) -> bool:
        """Check if any hash repeats `max_repeats` times consecutively."""
        if len(hashes) < self.max_repeats:
            return False

        for i in range(len(hashes) - self.max_repeats + 1):
            window = hashes[i : i + self.max_repeats]
            if len(window) == self.max_repeats and all(h == window[0] for h in window):
                return True
        return False

    def check_loop(self, messages: list[dict[str, Any]]) -> bool:
        """Analyze message history for loops.

        Triggers True if:
        - 3 consecutive identical tool calls are found.
        - 3 consecutive identical compiler/terminal/tool error outputs are found.
        - 3 consecutive identical user requests or assistant responses are found.
        - The current request state is identical 3 times in a row.

        Returns:
            bool: True if a loop is detected, False otherwise.
        """
        if not messages:
            return False

        # 1. Check Tool Calls
        tool_call_hashes: list[str] = []
        for msg in messages:
            tool_calls = msg.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if isinstance(tc, dict):
                        tool_call_hashes.append(self._hash_tool_call(tc))

            # Also check legacy function_call
            fn_call = msg.get("function_call")
            if isinstance(fn_call, dict):
                tool_call_hashes.append(self._hash_tool_call(fn_call))

        if self._has_consecutive_repeats(tool_call_hashes):
            self.loops_detected += 1
            return True

        # 2. Check Tool / Terminal / Compiler Error outputs
        error_hashes: list[str] = []
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if not isinstance(content, str) or not content.strip():
                continue

            content_lower = content.lower()
            is_tool = role in ("tool", "function")
            has_error_kw = any(kw in content_lower for kw in self.ERROR_KEYWORDS)

            if is_tool or has_error_kw:
                error_hashes.append(self._hash_error_or_output(content))

        if self._has_consecutive_repeats(error_hashes):
            self.loops_detected += 1
            return True

        # 3. Check Repeating User Queries
        user_hashes: list[str] = [
            self._hash_message_content("user", msg.get("content", ""))
            for msg in messages
            if msg.get("role") == "user" and msg.get("content")
        ]
        if self._has_consecutive_repeats(user_hashes):
            self.loops_detected += 1
            return True

        # 4. Check Repeating Assistant Messages (without tool calls)
        assistant_hashes: list[str] = [
            self._hash_message_content("assistant", msg.get("content", ""))
            for msg in messages
            if msg.get("role") == "assistant"
            and msg.get("content")
            and not msg.get("tool_calls")
        ]
        if self._has_consecutive_repeats(assistant_hashes):
            self.loops_detected += 1
            return True

        # 5. Check Cross-Request State (when client sends messages turn-by-turn)
        current_request_hash = hashlib.sha256(
            json.dumps(messages, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self._request_history.append(current_request_hash)
        if self._has_consecutive_repeats(self._request_history):
            self.loops_detected += 1
            return True

        return False

    def reset(self) -> None:
        """Reset internal history and loop counters."""
        self.loops_detected = 0
        self._request_history.clear()
