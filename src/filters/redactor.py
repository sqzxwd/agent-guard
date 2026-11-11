"""Secret redactor module for agent-guard.

Detects, masks, and restores sensitive API keys, secrets, and environment variable assignments.
"""

from __future__ import annotations

import re
from typing import Any


class SecretRedactor:
    """Detects and redacts sensitive API keys and secrets from text.

    Supported patterns:
    - OpenAI API keys (sk-*)
    - Anthropic API keys (sk-ant-*)
    - Google AI keys (AIza...)
    - AWS access keys (AKIA*, ASIA*, etc.) and secret access keys
    - JWT tokens (eyJ...)
    - .env format assignments (KEY=VALUE)
    """

    # Strict regex patterns for specific API key formats
    OPENAI_PATTERN = re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_\-]{20,}\b")
    ANTHROPIC_PATTERN = re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")
    GOOGLE_AI_PATTERN = re.compile(r"\bAIza[0-9A-Za-z\-_]{32,40}\b")
    AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA|AROA|AIPA)[0-9A-Z]{16}\b")
    AWS_SECRET_KEY_PATTERN = re.compile(
        r"(?i)\b(?:aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    )
    JWT_PATTERN = re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b")

    # .env format: KEY=VALUE or export KEY=VALUE
    ENV_LINE_PATTERN = re.compile(
        r"(?m)^[ \t]*((?:export[ \t]+)?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(['\"]?)(.+?)\3[ \t]*(?:\r?\n|$)"
    )
    # Inline KEY=VALUE for common secret key names
    INLINE_ENV_PATTERN = re.compile(
        r"(?:\b|(?<=[\s,;]))([A-Za-z_][A-Za-z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE)[A-Za-z0-9_]*)\s*=[ \t]*(['\"]?)(.+?)\2(?=[\s,;]|$)"
    )

    def sanitize(self, text: str) -> tuple[str, dict[str, str]]:
        """Sanitize text by replacing sensitive secrets with [REDACTED_SECRET_X] tokens.

        Returns:
            tuple[str, dict[str, str]]: (sanitized_text, mapping_dict)
            where mapping_dict maps token string -> original secret value.
        """
        if not text:
            return text, {}

        mapping: dict[str, str] = {}
        secret_to_token: dict[str, str] = {}
        counter = 1

        def _get_token(secret: str) -> str:
            nonlocal counter
            if secret in secret_to_token:
                return secret_to_token[secret]
            token = f"[REDACTED_SECRET_{counter}]"
            counter += 1
            secret_to_token[secret] = token
            mapping[token] = secret
            return token

        # 1. Process .env lines (e.g. KEY=VALUE or export KEY=VALUE)
        def _replace_env_line(match: re.Match[str]) -> str:
            prefix = match.group(1) or ""
            key = match.group(2)
            quote = match.group(3) or ""
            val = match.group(4)
            if val.startswith("[REDACTED_SECRET_") and val.endswith("]"):
                return match.group(0)
            token = _get_token(val)
            trailing_newline = "\n" if match.group(0).endswith("\n") else ""
            return f"{prefix}{key}={quote}{token}{quote}{trailing_newline}"

        result = self.ENV_LINE_PATTERN.sub(_replace_env_line, text)

        # 2. Process inline secret variable assignments (e.g. API_KEY=abc)
        def _replace_inline_env(match: re.Match[str]) -> str:
            key = match.group(1)
            quote = match.group(2) or ""
            val = match.group(3)
            if val.startswith("[REDACTED_SECRET_") and val.endswith("]"):
                return match.group(0)
            token = _get_token(val)
            return f"{key}={quote}{token}{quote}"

        result = self.INLINE_ENV_PATTERN.sub(_replace_inline_env, result)

        # 3. Process AWS secret key with key prefix context
        def _replace_aws_secret(match: re.Match[str]) -> str:
            full_str = match.group(0)
            secret_val = match.group(1)
            if secret_val.startswith("[REDACTED_SECRET_") and secret_val.endswith("]"):
                return full_str
            token = _get_token(secret_val)
            return full_str.replace(secret_val, token)

        result = self.AWS_SECRET_KEY_PATTERN.sub(_replace_aws_secret, result)

        # 4. Process direct standalone API key patterns
        standalone_patterns = [
            self.OPENAI_PATTERN,
            self.ANTHROPIC_PATTERN,
            self.GOOGLE_AI_PATTERN,
            self.AWS_ACCESS_KEY_PATTERN,
            self.JWT_PATTERN,
        ]

        for pattern in standalone_patterns:
            def _replace_standalone(match: re.Match[str]) -> str:
                secret_val = match.group(0)
                if secret_val.startswith("[REDACTED_SECRET_") and secret_val.endswith("]"):
                    return secret_val
                return _get_token(secret_val)

            result = pattern.sub(_replace_standalone, result)

        return result, mapping

    def restore(self, text: str, mapping: dict[str, str]) -> str:
        """Restore all redacted tokens in text back to their original secret values.

        Tokens are processed in order of descending length to prevent partial replacement
        collisions (e.g., [REDACTED_SECRET_10] before [REDACTED_SECRET_1]).
        """
        if not text or not mapping:
            return text

        restored = text
        for token in sorted(mapping.keys(), key=len, reverse=True):
            restored = restored.replace(token, mapping[token])
        return restored

    def sanitize_object(self, obj: Any) -> tuple[Any, dict[str, str]]:
        """Recursively sanitize any JSON-serializable object (dict, list, str, etc.).

        Returns:
            tuple[Any, dict[str, str]]: Sanitized object copy and the combined mapping dict.
        """
        combined_mapping: dict[str, str] = {}
        secret_to_token: dict[str, str] = {}
        counter = 1

        def _get_token(secret: str) -> str:
            nonlocal counter
            if secret in secret_to_token:
                return secret_to_token[secret]
            token = f"[REDACTED_SECRET_{counter}]"
            counter += 1
            secret_to_token[secret] = token
            combined_mapping[token] = secret
            return token

        def _walk(val: Any) -> Any:
            if isinstance(val, str):
                s_text, s_map = self.sanitize(val)
                # Remap tokens so all tokens across the object are unique and tracked
                for t, orig in s_map.items():
                    global_tok = _get_token(orig)
                    if global_tok != t:
                        s_text = s_text.replace(t, global_tok)
                return s_text
            elif isinstance(val, dict):
                return {k: _walk(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [_walk(item) for item in val]
            return val

        sanitized_obj = _walk(obj)
        return sanitized_obj, combined_mapping
