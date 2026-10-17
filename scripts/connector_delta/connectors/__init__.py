# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Explicit trusted registry. Only Claude Code and Codex are supported."""

from .claudecode.provider import ClaudeProvider
from .codex.provider import CodexProvider

PROVIDERS = {"claudecode": ClaudeProvider, "codex": CodexProvider}
