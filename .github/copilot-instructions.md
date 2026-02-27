# nanobot — Copilot Instructions

Ultra-lightweight personal AI assistant framework (~4,000 lines). Python ≥3.11, MIT license.

## Architecture

```
Channel  →  MessageBus (asyncio.Queue)  →  AgentLoop  →  LLMProvider  →  ToolRegistry
                                                ↓
                                         ContextBuilder  (AGENTS.md, SOUL.md, skills, memory)
```

Key modules:
- [nanobot/agent/loop.py](../nanobot/agent/loop.py) — ReAct agent loop (max 40 iterations), `/new` `/stop` `/help` slash commands
- [nanobot/agent/context.py](../nanobot/agent/context.py) — assembles system prompt (workspace files → memory → skills)
- [nanobot/agent/memory.py](../nanobot/agent/memory.py) — two-layer store: `MEMORY.md` (LLM-rewritten facts) + `HISTORY.md` (append-only log); consolidation triggers at `memory_window` messages
- [nanobot/agent/tools/registry.py](../nanobot/agent/tools/registry.py) — JSON-schema validation before `execute()`; error strings get retry hints appended
- [nanobot/channels/manager.py](../nanobot/channels/manager.py) — guarded-import pattern per channel (only imports if `enabled`)
- [nanobot/providers/registry.py](../nanobot/providers/registry.py) — `PROVIDERS` tuple drives auto-detection by model keyword / key prefix / API base
- [nanobot/config/schema.py](../nanobot/config/schema.py) — Pydantic `BaseSettings`, env prefix `NANOBOT_`, nested delimiter `__`
- [bridge/src/](../bridge/src/) — TypeScript WhatsApp bridge (websocket proxy to wpp-connect)

## Adding a New Tool

Subclass `Tool` from [nanobot/agent/tools/base.py](../nanobot/agent/tools/base.py); implement `name`, `description`, `parameters` (JSON Schema dict), and `async execute(**kwargs) -> str`. Register in `AgentLoop._register_default_tools()`.

Reference: [nanobot/agent/tools/shell.py](../nanobot/agent/tools/shell.py), [nanobot/agent/tools/web.py](../nanobot/agent/tools/web.py)

## Adding a New Channel

Subclass `BaseChannel` from [nanobot/channels/base.py](../nanobot/channels/base.py); implement `name`, `async start()`, `async stop()`, `async send()`. Call inherited `_handle_message()` with `sender_id`, `chat_id`, `content` — it enforces `allow_from` and publishes to the `MessageBus`. Add guarded import to `ChannelManager._init_channels()` and a config class in `schema.py`.

Reference: [nanobot/channels/telegram.py](../nanobot/channels/telegram.py)

## Adding a New Provider

1. Add a `ProviderSpec` to the `PROVIDERS` tuple in [nanobot/providers/registry.py](../nanobot/providers/registry.py) — copy an existing entry, set `name`, `keywords`, `env_key`, `litellm_prefix`.
2. Add a `ProviderConfig` field to `ProvidersConfig` in [nanobot/config/schema.py](../nanobot/config/schema.py).

`LiteLLMProvider` handles the rest. Custom providers go in [nanobot/providers/custom_provider.py](../nanobot/providers/custom_provider.py).

## Skills

Skills are Markdown files at `skills/<name>/SKILL.md` (workspace: `~/.nanobot/workspace/skills/`, built-in: [nanobot/skills/](../nanobot/skills/)). Frontmatter YAML controls metadata:

```yaml
---
name: github
description: "Interact with GitHub using the gh CLI"
metadata: {"nanobot":{"emoji":"🐙","requires":{"bins":["gh"]}}}
---
```

Set `"nanobot":{"always": true}` to embed the skill into every system prompt. Otherwise it's listed in XML and loaded on demand by the agent via `read_file`.

Reference: [nanobot/agent/skills.py](../nanobot/agent/skills.py), [nanobot/skills/README.md](../nanobot/skills/README.md)

## Build & Test

```bash
# Install (dev)
pip install -e ".[dev,matrix]"

# Run tests
pytest tests/

# Specific test file
pytest tests/test_message_tool.py -v

# Check line count
bash core_agent_lines.sh

# Run locally
nanobot start --channel cli
```

## Project Conventions

- **Async throughout**: all I/O is `async/await`; channels run as `asyncio.Task`s; never block the event loop
- **`loguru`** for logging (`from loguru import logger`); not the stdlib `logging`
- **Pydantic v2** for all config and data models
- **`nanobot/templates/AGENTS.md`** is a *template* deployed to user workspaces — not instructions for this dev repo
- Tool result truncation: session history stores at most 500 chars per tool result (`_save_turn`)
- `[Runtime Context]` injected as an untrusted `user` message (not system) just before the real message
- Provider selection priority: model-keyword match → key-prefix match → API-base substring → fallback to `openai`
- The `bridge/` TypeScript component is a standalone npm package; build with `cd bridge && npm install && npm run build`
