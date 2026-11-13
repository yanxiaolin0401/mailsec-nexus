"""Official provider presets verified 2026-11-12; model IDs remain editable."""

PROVIDERS = [
    {
        "id": "deepseek", "name": "DeepSeek", "website": "https://www.deepseek.com",
        "provider": "openai", "base_url": "https://api.deepseek.com",
        "models": ["deepseek-flash", "deepseek-v4-pro"],
        "docs_url": "https://api-docs.deepseek.com/",
    },
    {
        "id": "qwen", "name": "阿里云百炼 / 通义千问", "website": "https://bailian.console.aliyun.com",
        "provider": "openai", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": ["qwen-plus", "qwen-flash"],
        "docs_url": "https://help.aliyun.com/zh/model-studio/first-api-call-to-qwen",
    },
    {
        "id": "openai", "name": "OpenAI", "website": "https://platform.openai.com",
        "provider": "openai", "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4.1-mini"],
        "docs_url": "https://developers.openai.com/api/docs/models/gpt-4.1-mini",
    },
    {
        "id": "anthropic", "name": "Anthropic / Claude", "website": "https://platform.claude.com",
        "provider": "anthropic", "base_url": "https://api.anthropic.com/v1",
        "models": ["claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
        "docs_url": "https://platform.claude.com/docs/en/about-claude/model-deprecations",
    },
]
