# Model Selection Guide

Configuration options for different use cases and performance requirements.

## Model Configurations

### 1. High Performance (Most Capable)

```bash
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
OPENAI_MODEL=gpt-4o
ANTHROPIC_MAX_TOKENS=4000
OPENAI_MAX_TOKENS=4000
ANTHROPIC_TEMPERATURE=0.1
OPENAI_TEMPERATURE=0.1
```

### 2. Cost-Optimized (Faster, Cheaper)

```bash
ANTHROPIC_MODEL=claude-3-5-haiku-20241022
OPENAI_MODEL=gpt-4o-mini
ANTHROPIC_MAX_TOKENS=1000
OPENAI_MAX_TOKENS=1000
ANTHROPIC_TEMPERATURE=0.2
OPENAI_TEMPERATURE=0.2
```

### 3. Development (Fastest)

```bash
ANTHROPIC_MODEL=claude-3-5-haiku-20241022
OPENAI_MODEL=gpt-3.5-turbo
ANTHROPIC_MAX_TOKENS=500
OPENAI_MAX_TOKENS=500
ANTHROPIC_TEMPERATURE=0.3
OPENAI_TEMPERATURE=0.3
```

## Available Models

### Anthropic Models

- `claude-3-5-sonnet-20241022` - Latest, most capable
- `claude-3-5-haiku-20241022` - Faster, cheaper
- `claude-3-opus-20240229` - Previous generation

### OpenAI Models

- `gpt-4o` - Latest, most capable
- `gpt-4o-mini` - Faster, cheaper
- `gpt-4-turbo` - Previous generation
- `gpt-3.5-turbo` - Fastest, cheapest

## Reference

https://artificialanalysis.ai/models
