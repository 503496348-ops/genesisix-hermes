---
name: genesisix-hermes
description: "Use when scanning AI agent input/output for security threats in Hermes Python environment. 13-layer, 825-rule security detector with self-learning loop, Hook system, and all specialized APIs."
version: 2.0.0
author: 奇点造物
license: MIT
metadata:
  hermes:
    tags: [security, ai-agent, prompt-injection, hermes-native, python]
    related_skills: [clawsafe, security-engineering, incident-response-sop]
---

# 奇点造物-Genesisix v2.0.0 — Hermes版

> Python原生的AI Agent安全检测框架，13层防护 + 自循环学习 + Hook系统 + 825条规则

## When to Use

- Hermes Agent Python环境中需要安全扫描
- 不想引入Node.js依赖
- 需要与Hermes原生memory/cron系统集成

## Quick Start

```python
from genesisix_detector import Detector

detector = Detector()
result = detector.scan('用户输入')
```

## API

```python
# 全面扫描
detector.scan(input_text)

# 指定层扫描
detector.scan_llm(input_text)
detector.scan_outbound(url)
detector.scan_resource(url)
detector.scan_memory(content)
detector.scan_integrity(content, filepath)
detector.scan_mcp(tool_schema, tool_output)
detector.scan_multiturn(messages)

# 自循环
detector.log_missed_case(...)
detector.analyze_and_suggest()
detector.approve_suggestion(suggestion_id)
```

## Common Pitfalls

1. **正则超时** — ReDoS防护已内置，超时的规则会被跳过
2. **白名单配置** — 编辑whitelist.json后需调用detector.reload()
3. **规则文件路径** — rules/目录必须与genesisix_detector.py同级
