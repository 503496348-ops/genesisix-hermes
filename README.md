# 奇点造物-Genesisix v2.0.0 — Hermes版

AI Agent 多层安全检测框架 — 13层防护 + 自循环学习 + Hook系统

## 这是什么

奇点造物-Genesisix 是专为 AI Agent 系统设计的安全中间件，在输入到达大模型之前进行多层扫描，拦截恶意指令、数据外泄、工具投毒等攻击。

**Hermes版**是Python原生实现，直接集成到Hermes Agent的Python环境中，无需Node.js。

## 快速开始

```python
from genesisix_detector import Detector

detector = Detector()

# 扫描用户输入
result = detector.scan('用户说的话')
if not result.safe:
    print(f'拦截: {result.threats}')
    print(f'动作: {result.action}')  # pass / alert / block
```

## 13层防护

| 层 | 检测内容 |
|----|---------|
| Preprocess | 结构化清理/编码归一化/金丝雀注入/元数据提取 |
| Resource Guard | SSRF/内网IP/危险协议/危险路径/域名白名单/端口扫描 |
| LLM | Prompt注入/越狱/多语言绕过/Few-Shot/间接注入/多轮越狱/提示泄露 |
| Web | SQL注入/XSS/CSRF/SSRF/命令注入/路径遍历/SSTI/XXE |
| API | 密钥泄露/速率限制/认证绕过/GraphQL/JWT/OAuth |
| Supply Chain | 危险依赖/Typosquat/恶意导入/Skill完整性 |
| Deploy | 环境变量泄露/Docker/CI-CD/源码泄露 |
| Ingest | 零宽字符/同形字/Trojan Source/隐藏文本/编码绕过 |
| Outbound | PII泄露/DNS外泄/恶意URL/短链接/内网地址 |
| MCP Security | 工具投毒/Schema验证/危险工具/数据外泄/OAuth/签名 |
| Memory | 记忆投毒/Checkpoint篡改 |
| Integrity | Profile后门/反向Shell/凭据窃取 |
| Multi-Agent | 跨Agent注入/身份冒充/工具链攻击/信任评估 |

## 专用 API

```python
detector = Detector()

# 资源安全扫描（SSRF/协议/路径/端口）
detector.scan_resource('http://127.0.0.1:6379/')

# MCP工具扫描
detector.scan_mcp(tool_schema, tool_output)

# 外发数据扫描
detector.scan_outbound('https://api.example.com/data')

# 记忆安全扫描
detector.scan_memory(memory_content)

# Profile完整性扫描
detector.scan_integrity(agents_md_content, 'AGENTS.md')

# 多Agent安全扫描
detector.scan_multi_agent(message, {'sourceAgent': 'user', 'targetAgent': 'coder'})

# 多轮越狱扫描
detector.scan_multiturn(recent_messages, {'windowSize': 10})

# 摄入层扫描
detector.scan_ingest(content, {'includeLlm': True})

# 代码扫描
detector.scan_code(code_content)

# 快速检查（仅LLM层）
safe = detector.quick_check(input_text)

# 统计信息
stats = detector.get_stats()

# 热重载
detector.reload()
```

## Hook 系统

```python
detector = Detector()

# 扫描前拦截
detector.before_scan(lambda ctx: {'reject': True, 'rejectReason': 'too long'} if len(ctx['input']) > 50000 else ctx)

# 发现威胁时记录
detector.on_threat(lambda ctx: log(f"威胁: {ctx['threat']}"))

# 扫描后修改结果
detector.after_scan(lambda ctx: ctx)

# 注销hook
unsub = detector.on_threat(my_callback)
unsub()  # 移除
```

## 白名单

在 `whitelist.json` 中配置：

```json
{
  "users": ["admin-user-id"],
  "sessions": ["trusted-session-id"],
  "keywords": ["系统状态查询"],
  "patterns": ["^test_.*"]
}
```

白名单用户/会话/关键词匹配后跳过所有13层检测。

## 置信度阈值

在 `config.json` 中配置：

```json
{
  "detection": {
    "alert_threshold": 0.5,
    "block_threshold": 0.8
  }
}
```

- `pass`：置信度 < 0.5，放行
- `alert`：0.5 ≤ 置信度 < 0.8，告警
- `block`：置信度 ≥ 0.8，拦截

## 自循环学习

```python
from self_loop import SelfLoop
from pathlib import Path

loop = SelfLoop(Path('./data'))

# 记录漏报
loop.log_missed_case(input_text='恶意输入', expected_threat='prompt_injection', layer='llm')

# 分析并生成规则建议
suggestions = loop.analyze_and_suggest()

# 审核落地
loop.approve_suggestion(suggestions[0]['id'])
```

## 安装

```bash
# 复制到Hermes skills目录
cp -r 奇点造物-Genesisix ~/.hermes/skills/security/genesisix

# 或直接使用
python3 genesisix_detector.py "要检测的输入"
python3 genesisix_detector.py "要检测的输入" --layer llm --json
```

## 测试

```bash
python3 test_genesisix.py
# 21 tests, 0 failures
```

## 版本历史

| 版本 | 变化 |
|------|------|
| v2.0.0 | 大版本升级：+7层(Resource Guard/Preprocess/Ingest/Outbound/MCP/Memory/Integrity/Multi-Agent) +Hook系统 +白名单 +置信度阈值 +全部专用API +SelfLoop集成 +825条规则 +ReDoS防护 |
| v1.5.0 | 6层防护 + 自循环门禁 |
| v1.0.0 | 初始版本 |
