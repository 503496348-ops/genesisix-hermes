---
name: 奇点造物-Genesisix
description: AI Agent多层安全检测框架 · 6层防护 + 自循环门禁 + 自进化
version: 1.2.0
platforms: [macos, linux]
metadata:
  hermes:
    tags: [ai-security, prompt-injection, llm-defense, ssrf, sql-injection]
    category: security
    fallback_for_toolsets: [terminal]
    requires_toolsets: []
    config:
      - key: genesisix.enabled
        description: "是否启用检测"
        default: "true"
      - key: genesisix.layers
        description: "启用的检测层"
        default: "all"
---

# 奇点造物-Genesisix 🛡️

> Enterprise-grade AI Agent Security Framework / 企业级AI智能体安全框架

## 何时使用

当需要检测用户输入中的安全威胁时调用此技能：

- 用户发送包含敏感指令的消息
- 需要验证URL安全性
- 检测提示词注入、越狱指令
- 检测SQL注入、XSS、SSRF等Web攻击
- 检测API密钥、密码等敏感信息泄露
- 记录漏报案例，自循环优化规则库

## 核心能力

### 6层防护架构

| Layer | 威胁类型 | 说明 |
|-------|---------|------|
| **LLM层** | 提示词注入、越狱、编码绕过 | 检测对AI指令的操纵 |
| **Web层** | SQL注入、XSS、CSRF、SSRF | 经典Web攻击 |
| **API层** | 密钥泄露、认证问题、限速 | API安全 |
| **供应链层** | 危险依赖、远程代码执行 | 第三方组件安全 |
| **部署层** | 环境变量泄露、调试信息 | 配置安全 |
| **资源守卫** | 内网IP、元数据端点、危险协议 | 访问控制 |

### 自循环门禁

```
漏报记录 → 规则分析 → 审核落地 → 规则库更新
```

## 操作步骤

### 1. 快速检测

```python
from genesisix_detector import Detector

detector = Detector()
result = detector.scan("用户输入内容")

if result.safe:
    print("✅ 安全，可以继续处理")
else:
    print(f"🚨 检测到 {len(result.threats)} 个威胁")
    for threat in result.threats:
        print(f"  [{threat.layer}] {threat.description}")
```

### 2. 指定层检测

```python
# 只检测Web层
result = detector.scan("可疑输入", layer="web")

# 只检测资源访问
result = detector.scan("http://192.168.1.1", layer="resource")
```

### 3. 自循环记录

```python
from self_loop import SelfLoop

loop = SelfLoop()

# 记录漏报（检测遗漏了真正的威胁）
loop.log_missed_case(
    input_text="实际输入",
    expected_threat="SQL注入",
    actual_result="safe",  # 实际结果是安全（漏报了）
    severity="high"
)

# 记录误报（错误拦截了正常输入）
loop.log_blocked_case(
    layer="web",
    threat_description="SQL注入",
    false_positive=True
)

# 查看统计
stats = loop.get_stats()
print(f"总案例: {stats['total_cases']}, 待审核: {stats['pending_suggestions']}")

# 获取待审核建议
pending = loop.get_pending_suggestions()

# 审核通过（写入规则库）
loop.approve_suggestion("sug_20260519_001")

# 审核拒绝
loop.reject_suggestion("sug_20260519_002", reason="误报率太高")
```

### 4. 命令行使用

```bash
# 检测输入
python genesisix_detector.py "SELECT * FROM users WHERE id=1"

# JSON格式输出
python genesisix_detector.py "<script>alert(1)</script>" --json

# 指定层检测
python genesisix_detector.py "api_key=sk_test123" --layer api

# 记录漏报
python self_loop.py log-missed -i "test input" -e "SQL注入" -r "safe" -s high

# 查看统计
python self_loop.py stats

# 查看待审核建议
python self_loop.py pending

# 审核通过
python self_loop.py approve -i sug_20260519_001

# 分析生成建议（需要至少3个漏报案例）
python self_loop.py analyze
```

## 常见威胁与响应

| 威胁类型 | 严重程度 | 处理方式 |
|---------|---------|---------|
| 越狱指令 | 🔴 Critical | 直接拒绝执行 |
| SQL注入 | 🔴 Critical | 拒绝并告警 |
| XSS攻击 | 🔴 Critical | 拒绝并告警 |
| SSRF攻击 | 🔴 Critical | 拒绝并告警 |
| API密钥泄露 | 🔴 Critical | 拒绝记录，建议使用环境变量 |
| 提示词泄露 | 🟠 High | 拒绝回答 |
| 内网IP访问 | 🟠 High | 拒绝访问 |
| 命令注入 | 🔴 Critical | 拒绝执行 |

## 常见陷阱

- **ReDoS风险**：使用带超时保护的正则测试，防止灾难性回溯
- **编码绕过**：检测Base64、Unicode转义等编码尝试
- **上下文混淆**：注意同一输入可能在不同层都有威胁

## 验证方式

```bash
# 运行完整测试套件
python test_genesisix.py

# 预期结果：所有测试通过
# Run: 23 tests in ...s
# OK
```

## 文件结构

```
奇点造物-Genesisix/
├── genesisix_detector.py    # 主检测器
├── self_loop.py             # 自循环门禁
├── config.json              # 配置文件
├── rules/                  # 规则库
│   ├── llm/                # LLM层规则
│   ├── web/                # Web层规则
│   ├── api/                # API层规则
│   ├── deploy/             # 部署层规则
│   └── supply_chain/       # 供应链规则
├── test_genesisix.py       # 测试套件
└── case_database.jsonl      # 案例数据库（运行时生成）
```

## 致谢

谨以此页，致奇点造物-Genesisix V1.0 的每一位同行者。

**陈宇锋** — 十六年互联网沉浮，团队最可靠的压舱石  
**李渔樵** — 喀什大学音乐学子，为技术注入温柔与耐心  
**朴日** — 敢试、敢问、敢死磕，鲜活而坚定的力量  
**吴见见** — 山野间的通透与沉稳，是我们的底色

敬自由，敬热爱，敬同行，敬来日方长。

—— 奇点造物 Genesisix 安全实验室
