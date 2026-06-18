#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import io

# Windows终端UTF-8支持（局部化，只在CLI输出时使用）
def _setup_windows_stdout():
    if sys.platform == 'win32':
        return io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    return sys.stdout
"""
奇点造物-Genesisix Security Detector - Python版 (Hermes Native)
多层安全检测框架 · 11层防护 + 自循环门禁 + Resource Guard

@author 小乖 (OpenClaw Agent) → Hermes移植版
@version 2.0.0
"""

import re
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

# Behavioral analysis modules (AtomCollide-智械工坊团队)
try:
    from behavioral_ast import analyze_python_ast
    _HAS_AST_ANALYZER = True
except ImportError:
    _HAS_AST_ANALYZER = False

try:
    from taint_tracking import analyze_taint
    _HAS_TAINT_TRACKER = True
except ImportError:
    _HAS_TAINT_TRACKER = False

# ============================================================
# 常量与配置
# ============================================================

SKILL_PATH = Path(__file__).parent
CONFIG_PATH = SKILL_PATH / "config.json"
RULES_DIR = SKILL_PATH / "rules"
LAYERS_DIR = SKILL_PATH / "layers"

REGEX_TIMEOUT_SEC = 1.0  # ReDoS保护超时

@dataclass
class Threat:
    """检测到的威胁"""
    layer: str
    rule_id: str
    description: str
    severity: str  # critical/high/medium/low
    confidence: float
    matched: str
    mitigation: str

@dataclass
class ScanResult:
    """扫描结果"""
    safe: bool
    threats: List[Threat]
    confidence: float
    layers_scanned: List[str]
    action: str = "pass"  # pass/alert/block
    thresholds: dict = None
    whitelist_match: str = ""
    preprocessing: dict = None

    def to_dict(self) -> dict:
        return {
            "safe": self.safe,
            "threats": [asdict(t) for t in self.threats],
            "confidence": self.confidence,
            "layers_scanned": self.layers_scanned,
            "action": self.action,
            "thresholds": self.thresholds or {},
            "whitelist_match": self.whitelist_match,
            "preprocessing": self.preprocessing or {}
        }

# ============================================================
# 工具函数
# ============================================================

def safe_regex_test(pattern: str, input_text: str) -> Tuple[bool, bool]:
    """
    带超时保护的正则测试（ReDoS保护）
    返回: (is_safe, matched)
    - is_safe=False: 模式匹配成功（=威胁检测到）
    - is_safe=True: 无匹配 或 出错/超时（=安全或跳过）
    - matched=True: 模式匹配成功
    """
    try:
        regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        start = time.time()
        
        # 分步匹配，防止灾难性回溯
        if len(input_text) > 10000:
            input_text = input_text[:10000]
        
        matched = bool(regex.search(input_text))
        
        elapsed = time.time() - start
        if elapsed > REGEX_TIMEOUT_SEC:
            return True, False  # 超时，视为安全（跳过）
        
        if matched:
            return False, True  # 匹配=不安全
        else:
            return True, False  # 不匹配=安全
    except re.error:
        return True, False  # 正则错误，视为安全

def load_json(filepath: Path) -> dict:
    """安全加载JSON文件"""
    try:
        if filepath.exists():
            return json.loads(filepath.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def load_rules(category: str) -> List[dict]:
    """加载指定类别的规则，扁平化patterns数组"""
    rules = []
    category_dir = RULES_DIR / category
    if category_dir.exists():
        for rule_file in category_dir.glob("*.json"):
            rule_data = load_json(rule_file)
            if rule_data:
                # 从容器中提取patterns数组
                patterns = rule_data.get("patterns", [])
                if patterns:
                    for p in patterns:
                        # 继承容器级别的severity（如果pattern没有自己的）
                        if "severity" not in p and "severity" in rule_data:
                            p["severity"] = rule_data["severity"]
                        rules.append(p)
                elif "pattern" in rule_data:
                    # 单个pattern格式（兼容）
                    rules.append(rule_data)
    return rules

def load_all_rules() -> Dict[str, List[dict]]:
    """加载所有规则（包括根目录规则文件）"""
    categories = ["llm", "web", "api", "deploy", "supply_chain", "ingest", "outbound", "mcp_security", "memory", "integrity", "multi_agent", "resource_guard"]
    all_rules = {}
    for cat in categories:
        all_rules[cat] = load_rules(cat)
    # 加载根目录规则文件（归入llm类别）
    for rule_file in RULES_DIR.glob("*.json"):
        rule_data = load_json(rule_file)
        if rule_data:
            patterns = rule_data.get("patterns", [])
            if patterns:
                for p in patterns:
                    if "severity" not in p and "severity" in rule_data:
                        p["severity"] = rule_data["severity"]
                    all_rules.setdefault("llm", []).append(p)
            elif "pattern" in rule_data:
                all_rules.setdefault("llm", []).append(rule_data)
    return all_rules

# ============================================================
# 各层检测器
# ============================================================

class BaseDetector:
    """检测器基类"""
    def __init__(self, category: str, rules: List[dict]):
        self.category = category
        self.rules = rules

    def detect(self, input_text: str) -> Tuple[bool, List[Threat], float]:
        """检测输入，返回 (has_threats, threats, avg_confidence)"""
        threats = []
        confidences = []
        
        for rule in self.rules:
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            
            is_safe, matched = safe_regex_test(pattern, input_text)
            
            if not is_safe and matched:
                severity = rule.get("severity", "medium")
                confidence = rule.get("confidence", 0.8)
                
                threats.append(Threat(
                    layer=self.category,
                    rule_id=rule.get("id", "unknown"),
                    description=rule.get("description", "检测到威胁"),
                    severity=severity,
                    confidence=confidence,
                    matched=input_text[:200],  # 截断显示
                    mitigation=rule.get("mitigation", "")
                ))
                confidences.append(confidence)
        
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
        return len(threats) > 0, threats, avg_conf

class LLMDetector(BaseDetector):
    """LLM层检测器 - Prompt注入/越狱/编码"""
    def __init__(self):
        super().__init__("llm", load_rules("llm"))

class WebDetector(BaseDetector):
    """Web层检测器 - SQL注入/XSS/CSRF/SSRF"""
    def __init__(self):
        super().__init__("web", load_rules("web"))

class APIDetector(BaseDetector):
    """API层检测器 - 密钥泄露/速率限制/认证"""
    def __init__(self):
        super().__init__("api", load_rules("api"))

class DeployDetector(BaseDetector):
    """部署层检测器 - 环境变量泄露/调试信息"""
    def __init__(self):
        super().__init__("deploy", load_rules("deploy"))

class SupplyChainDetector(BaseDetector):
    """供应链检测器 - 危险依赖"""
    def __init__(self):
        super().__init__("supply_chain", load_rules("supply_chain"))

class ResourceGuard:
    """资源守卫 - URL/内网IP/危险协议"""
    
    # 危险协议
    DANGEROUS_PROTOCOLS = ["file://", "dict://", "gopher://", "sftp://", "ldap://"]
    
    # 私有IP模式（不带^锚点，支持URL中提取IP）
    PRIVATE_IP_PATTERNS = [
        r"(?<![\d.])10\.\d+\.\d+\.\d+(?![\d.])",      # 10.x.x.x
        r"(?<![\d.])172\.(1[6-9]|2\d|3[01])\.\d+\.\d+(?![\d.])",  # 172.16-31.x.x
        r"(?<![\d.])192\.168\.\d+\.\d+(?![\d.])",      # 192.168.x.x
        r"(?<![\d.])127\.\d+\.\d+\.\d+(?![\d.])",      # 127.x.x.x
        r"(?<![\w.])localhost(?![\w.])",                       # localhost
        r"(?<![\w:])::1(?![\w:])",                             # ::1
        r"(?<![\d.])0\.0\.0\.0(?![\d.])",                  # 0.0.0.0
    ]
    
    # SSRF关键词
    SSRF_KEYWORDS = ["metadata.google.internal", "169.254.169.254", "metadata.azure.com"]
    
    def __init__(self):
        self.private_ip_regex = [re.compile(p, re.IGNORECASE) for p in self.PRIVATE_IP_PATTERNS]
    
    def validate_url(self, url: str) -> Tuple[bool, List[str]]:
        """验证URL安全性，返回 (is_safe, threats)"""
        from urllib.parse import urlparse
        
        threats = []
        url_lower = url.lower()
        
        # 检查危险协议
        for proto in self.DANGEROUS_PROTOCOLS:
            if url_lower.startswith(proto):
                threats.append(f"危险协议: {proto}")
        
        # 提取hostname检查内网IP
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            
            # 检查hostname是否匹配私有IP
            for ip_pattern in self.private_ip_regex:
                if ip_pattern.search(hostname):
                    threats.append(f"内网IP访问: {hostname}")
                    break
        except Exception:
            pass
        
        # 检查SSRF关键词
        for keyword in self.SSRF_KEYWORDS:
            if keyword in url_lower:
                threats.append(f"SSRF元数据端点: {keyword}")
        
        return len(threats) == 0, threats
    
    def detect(self, input_text: str) -> Tuple[bool, List[Threat], float]:
        """检测输入中的URL"""
        threats = []
        
        # 提取URL
        url_pattern = r"https?://[^\s'\"<>]+"
        urls = re.findall(url_pattern, input_text, re.IGNORECASE)
        
        for url in urls:
            is_safe, url_threats = self.validate_url(url)
            if not is_safe:
                for threat_desc in url_threats:
                    threats.append(Threat(
                        layer="resource_guard",
                        rule_id="rg_url",
                        description=threat_desc,
                        severity="critical",
                        confidence=0.95,
                        matched=url[:200],
                        mitigation="禁止访问内部资源或元数据端点"
                    ))
        
        return len(threats) > 0, threats, 0.95

# ============================================================
# 主检测器
# ============================================================



class IngestDetector(BaseDetector):
    """摄入层 - 零宽字符/同形字/Trojan Source/隐藏文本"""
    def __init__(self):
        super().__init__("ingest", load_rules("ingest"))


class OutboundDetector(BaseDetector):
    """外发层 - PII泄露/DNS外泄/恶意URL"""
    def __init__(self):
        super().__init__("outbound", load_rules("outbound"))


class MCPSecurityDetector(BaseDetector):
    """MCP Security层 - 工具投毒/Schema验证"""
    def __init__(self):
        super().__init__("mcp_security", load_rules("mcp_security"))


class MemoryDetector(BaseDetector):
    """记忆安全层 - 记忆投毒/Checkpoint篡改"""
    def __init__(self):
        super().__init__("memory", load_rules("memory"))


class IntegrityDetector(BaseDetector):
    """完整性层 - Profile后门/反向Shell"""
    def __init__(self):
        super().__init__("integrity", load_rules("integrity"))


class MultiAgentDetector(BaseDetector):
    """多Agent安全层 - 跨Agent注入/身份冒充"""
    def __init__(self):
        super().__init__("multi_agent", load_rules("multi_agent"))
class PreprocessDetector:
    """
    预处理层 - FireClaw 4-stage管线
    Stage 1: 结构化清理（HTML/Unicode tricks）
    Stage 2: 编码归一化（解码混淆）
    Stage 3: 金丝雀标记注入（绕过检测）
    Stage 4: 元数据提取（结构分析）
    """
    
    def __init__(self):
        self.stats = {"processed": 0, "sanitized": 0, "canaries_injected": 0}
    
    def preprocess(self, input_text: str, options: dict = None) -> dict:
        """
        完整预处理管线
        
        Args:
            input_text: 原始输入
            options: { inject_canary?, source? }
        
        Returns:
            dict: { sanitized, original, metadata }
        """
        if not input_text or not isinstance(input_text, str):
            return {"sanitized": input_text, "original": input_text, "metadata": {"stages": []}}
        
        options = options or {}
        inject_canary = options.get("inject_canary", True)
        source = options.get("source", "unknown")
        
        original = input_text
        sanitized = input_text
        stages = []
        
        # Stage 1: 结构化清理
        sanitized = self._stage1_structural(sanitized)
        stages.append({"stage": 1, "name": "structural_sanitization", "applied": sanitized != input_text})
        
        # Stage 2: 编码归一化
        after_stage2 = self._stage2_encoding(sanitized)
        stages.append({"stage": 2, "name": "encoding_normalization", "applied": after_stage2 != sanitized})
        sanitized = after_stage2
        
        # Stage 3: 金丝雀标记注入
        if inject_canary:
            canary = self._generate_canary()
            sanitized = f"{sanitized}\n\n<!-- CANARY:{canary} -->"
            stages.append({"stage": 3, "name": "canary_injection", "canary": canary, "applied": True})
            self.stats["canaries_injected"] += 1
        
        # Stage 4: 元数据提取
        metadata = self._stage4_metadata(sanitized, source)
        stages.append({"stage": 4, "name": "metadata_extraction", "applied": True})
        
        self.stats["processed"] += 1
        if sanitized != original:
            self.stats["sanitized"] += 1
        
        return {
            "sanitized": sanitized,
            "original": original,
            "metadata": {
                **metadata,
                "stages": stages,
                "source": source,
                "processed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "length_delta": len(sanitized) - len(original)
            }
        }
    
    def _stage1_structural(self, input_text: str) -> str:
        """Stage 1: 结构化清理"""
        result = input_text
        
        # 移除HTML注释（可能隐藏指令）
        result = re.sub(r'<!--[\s\S]*?-->', '', result)
        
        # 移除script/style/iframe/object/embed标签
        result = re.sub(r'<script[^>]*>[\s\S]*?</script>', '[STRIPPED:script]', result, flags=re.IGNORECASE)
        result = re.sub(r'<style[^>]*>[\s\S]*?</style>', '[STRIPPED:style]', result, flags=re.IGNORECASE)
        result = re.sub(r'<iframe[^>]*>[\s\S]*?</iframe>', '[STRIPPED:iframe]', result, flags=re.IGNORECASE)
        result = re.sub(r'<object[^>]*>[\s\S]*?</object>', '[STRIPPED:object]', result, flags=re.IGNORECASE)
        result = re.sub(r'<embed[^>]*>', '[STRIPPED:embed]', result, flags=re.IGNORECASE)
        
        # 移除零宽字符
        result = re.sub(r'[\u200B\u200C\u200D\uFEFF]', '', result)
        
        # 移除RTL/LTR覆盖字符
        result = re.sub(r'[\u202A-\u202E]', '', result)
        
        # 移除控制字符（保留换行、制表、回车）
        result = re.sub(r'[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]', '', result)
        
        # 移除替换字符
        result = result.replace('\uFFFD', '')
        
        # 移除软连字符
        result = result.replace('\u00AD', '')
        
        # 移除不可见分隔符
        result = re.sub(r'[\u2063\u2064]', '', result)
        
        # 折叠过多的空白
        result = re.sub(r'[ \t]{10,}', ' ', result)
        result = re.sub(r'\n{5,}', '\n\n', result)
        
        return result
    
    def _stage2_encoding(self, input_text: str) -> str:
        """Stage 2: 编码归一化"""
        result = input_text
        
        # 解码双重URL编码
        try:
            from urllib.parse import unquote
            decoded = unquote(result)
            if decoded != result:
                result = decoded
        except Exception:
            pass
        
        # 归一化Unicode混淆字符（基本拉丁/西里尔）
        confusable_map = {
            '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
            '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
            '\u0410': 'A', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P',
            '\u0421': 'C', '\u0423': 'Y', '\u0425': 'X'
        }
        for cyrillic, latin in confusable_map.items():
            result = result.replace(cyrillic, latin)
        
        return result
    
    def _generate_canary(self) -> str:
        """Stage 3: 生成金丝雀标记"""
        import random
        import string
        chars = string.ascii_uppercase + string.digits
        canary = 'CANARY_' + ''.join(random.choices(chars, k=12))
        return canary
    
    def check_canary(self, output: str) -> dict:
        """检查金丝雀标记是否存活（绕过检测）"""
        match = re.search(r'CANARY_[A-Z0-9]{8,16}', output)
        return {
            "survived": bool(match),
            "canary": match.group(0) if match else None
        }
    
    def _stage4_metadata(self, input_text: str, source: str) -> dict:
        """Stage 4: 元数据提取"""
        return {
            "input_length": len(input_text),
            "line_count": input_text.count('\n') + 1,
            "has_urls": bool(re.search(r'https?://', input_text)),
            "has_base64": bool(re.search(r'[A-Za-z0-9+/]{100,}={0,2}', input_text)),
            "has_html": bool(re.search(r'<[a-z][\s\S]*>', input_text, re.IGNORECASE)),
            "has_unicode_anomalies": bool(re.search(r'[\u200B-\u200F\u202A-\u202E\u2063-\u2064\uFEFF]', input_text)),
            "encoding_entropy": self._calculate_entropy(input_text)
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """计算Shannon熵（高熵=可能编码/加密）"""
        import math
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return round(entropy, 2)
    
    def get_stats(self) -> dict:
        """获取处理统计"""
        return self.stats.copy()


class Detector:
    """奇点造物-Genesisix 主检测器"""
    
    def __init__(self, skill_path: Optional[Path] = None):
        if skill_path:
            global SKILL_PATH, CONFIG_PATH, RULES_DIR
            SKILL_PATH = Path(skill_path)
            CONFIG_PATH = SKILL_PATH / "config.json"
            RULES_DIR = SKILL_PATH / "rules"
        
        self.config = self._load_config()
        self.whitelist = self._load_whitelist()
        self.preprocessor = PreprocessDetector()
        
        self.llm = LLMDetector()
        self.web = WebDetector()
        self.api = APIDetector()
        self.deploy = DeployDetector()
        self.supply_chain = SupplyChainDetector()
        self.resource_guard = ResourceGuard()
        self.ingest = IngestDetector()
        self.outbound = OutboundDetector()
        self.mcp_security = MCPSecurityDetector()
        self.memory = MemoryDetector()
        self.integrity = IntegrityDetector()
        self.multi_agent = MultiAgentDetector()
        
        # Hook系统（6种hook）
        self.hooks: Dict[str, list] = {
            "beforeScan": [],
            "afterScan": [],
            "beforeLayer": [],
            "afterLayer": [],
            "onThreat": [],
            "onBypass": [],
        }
        
        # SelfLoop集成
        try:
            from self_loop import SelfLoop
            self.self_loop = SelfLoop(SKILL_PATH)
            self._integrate_self_loop()
        except ImportError:
            self.self_loop = None
    
    def _load_config(self) -> dict:
        """加载配置"""
        default_config = {
            "enabled": True,
            "layers": {
                "llm": {"enabled": True},
                "web": {"enabled": True},
                "api": {"enabled": True},
                "supply_chain": {"enabled": True},
                "deploy": {"enabled": True},
                "resource_guard": {"enabled": True}
            }
        }
        
        config = load_json(CONFIG_PATH)
        return config if config else default_config
    
    def _load_whitelist(self) -> dict:
        """加载白名单配置"""
        whitelist_path = SKILL_PATH / "whitelist.json"
        return load_json(whitelist_path)
    
    def _check_whitelist(self, input_text: str, options: dict = None) -> Tuple[bool, str]:
        """
        白名单检查
        返回: (should_skip, reason)
        """
        if not self.whitelist:
            return False, ""
        
        options = options or {}
        
        # 检查用户ID白名单
        if options.get("userId") and self.whitelist.get("users"):
            if options["userId"] in self.whitelist["users"]:
                return True, f"whitelisted_user:{options['userId']}"
        
        # 检查会话ID白名单
        if options.get("sessionId") and self.whitelist.get("sessions"):
            if options["sessionId"] in self.whitelist["sessions"]:
                return True, f"whitelisted_session:{options['sessionId']}"
        
        # 检查关键词白名单（输入完全匹配时跳过）
        if input_text and self.whitelist.get("keywords"):
            normalized_input = input_text.strip().lower()
            for keyword in self.whitelist["keywords"]:
                if normalized_input == keyword.lower():
                    return True, f"whitelisted_keyword:{keyword}"
        
        # 检查模式白名单（输入匹配正则模式时跳过）
        if input_text and self.whitelist.get("patterns"):
            for pattern in self.whitelist["patterns"]:
                try:
                    if re.search(pattern, input_text.strip(), re.IGNORECASE):
                        return True, f"whitelisted_pattern:{pattern}"
                except re.error:
                    pass
        
        return False, ""
    
    def _apply_thresholds(self, result: ScanResult) -> dict:
        """
        置信度阈值分级
        返回: { action, thresholds }
        """
        detection = self.config.get("detection", {})
        alert_threshold = detection.get("alert_threshold", 0.5)
        block_threshold = detection.get("block_threshold", 0.8)
        confidence = result.confidence or 0
        
        if confidence < alert_threshold:
            action = "pass"       # 低风险，放行
        elif confidence < block_threshold:
            action = "alert"      # 中风险，告警
        else:
            action = "block"      # 高风险，拦截
        
        return {
            "action": action,
            "thresholds": {
                "alert_threshold": alert_threshold,
                "block_threshold": block_threshold,
                "confidence_threshold": detection.get("confidence_threshold", 0.7)
            }
        }
    
    # ============================================================
    # Hook 系统
    # ============================================================
    
    def on(self, hook_type: str, callback) -> callable:
        """
        注册hook回调
        
        Args:
            hook_type: beforeScan/afterScan/beforeLayer/afterLayer/onThreat/onBypass
            callback: 回调函数
        
        Returns:
            注销函数（调用即移除）
        
        Raises:
            ValueError: 未知hook类型
            TypeError: callback不是可调用对象
        """
        if hook_type not in self.hooks:
            raise ValueError(f"Unknown hook type: {hook_type}. Valid types: {', '.join(self.hooks.keys())}")
        if not callable(callback):
            raise TypeError("Hook callback must be callable")
        
        self.hooks[hook_type].append(callback)
        
        # 返回注销函数
        def unregister():
            try:
                self.hooks[hook_type].remove(callback)
            except ValueError:
                pass
        return unregister
    
    def _execute_hooks(self, hook_type: str, context: dict) -> dict:
        """
        执行所有同类型hook
        
        Args:
            hook_type: hook类型
            context: 上下文数据
        
        Returns:
            修改后的context（hook可修改）
        """
        callbacks = self.hooks.get(hook_type, [])
        if not callbacks:
            return context
        
        modified = dict(context)
        for cb in callbacks:
            try:
                result = cb(modified)
                if result and isinstance(result, dict):
                    modified.update(result)
            except Exception as e:
                # hook错误不应中断扫描
                if hook_type in ("onThreat", "onBypass"):
                    print(f"[Genesisix] hook error ({hook_type}): {e}", file=sys.stderr)
        return modified
    
    def before_scan(self, callback):
        """注册beforeScan hook — 扫描前执行，可修改或拒绝输入"""
        return self.on("beforeScan", callback)
    
    def after_scan(self, callback):
        """注册afterScan hook — 扫描后执行，可修改结果"""
        return self.on("afterScan", callback)
    
    def before_layer(self, callback):
        """注册beforeLayer hook — 每层执行前"""
        return self.on("beforeLayer", callback)
    
    def after_layer(self, callback):
        """注册afterLayer hook — 每层执行后"""
        return self.on("afterLayer", callback)
    
    def on_threat(self, callback):
        """注册onThreat hook — 发现威胁时"""
        return self.on("onThreat", callback)
    
    def on_bypass(self, callback):
        """注册onBypass hook — 金丝雀存活时（检测到绕过）"""
        return self.on("onBypass", callback)
    
    def _integrate_self_loop(self):
        """
        集成SelfLoop — 注册onThreat hook自动记录漏报
        """
        if not self.self_loop:
            return
        
        def _on_threat(ctx):
            threat = ctx.get("threat")
            if threat and self.self_loop:
                try:
                    self.self_loop.log_missed_case(
                        input_text=ctx.get("input", "")[:500],
                        expected_threat=getattr(threat, "description", str(threat)),
                        layer=getattr(threat, "layer", "unknown"),
                        severity=getattr(threat, "severity", "high"),
                    )
                except Exception:
                    pass
        
        self.on("onThreat", _on_threat)
    
    def _execute_layer(self, layer_name: str, detector, input_text: str, detect_method: str = "detect") -> dict:
        """
        执行单个检测层（带hook支持）
        
        Args:
            layer_name: 层名
            detector: 检测器实例
            input_text: 输入文本
            detect_method: 检测方法名
        
        Returns:
            dict: { safe, threats, confidence }
        """
        # beforeLayer hook
        layer_ctx = self._execute_hooks("beforeLayer", {"layer": layer_name, "input": input_text})
        if layer_ctx.get("skip"):
            return {"safe": True, "threats": [], "confidence": 0.0, "skipped": True}
        
        # 执行检测
        method = getattr(detector, detect_method)
        has_threats, threats, confidence = method(input_text)
        
        result = {
            "safe": not has_threats,
            "threats": threats,
            "confidence": confidence,
        }
        
        # afterLayer hook
        layer_ctx = self._execute_hooks("afterLayer", {"layer": layer_name, "result": result})
        return layer_ctx.get("result", result)
    
    def scan(self, input_text: str, layer: str = "all", options: dict = None) -> ScanResult:
        """
        主扫描入口
        
        Args:
            input_text: 用户输入
            layer: 'all' 或指定层 ('llm', 'web', 'api', 'deploy', 'supply_chain', 'resource')
            options: 可选参数 { userId?, sessionId? } (default: None)
        
        Returns:
            ScanResult: { safe, threats, confidence, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return ScanResult(safe=True, threats=[], confidence=0.0, layers_scanned=[], action="pass", thresholds={})
        
        # 空白输入直接放行（无实际内容可检测）
        if not input_text or not input_text.strip():
            return ScanResult(safe=True, threats=[], confidence=0.0, layers_scanned=[], action="pass", thresholds={})
        
        options = options or {}
        
        # beforeScan hook — 可修改输入或拒绝
        scan_ctx = self._execute_hooks("beforeScan", {"input": input_text, "options": options})
        if scan_ctx.get("reject"):
            return ScanResult(
                safe=False, threats=[], confidence=0.0,
                layers_scanned=["hook_reject"], action="block",
                thresholds={}, whitelist_match=f"hook_reject:{scan_ctx.get('rejectReason', '')}"
            )
        input_text = scan_ctx.get("input", input_text)
        options = scan_ctx.get("options", options)
        
        # Preprocess层（如果启用）— 默认不注入金丝雀（避免误报）
        preprocess_result = None
        original_input = input_text  # 保留原始输入用于检测
        if self.config.get("layers", {}).get("preprocessing", {}).get("enabled", True):
            preprocess_result = self.preprocessor.preprocess(input_text, {"source": "scan", "inject_canary": False})
            input_text = preprocess_result["sanitized"]
        
        # P1-1: 白名单检查
        should_skip, whitelist_reason = self._check_whitelist(input_text, options or {})
        if should_skip:
            return ScanResult(
                safe=True,
                threats=[],
                confidence=0.0,
                layers_scanned=["whitelist"],
                action="pass",
                whitelist_match=whitelist_reason,
                thresholds={}
            )
        
        all_threats = []
        layers_scanned = []
        confidences = []
        
        layers_to_scan = []
        if layer == "all":
            layers_to_scan = ["llm", "web", "api", "deploy", "supply_chain", "resource_guard", "ingest", "outbound", "mcp_security", "memory", "integrity", "multi_agent"]
        else:
            layers_to_scan = [layer]
        
        for ly in layers_to_scan:
            if not self.config.get("layers", {}).get(ly, {}).get("enabled", True):
                continue
            
            # ingest层用预处理后的输入（检测编码混淆），其他层用原始输入（保留攻击特征）
            detect_input = input_text if ly == "ingest" else original_input
            
            try:
                if ly == "llm":
                    _, threats, conf = self.llm.detect(detect_input)
                elif ly == "web":
                    _, threats, conf = self.web.detect(detect_input)
                elif ly == "api":
                    _, threats, conf = self.api.detect(detect_input)
                elif ly == "deploy":
                    _, threats, conf = self.deploy.detect(detect_input)
                elif ly == "supply_chain":
                    _, threats, conf = self.supply_chain.detect(detect_input)
                elif ly == "resource_guard":
                    _, threats, conf = self.resource_guard.detect(detect_input)
                elif ly == "ingest":
                    _, threats, conf = self.ingest.detect(detect_input)
                elif ly == "outbound":
                    _, threats, conf = self.outbound.detect(detect_input)
                elif ly == "mcp_security":
                    _, threats, conf = self.mcp_security.detect(detect_input)
                elif ly == "memory":
                    _, threats, conf = self.memory.detect(detect_input)
                elif ly == "integrity":
                    _, threats, conf = self.integrity.detect(detect_input)
                elif ly == "multi_agent":
                    _, threats, conf = self.multi_agent.detect(detect_input)
                else:
                    continue
                
                if threats:
                    all_threats.extend(threats)
                    confidences.append(conf)
                    layers_scanned.append(ly)
            except Exception as e:
                # 某层检测失败不影响其他层
                pass
        
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
        safe = len(all_threats) == 0
        
        result = ScanResult(
            safe=safe,
            threats=all_threats,
            confidence=avg_conf,
            layers_scanned=layers_scanned
        )
        
        # P1-2: 阈值分级
        threshold_info = self._apply_thresholds(result)
        result.action = threshold_info["action"]
        result.thresholds = threshold_info["thresholds"]
        
        # 添加预处理信息
        if preprocess_result:
            result.preprocessing = preprocess_result["metadata"]
        
        # afterScan hook — 可修改结果
        result_dict = self._execute_hooks("afterScan", {"input": input_text, "result": result, "options": options})
        if "result" in result_dict and isinstance(result_dict["result"], ScanResult):
            result = result_dict["result"]
        
        # onThreat hook — 发现威胁时通知
        if not result.safe:
            for threat in result.threats:
                self._execute_hooks("onThreat", {"threat": threat, "layer": threat.layer, "input": input_text})
        
        return result

    # ============================================================
    # 专用扫描 API
    # ============================================================
    
    def preprocess(self, input_text: str, options: dict = None) -> dict:
        """
        预处理扫描内容 - 公开API
        执行4-stage管线：结构化清理→编码归一化→金丝雀注入→元数据提取
        
        Args:
            input_text: 原始输入
            options: { inject_canary?, source? }
        
        Returns:
            dict: { sanitized, original, metadata }
        """
        if not self.config.get("enabled", True):
            return {"sanitized": input_text, "original": input_text, "metadata": {"stages": []}}
        
        if not self.config.get("layers", {}).get("preprocessing", {}).get("enabled", True):
            return {"sanitized": input_text, "original": input_text, "metadata": {"stages": []}}
        
        return self.preprocessor.preprocess(input_text, options)
    
    def check_canary(self, output: str) -> dict:
        """
        检查金丝雀标记是否存活 - 公开API
        用于检测绕过行为
        
        Args:
            output: 处理后的输出
        
        Returns:
            dict: { survived, canary }
        """
        return self.preprocessor.check_canary(output)
    
    def scan_resource(self, input_text: str) -> dict:
        """
        资源安全扫描 - 公开API
        检测URL中的SSRF/危险协议/危险路径/端口
        
        Args:
            input_text: URL / 包含URL的内容
        
        Returns:
            dict: { safe, threats, confidence, layer, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0}
        
        if not self.config.get("layers", {}).get("resource_guard", {}).get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "layers_scanned": []}
        
        has_threats, threats, confidence = self.resource_guard.detect(input_text)
        
        return {
            "safe": not has_threats,
            "threats": [asdict(t) for t in threats],
            "confidence": confidence,
            "layer": "resource_guard",
            "layers_scanned": ["resource_guard"],
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def scan_mcp(self, tool_schema: dict, tool_output: str) -> dict:
        """
        MCP安全扫描 - 公开API
        检测MCP工具Schema和输出的安全性
        
        Args:
            tool_schema: MCP工具schema
            tool_output: MCP工具输出
        
        Returns:
            dict: { safe, threats, confidence, layer, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0}
        
        if not self.config.get("layers", {}).get("mcp_security", {}).get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "layers_scanned": []}
        
        # 扫描工具输出
        has_threats, threats, confidence = self.mcp_security.detect(tool_output)
        
        # 扫描工具schema（如果有）
        schema_text = json.dumps(tool_schema) if isinstance(tool_schema, dict) else str(tool_schema)
        if schema_text:
            has_threats_schema, threats_schema, conf_schema = self.llm.detect(schema_text)
            if has_threats_schema:
                threats.extend(threats_schema)
                confidence = max(confidence, conf_schema)
        
        return {
            "safe": len(threats) == 0,
            "threats": [asdict(t) for t in threats],
            "confidence": confidence,
            "layer": "mcp_security",
            "layers_scanned": ["mcp_security", "llm"],
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def scan_outbound(self, url: str, options: dict = None) -> dict:
        """
        外发数据扫描 - 公开API
        检测URL信誉/短链/内网/PII/DNS外泄
        
        Args:
            url: 要检查的URL
            options: 可选参数
        
        Returns:
            dict: { safe, threats, confidence, layer, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0}
        
        if not self.config.get("layers", {}).get("outbound", {}).get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "layers_scanned": []}
        
        has_threats, threats, confidence = self.outbound.detect(url)
        
        return {
            "safe": not has_threats,
            "threats": [asdict(t) for t in threats],
            "confidence": confidence,
            "layer": "outbound",
            "layers_scanned": ["outbound"],
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def scan_memory(self, content: str) -> dict:
        """
        记忆安全扫描 - 公开API
        检测记忆/checkpoint内容安全性
        
        Args:
            content: 记忆内容
        
        Returns:
            dict: { safe, threats, confidence, layer, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0}
        
        if not self.config.get("layers", {}).get("memory", {}).get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "layers_scanned": []}
        
        has_threats, threats, confidence = self.memory.detect(content)
        
        # 同时扫描LLM层
        has_threats_llm, threats_llm, conf_llm = self.llm.detect(content)
        if has_threats_llm:
            threats.extend(threats_llm)
            confidence = max(confidence, conf_llm)
        
        return {
            "safe": len(threats) == 0,
            "threats": [asdict(t) for t in threats],
            "confidence": confidence,
            "layer": "memory",
            "layers_scanned": ["memory", "llm"],
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def scan_integrity(self, content: str, file_path: str = "") -> dict:
        """
        Profile完整性扫描 - 公开API
        检测AGENTS.md/SOUL.md等配置文件的安全性
        
        Args:
            content: 文件内容
            file_path: 文件路径
        
        Returns:
            dict: { safe, threats, confidence, layer, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0}
        
        if not self.config.get("layers", {}).get("integrity", {}).get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "layers_scanned": []}
        
        has_threats, threats, confidence = self.integrity.detect(content)
        
        return {
            "safe": not has_threats,
            "threats": [asdict(t) for t in threats],
            "confidence": confidence,
            "layer": "integrity",
            "layers_scanned": ["integrity"],
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def scan_multi_agent(self, content: str, context: dict = None) -> dict:
        """
        多Agent安全扫描 - 公开API
        检测跨Agent注入/身份冒充/工具链攻击
        
        Args:
            content: 消息内容
            context: 上下文信息 { sourceAgent?, targetAgent? }
        
        Returns:
            dict: { safe, threats, confidence, layer, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0}
        
        if not self.config.get("layers", {}).get("multi_agent", {}).get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "layers_scanned": []}
        
        has_threats, threats, confidence = self.multi_agent.detect(content)
        
        return {
            "safe": not has_threats,
            "threats": [asdict(t) for t in threats],
            "confidence": confidence,
            "layer": "multi_agent",
            "layers_scanned": ["multi_agent"],
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def scan_multiturn(self, messages: List[str], options: dict = None) -> dict:
        """
        多轮越狱扫描 - 公开API
        检测多轮对话中的渐进式攻击
        
        Args:
            messages: 最近N条消息列表
            options: 可选参数 { windowSize?, includeCurrentScan?, currentInput? }
        
        Returns:
            dict: { safe, threats, confidence, layer, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "phases": []}
        
        if not self.config.get("layers", {}).get("llm", {}).get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "phases": [], "layers_scanned": []}
        
        # 合并所有消息进行检测
        combined_text = " ".join(messages)
        has_threats, threats, confidence = self.llm.detect(combined_text)
        
        # 如果有当前输入，也扫描
        if options and options.get("includeCurrentScan") and options.get("currentInput"):
            has_threats_current, threats_current, conf_current = self.llm.detect(options["currentInput"])
            if has_threats_current:
                threats.extend(threats_current)
                confidence = max(confidence, conf_current)
        
        return {
            "safe": len(threats) == 0,
            "threats": [asdict(t) for t in threats],
            "confidence": confidence,
            "layer": "llm",
            "layers_scanned": ["llm"],
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def scan_ingest(self, content: str, options: dict = None) -> dict:
        """
        摄入层扫描 - 公开API
        扫描ingest层 + llm层（可选）
        
        Args:
            content: 要检查的内容
            options: { includeLlm?: bool }
        
        Returns:
            dict: { safe, threats, confidence, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0}
        
        if not self.config.get("layers", {}).get("ingest", {}).get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0, "layers_scanned": []}
        
        options = options or {}
        threats = []
        confidences = []
        layers_scanned = ["ingest"]
        
        # Ingest层
        has_threats, t, c = self.ingest.detect(content)
        if has_threats:
            threats.extend(t)
            confidences.append(c)
        
        # LLM层（默认启用）
        if options.get("includeLlm", True):
            has_threats_llm, t_llm, c_llm = self.llm.detect(content)
            if has_threats_llm:
                threats.extend(t_llm)
                confidences.append(c_llm)
            layers_scanned.append("llm")
        
        avg_conf = max(confidences) if confidences else 0.0
        
        return {
            "safe": len(threats) == 0,
            "threats": [asdict(t_item) for t_item in threats],
            "confidence": avg_conf,
            "layers_scanned": layers_scanned,
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def scan_code(self, code: str) -> dict:
        """
        代码扫描 - 公开API
        扫描api + supply_chain + deploy + outbound + behavioral_ast + taint_tracking层
        
        Args:
            code: 代码/脚本内容
        
        Returns:
            dict: { safe, threats, confidence, layers_scanned }
        """
        if not self.config.get("enabled", True):
            return {"safe": True, "threats": [], "confidence": 0}
        
        all_threats = []
        confidences = []
        layers_scanned = []
        
        layer_map = {
            "api": self.api,
            "supply_chain": self.supply_chain,
            "deploy": self.deploy,
            "outbound": self.outbound,
        }
        
        for layer_name, detector in layer_map.items():
            if not self.config.get("layers", {}).get(layer_name, {}).get("enabled", True):
                continue
            try:
                has_threats, threats, conf = detector.detect(code)
                if has_threats:
                    all_threats.extend(threats)
                    confidences.append(conf)
                layers_scanned.append(layer_name)
            except Exception:
                pass
        
        # Behavioral AST analysis (AtomCollide-智械工坊团队)
        if _HAS_AST_ANALYZER:
            try:
                ast_threats = analyze_python_ast(code, "<scan_code>")
                for at in ast_threats:
                    all_threats.append(Threat(
                        layer="behavioral_ast",
                        rule_id=at.rule_id,
                        description=at.message,
                        severity=at.severity,
                        confidence=at.confidence,
                        matched=at.matched_text[:200],
                        mitigation="Review dangerous code execution pattern"
                    ))
                    confidences.append(at.confidence)
                if ast_threats:
                    layers_scanned.append("behavioral_ast")
            except Exception:
                pass
        
        # Taint tracking analysis (AtomCollide-智械工坊团队)
        if _HAS_TAINT_TRACKER:
            try:
                taint_threats = analyze_taint(code, "<scan_code>")
                for tt in taint_threats:
                    all_threats.append(Threat(
                        layer="taint_tracking",
                        rule_id=tt.rule_id,
                        description=tt.message,
                        severity=tt.severity,
                        confidence=tt.confidence,
                        matched=tt.matched_text[:200],
                        mitigation="Review data flow from sensitive source to dangerous sink"
                    ))
                    confidences.append(tt.confidence)
                if taint_threats:
                    layers_scanned.append("taint_tracking")
            except Exception:
                pass
        
        avg_conf = max(confidences) if confidences else 0.0
        
        return {
            "safe": len(all_threats) == 0,
            "threats": [asdict(t) for t in all_threats],
            "confidence": avg_conf,
            "layers_scanned": layers_scanned,
            "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
    
    def _verify_schema_signature(self, tool_schema) -> dict:
        """
        Schema签名验证 - 内部API
        检测MCP工具schema是否有密码学签名
        
        Args:
            tool_schema: MCP工具schema (dict或str)
        
        Returns:
            dict: { safe, threats, confidence }
        """
        threats = []
        max_confidence = 0.0
        
        schema_text = json.dumps(tool_schema) if isinstance(tool_schema, dict) else str(tool_schema)
        
        # 加载schema_signature规则
        try:
            sig_rules = load_rules("mcp_security")
            for rule_set in sig_rules:
                if "schema_signature" in rule_set.get("category", ""):
                    for pattern in rule_set.get("patterns", []):
                        is_safe, matched = safe_regex_test(pattern.get("pattern", ""), schema_text)
                        if matched:
                            threats.append(Threat(
                                layer="mcp_security",
                                rule_id=pattern.get("id", "SS-000"),
                                description=pattern.get("description", "Schema signature issue"),
                                severity=pattern.get("severity", "high"),
                                confidence=pattern.get("weight", 0.8),
                                matched=schema_text[:200],
                                mitigation=""
                            ))
                            max_confidence = max(max_confidence, pattern.get("weight", 0.8))
        except Exception:
            pass
        
        # 检查未签名schema（SchemaPin要求）
        if isinstance(tool_schema, dict):
            if "signature" not in tool_schema and "x-schema-signature" not in tool_schema:
                threats.append(Threat(
                    layer="mcp_security",
                    rule_id="SS-UNSIGNED",
                    description="MCP tool schema has no cryptographic signature — unsigned schemas are vulnerable to rug-pull attacks",
                    severity="high",
                    confidence=0.80,
                    matched=str(tool_schema)[:200],
                    mitigation="Add ECDSA P-256 signature to tool schema"
                ))
                max_confidence = max(max_confidence, 0.80)
        
        return {
            "safe": len(threats) == 0,
            "threats": [asdict(t) for t in threats],
            "confidence": max_confidence
        }
    
    def quick_check(self, input_text: str) -> bool:
        """
        快速安全检查 - 公开API
        仅扫描LLM层，返回是否安全
        
        Args:
            input_text: 要检查的输入
        
        Returns:
            bool: True=安全, False=检测到威胁
        """
        result = self.scan(input_text, layer="llm")
        return result.safe
    
    def get_stats(self) -> dict:
        """
        获取检测器统计信息 - 公开API
        返回规则数、层状态、hook数等
        
        Returns:
            dict: 统计信息
        """
        def _count_patterns(detector, *category_names):
            """统计检测器的规则模式数"""
            count = 0
            for cat in category_names:
                rules = getattr(detector, "rules", None)
                if rules and isinstance(rules, dict):
                    rule_set = rules.get(cat)
                    if rule_set and isinstance(rule_set, dict):
                        patterns = rule_set.get("patterns", [])
                        count += len(patterns)
            return count
        
        def _layer_enabled(layer_name):
            return self.config.get("layers", {}).get(layer_name, {}).get("enabled", True) is not False
        
        return {
            "version": "2.0.0",
            "layers": {
                "llm": _layer_enabled("llm"),
                "web": _layer_enabled("web"),
                "api": _layer_enabled("api"),
                "supply_chain": _layer_enabled("supply_chain"),
                "deploy": _layer_enabled("deploy"),
                "outbound": _layer_enabled("outbound"),
                "ingest": _layer_enabled("ingest"),
                "memory": _layer_enabled("memory"),
                "mcp_security": _layer_enabled("mcp_security"),
                "multi_agent": _layer_enabled("multi_agent"),
                "integrity": _layer_enabled("integrity"),
                "resource_guard": _layer_enabled("resource_guard"),
                "preprocessing": _layer_enabled("preprocessing"),
            },
            "hooks": {
                hook_type: len(callbacks)
                for hook_type, callbacks in self.hooks.items()
            },
            "self_loop": self.self_loop is not None,
            "config": self.config,
        }
    
    def reload(self):
        """
        热重载配置和规则 - 公开API
        重新加载config.json、whitelist.json和所有规则文件
        """
        self.config = self._load_config()
        self.whitelist = self._load_whitelist()
        
        # 重建所有检测器
        self.llm = LLMDetector()
        self.web = WebDetector()
        self.api = APIDetector()
        self.deploy = DeployDetector()
        self.supply_chain = SupplyChainDetector()
        self.resource_guard = ResourceGuard()
        self.ingest = IngestDetector()
        self.outbound = OutboundDetector()
        self.mcp_security = MCPSecurityDetector()
        self.memory = MemoryDetector()
        self.integrity = IntegrityDetector()
        self.multi_agent = MultiAgentDetector()
        
        # 重新集成SelfLoop
        if self.self_loop:
            try:
                self.self_loop = SelfLoop(SKILL_PATH)
                self._integrate_self_loop()
            except Exception:
                pass
# ============================================================
# CLI入口
# ============================================================

def main():
    import argparse
    # Windows终端UTF-8输出（局部作用域）
    if sys.platform == 'win32':
        old_stdout = sys.stdout
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        old_stderr = sys.stderr
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    else:
        old_stdout = old_stderr = None
    
    parser = argparse.ArgumentParser(description="奇点造物-Genesisix 安全检测")
    parser.add_argument("input", help="要检测的输入文本")
    parser.add_argument("--layer", "-l", default="all", 
                       choices=["all", "llm", "web", "api", "deploy", "supply_chain", "resource_guard", "ingest", "outbound", "mcp_security", "memory", "integrity", "multi_agent"],
                       help="指定检测层")
    parser.add_argument("--json", "-j", action="store_true", help="JSON格式输出")
    
    args = parser.parse_args()
    
    detector = Detector()
    result = detector.scan(args.input, args.layer)
    
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        if result.safe:
            print("[OK] 未检测到威胁")
        else:
            print(f"[CRITICAL] 检测到 {len(result.threats)} 个威胁:")
            for threat in result.threats:
                print(f"  [{threat.layer.upper()}] {threat.description} (置信度: {threat.confidence:.0%})")
        
        print(f"\n扫描层: {', '.join(result.layers_scanned)}")
        print(f"整体置信度: {result.confidence:.0%}")
    
    # 恢复stdout/stderr
    if old_stdout is not None:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

if __name__ == "__main__":
    main()


# ============================================================
# v2.0.0 新增层
# ============================================================

    def scan_with_score(self, text: str, context: dict = None) -> dict:
        """Enhanced scan with 0-100 risk scoring (inspired by SkillSpector).
        
        Returns:
            dict with keys: score, severity, findings, summary, recommendation
        """
        result = self.scan(text)
        findings = result if isinstance(result, list) else []
        
        # Calculate risk score
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        raw_score = 0
        for f in findings:
            sev = f.get("severity", "info") if isinstance(f, dict) else "info"
            raw_score += severity_weights.get(sev, 1)
        
        # Cap at 100
        score = min(raw_score, 100)
        
        # Severity label
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        elif score >= 20:
            severity = "LOW"
        else:
            severity = "SAFE"
        
        return {
            "score": score,
            "severity": severity,
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "critical"),
            "high_count": sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == "high"),
            "findings": findings,
            "recommendation": self._get_recommendation(severity, findings),
        }
    
    def _get_recommendation(self, severity: str, findings: list) -> str:
        """Generate actionable recommendation based on scan results."""
        if severity == "CRITICAL":
            return "BLOCK: Do not install/use. Contains critical security vulnerabilities."
        elif severity == "HIGH":
            return "REVIEW: Requires security review before deployment."
        elif severity == "MEDIUM":
            return "CAUTION: Minor risks detected. Review findings before use."
        elif severity == "LOW":
            return "ADVISORY: Low-risk findings. Safe to use with awareness."
        else:
            return "PASS: No significant security issues detected."

    def scan_skill_repo(self, repo_path: str) -> dict:
        """Scan an entire skill repository for security issues.
        
        Scans: SKILL.md, references/, scripts/, assets/ for vulnerabilities.
        Returns aggregated risk score across all files.
        """
        import os
        all_findings = []
        scanned_files = 0
        
        scan_targets = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
            for f in files:
                if f.endswith(('.pyc', '.png', '.jpg', '.mp3', '.mp4')):
                    continue
                scan_targets.append(os.path.join(root, f))
        
        for fpath in scan_targets:
            try:
                with open(fpath, 'r', errors='ignore') as fh:
                    content = fh.read()
                result = self.scan(content)
                if isinstance(result, list):
                    for finding in findings:
                        if isinstance(finding, dict):
                            finding['source_file'] = os.path.relpath(fpath, repo_path)
                    all_findings.extend(result)
                scanned_files += 1
            except Exception:
                continue
        
        # Calculate aggregate score
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        raw_score = sum(severity_weights.get(f.get("severity", "info"), 1) for f in all_findings if isinstance(f, dict))
        score = min(raw_score, 100)
        
        return {
            "score": score,
            "severity": "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "SAFE",
            "scanned_files": scanned_files,
            "total_findings": len(all_findings),
            "findings": all_findings,
        }

    def export_sarif(self, scan_result: dict) -> dict:
        """Export scan results in SARIF format (industry standard for security tools).
        
        SARIF (Static Analysis Results Interchange Format) is used by GitHub CodeQL,
        Semgrep, and other security tools for standardized reporting.
        """
        findings = scan_result.get("findings", [])
        runs = [{
            "tool": {
                "driver": {
                    "name": "Genesisix",
                    "version": "2.1.0",
                    "informationUri": "https://github.com/503496348-ops/genesisix-hermes",
                    "rules": []
                }
            },
            "results": []
        }]
        
        rule_ids = set()
        for f in findings:
            if not isinstance(f, dict):
                continue
            rule_id = f.get("rule_id", f.get("type", "unknown"))
            if rule_id not in rule_ids:
                runs[0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": f.get("type", "Security Finding"),
                    "shortDescription": {"text": f.get("message", "Security issue detected")},
                    "defaultConfiguration": {
                        "level": "error" if f.get("severity") in ["critical", "high"] else "warning"
                    }
                })
                rule_ids.add(rule_id)
            
            runs[0]["results"].append({
                "ruleId": rule_id,
                "level": "error" if f.get("severity") in ["critical", "high"] else "warning",
                "message": {"text": f.get("message", "Security issue detected")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("source_file", "unknown")},
                    }
                }]
            })
        
        return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": runs}
