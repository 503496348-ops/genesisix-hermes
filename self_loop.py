#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix Self-Learning Loop / 自循环学习模块

核心流程：漏报记录 → 案例分析 → 规则建议 → 人工审核 → 落地规则 → 验证闭环

@author Hermes Agent (Python移植版)
@version 2.0.0
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field

# ============================================================
# 常量
# ============================================================

DEFAULT_CONFIG = {
    "caseDbPath": "data/case_database.jsonl",
    "suggestionsPath": "data/rule_suggestions.json",
    "rulesDir": "rules",
    "minCasesForSuggestion": 3,
    "maxCaseInputLength": 500,
    "autoApproveThreshold": 0,
    "statsWindowSize": 1000,
}


# ============================================================
# 数据模型
# ============================================================

@dataclass
class MissedCase:
    """漏报案例"""
    id: str
    timestamp: str
    type: str = "missed"
    input: str = ""
    expected_threat: str = ""
    actual_result: str = "safe"
    layer: str = "unknown"
    severity: str = "high"
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BlockedCase:
    """拦截案例"""
    id: str
    timestamp: str
    type: str = "blocked"
    layer: str = ""
    threat_type: str = ""
    threat_description: str = ""
    false_positive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleSuggestion:
    """规则建议"""
    id: str
    timestamp: str
    layer: str
    rule_set: str
    pattern: str
    description: str
    severity: str
    confidence: float
    source_cases: List[str] = field(default_factory=list)
    status: str = "pending"
    approved_at: Optional[str] = None
    rejected_at: Optional[str] = None
    rejection_reason: Optional[str] = None
    rule_file: Optional[str] = None


# ============================================================
# SelfLoop 核心类
# ============================================================

class SelfLoop:
    """
    自循环学习模块

    Args:
        skill_path: 奇点造物-Genesisix 根目录
        config: 配置覆盖
    """

    def __init__(self, skill_path: Optional[Path] = None, config: Optional[Dict] = None):
        self.skill_path = Path(skill_path) if skill_path else Path(__file__).parent
        self.config: Dict[str, Any] = {**DEFAULT_CONFIG, **(config or {})}

        # 解析绝对路径
        self.case_db_path = self.skill_path / self.config["caseDbPath"]
        self.suggestions_path = self.skill_path / self.config["suggestionsPath"]
        self.rules_dir = self.skill_path / self.config["rulesDir"]

        # 确保数据目录存在
        self.case_db_path.parent.mkdir(parents=True, exist_ok=True)

    # ============================================================
    # 内部工具
    # ============================================================

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _generate_id(prefix: str = "case") -> str:
        ts = hex(int(time.time() * 1000))[2:]
        rand = hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:8]
        return f"{prefix}_{ts}_{rand}"

    def _append_jsonl(self, filepath: Path, record: Dict) -> bool:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return True

    def _read_jsonl(self, filepath: Path) -> List[Dict]:
        if not filepath.exists():
            return []
        records = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return records

    def _read_json(self, filepath: Path, default: Any = None) -> Any:
        if default is None:
            default = []
        if not filepath.exists():
            return default
        try:
            return json.loads(filepath.read_text(encoding="utf-8"))
        except Exception:
            return default

    def _write_json(self, filepath: Path, data: Any) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    # ============================================================
    # 案例记录
    # ============================================================

    def log_missed_case(self, input_text: str, expected_threat: str,
                        actual_result: str = "safe", layer: str = "unknown",
                        severity: str = "high", notes: str = "",
                        metadata: Optional[Dict] = None) -> Dict:
        """记录漏报案例"""
        record = {
            "id": self._generate_id("missed"),
            "timestamp": self._now(),
            "type": "missed",
            "input": (input_text or "")[:self.config["maxCaseInputLength"]],
            "expectedThreat": expected_threat,
            "actualResult": actual_result,
            "layer": layer,
            "severity": severity,
            "notes": notes,
            "metadata": metadata or {}
        }
        self._append_jsonl(self.case_db_path, record)
        return record

    def log_blocked_case(self, layer: str, threat_type: str = "",
                         threat_description: str = "", false_positive: bool = False,
                         metadata: Optional[Dict] = None) -> Dict:
        """记录拦截案例"""
        record = {
            "id": self._generate_id("blocked"),
            "timestamp": self._now(),
            "type": "blocked",
            "layer": layer,
            "threatType": threat_type,
            "threatDescription": threat_description,
            "falsePositive": false_positive,
            "metadata": metadata or {}
        }
        self._append_jsonl(self.case_db_path, record)
        return record

    def log_scan_result(self, input_text: str, scan_result: Any,
                        expected_threat: Optional[str] = None,
                        layer: Optional[str] = None,
                        false_positive: bool = False) -> Any:
        """记录扫描结果（自动判断漏报/拦截）"""
        safe = getattr(scan_result, "safe", True)
        threats = getattr(scan_result, "threats", [])

        if safe and expected_threat:
            return self.log_missed_case(
                input_text=input_text,
                expected_threat=expected_threat,
                layer=layer or "unknown",
                severity="high"
            )
        elif not safe and threats:
            records = []
            for threat in threats:
                records.append(self.log_blocked_case(
                    layer=getattr(threat, "layer", layer or "unknown"),
                    threat_type=getattr(threat, "rule_id", ""),
                    threat_description=getattr(threat, "description", ""),
                    false_positive=false_positive
                ))
            return records
        return None

    # ============================================================
    # 案例分析与规则建议
    # ============================================================

    def analyze_and_suggest(self, min_cases: Optional[int] = None,
                            dry_run: bool = False) -> List[Dict]:
        """分析漏报案例，生成规则建议"""
        min_cases = min_cases or self.config["minCasesForSuggestion"]
        all_cases = self._read_jsonl(self.case_db_path)
        missed_cases = [c for c in all_cases if c.get("type") == "missed"]

        if len(missed_cases) < min_cases:
            return []

        # 按 (layer, expectedThreat) 分组
        groups: Dict[str, List[Dict]] = {}
        for c in missed_cases:
            key = f"{c.get('layer', 'unknown')}:{c.get('expectedThreat', '')}"
            groups.setdefault(key, []).append(c)

        suggestions = []
        for key, cases in groups.items():
            if len(cases) < min_cases:
                continue

            layer, threat = key.split(":", 1)
            latest = cases[-1]
            patterns = self._extract_patterns(cases)
            if not patterns:
                continue

            suggestion = {
                "id": self._generate_id("sug"),
                "timestamp": self._now(),
                "layer": layer,
                "ruleSet": self._infer_rule_set(layer, threat),
                "pattern": patterns[0],
                "description": f"基于{len(cases)}个漏报案例自动生成: {threat}",
                "severity": latest.get("severity", "medium"),
                "confidence": self._calculate_confidence(cases, patterns),
                "sourceCases": [c["id"] for c in cases],
                "status": "pending"
            }
            suggestions.append(suggestion)

        if not dry_run and suggestions:
            existing = self._read_json(self.suggestions_path, [])
            existing.extend(suggestions)
            self._write_json(self.suggestions_path, existing)

        return suggestions

    def _extract_patterns(self, cases: List[Dict]) -> List[str]:
        """从案例中提取攻击模式"""
        inputs = [c.get("input", "") for c in cases if c.get("input")]
        if not inputs:
            return []

        patterns = []
        # 找共同子串
        common = self._find_common_substrings(inputs)
        patterns.extend(common)

        # 提取关键词
        keywords = self._extract_keywords(inputs)
        import re as _re
        patterns.extend([rf"\b{_re.escape(k)}\b" for k in keywords])

        return list(dict.fromkeys(patterns))[:5]

    @staticmethod
    def _find_common_substrings(strings: List[str]) -> List[str]:
        if len(strings) < 2:
            return []
        base = strings[0]
        substrings = []
        for length in range(4, min(len(base), 50) + 1):
            for i in range(len(base) - length + 1):
                sub = base[i:i + length]
                if all(sub in s for s in strings):
                    substrings.append(sub)
        return sorted(set(substrings), key=len, reverse=True)[:3]

    @staticmethod
    def _extract_keywords(inputs: List[str]) -> List[str]:
        import re as _re
        word_count: Dict[str, int] = {}
        for inp in inputs:
            words = _re.sub(r"[^a-z0-9\s]", " ", inp.lower()).split()
            words = [w for w in words if len(w) > 3]
            for w in words:
                word_count[w] = word_count.get(w, 0) + 1
        threshold = len(inputs) * 0.5
        return [w for w, c in word_count.items() if c >= threshold][:5]

    @staticmethod
    def _calculate_confidence(cases: List[Dict], patterns: List[str]) -> float:
        score = 0.5
        score += min(len(cases) * 0.05, 0.3)
        score += min(len(patterns) * 0.05, 0.15)
        return min(round(score, 2), 0.95)

    @staticmethod
    def _infer_rule_set(layer: str, threat: str) -> str:
        mapping = {
            "llm:prompt_injection": "injection",
            "llm:jailbreak": "jailbreak",
            "web:sql_injection": "sql_injection",
            "web:xss": "xss",
            "outbound:url_reputation": "url_reputation",
            "outbound:data_exfiltration": "data_exfiltration",
            "ingest:hidden_text": "hidden_text",
            "ingest:zero_width": "zero_width",
            "memory:memory_injection": "memory_injection",
        }
        return mapping.get(f"{layer}:{threat}", threat or "general")

    # ============================================================
    # 审核与落地
    # ============================================================

    def get_pending_suggestions(self) -> List[Dict]:
        return [s for s in self._read_json(self.suggestions_path, []) if s.get("status") == "pending"]

    def get_all_suggestions(self) -> List[Dict]:
        return self._read_json(self.suggestions_path, [])

    def approve_suggestion(self, suggestion_id: str,
                           target_file: Optional[str] = None) -> Dict:
        """审核通过建议并落地为规则"""
        suggestions = self._read_json(self.suggestions_path, [])
        idx = next((i for i, s in enumerate(suggestions) if s["id"] == suggestion_id), -1)
        if idx == -1:
            return {"success": False, "error": "Suggestion not found"}

        suggestion = suggestions[idx]
        if suggestion.get("status") != "pending":
            return {"success": False, "error": f"Suggestion already {suggestion.get('status')}"}

        rule_file = target_file or str(
            self.rules_dir / suggestion.get("layer", "") / f"{suggestion.get('ruleSet', 'general')}.json"
        )
        abs_rule_file = self.skill_path / rule_file

        rule_data = self._read_json(abs_rule_file, {"patterns": []})
        if "patterns" not in rule_data:
            rule_data["patterns"] = []

        new_rule = {
            "id": f"auto_{self._generate_id('rule')}",
            "pattern": suggestion.get("pattern", ""),
            "weight": suggestion.get("confidence", 0.5),
            "severity": suggestion.get("severity", "medium"),
            "source": "self_loop",
            "sourceSuggestion": suggestion["id"],
            "created": self._now(),
            "description": suggestion.get("description", "")
        }

        if any(p.get("pattern") == new_rule["pattern"] for p in rule_data["patterns"]):
            return {"success": False, "error": "Duplicate pattern already exists"}

        rule_data["patterns"].append(new_rule)
        self._write_json(abs_rule_file, rule_data)

        suggestions[idx]["status"] = "approved"
        suggestions[idx]["approvedAt"] = self._now()
        suggestions[idx]["ruleFile"] = rule_file
        self._write_json(self.suggestions_path, suggestions)

        return {"success": True, "ruleFile": rule_file, "rule": new_rule}

    def reject_suggestion(self, suggestion_id: str, reason: str = "") -> Dict:
        suggestions = self._read_json(self.suggestions_path, [])
        idx = next((i for i, s in enumerate(suggestions) if s["id"] == suggestion_id), -1)
        if idx == -1:
            return {"success": False, "error": "Suggestion not found"}

        suggestions[idx]["status"] = "rejected"
        suggestions[idx]["rejectedAt"] = self._now()
        suggestions[idx]["rejectionReason"] = reason
        self._write_json(self.suggestions_path, suggestions)
        return {"success": True}

    # ============================================================
    # 统计
    # ============================================================

    def get_stats(self) -> Dict:
        all_cases = self._read_jsonl(self.case_db_path)
        suggestions = self._read_json(self.suggestions_path, [])

        missed = [c for c in all_cases if c.get("type") == "missed"]
        blocked = [c for c in all_cases if c.get("type") == "blocked"]
        false_positives = [c for c in blocked if c.get("falsePositive")]

        by_layer: Dict[str, Dict] = {}
        for c in all_cases:
            layer = c.get("layer", "unknown")
            if layer not in by_layer:
                by_layer[layer] = {"missed": 0, "blocked": 0, "falsePositive": 0}
            if c.get("type") == "missed":
                by_layer[layer]["missed"] += 1
            if c.get("type") == "blocked":
                by_layer[layer]["blocked"] += 1
                if c.get("falsePositive"):
                    by_layer[layer]["falsePositive"] += 1

        by_threat: Dict[str, int] = {}
        for c in missed:
            threat = c.get("expectedThreat", "unknown")
            by_threat[threat] = by_threat.get(threat, 0) + 1

        fp_rate = (f"{len(false_positives) / len(blocked) * 100:.1f}%" if blocked else "N/A")

        return {
            "totalCases": len(all_cases),
            "missedCases": len(missed),
            "blockedCases": len(blocked),
            "falsePositives": len(false_positives),
            "falsePositiveRate": fp_rate,
            "pendingSuggestions": sum(1 for s in suggestions if s.get("status") == "pending"),
            "approvedSuggestions": sum(1 for s in suggestions if s.get("status") == "approved"),
            "rejectedSuggestions": sum(1 for s in suggestions if s.get("status") == "rejected"),
            "byLayer": by_layer,
            "byThreat": by_threat,
            "recentMissed": [
                {"id": c["id"], "timestamp": c.get("timestamp"), "input": c.get("input", "")[:50] + "...", "expectedThreat": c.get("expectedThreat")}
                for c in missed[-5:]
            ],
            # snake_case aliases for Python conventions
            "total_cases": len(all_cases),
            "missed_cases": len(missed),
            "blocked_cases": len(blocked),
            "false_positives": len(false_positives),
            "false_positive_rate": fp_rate,
        }

    def cleanup(self, keep_recent: Optional[int] = None) -> int:
        """清理旧案例（保留最近N条）"""
        keep_recent = keep_recent or self.config["statsWindowSize"]
        all_cases = self._read_jsonl(self.case_db_path)
        if len(all_cases) <= keep_recent:
            return 0
        to_remove = len(all_cases) - keep_recent
        kept = all_cases[-keep_recent:]
        content = "\n".join(json.dumps(c, ensure_ascii=False) for c in kept) + "\n"
        self.case_db_path.write_text(content, encoding="utf-8")
        return to_remove


# ============================================================
# CLI 入口
# ============================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="奇点造物-Genesisix Self-Learning Loop")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("stats", help="显示统计信息")
    sub.add_parser("pending", help="显示待审核建议")
    sub.add_parser("analyze", help="分析漏报并生成建议")

    p_approve = sub.add_parser("approve", help="审核通过建议")
    p_approve.add_argument("--id", required=True)

    p_reject = sub.add_parser("reject", help="拒绝建议")
    p_reject.add_argument("--id", required=True)
    p_reject.add_argument("--reason", default="")

    args = parser.parse_args()
    loop = SelfLoop()

    if args.command == "stats":
        print(json.dumps(loop.get_stats(), ensure_ascii=False, indent=2))
    elif args.command == "pending":
        print(json.dumps(loop.get_pending_suggestions(), ensure_ascii=False, indent=2))
    elif args.command == "analyze":
        suggestions = loop.analyze_and_suggest()
        print(f"生成 {len(suggestions)} 条建议:")
        for s in suggestions:
            print(f"  - {s['id']}: {s['description']}")
    elif args.command == "approve":
        result = loop.approve_suggestion(args.id)
        print("✅ 建议已落地" if result["success"] else f"❌ {result['error']}")
    elif args.command == "reject":
        result = loop.reject_suggestion(args.id, args.reason)
        print("✅ 建议已拒绝" if result["success"] else f"❌ {result['error']}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
