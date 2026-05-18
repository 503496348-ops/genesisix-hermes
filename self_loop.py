#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import io

# Windows终端UTF-8支持（CLI局部作用域）
def _setup_windows_stdout():
    if sys.platform == 'win32':
        return io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    return sys.stdout
"""
奇点造物-Genesisix Self-Learning Loop - 自循环门禁
漏报记录 → 规则分析 → 审核落地

@author 小乖 (OpenClaw Agent)
@version 1.2.0
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# ============================================================
# 常量
# ============================================================

SKILL_PATH = Path(__file__).parent
CASE_DB_PATH = SKILL_PATH / "case_database.jsonl"
RULES_DIR = SKILL_PATH / "rules"
SUGGESTIONS_FILE = SKILL_PATH / "rule_suggestions.json"

# ============================================================
# 数据模型
# ============================================================

@dataclass
class MissedCase:
    """漏报案例"""
    timestamp: str
    input_text: str
    expected_threat: str
    actual_result: str
    severity: str  # critical/high/medium/low
    notes: str = ""

@dataclass
class BlockedCase:
    """拦截案例（用于统计）"""
    timestamp: str
    layer: str
    threat_description: str
    false_positive: bool  # 是否是误报

@dataclass
class RuleSuggestion:
    """规则建议"""
    id: str
    layer: str
    pattern: str
    description: str
    severity: str
    confidence: float
    source_case: str
    status: str  # pending/approved/rejected

# ============================================================
# Self-Loop 核心逻辑
# ============================================================

class SelfLoop:
    """自循环门禁"""
    
    def __init__(self, skill_path: Optional[Path] = None):
        if skill_path:
            global SKILL_PATH, CASE_DB_PATH, RULES_DIR, SUGGESTIONS_FILE
            skill_path = Path(skill_path)
            # 如果传入的是文件路径，取父目录
            if skill_path.is_file():
                SKILL_PATH = skill_path.parent
            else:
                SKILL_PATH = skill_path
            CASE_DB_PATH = SKILL_PATH / "case_database.jsonl"
            RULES_DIR = SKILL_PATH / "rules"
            SUGGESTIONS_FILE = SKILL_PATH / "rule_suggestions.json"
    
    def _now(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # -------- 漏报记录 --------
    
    def log_missed_case(self, input_text: str, expected_threat: str, 
                       actual_result: str, severity: str = "high", 
                       notes: str = "") -> bool:
        """
        记录漏报案例
        
        Args:
            input_text: 被漏检的输入
            expected_threat: 期望检测到的威胁
            actual_result: 实际检测结果
            severity: 严重程度
            notes: 备注
        
        Returns:
            bool: 是否记录成功
        """
        # 确保目录存在
        CASE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        case = MissedCase(
            timestamp=self._now(),
            input_text=input_text[:500],  # 截断存储
            expected_threat=expected_threat,
            actual_result=actual_result,
            severity=severity,
            notes=notes
        )
        
        try:
            with open(CASE_DB_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(case), ensure_ascii=False) + "\n")
            return True
        except Exception as e:
            print(f"[SelfLoop] 记录漏报失败: {e}")
            return False
    
    def log_blocked_case(self, layer: str, threat_description: str,
                        false_positive: bool = False) -> bool:
        """
        记录拦截案例（用于统计误报率）
        """
        # 确保目录存在
        CASE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        case = BlockedCase(
            timestamp=self._now(),
            layer=layer,
            threat_description=threat_description,
            false_positive=false_positive
        )
        
        try:
            with open(CASE_DB_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(case), ensure_ascii=False) + "\n")
            return True
        except Exception as e:
            print(f"[SelfLoop] 记录拦截案例失败: {e}")
            return False
    
    # -------- 规则建议 --------
    
    def analyze_and_suggest(self, min_cases: int = 3) -> List[RuleSuggestion]:
        """
        分析漏报案例，生成规则建议
        
        Args:
            min_cases: 最少案例数才触发建议
        
        Returns:
            List[RuleSuggestion]: 规则建议列表
        """
        suggestions = []
        
        # 读取漏报案例
        missed_cases = []
        if CASE_DB_PATH.exists():
            with open(CASE_DB_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if "expected_threat" in data and "input_text" in data:
                                missed_cases.append(data)
                        except json.JSONDecodeError:
                            continue
        
        if len(missed_cases) < min_cases:
            return []
        
        # 按威胁类型分组
        threat_groups = {}
        for case in missed_cases:
            threat = case.get("expected_threat", "unknown")
            if threat not in threat_groups:
                threat_groups[threat] = []
            threat_groups[threat].append(case)
        
        # 生成建议
        suggestion_id = 1
        for threat, cases in threat_groups.items():
            if len(cases) >= min_cases:
                # 取最新案例作为样本
                latest = cases[-1]
                
                # 简单启发式：从输入中提取模式
                input_text = latest.get("input_text", "")
                severity = latest.get("severity", "medium")
                
                suggestion = RuleSuggestion(
                    id=f"sug_{datetime.now().strftime('%Y%m%d')}_{suggestion_id:03d}",
                    layer="llm",  # 默认归入LLM层
                    pattern=self._extract_pattern(input_text),
                    description=f"基于{len(cases)}个漏报案例生成: {threat}",
                    severity=severity,
                    confidence=min(0.9, 0.5 + len(cases) * 0.1),
                    source_case=f"case_db:{latest.get('timestamp', '')}",
                    status="pending"
                )
                suggestions.append(suggestion)
                suggestion_id += 1
        
        # 保存建议
        if suggestions:
            existing = []
            if SUGGESTIONS_FILE.exists():
                try:
                    existing = json.loads(SUGGESTIONS_FILE.read_text(encoding="utf-8"))
                except:
                    existing = []
            
            all_suggestions = existing + [asdict(s) for s in suggestions]
            SUGGESTIONS_FILE.write_text(
                json.dumps(all_suggestions, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
        
        return suggestions
    
    def _extract_pattern(self, text: str) -> str:
        """简单启发式：从文本中提取潜在模式"""
        # 移除明显随机部分，保留结构
        text = text.strip()
        if len(text) > 100:
            text = text[:100] + "..."
        
        # 转义特殊字符
        import re
        pattern = re.escape(text)
        # 简化连续字符
        pattern = re.sub(r'\\{3,}', '{3,}', pattern)
        
        return pattern
    
    # -------- 审核与落地 --------
    
    def get_pending_suggestions(self) -> List[dict]:
        """获取待审核的建议"""
        if not SUGGESTIONS_FILE.exists():
            return []
        
        try:
            suggestions = json.loads(SUGGESTIONS_FILE.read_text(encoding="utf-8"))
            return [s for s in suggestions if s.get("status") == "pending"]
        except:
            return []
    
    def approve_suggestion(self, suggestion_id: str, target_rule_file: str = None) -> bool:
        """
        审核通过建议，写入规则库
        
        Args:
            suggestion_id: 建议ID
            target_rule_file: 目标规则文件路径（可选，默认根据layer推断）
        
        Returns:
            bool: 是否落地成功
        """
        if not SUGGESTIONS_FILE.exists():
            return False
        
        try:
            suggestions = json.loads(SUGGESTIONS_FILE.read_text(encoding="utf-8"))
            
            target = None
            for s in suggestions:
                if s.get("id") == suggestion_id:
                    target = s
                    s["status"] = "approved"
                    s["approved_at"] = self._now()
                    break
            
            if not target:
                return False
            
            # 写入规则文件
            layer = target.get("layer", "llm")
            rule_data = {
                "id": target["id"],
                "pattern": target["pattern"],
                "description": target["description"],
                "severity": target["severity"],
                "confidence": target["confidence"],
                "created_from": "self_loop",
                "approved_at": self._now()
            }
            
            rule_file = Path(target_rule_file) if target_rule_file else \
                        RULES_DIR / layer / f"{suggestion_id}.json"
            
            rule_file.parent.mkdir(parents=True, exist_ok=True)
            rule_file.write_text(
                json.dumps(rule_data, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            
            # 保存更新后的建议
            SUGGESTIONS_FILE.write_text(
                json.dumps(suggestions, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            
            return True
        except Exception as e:
            print(f"[SelfLoop] 审核落地失败: {e}")
            return False
    
    def reject_suggestion(self, suggestion_id: str, reason: str = "") -> bool:
        """拒绝建议"""
        if not SUGGESTIONS_FILE.exists():
            return False
        
        try:
            suggestions = json.loads(SUGGESTIONS_FILE.read_text(encoding="utf-8"))
            
            for s in suggestions:
                if s.get("id") == suggestion_id:
                    s["status"] = "rejected"
                    s["rejected_at"] = self._now()
                    s["rejection_reason"] = reason
                    break
            
            SUGGESTIONS_FILE.write_text(
                json.dumps(suggestions, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            return True
        except:
            return False
    
    # -------- 统计 --------
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        stats = {
            "total_cases": 0,
            "missed_cases": 0,
            "blocked_cases": 0,
            "false_positives": 0,
            "pending_suggestions": 0,
            "approved_suggestions": 0,
            "rejected_suggestions": 0
        }
        
        if not CASE_DB_PATH.exists():
            return stats
        
        try:
            with open(CASE_DB_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        stats["total_cases"] += 1
                        try:
                            data = json.loads(line)
                            if "expected_threat" in data:
                                stats["missed_cases"] += 1
                            elif "false_positive" in data:
                                stats["blocked_cases"] += 1
                                if data.get("false_positive"):
                                    stats["false_positives"] += 1
                        except json.JSONDecodeError:
                            continue
        except:
            pass
        
        if SUGGESTIONS_FILE.exists():
            try:
                suggestions = json.loads(SUGGESTIONS_FILE.read_text(encoding="utf-8"))
                for s in suggestions:
                    status = s.get("status", "pending")
                    if status == "pending":
                        stats["pending_suggestions"] += 1
                    elif status == "approved":
                        stats["approved_suggestions"] += 1
                    elif status == "rejected":
                        stats["rejected_suggestions"] += 1
            except:
                pass
        
        return stats

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
    
    parser = argparse.ArgumentParser(description="奇点造物-Genesisix 自循环门禁")
    subparsers = parser.add_subparsers(dest="cmd")
    
    # 记录漏报
    miss_parser = subparsers.add_parser("log-missed", help="记录漏报")
    miss_parser.add_argument("--input", "-i", required=True, help="被漏检的输入")
    miss_parser.add_argument("--expected", "-e", required=True, help="期望检测到的威胁")
    miss_parser.add_argument("--result", "-r", required=True, help="实际检测结果")
    miss_parser.add_argument("--severity", "-s", default="high", choices=["critical", "high", "medium", "low"])
    
    # 记录误报
    fp_parser = subparsers.add_parser("log-false-positive", help="记录误报")
    fp_parser.add_argument("--layer", "-l", required=True, help="检测层")
    fp_parser.add_argument("--threat", "-t", required=True, help="威胁描述")
    
    # 获取统计
    subparsers.add_parser("stats", help="获取统计信息")
    
    # 待审核建议
    subparsers.add_parser("pending", help="获取待审核建议")
    
    # 审核建议
    approve_parser = subparsers.add_parser("approve", help="审核通过建议")
    approve_parser.add_argument("--id", "-i", required=True, help="建议ID")
    
    reject_parser = subparsers.add_parser("reject", help="拒绝建议")
    reject_parser.add_argument("--id", "-i", required=True, help="建议ID")
    reject_parser.add_argument("--reason", "-r", default="", help="拒绝原因")
    
    # 分析生成建议
    subparsers.add_parser("analyze", help="分析漏报生成建议")
    
    args = parser.parse_args()
    sl = SelfLoop()
    
    if args.cmd == "log-missed":
        success = sl.log_missed_case(args.input, args.expected, args.result, args.severity)
        print("✅ 漏报已记录" if success else "❌ 记录失败")
    
    elif args.cmd == "log-false-positive":
        success = sl.log_blocked_case(args.layer, args.threat, false_positive=True)
        print("✅ 误报已记录" if success else "❌ 记录失败")
    
    elif args.cmd == "stats":
        stats = sl.get_stats()
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    
    elif args.cmd == "pending":
        pending = sl.get_pending_suggestions()
        print(json.dumps(pending, ensure_ascii=False, indent=2))
    
    elif args.cmd == "approve":
        success = sl.approve_suggestion(args.id)
        print("✅ 建议已落地" if success else "❌ 落地失败")
    
    elif args.cmd == "reject":
        success = sl.reject_suggestion(args.id, args.reason)
        print("✅ 建议已拒绝" if success else "❌ 拒绝失败")
    
    elif args.cmd == "analyze":
        suggestions = sl.analyze_and_suggest()
        print(f"生成 {len(suggestions)} 条建议")
        for s in suggestions:
            print(f"  - {s.id}: {s.description}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
