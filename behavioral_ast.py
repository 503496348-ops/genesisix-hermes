#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AtomCollide-智械工坊 Behavioral AST Analyzer
基于Python AST的危险代码执行模式检测

Inspired by NVIDIA SkillSpector's behavioral_ast analyzer.
Enhanced with chain detection and additional dangerous patterns.

@author AtomCollide-智械工坊团队
@version 1.0.0
"""

import ast
from typing import List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ASTThreat:
    """AST分析检测到的威胁"""
    rule_id: str
    message: str
    severity: str
    confidence: float
    line: int
    end_line: Optional[int]
    matched_text: str


# Dangerous builtins that can execute code
_DANGEROUS_BUILTINS = frozenset({"exec", "eval", "compile", "__import__"})

# subprocess module calls
_SUBPROCESS_CALLS = frozenset({
    "call", "run", "Popen", "check_output", "check_call",
    "getoutput", "getstatusoutput",
})

# os exec-family calls
_OS_EXEC_CALLS = frozenset({
    "system", "popen", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "posix_spawn", "posix_spawnp",
})

# Dangerous modules/patterns that can be chained with exec/eval
_DANGEROUS_CHAIN_SOURCES = frozenset({
    "base64", "codecs", "marshal", "urllib", "requests", "httpx",
    "pickle", "shelve", "yaml", "subprocess", "os",
})

_RULE_INFO: dict[str, dict] = {
    "AST1": {"message": "exec() call detected — arbitrary code execution", "severity": "high", "confidence": 0.85},
    "AST2": {"message": "eval() call detected — arbitrary expression evaluation", "severity": "high", "confidence": 0.85},
    "AST3": {"message": "Dynamic import via __import__()", "severity": "medium", "confidence": 0.75},
    "AST4": {"message": "subprocess module call — possible command execution", "severity": "medium", "confidence": 0.70},
    "AST5": {"message": "os.system() or os exec-family call", "severity": "high", "confidence": 0.85},
    "AST6": {"message": "compile() call — possible dynamic code generation", "severity": "medium", "confidence": 0.65},
    "AST7": {"message": "Dynamic attribute access via getattr() with non-literal", "severity": "low", "confidence": 0.50},
    "AST8": {"message": "Dangerous execution chain detected", "severity": "critical", "confidence": 0.95},
    "AST9": {"message": "Inline import with exec/eval — obfuscated execution", "severity": "high", "confidence": 0.90},
}


def _resolve_call_name(node: ast.Call) -> Optional[str]:
    """Resolve a Call node to its dotted name string."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def _contains_dangerous_source(node: ast.AST) -> Optional[str]:
    """Walk children to find a nested dangerous call that forms a chain."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = _resolve_call_name(child)
        if name is None:
            continue
        if name in ("compile", "__import__"):
            return name
        if name.startswith("subprocess.") or name.startswith("os."):
            return name
        for part in _DANGEROUS_CHAIN_SOURCES:
            if part in name:
                return name
    return None


def _is_chain_sink(node: ast.Call) -> bool:
    """True if this call is exec(), eval(), or compile()."""
    name = _resolve_call_name(node)
    return name in ("exec", "eval", "compile")


def analyze_python_ast(content: str, file_path: str = "<unknown>") -> List[ASTThreat]:
    """
    Analyze Python source code for dangerous execution patterns using AST.
    
    Args:
        content: Python source code string
        file_path: Path of the file being analyzed (for reporting)
    
    Returns:
        List of ASTThreat findings
    """
    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return []

    lines = content.splitlines()
    findings: List[ASTThreat] = []
    seen: set[Tuple[str, int]] = set()

    def _get_source_segment(lineno: int, end_lineno: Optional[int]) -> str:
        if not lines:
            return ""
        start = max(0, lineno - 1)
        end = min(len(lines), end_lineno) if end_lineno else min(len(lines), lineno)
        return "\n".join(lines[start:end])[:300]

    def _emit(rule_id: str, lineno: int, end_lineno: Optional[int], msg_override: Optional[str] = None):
        key = (rule_id, lineno)
        if key in seen:
            return
        seen.add(key)
        info = _RULE_INFO[rule_id]
        findings.append(ASTThreat(
            rule_id=rule_id,
            message=msg_override or info["message"],
            severity=info["severity"],
            confidence=info["confidence"],
            line=lineno,
            end_line=end_lineno,
            matched_text=_get_source_segment(lineno, end_lineno),
        ))

    for ast_node in ast.walk(tree):
        if not isinstance(ast_node, ast.Call):
            continue

        call_name = _resolve_call_name(ast_node)
        if call_name is None:
            continue

        lineno = getattr(ast_node, "lineno", 1)
        end_lineno = getattr(ast_node, "end_lineno", None)

        # Check for dangerous execution chains (exec wrapping dangerous sources)
        if call_name == "exec":
            if _is_chain_sink(ast_node) and ast_node.args:
                source = _contains_dangerous_source(ast_node.args[0])
                if source:
                    _emit("AST8", lineno, end_lineno,
                          f"Dangerous chain: exec() wrapping {source}")
            _emit("AST1", lineno, end_lineno)

        elif call_name == "eval":
            if _is_chain_sink(ast_node) and ast_node.args:
                source = _contains_dangerous_source(ast_node.args[0])
                if source:
                    _emit("AST8", lineno, end_lineno,
                          f"Dangerous chain: eval() wrapping {source}")
            _emit("AST2", lineno, end_lineno)

        elif call_name == "__import__":
            _emit("AST3", lineno, end_lineno)

        elif call_name == "compile":
            _emit("AST6", lineno, end_lineno)

        elif call_name.startswith("subprocess."):
            attr = call_name.split(".", 1)[1]
            if attr in _SUBPROCESS_CALLS:
                _emit("AST4", lineno, end_lineno)

        elif call_name.startswith("os."):
            attr = call_name.split(".", 1)[1]
            if attr in _OS_EXEC_CALLS:
                _emit("AST5", lineno, end_lineno)

        elif call_name == "getattr" and len(ast_node.args) >= 2:
            if not isinstance(ast_node.args[1], ast.Constant):
                _emit("AST7", lineno, end_lineno)

    # Detect inline import + exec patterns (e.g., exec("import os; os.system('...')")
    for ast_node in ast.walk(tree):
        if not isinstance(ast_node, ast.Call):
            continue
        call_name = _resolve_call_name(ast_node)
        if call_name not in ("exec", "eval"):
            continue
        if ast_node.args and isinstance(ast_node.args[0], ast.Constant):
            code_str = str(ast_node.args[0].value)
            if "import " in code_str and any(
                mod in code_str for mod in ("os", "subprocess", "sys", "shutil")
            ):
                lineno = getattr(ast_node, "lineno", 1)
                end_lineno = getattr(ast_node, "end_lineno", None)
                _emit("AST9", lineno, end_lineno,
                      f"Inline import detected inside {call_name}() — obfuscated code execution")

    return findings


if __name__ == "__main__":
    # Quick self-test
    test_code = """
import os
os.system("ls -la")
result = eval("1+1")
exec("import subprocess; subprocess.run(['whoami'])")
cmd = getattr(obj, dynamic_attr)
"""
    threats = analyze_python_ast(test_code, "<test>")
    for t in threats:
        print(f"[{t.severity.upper()}] {t.rule_id}: {t.message} (line {t.line}, conf={t.confidence})")
