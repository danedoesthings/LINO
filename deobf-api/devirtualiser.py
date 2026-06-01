import re
from typing import Optional
from math_fold import fold_constants, safe_eval_int
from string_decoder import StringTableDecoder
from constants import escape_lua_string

_BOOTSTRAP_MARKERS = [
    'return(function(R,M,Y,r,m,N,h,d,o,l,q,I,w,g,S,z,Q,T,e,O,J)',
    'return(function(R,M,Y,r,m,N,h,d,o,l,q,I,w,g',
    'return(function(',
]

def strip_bootstrap(source: str) -> str:
    for marker in _BOOTSTRAP_MARKERS:
        pos = source.find(marker)
        if pos != -1:
            return source[pos:]
    return source

_CALL_PAT = re.compile(r'\b(?:E|GetStr|GetString)\s*\(\s*([^)]+?)\s*\)')

def substitute_string_calls(source: str, decoder: StringTableDecoder) -> str:
    def _repl(m: re.Match) -> str:
        inner = m.group(1).strip()
        n = safe_eval_int(inner)
        if n is None:
            return m.group(0)
        val = decoder.resolve(n)
        if val is None:
            return m.group(0)
        if not val:
            return 'nil'
        return escape_lua_string(str(val))
    return _CALL_PAT.sub(_repl, source)

_INDEX_PAT = re.compile(r'\b(?:R|EncStr|EncryptedStrings)\s*\[\s*([^\]]+?)\s*\]')

def substitute_table_indices(source: str, decoder: StringTableDecoder) -> str:
    def _repl(m: re.Match) -> str:
        inner = m.group(1).strip()
        n = safe_eval_int(inner)
        if n is None:
            return m.group(0)
        py_idx = n - 1
        if 0 <= py_idx < len(decoder.strings):
            val = decoder.strings[py_idx]
            if not val:
                return 'nil'
            return escape_lua_string(str(val))
        return m.group(0)
    return _INDEX_PAT.sub(_repl, source)

_VM_INDICATORS = [
    re.compile(r'while\s+\w+\s+do\s+if\s+\w+\s*<\s*\d+\s+then'),
    re.compile(r'if\s+\w+\s*<\s*-?\d+\s+then'),
    re.compile(r'\w+\[\w+\]\s*=\s*\w+\[\w+\]\s*[+\-]\s*\d+'),
]

def is_vm_obfuscated(source: str) -> bool:
    inner = source
    m = re.search(r'while\s+\w+\s+do', source)
    if m:
        inner = source[m.start():]
    hits = sum(1 for p in _VM_INDICATORS if p.search(inner))
    return hits >= 2

class DispatcherUnflattener:
    def __init__(self, source: str) -> None:
        self.source = source
        self.transitions: dict[int, Optional[int]] = {}
        self._extract_blocks()

    def _extract_blocks(self) -> None:
        states = {int(v) for v in re.findall(r'\bvmState\s*=\s*(-?\d+)\b', self.source)}
        for state in states:
            self.transitions[state] = self._find_next(state)

    def _find_next(self, state: int) -> Optional[int]:
        region_pat = re.compile(
            rf'vmState\s*=\s*{re.escape(str(state))}\b(.{{0,1200}}?)vmState\s*=\s*(-?\d+)',
            re.DOTALL,
        )
        m = region_pat.search(self.source)
        if m:
            return int(m.group(2))
        return None

    def linearise(self) -> list[int]:
        if not self.transitions:
            return []
        positives = [s for s in self.transitions if s > 0]
        entry = min(positives) if positives else min(self.transitions)
        visited: list[int] = []
        seen: set[int] = set()
        current: Optional[int] = entry
        while current is not None and current not in seen:
            seen.add(current)
            visited.append(current)
            current = self.transitions.get(current)
        return visited

class Devirtualiser:
    def __init__(self, decoder: StringTableDecoder) -> None:
        self.decoder = decoder
        self.vm_detected = False
        self.state_count = 0

    def process(self, source: str) -> str:
        source = substitute_string_calls(source, self.decoder)
        source = substitute_table_indices(source, self.decoder)
        source = fold_constants(source)
        source = strip_bootstrap(source)
        self.vm_detected = is_vm_obfuscated(source)
        if self.vm_detected:
            source = self._annotate_vm(source)
        return source

    def _annotate_vm(self, source: str) -> str:
        unflat = DispatcherUnflattener(source)
        order = unflat.linearise()
        self.state_count = len(order)
        if not order:
            return '-- [VM DETECTED] Could not linearise state machine\n\n' + source
        header = (
            f'-- [VM DETECTED]  {self.state_count} reachable states identified\n'
            f'-- Execution order: {order[:20]}'
            + ('...' if len(order) > 20 else '') + '\n\n'
        )
        return header + source
