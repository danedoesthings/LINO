import re
from constants import PROTECTED_NAMES, VM_SINGLE_LETTERS, SEMANTIC_RENAMES, LUA_KEYWORDS

_IDENT = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b')

def _is_obfuscated(name: str) -> bool:
    if name in PROTECTED_NAMES:
        return False
    if re.fullmatch(r'[a-z]{1,2}\d{5,}', name):
        return True
    if re.fullmatch(r'[A-Z]{1,3}', name) and name not in PROTECTED_NAMES:
        return True
    if re.fullmatch(r'[a-z]', name) and name not in LUA_KEYWORDS:
        return True
    return False

class VarRenamer:
    def __init__(self) -> None:
        self._counter = 0
        self._renamed: set[str] = set()

    def _fresh_reg(self) -> str:
        self._counter += 1
        prefix = 'v' if self._counter % 2 == 0 else 'r'
        return f'{prefix}{self._counter}'

    @staticmethod
    def _replace_word(code: str, old: str, new: str) -> str:
        if old == new:
            return code
        pattern = r'(?<![a-zA-Z0-9_])' + re.escape(old) + r'(?![a-zA-Z0-9_])'
        return re.sub(pattern, new, code)

    @staticmethod
    def _apply_semantic(code: str) -> str:
        for pattern, replacement in SEMANTIC_RENAMES:
            code = re.sub(pattern, replacement, code)
        return code

    @staticmethod
    def _apply_vm_letters(code: str) -> str:
        for old, new in sorted(VM_SINGLE_LETTERS.items(), key=lambda kv: -len(kv[0])):
            if old in PROTECTED_NAMES:
                continue
            code = VarRenamer._replace_word(code, old, new)
        return code

    def _apply_register_names(self, code: str) -> str:
        seen: dict[str, str] = {}
        def _repl(m: re.Match) -> str:
            name = m.group(0)
            if name in PROTECTED_NAMES:
                return name
            if name in LUA_KEYWORDS:
                return name
            if not _is_obfuscated(name):
                return name
            if name not in seen:
                seen[name] = self._fresh_reg()
            return seen[name]
        return _rename_outside_strings(code, _IDENT, _repl)

    def rename(self, code: str) -> str:
        self._counter = 0
        self._renamed = set()
        code = self._apply_semantic(code)
        code = self._apply_vm_letters(code)
        code = self._apply_register_names(code)
        return code

_STR_LIT = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|--[^\n]*|--\[\[.*?\]\]')

def _rename_outside_strings(code: str, pattern: re.Pattern, repl_fn) -> str:
    parts: list[str] = []
    last = 0
    for m in _STR_LIT.finditer(code):
        outside = code[last:m.start()]
        parts.append(pattern.sub(repl_fn, outside))
        parts.append(m.group(0))
        last = m.end()
    parts.append(pattern.sub(repl_fn, code[last:]))
    return ''.join(parts)
