import re
from constants import PROTECTED_NAMES, VM_SINGLE_LETTERS, SEMANTIC_RENAMES, LUA_KEYWORDS

_IDENT = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b')

# Regex to match string literals and comments (to avoid renaming inside them)
_STR_LIT = re.compile(
    r'"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'"
    r'|--[^\n]*'
    r'|--\[\[.*?\]\]',
    re.DOTALL
)


def _is_obfuscated(name: str) -> bool:
    """Check if a variable name looks obfuscated."""
    if name in PROTECTED_NAMES:
        return False
    if re.fullmatch(r'[a-z]{1,2}\d{5,}', name):
        return True
    if re.fullmatch(r'[A-Z]{1,3}', name) and name not in PROTECTED_NAMES:
        return True
    if re.fullmatch(r'[a-z]', name) and name not in LUA_KEYWORDS:
        return True
    return False


def _rename_outside_strings(code: str, pattern: re.Pattern, repl_fn) -> str:
    """Apply a regex substitution only outside of string literals and comments."""
    parts = []
    last = 0

    for m in _STR_LIT.finditer(code):
        # Process the code outside the string/comment
        outside = code[last:m.start()]
        parts.append(pattern.sub(repl_fn, outside))
        # Keep the string/comment unchanged
        parts.append(m.group(0))
        last = m.end()

    # Process remaining code after last match
    parts.append(pattern.sub(repl_fn, code[last:]))
    return ''.join(parts)


class VarRenamer:
    """Renames obfuscated variables to readable names."""

    def __init__(self) -> None:
        self._counter = 0
        self._renamed: set[str] = set()

    def _fresh_reg(self) -> str:
        """Generate a fresh readable variable name."""
        self._counter += 1
        if self._counter == 1:
            return 'result'
        elif self._counter == 2:
            return 'value'
        elif self._counter == 3:
            return 'data'
        elif self._counter == 4:
            return 'config'
        elif self._counter == 5:
            return 'options'
        elif self._counter <= 10:
            return f'var{self._counter}'
        prefix = 'v' if self._counter % 2 == 0 else 'r'
        return f'{prefix}{self._counter}'

    @staticmethod
    def _replace_word(code: str, old: str, new: str) -> str:
        """Replace a whole word in code, being careful with word boundaries."""
        if old == new:
            return code
        pattern = r'(?<![a-zA-Z0-9_])' + re.escape(old) + r'(?![a-zA-Z0-9_])'
        return re.sub(pattern, new, code)

    @staticmethod
    def _apply_semantic(code: str) -> str:
        """Apply semantic renames (e.g., loadstring -> dynLoader)."""
        for pattern, replacement in SEMANTIC_RENAMES:
            code = re.sub(pattern, replacement, code)
        return code

    @staticmethod
    def _apply_vm_letters(code: str) -> str:
        """Rename common single-letter VM variables to descriptive names."""
        for old, new in sorted(VM_SINGLE_LETTERS.items(), key=lambda kv: -len(kv[0])):
            if old in PROTECTED_NAMES:
                continue
            code = VarRenamer._replace_word(code, old, new)
        return code

    def _apply_register_names(self, code: str) -> str:
        """Replace obfuscated register-style names with readable ones."""
        seen: dict[str, str] = {}

        def _repl(m: re.Match) -> str:
            name = m.group(0)
            # Never rename protected names or keywords
            if name in PROTECTED_NAMES or name in LUA_KEYWORDS:
                return name
            # Only rename obfuscated-looking names
            if not _is_obfuscated(name):
                return name
            # Assign a consistent readable name
            if name not in seen:
                seen[name] = self._fresh_reg()
            return seen[name]

        return _rename_outside_strings(code, _IDENT, _repl)

    def rename(self, code: str) -> str:
        """
        Rename all obfuscated variables in the given Lua code.
        Returns the code with readable variable names.
        """
        self._counter = 0
        self._renamed = set()
        # Apply semantic renames first
        code = self._apply_semantic(code)
        # Apply VM single-letter renames
        code = self._apply_vm_letters(code)
        # Apply register-style renames
        code = self._apply_register_names(code)
        return code
