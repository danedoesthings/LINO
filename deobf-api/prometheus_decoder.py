import re
import json
from typing import Optional, List
from math_fold import safe_eval_int, fold_constants, get_getter_name_and_offset


class PrometheusDecoder:
    def __init__(self, source: str, decoder):
        self.source = source
        self.decoder = decoder
        self.strings = list(decoder.strings)
        self.offset = decoder.offset
        self.getter_name = None
        self.table_name = None
        self.shuffle_pairs = []
        self._detect_getter()
        self._extract_shuffle_pairs()

    # ── Getter detection ──────────────────────────────────────────────────────

    def _detect_getter(self):
        """
        Detect the getter function name, table name, and offset.
        Uses get_getter_name_and_offset which accepts ANY var names,
        unlike the old regex that required param name == function name.
        """
        g, t, off = get_getter_name_and_offset(self.source)
        if g:
            self.getter_name = g
            self.table_name  = t
            self.offset      = off
            return

        # Legacy fallback — fixed single-letter names
        folded = fold_constants(self.source)
        for pat in [
            r'local\s+function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+R\s*\[\s*\w+\s*\+\s*\(?(-?\d+)\)?\s*\]',
            r'local\s+function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+EncStr\s*\[\s*\w+\s*\+\s*\(?(-?\d+)\)?\s*\]',
        ]:
            m = re.search(pat, folded)
            if m:
                self.getter_name = m.group(1)
                self.offset = int(m.group(2))
                return

    # ── Shuffle pair extraction ───────────────────────────────────────────────

    def _extract_shuffle_pairs(self):
        m = re.search(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)', self.source, re.DOTALL)
        if not m:
            return
        for pair_str in re.findall(r'\{([^}]+)\}', m.group(1)):
            parts = re.split(r'[;,]', pair_str)
            resolved = []
            for part in parts:
                n = safe_eval_int(part.strip())
                if n is not None:
                    resolved.append(n)
            if len(resolved) == 2:
                self.shuffle_pairs.append(tuple(resolved))

    def _apply_shuffle(self, arr: List[str]) -> List[str]:
        result = list(arr)
        for a, b in self.shuffle_pairs:
            lo, hi = a - 1, b - 1
            while lo < hi:
                if 0 <= lo < len(result) and 0 <= hi < len(result):
                    result[lo], result[hi] = result[hi], result[lo]
                lo += 1
                hi -= 1
        return result

    # ── Main decode entry ─────────────────────────────────────────────────────

    def decode(self) -> Optional[str]:
        if not self.strings or len(self.strings) < 4:
            return None
        if not self.getter_name:
            return None

        result = self._substitute_getter_calls(self.source)
        if result and self._looks_like_lua_source(result):
            return result
        return None

    # ── Getter-call substitution ──────────────────────────────────────────────

    def _substitute_getter_calls(self, source: str) -> Optional[str]:
        """
        Replace every  getter(N)  call in the source with the decoded string
        at index (N + offset), then strip the boilerplate setup block.

        Prometheus indexing:  R[arg + offset]  where offset is already the
        adjustment so that the 1-based Lua table index maps correctly.
        Example: offset = -1 → R[1 + (-1)] = R[0] which in Python = strings[0]
                 offset = 0  → R[1 + 0]   = R[1] which in Lua 1-based = strings[0]
        We detect which convention is used by probing both and picking the one
        that gives more valid decoded strings.
        """
        strings = self.strings
        offset  = self.offset
        getter  = re.escape(self.getter_name)
        pattern = re.compile(rf'\b{getter}\s*\(\s*([0-9+\-*/%\s()]+?)\s*\)')

        # Probe: try offset as-is (treat R[x] as Lua 1-based → Python x-1)
        # and also try direct mapping (R[x] → Python x) to pick the better one
        def make_repl(extra_adj):
            def _repl(m: re.Match) -> str:
                idx = safe_eval_int(m.group(1).strip())
                if idx is None:
                    return m.group(0)
                # Lua table is 1-based: R[idx + offset]
                # Python list is 0-based: strings[lua_index - 1]
                lua_index = idx + offset
                py_index  = lua_index - 1 + extra_adj
                if 0 <= py_index < len(strings):
                    s = strings[py_index]
                    return json.dumps(s)
                return m.group(0)
            return _repl

        best_result = None
        best_score  = -1

        for adj in (0, 1, -1):
            candidate = pattern.sub(make_repl(adj), source)
            score = self._score_substitution(candidate, source)
            if score > best_score:
                best_score  = score
                best_result = candidate

        if best_result is None or best_score == 0:
            return None

        return self._strip_setup_block(best_result)

    def _score_substitution(self, result: str, original: str) -> int:
        """Count how many getter calls were successfully replaced (became quoted strings)."""
        # Count JSON-quoted strings that appeared where getter calls were
        if result == original:
            return 0
        # Heuristic: count occurrences of readable quoted strings
        score = len(re.findall(r'"[A-Za-z][A-Za-z0-9 _.,;:!?()\[\]{}\'/\\-]{1,120}"', result))
        return score

    def _strip_setup_block(self, source: str) -> str:
        """
        Remove the Prometheus boilerplate:
          1. String table:  local <name> = { "...", ... }
          2. Alphabet table: local <name> = { A=0, B=1, ... }  or  local <name> = { ["X"]=0, ... }
          3. Shuffle loop:  for _,v in ipairs({...}) do ... end
          4. Getter function: local function <getter>(...) return ... end
        """
        # 1. Remove the encoded-string table (large table of quoted strings)
        source = re.sub(
            r'local\s+\w+\s*=\s*\{(?:"[^"]*",?\s*)+\}\s*',
            '', source, count=1
        )
        # 2. Remove the alphabet/N table (table of char->index entries)
        # Keys can be: bare letters (A=0), digits (0=52), or quoted non-alnum ([" "]=62, ["_"]=62)
        source = re.sub(
            r'local\s+\w+\s*=\s*\{(?:\s*(?:\w+|\["."\])\s*=\s*\d+\s*,?\s*)+\}\s*',
            '', source, count=1
        )
        # 3. Remove the shuffle loop
        source = re.sub(
            r'for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{[^}]+\}\s*\)'
            r'\s*do.*?end\s*',
            '', source, count=1, flags=re.DOTALL
        )
        # 4. Remove the getter function definition
        if self.getter_name:
            g = re.escape(self.getter_name)
            source = re.sub(
                rf'local\s+function\s+{g}\s*\([^)]*\).*?end\s*',
                '', source, count=1, flags=re.DOTALL
            )
        # Clean up leading/trailing whitespace and excess blank lines
        source = re.sub(r'^\s*\n+', '', source)
        source = re.sub(r'\n{3,}', '\n\n', source)
        return source.strip()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _looks_like_lua_source(self, code: str) -> bool:
        keywords = ['function', 'local', 'end', 'return', 'if', 'then',
                    'else', 'for', 'while', 'do', 'print', 'pcall', 'error',
                    'game', 'workspace', 'require', 'loadstring']
        found = sum(1 for kw in keywords if kw in code)
        has_structure = '=' in code or '(' in code or '{' in code
        # Lower threshold: even partial substitution is useful
        return found >= 1 and has_structure and len(code) > 20
