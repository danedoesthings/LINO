def _decode(self) -> None:
        alpha = _extract_alphabet_from_numeric_table(self.source)
        if not alpha:
            raw = _extract_raw_strings(self.source)
            if raw is None:
                raw = self._extract_keyed_strings(self.source)
            if raw:
                self.strings = [decode_numeric_escapes(s) for s in raw]
                self.ok = True
                self.diagnostics['raw_count'] = len(raw)
                self.diagnostics['decoded_count'] = len(self.strings)
                self.diagnostics['note'] = 'alphabet not found, used raw strings'
                return
            self.diagnostics['error'] = 'alphabet not found and no raw strings'
            return

        self.alphabet = alpha
        self.diagnostics['alphabet'] = alpha[:10] + '...'

        raw = _extract_raw_strings(self.source)
        if raw is None:
            raw = self._extract_keyed_strings(self.source)
        if raw is None:
            self.diagnostics['error'] = 'R table not found'
            return

        self.diagnostics['raw_count'] = len(raw)
        ops = _extract_shuffle_ops(self.source)
        self.diagnostics['shuffle_ops'] = len(ops)
        shuffled = _apply_shuffle(raw, ops)
        decoded: list[str] = []
        for s in shuffled:
            decoded.append(self._decode_entry(s))
        self.strings = decoded
        self.ok = True
        self.diagnostics['decoded_count'] = len(decoded)
        self.offset = get_string_table_offset(self.source)
        self.diagnostics['offset'] = self.offset

    @staticmethod
    def _extract_keyed_strings(source: str) -> Optional[list[str]]:
        pat = re.compile(
            r'local\s+\w+\s*=\s*\{((?:\s*\[\d+\]\s*=\s*"[^"]*"\s*[,;]?\s*){4,})\}',
            re.DOTALL,
        )
        m = pat.search(source)
        if m:
            return re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
        return None
