class Unveiler:
    def __init__(self, harness: LuaHarness) -> None:
        self.harness = harness
        self.trace: List[Dict] = []

    def _log(self, stage: str, success: bool, message: str) -> None:
        self.trace.append({'stage': stage, 'success': success, 'message': message, 'timestamp': time.time()})

    def _is_valid_lua(self, code: str) -> bool:
        if not HAS_LUAPARSER:
            return True
        try:
            lua_ast.parse(code)
            return True
        except Exception:
            return False

    def _score_lua_quality(self, code: str) -> int:
        score = 0
        if not code or len(code) < 10:
            return 0
        if self._is_valid_lua(code):
            score += 50
        score += len(re.findall(r'\bfunction\b', code)) * 10
        score += len(re.findall(r'\blocal\s+\w+\s*=', code)) * 5
        score += len(re.findall(r'\breturn\b', code)) * 8
        score += len(re.findall(r'\bif\b.*\bthen\b', code)) * 8
        score += len(re.findall(r'\bwhile\b.*\bdo\b', code)) * 8
        score += len(re.findall(r'\bfor\b.*\bdo\b', code)) * 8
        score += len(re.findall(r'\bend\b', code)) * 5
        vm_dispatch_count = len(re.findall(r'while\s+\w+\s+do\s+if\s+\w+\s*[<>=]+\s*-?\d+\s+then', code))
        score -= vm_dispatch_count * 20
        score -= len(re.findall(r'vmState\s*=\s*-?\d+', code)) * 20
        score -= len(re.findall(r'GetStr\s*\(', code)) * 30
        score -= len(re.findall(r'EncStr\s*\[', code)) * 15
        return score

    def _is_quality_output(self, code: str) -> bool:
        return len(code) > 200 and ('function' in code or 'local' in code or 'end' in code)

    def _calculate_vm_score(self, source: str) -> int:
        score = 0
        indicators = [
            (r'while\s+\w+\s+do\s+if\s+\w+\s*[<>=]+\s*-?\d+\s+then', 20),
            (r'if\s+\w+\s*[<>=]+\s*-?\d+\s+then', 5),
            (r'local\s+function\s+\w+\s*\([^)]*\)\s*return\s+R\s*\[[^\]]*[+\-*/%][^\]]*\d+\]', 15),
            (r'\w+\s*=\s*\{\s*\[?\d+\]?\s*=\s*function', 10),
        ]
        for pattern, weight in indicators:
            score += len(re.findall(pattern, source)) * weight
        return score

    def unveil(self, source: str) -> Tuple[str, str, str]:
        self.trace = []
        decoder = StringTableDecoder(source)
        if not decoder.ok:
            self._log('decode', False, decoder.diagnostics.get('error', 'decode failed'))
            return '', 'unable', 'String decode failed'

        self._log('decode', True, f'decoded {len(decoder.strings)} strings')

        vm_score = self._calculate_vm_score(source)
        self._log('vm_detect', True, f'VM score: {vm_score}')

        if self.harness.lune_available:
            self._log('harness', True, 'attempting Lune runtime capture')
            harness_result = self.harness.run(source, timeout=120, decoded_strings=decoder.strings)
            if harness_result and self._is_quality_output(harness_result):
                self._log('harness_success', True, f'captured {len(harness_result)} chars')
                renamer = VarRenamer()
                cleaned = renamer.rename(harness_result)
                cleaned = beautify(cleaned)
                return cleaned, 'lua_harness', 'Runtime capture successful'

        if vm_score >= 30:
            self._log('devirtualise', True, 'VM detected, attempting VM devirtualization')
            try:
                vm_devirt = VMDevirtualizer(source, decoder)
                lifted = vm_devirt.devirtualize()
                if lifted and self._is_valid_lua(lifted):
                    self._log('devirtualise_success', True, f'VM lifted, {len(vm_devirt.states)} states')
                    renamer = VarRenamer()
                    lifted = renamer.rename(lifted)
                    lifted = beautify(lifted)
                    return lifted, 'vm_devirtualized', 'VM successfully devirtualized'
            except Exception as e:
                self._log('devirtualise', False, f'VM devirtualizer exception: {str(e)[:200]}')

        self._log('devirtualise', True, 'attempting static devirtualisation')
        devirt = Devirtualiser(decoder, annotate=True)
        processed = devirt.process(source)
        if processed and self._is_quality_output(processed):
            renamer = VarRenamer()
            result = renamer.rename(processed)
            result = beautify(result)
            return result, 'static_analysis', 'Static devirtualisation complete'

        try:
            dumper = InstructionTableDumper(source, decoder.strings)
            dumped = dumper.dump()
            if dumped and len(dumped) > 200:
                self._log('devirtualise_success', True, 'instruction table dumped')
                return dumped, 'instr_table_dump', 'String table with reconstruction'
        except Exception as e:
            self._log('devirtualise', False, f'instruction dumper failed: {str(e)[:100]}')

        lines = [f'-- [{i}] {json.dumps(str(s))}' for i, s in enumerate(decoder.strings) if s]
        return '\n'.join(lines), 'wearedevs_decode', 'Decoded string table'
