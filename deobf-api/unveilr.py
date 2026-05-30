import base64
import re
import zlib
import binascii
import time
from typing import Optional, List, Tuple

from engine import (
    _wearedevs_decode,
    _is_wearedevs_vm,
    _detect_prometheus_vm,
    _prometheus_decompile,
    _try_base64_decode,
    _custom_b64_decode,
    _extract_wearedevs_alphabet,
    _is_probably_text,
    _looks_like_real_code,
    _is_lua_bytecode,
    LUA_KEYWORDS,
)

class Unveiler:
    def __init__(self, java_available, unluac_path, lua_harness_fn, run_unluac_fn):
        self.java_available = java_available
        self.unluac_path = unluac_path
        self._run_lua_harness = lua_harness_fn
        self._run_unluac = run_unluac_fn
        self.trace = []
        self.max_layers = 10

    def _log(self, stage, success, message):
        self.trace.append({'stage': stage, 'success': success, 'message': message, 'timestamp': time.time()})

    def unveil(self, source):
        self.trace = []
        peeled = self._peel_outer_base64(source)
        if peeled != source:
            self._log("outer_b64_peel", True, f"decoded outer base64 ({len(peeled)} chars)")
            source = peeled

        wd = _wearedevs_decode(source)
        if wd['success']:
            self._log("wearedevs_decode", True, f"decoded {wd['diagnostics'].get('decoded_count',0)} strings")
            self._log("harness", True, "executing Lua harness for VM")
            harness_result = self._run_lua_harness(source)
            if harness_result and _looks_like_real_code(harness_result):
                self._log("harness_success", True, f"captured {len(harness_result)} chars of real code")
                return harness_result, 'lua_harness', 'Harness captured original source'

            vm_result = self._attempt_vm_lift(source, wd['decoded_strings'])
            if vm_result:
                return vm_result, 'wearedevs_vm_lifted', 'VM lifted'

            lines = [f"-- [{i}] {s!r}" for i, s in enumerate(wd['decoded_strings']) if s]
            return '\n'.join(lines), 'wearedevs_decode', 'Decoded string table (no harness capture)'

        if _detect_prometheus_vm(source):
            self._log("prometheus_detect", True, "Prometheus VM detected")
            result = _prometheus_decompile(source)
            if result and len(result) >= 50:
                return result, 'prometheus_vm', 'Prometheus VM decompiled'

        self._log("harness_fallback", True, "running harness as final attempt")
        harness_result = self._run_lua_harness(source)
        if harness_result:
            return harness_result, 'lua_harness', 'Harness captured output'

        recursive_result = self._recursive_unveil(source)
        if recursive_result and recursive_result != source:
            return recursive_result, 'recursive_unveil', 'Multi-layer unwrapping'

        return '', 'unable', 'All strategies failed'

    def _peel_outer_base64(self, text):
        cleaned = re.sub(r'\s+', '', text.strip())
        if re.match(r'^[A-Za-z0-9+/=]+$', cleaned):
            decoded = _try_base64_decode(cleaned)
            if decoded:
                for enc in ('utf-8', 'latin-1'):
                    try:
                        dec_text = decoded.decode(enc)
                        if len(dec_text) > 50:
                            return dec_text
                    except:
                        pass
        return text

    def _attempt_vm_lift(self, source, decoded_strings):
        self._log("vm_lift_attempt", True, "trying static VM lift")
        if not _is_wearedevs_vm(source):
            return None
        try:
            from engine import (
                _extract_vm_structure, _extract_instruction_stream,
                _build_handler_table, _build_cfg, _detect_loops,
                _symbolic_execute, _extract_all_constants, VMLifterState
            )
            vm = _extract_vm_structure(source)
            insts = _extract_instruction_stream(source, vm)
            if len(insts) < 10:
                return None
            op_handlers, _ = _build_handler_table(source, vm)
            if not op_handlers:
                return None
            blocks, block_map = _build_cfg(insts, op_handlers)
            loop_headers, _ = _detect_loops(blocks)
            constants = _extract_all_constants(source, decoded_strings or [])
            state = VMLifterState()
            state.constants = constants
            state.instructions = insts
            lifted = _symbolic_execute(state, insts, op_handlers, blocks, block_map, loop_headers)
            if lifted and _looks_like_real_code(lifted):
                return lifted
        except Exception:
            pass
        return None

    def _recursive_unveil(self, source, depth=0):
        if depth > self.max_layers:
            return None
        self._log(f"recursive_layer_{depth}", True, f"attempting layer {depth}")

        if re.match(r'^[A-Za-z0-9+/=]+$', source.strip()):
            decoded = _try_base64_decode(source.strip())
            if decoded:
                try:
                    text = decoded.decode('utf-8')
                    if _is_probably_text(text) and text != source:
                        result = self._recursive_unveil(text, depth+1)
                        return result if result else text
                except:
                    pass

        try:
            alpha = _extract_wearedevs_alphabet(source)
            if alpha:
                decoded = _custom_b64_decode(source.strip(), alpha)
                if decoded and decoded != source.encode('latin-1'):
                    text = decoded.decode('latin-1', errors='replace')
                    if _is_probably_text(text) and text != source:
                        result = self._recursive_unveil(text, depth+1)
                        return result if result else text
        except:
            pass

        for key in range(1, 256):
            try:
                raw = source.encode('latin-1')
                decoded = bytes(b ^ key for b in raw)
                if _is_lua_bytecode(decoded) and self.java_available:
                    text, _ = self._run_unluac(decoded)
                    if text:
                        return text
                text = decoded.decode('utf-8', errors='replace')
                if _looks_like_real_code(text):
                    return text
            except:
                pass

        try:
            raw = source.encode('latin-1')
            dec = zlib.decompress(raw)
            text = dec.decode('utf-8', errors='replace')
            if _looks_like_real_code(text):
                return text
        except:
            pass

        try:
            if re.match(r'^[0-9a-fA-F]+$', source.strip()):
                raw = binascii.unhexlify(source.strip())
                text = raw.decode('utf-8', errors='replace')
                if _looks_like_real_code(text):
                    return text
        except:
            pass

        return None
