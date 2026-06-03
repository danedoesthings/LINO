import os
import re
import shutil
import tempfile
import subprocess
import signal
from typing import Optional


class LuaHarness:
    def __init__(self, unluac_path: str = None) -> None:
        self.unluac_path = unluac_path
        self.available = shutil.which('lune') is not None

    def run(self, source: str, timeout: int = 30, decoded_strings: list = None) -> Optional[str]:
        if not self.available:
            return None

        patched_source = self._patch_source_for_expression_hooks(source)

        result = self._run_symbolic(patched_source, timeout, decoded_strings)
        if result and len(result) > 200 and not self._is_raw_vm_output(result):
            return result

        result = self._run_dynamic(patched_source, timeout)
        if result and len(result) > 100:
            return result

        return None

    def _is_raw_vm_output(self, output: str) -> bool:
        octal_count = output.count('\\07') + output.count('\\1') + output.count('\\09')
        vm_indicators = ['while l do if l<', 'while vmState do', 'local function E(E)return R[E+']
        for indicator in vm_indicators:
            if indicator in output:
                return True
        return octal_count > 20

    def _patch_source_for_expression_hooks(self, source: str) -> str:
        source = re.sub(
            r'(?<![a-zA-Z0-9_\.\]\)])([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^=;,\n\{\}]+)',
            r'\1 = _log_assign("\1", \2)',
            source
        )

        replacements = [
            (r'(\S+)\s*\.\.\s*(\S+)', r'_raw_concat(\1, \2)'),
            (r'(\S+)\s*==\s*(\S+)', r'_raw_eq(\1, \2)'),
            (r'(\S+)\s*<=\s*(\S+)', r'_raw_le(\1, \2)'),
            (r'(\S+)\s*>=\s*(\S+)', r'_raw_ge(\1, \2)'),
            (r'(\S+)\s*<\s*(\S+)', r'_raw_lt(\1, \2)'),
            (r'(\S+)\s*>\s*(\S+)', r'_raw_gt(\1, \2)'),
            (r'(\S+)\s*\+\s*(\S+)', r'_raw_add(\1, \2)'),
            (r'(\S+)\s*\-\s*(\S+)', r'_raw_sub(\1, \2)'),
            (r'(\S+)\s*\*\s*(\S+)', r'_raw_mul(\1, \2)'),
            (r'(\S+)\s*/\s*(\S+)', r'_raw_div(\1, \2)'),
            (r'\bnot\s+(\S+)', r'_raw_not(\1)'),
            (r'#(\w+)', r'_raw_len(\1)'),
        ]
        for pattern, replacement in replacements:
            source = re.sub(pattern, replacement, source)

        return source

    def _run_symbolic(self, source: str, timeout: int = 30, decoded_strings: list = None) -> Optional[str]:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        strings_path = os.path.join(tmpdir, "strings.lua")
        output_path = os.path.join(tmpdir, "deobfuscated.lua")
        harness_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "symbolic_eval.luau")

        if not os.path.isfile(harness_path):
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(source)

            if decoded_strings:
                escaped = []
                for s in decoded_strings:
                    if s:
                        esc = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                        escaped.append(f'"{esc}"')
                    else:
                        escaped.append('""')
                lua_table = "return {\n" + ",\n".join(escaped) + "\n}"
                with open(strings_path, "w", encoding="utf-8") as f:
                    f.write(lua_table)

            proc = subprocess.Popen(
                ["lune", "run", harness_path, input_path, output_path, strings_path if decoded_strings else ""],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True
            )
            try:
                proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    if hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    pass

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                    captured = f.read().strip()
                if captured and len(captured) > 100 and not captured.startswith("-- [ERROR]"):
                    return captured
            return None
        except Exception:
            return None
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _run_dynamic(self, source: str, timeout: int = 30) -> Optional[str]:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        harness_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "httplog_harness.luau")

        if not os.path.isfile(harness_path):
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(source)

            proc = subprocess.Popen(
                ["lune", "run", harness_path, input_path, output_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True
            )
            try:
                proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    if hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    pass

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                    captured = f.read().strip()
                if captured and len(captured) > 50 and not captured.startswith("-- [ERROR]"):
                    return captured
            return None
        except Exception:
            return None
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def run_with_trace(self, source: str, timeout: int = 30) -> dict:
        captured = self.run(source, timeout)
        return {
            'captured': captured,
            'trace': '',
            'error': None,
            'stdout': '',
            'stderr': '',
            'timed_out': False,
        }
