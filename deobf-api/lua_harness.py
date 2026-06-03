import os
import json
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

        result = self._run_symbolic(source, timeout, decoded_strings)
        if result and len(result) > 200:
            return result

        return None

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
