import os
import shutil
import tempfile
import subprocess
import signal
from typing import Optional


class LuaHarness:
    def __init__(self, unluac_path: str = None) -> None:
        self.unluac_path = unluac_path
        self.available = shutil.which('lune') is not None

    def run(self, source: str, timeout: int = 30) -> Optional[str]:
        if not self.available:
            return None
        return self._run_symbolic(source, timeout)

    def _run_symbolic(self, source: str, timeout: int = 30) -> Optional[str]:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "deobfuscated.lua")
        harness_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "symbolic_eval.luau")

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
                if captured and len(captured) > 10:
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
                _, stderr_b = proc.communicate(timeout=timeout)
                stderr_output = stderr_b.decode('latin-1', errors='replace') if stderr_b else ''
            except subprocess.TimeoutExpired:
                try:
                    if hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    pass
                shutil.rmtree(tmpdir, ignore_errors=True)
                return None

            if stderr_output.strip():
                return None

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                    captured = f.read().strip()
                if captured and len(captured) > 10:
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
