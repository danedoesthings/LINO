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
        
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        harness_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "httplog_harness.luau")

        if not os.path.isfile(harness_path):
            shutil.rmtree(tmpdir, ignore_errors=True)
            return "ERROR: httplog_harness.luau not found at " + harness_path

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(source)

            proc = subprocess.Popen(
                ["lune", "run", harness_path, input_path, output_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True
            )
            try:
                stdout_b, stderr_b = proc.communicate(timeout=timeout)
                stderr_output = stderr_b.decode('latin-1', errors='replace') if stderr_b else ''
            except subprocess.TimeoutExpired:
                try:
                    if hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    pass
                return "ERROR: Lune timed out after " + str(timeout) + "s"

            if stderr_output.strip():
                return "LUNE ERROR: " + stderr_output[:1000]

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    captured = f.read().strip()
                if captured and len(captured) > 10 and not captured.startswith("-- [ERROR]"):
                    return captured
                if captured:
                    return "LUNE OUTPUT: " + captured[:1000]

            return "ERROR: No output from Lune"
        except Exception as e:
            return "LUNE EXCEPTION: " + str(e)[:500]
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
