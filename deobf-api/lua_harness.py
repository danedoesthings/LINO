import subprocess
import tempfile
import os
import shutil
import signal
import time

class LuaHarness:
    def __init__(self, unluac_path: str = None) -> None:
        self.unluac_path = unluac_path
        self.node_available = shutil.which('node') is not None
        self.lune_available = shutil.which('lune') is not None
        self.available = self.node_available or self.lune_available

    def run(self, source: str, timeout: int = 30) -> str | None:
        if not self.available:
            return None
        if self.node_available:
            return self._run_node(source, timeout)
        if self.lune_available:
            return self._run_lune(source, timeout)
        return None

    def _run_node(self, source: str, timeout: int = 30) -> str | None:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        runner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lunr_runner.js")

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(source)

            proc = subprocess.Popen(
                ["node", runner_path, input_path, output_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
                cwd=os.path.dirname(os.path.abspath(__file__))
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
                with open(output_path, "r", encoding="utf-8") as f:
                    captured = f.read().strip()
                if captured:
                    return captured
            return None
        except Exception:
            return None
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _run_lune(self, source: str, timeout: int = 30) -> str | None:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        harness_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "httplog_harness.luau")

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
                with open(output_path, "r", encoding="utf-8") as f:
                    captured = f.read().strip()
                if captured:
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
