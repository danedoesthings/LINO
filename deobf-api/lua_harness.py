import subprocess
import tempfile
import os
import shutil
import signal
import time

HARNESS_LUAU = os.path.join(os.path.dirname(os.path.abspath(__file__)), "httplog_harness.luau")


class LuaHarness:
    def __init__(self, unluac_path: str = None) -> None:
        self.unluac_path = unluac_path
        self.lune_available = shutil.which('lune') is not None
        self.available = self.lune_available or self._find_lua() is not None

    @staticmethod
    def _find_lua() -> str | None:
        for candidate in ('lua5.1', 'lua5.2', 'lua', 'lua5.4', 'lua5.3'):
            if shutil.which(candidate):
                return candidate
        return None

    def run(self, source: str, timeout: int = 30) -> str | None:
        if not self.available:
            return None
        if self.lune_available and os.path.isfile(HARNESS_LUAU):
            return self._run_lune(source, timeout)
        return self._run_lua(source, timeout)

    def _run_lune(self, source: str, timeout: int = 30) -> str | None:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.lua")

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(source)

            proc = subprocess.Popen(
                ["lune", "run", HARNESS_LUAU, input_path, output_path],
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

    def _run_lua(self, source: str, timeout: int = 30) -> str | None:
        lua_bin = self._find_lua()
        if not lua_bin:
            return None
        tmpdir = tempfile.mkdtemp()
        output_path = os.path.join(tmpdir, "captured.lua")
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path_fixed = output_path.replace('\\', '/')

        harness_code = (
            'local _r = {}; local _c = 0;\n'
            'local function _25ms(var)\n'
            '  if type(var) == "string" then _c = _c + 1; _r[_c] = var end\n'
            '  return var\n'
            'end\n'
            'local _real_pcall = pcall;\n'
            'local ok, err = _real_pcall(function()\n'
            + source +
            '\nend)\n'
            'if _c > 0 then\n'
            '  local f = io.open("' + output_path_fixed + '", "w");\n'
            '  if f then f:write(table.concat(_r, "\\n")); f:close() end\n'
            'end\n'
        )

        try:
            with open(harness_path, "w", encoding="utf-8") as f:
                f.write(harness_code)
            proc = subprocess.Popen(
                [lua_bin, harness_path],
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
