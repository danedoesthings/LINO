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
        self.available = self._find_lua() is not None
        self.lune_available = self._find_lune() is not None

    @staticmethod
    def _find_lua() -> str | None:
        for candidate in ('lua5.1', 'lua5.2', 'lua', 'lua5.4', 'lua5.3'):
            if shutil.which(candidate):
                return candidate
        return None

    @staticmethod
    def _find_lune() -> str | None:
        if shutil.which('lune'):
            return 'lune'
        return None

    def run(self, source: str, timeout: int = 30) -> str | None:
        if self.lune_available and os.path.isfile(HARNESS_LUAU):
            return self._run_lune(source, timeout)
        if self.available:
            return self._run_lua(source, timeout)
        return None

    def _run_lune(self, source: str, timeout: int = 30) -> str | None:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        log_path = os.path.join(tmpdir, "log.txt")

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(source)

            proc = subprocess.Popen(
                ["lune", "run", HARNESS_LUAU, input_path, output_path, log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, cwd=tmpdir
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
        if not self.available:
            return None
        tmpdir = tempfile.mkdtemp()
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        log_path = os.path.join(tmpdir, "log.txt")
        output_path_fixed = output_path.replace('\\', '/')
        log_path_fixed = log_path.replace('\\', '/')

        harness_code = (
            'local _outpath = "' + output_path_fixed + '"\n'
            + 'local _log_file = io.open("' + log_path_fixed + '", "w")\n'
            + 'local _r = {}\n'
            + 'local _c = 0\n'
            + 'local function _25ms(var)\n'
            + '  if type(var) == "string" then\n'
            + '    _c = _c + 1\n'
            + '    _r[_c] = var\n'
            + '    _log_file:write("[25ms][" .. _c .. "] " .. var:sub(1, 150) .. "\\n")\n'
            + '  end\n'
            + '  return var\n'
            + 'end\n'
            + 'local _real_pcall = pcall\n'
            + 'local ok, err = _real_pcall(function()\n'
            + source +
            '\nend)\n'
            + '_log_file:write("EXECUTION_FINISHED ok=" .. tostring(ok) .. "\\n")\n'
            + 'if not ok then _log_file:write("RUNTIME_ERROR: " .. tostring(err) .. "\\n") end\n'
            + '_log_file:write("Strings captured: " .. _c .. "\\n")\n'
            + 'if _c > 0 then\n'
            + '  local f = io.open(_outpath, "w")\n'
            + '  if f then f:write(table.concat(_r, "\\n")); f:close() end\n'
            + 'end\n'
            + 'if _log_file then _log_file:close() end\n'
        )

        try:
            with open(harness_path, "w", encoding="utf-8") as f:
                f.write(harness_code)
            lua_bin = self._find_lua()
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
        if self.lune_available and os.path.isfile(HARNESS_LUAU):
            return self._run_lune_with_trace(source, timeout)
        result = {'captured': self.run(source, timeout), 'trace': '', 'error': None, 'stdout': '', 'stderr': '', 'timed_out': False}
        return result

    def _run_lune_with_trace(self, source: str, timeout: int = 30) -> dict:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        log_path = os.path.join(tmpdir, "log.txt")

        result = {'captured': None, 'trace': '', 'error': None, 'stdout': '', 'stderr': '', 'timed_out': False}

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(source)

            proc = subprocess.Popen(
                ["lune", "run", HARNESS_LUAU, input_path, output_path, log_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, cwd=tmpdir
            )
            try:
                stdout_b, stderr_b = proc.communicate(timeout=timeout)
                result['stdout'] = stdout_b.decode('latin-1', errors='replace') if stdout_b else ''
                result['stderr'] = stderr_b.decode('latin-1', errors='replace') if stderr_b else ''
            except subprocess.TimeoutExpired:
                try:
                    if hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    pass
                proc.wait()
                result['timed_out'] = True

            if os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8") as tf:
                    result['trace'] = tf.read()[:10000]

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    captured = f.read().strip()
                if captured:
                    result['captured'] = captured

        except Exception as e:
            result['error'] = str(e)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return result
