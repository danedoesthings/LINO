import subprocess
import tempfile
import os
import shutil
import signal

class LuaHarness:
    def __init__(self, unluac_path: str = None) -> None:
        self.unluac_path = unluac_path
        self.available = self._find_lua() is not None

    @staticmethod
    def _find_lua() -> str | None:
        for candidate in ('lua5.1', 'lua5.2', 'lua', 'lua5.4', 'lua5.3'):
            if shutil.which(candidate):
                return candidate
        return None

    def run(self, source: str, timeout: int = 20) -> str | None:
        if not self.available:
            return None
        tmpdir = tempfile.mkdtemp()
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        trace_path = os.path.join(tmpdir, "vm_trace.txt")
        output_path_fixed = output_path.replace('\\', '/')
        trace_path_fixed = trace_path.replace('\\', '/')

        harness_code = (
            'local _real_loadstring = loadstring or load\n'
            'local _real_load = load or loadstring\n'
            'local _captured_payload = ""\n'
            '\n'
            'local _trace_file = io.open("' + trace_path_fixed + '", "w")\n'
            'local _trace_count = 0\n'
            'local _trace_limit = 500\n'
            '\n'
            'local function _log_trace(msg)\n'
            ' if _trace_file and _trace_count < _trace_limit then\n'
            '  _trace_file:write(msg .. "\\n")\n'
            '  _trace_file:flush()\n'
            '  _trace_count = _trace_count + 1\n'
            ' end\n'
            'end\n'
            '\n'
            'local _original_vmState = nil\n'
            'local _vmState_var_found = false\n'
            '\n'
            'local function hook_load(chunk, chunkname)\n'
            ' _log_trace("HOOK_LOADSTRING called, chunk len=" .. tostring(type(chunk) == "string" and #chunk or "not_string"))\n'
            ' if type(chunk) == "string" and #chunk > 0 then\n'
            '  _captured_payload = chunk\n'
            '  _log_trace("HOOK_LOADSTRING captured payload, first 200 chars: " .. string.sub(chunk, 1, 200))\n'
            '  local f = io.open("' + output_path_fixed + '", "w")\n'
            '  if f then\n'
            '   f:write(chunk)\n'
            '   f:close()\n'
            '  end\n'
            ' end\n'
            ' return _real_loadstring(chunk, chunkname)\n'
            'end\n'
            '\n'
            '_G.loadstring = hook_load\n'
            '_G.load = hook_load\n'
            'if getfenv then\n'
            ' local env = getfenv()\n'
            ' env.loadstring = hook_load\n'
            ' env.load = hook_load\n'
            'end\n'
            '\n'
            'local _real_newproxy = newproxy\n'
            'if _real_newproxy then\n'
            ' local _proxy_count = 0\n'
            ' _G.newproxy = function(addmeta)\n'
            '  _proxy_count = _proxy_count + 1\n'
            '  _log_trace("newproxy called, count=" .. _proxy_count)\n'
            '  return _real_newproxy(addmeta)\n'
            ' end\n'
            'end\n'
            '\n'
            'local _real_setfenv = setfenv or (getfenv and function(f, e) end)\n'
            'if _real_setfenv then\n'
            ' _G.setfenv = function(f, e)\n'
            '  _log_trace("setfenv called")\n'
            '  return _real_setfenv(f, e)\n'
            ' end\n'
            'end\n'
            '\n'
            'local _real_getfenv = getfenv or function() return _G end\n'
            '_G.getfenv = function(f)\n'
            ' _log_trace("getfenv called")\n'
            ' return _real_getfenv(f)\n'
            'end\n'
            '\n'
            'os.execute = nil\n'
            'os.exit = nil\n'
            'os.remove = nil\n'
            'os.rename = nil\n'
            'os.getenv = nil\n'
            'package = nil\n'
            'require = function() return {} end\n'
            '\n'
            'local _real_pcall = pcall\n'
            'local ok, err = _real_pcall(function()\n'
            + source +
            '\nend)\n'
            '\n'
            'if _trace_file then\n'
            ' _log_trace("EXECUTION_FINISHED ok=" .. tostring(ok))\n'
            ' if not ok then\n'
            '  _log_trace("RUNTIME_ERROR: " .. tostring(err))\n'
            ' end\n'
            ' _trace_file:close()\n'
            'end\n'
            '\n'
            'if not ok and _captured_payload == "" then\n'
            ' local f = io.open("' + output_path_fixed + '", "w")\n'
            ' if f then\n'
            '  f:write("-- [HARNESS ERROR] " .. tostring(err))\n'
            '  f:close()\n'
            ' end\n'
            'end\n'
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
                if os.path.exists(trace_path):
                    with open(trace_path, "a", encoding="utf-8") as tf:
                        tf.write("TIMEOUT_EXPIRED after " + str(timeout) + "s\n")
                if os.path.exists(output_path):
                    with open(output_path, "r", encoding="utf-8") as f:
                        captured = f.read().strip()
                    if captured and not captured.startswith("-- [HARNESS ERROR]"):
                        return captured
                return None
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    captured = f.read().strip()
                if captured and not captured.startswith("-- [HARNESS ERROR]"):
                    return captured
            return None
        except Exception:
            return None
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def run_with_trace(self, source: str, timeout: int = 30) -> dict:
        if not self.available:
            return {'captured': None, 'trace': 'lua not found', 'error': None}
        tmpdir = tempfile.mkdtemp()
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        trace_path = os.path.join(tmpdir, "vm_trace.txt")
        output_path_fixed = output_path.replace('\\', '/')
        trace_path_fixed = trace_path.replace('\\', '/')

        harness_code = (
            'local _real_loadstring = loadstring or load\n'
            'local _real_load = load or loadstring\n'
            'local _captured_payload = ""\n'
            '\n'
            'local _trace_file = io.open("' + trace_path_fixed + '", "w")\n'
            'local _trace_count = 0\n'
            'local _trace_limit = 500\n'
            '\n'
            'local function _log_trace(msg)\n'
            ' if _trace_file and _trace_count < _trace_limit then\n'
            '  _trace_file:write(msg .. "\\n")\n'
            '  _trace_file:flush()\n'
            '  _trace_count = _trace_count + 1\n'
            ' end\n'
            'end\n'
            '\n'
            'local function hook_load(chunk, chunkname)\n'
            ' _log_trace("HOOK_LOADSTRING called, chunk len=" .. tostring(type(chunk) == "string" and #chunk or "not_string"))\n'
            ' if type(chunk) == "string" and #chunk > 0 then\n'
            '  _captured_payload = chunk\n'
            '  _log_trace("HOOK_LOADSTRING captured payload, first 200 chars: " .. string.sub(chunk, 1, 200))\n'
            '  local f = io.open("' + output_path_fixed + '", "w")\n'
            '  if f then\n'
            '   f:write(chunk)\n'
            '   f:close()\n'
            '  end\n'
            ' end\n'
            ' return _real_loadstring(chunk, chunkname)\n'
            'end\n'
            '\n'
            '_G.loadstring = hook_load\n'
            '_G.load = hook_load\n'
            'if getfenv then\n'
            ' local env = getfenv()\n'
            ' env.loadstring = hook_load\n'
            ' env.load = hook_load\n'
            'end\n'
            '\n'
            'local _real_newproxy = newproxy\n'
            'if _real_newproxy then\n'
            ' local _proxy_count = 0\n'
            ' _G.newproxy = function(addmeta)\n'
            '  _proxy_count = _proxy_count + 1\n'
            '  _log_trace("newproxy called, count=" .. _proxy_count)\n'
            '  return _real_newproxy(addmeta)\n'
            ' end\n'
            'end\n'
            '\n'
            'local _real_setfenv = setfenv or (getfenv and function(f, e) end)\n'
            'if _real_setfenv then\n'
            ' _G.setfenv = function(f, e)\n'
            '  _log_trace("setfenv called")\n'
            '  return _real_setfenv(f, e)\n'
            ' end\n'
            'end\n'
            '\n'
            'local _real_getfenv = getfenv or function() return _G end\n'
            '_G.getfenv = function(f)\n'
            ' _log_trace("getfenv called")\n'
            ' return _real_getfenv(f)\n'
            'end\n'
            '\n'
            'local _real_pcall = pcall\n'
            '\n'
            'os.execute = nil\n'
            'os.exit = nil\n'
            'os.remove = nil\n'
            'os.rename = nil\n'
            'os.getenv = nil\n'
            'package = nil\n'
            'require = function() return {} end\n'
            '\n'
            'local ok, err = _real_pcall(function()\n'
            + source +
            '\nend)\n'
            '\n'
            'if _trace_file then\n'
            ' _log_trace("EXECUTION_FINISHED ok=" .. tostring(ok))\n'
            ' if not ok then\n'
            '  _log_trace("RUNTIME_ERROR: " .. tostring(err))\n'
            ' end\n'
            ' _trace_file:close()\n'
            'end\n'
            '\n'
            'if not ok and _captured_payload == "" then\n'
            ' local f = io.open("' + output_path_fixed + '", "w")\n'
            ' if f then\n'
            '  f:write("-- [HARNESS ERROR] " .. tostring(err))\n'
            '  f:close()\n'
            ' end\n'
            'end\n'
        )

        result = {'captured': None, 'trace': '', 'error': None, 'vm_states': []}

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
                if os.path.exists(trace_path):
                    with open(trace_path, "a", encoding="utf-8") as tf:
                        tf.write("TIMEOUT_EXPIRED after " + str(timeout) + "s\n")
            else:
                result['timed_out'] = False

            if os.path.exists(trace_path):
                with open(trace_path, "r", encoding="utf-8") as tf:
                    result['trace'] = tf.read()

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    captured = f.read().strip()
                if captured and not captured.startswith("-- [HARNESS ERROR]"):
                    result['captured'] = captured

            if not result['captured'] and os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    err_content = f.read().strip()
                if err_content:
                    result['error'] = err_content

        except Exception as e:
            result['error'] = str(e)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return result
