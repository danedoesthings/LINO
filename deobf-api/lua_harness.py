import os
import re
import shutil
import tempfile
import subprocess
import signal
from typing import Optional, List

class LuaHarness:
    def __init__(self, unluac_path: str = None) -> None:
        self.unluac_path = unluac_path
        self.lune_available = shutil.which('lune') is not None
        self.lua_available = shutil.which('lua5.1') is not None or shutil.which('lua') is not None

    @property
    def available(self) -> bool:
        return self.lune_available or self.lua_available

    def run(self, source: str, timeout: int = 120, decoded_strings: List[str] = None) -> Optional[str]:
        if self.lune_available:
            result = self._run_lune(source, timeout, decoded_strings)
            if result and len(result) > 200 and not self._is_vm_output(result):
                return result
        if self.lua_available:
            result = self._run_lua(source, timeout)
            if result and len(result) > 100:
                return result
        return None

    def _is_vm_output(self, output: str) -> bool:
        indicators = ['while vmState do', 'while l do', 'GetStr(', 'EncStr[']
        for ind in indicators:
            if ind in output:
                return True
        return False

    def _run_lune(self, source: str, timeout: int, decoded_strings: List[str] = None) -> Optional[str]:
        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        strings_path = None
        base_dir = os.path.dirname(os.path.abspath(__file__))
        harness_path = os.path.join(base_dir, "wearedevs_harness.luau")

        if not os.path.isfile(harness_path):
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(source)

            if decoded_strings:
                strings_path = os.path.join(tmpdir, "strings.lua")
                escaped = []
                for s in decoded_strings:
                    if s:
                        esc = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                        escaped.append(f'"{esc}"')
                    else:
                        escaped.append('""')
                with open(strings_path, "w", encoding="utf-8") as f:
                    f.write("return {\n" + ",\n".join(escaped) + "\n}")

            cmd = ["lune", "run", harness_path, input_path, output_path]
            if strings_path:
                cmd.append(strings_path)

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True
            )
            try:
                proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except:
                    proc.kill()
                proc.wait()
                return None

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                    data = f.read().strip()
                if data and not data.startswith("-- ERROR"):
                    return data
            return None
        except Exception:
            return None
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _run_lua(self, source: str, timeout: int) -> Optional[str]:
        lua_bin = shutil.which('lua5.1') or shutil.which('lua')
        if not lua_bin:
            return None

        tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(tmpdir, "input.lua")
        output_path = os.path.join(tmpdir, "captured.txt")

        capture_code = '''
local _r = {}
local function _25ms(s)
    if type(s) == "string" and #s > 0 then
        _r[#_r + 1] = s
    end
    return s
end
local _orig_pcall = pcall
local ok, err = _orig_pcall(function()
''' + source + '''
end)
if #_r > 0 then
    local f = io.open("''' + output_path.replace('\\', '/') + '''", "w")
    if f then
        f:write(table.concat(_r, "\\n"))
        f:close()
    end
end
'''

        try:
            with open(input_path, "w", encoding="utf-8") as f:
                f.write(capture_code)

            proc = subprocess.Popen(
                [lua_bin, input_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True
            )
            try:
                proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except:
                    proc.kill()
                proc.wait()
                return None

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8", errors="replace") as f:
                    data = f.read().strip()
                if data:
                    return data
            return None
        except Exception:
            return None
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def run_with_trace(self, source: str, timeout: int = 30) -> dict:
        captured = self.run(source, timeout)
        return {'captured': captured, 'trace': '', 'error': None, 'timed_out': False}
