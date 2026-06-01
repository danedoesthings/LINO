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

        harness_code = f'''
local _real_loadstring = loadstring or load
local _real_load = load or loadstring
local _captured_payload = ""

local function hook_load(chunk, chunkname)
    if type(chunk) == "string" and #chunk > 0 then
        _captured_payload = chunk
        local f = io.open("{output_path.replace('\\\\', '/')}", "w")
        if f then
            f:write(chunk)
            f:close()
        end
    end
    return _real_loadstring(chunk, chunkname)
end

_G.loadstring = hook_load
_G.load = hook_load
if getfenv then
    local env = getfenv()
    env.loadstring = hook_load
    env.load = hook_load
end

os.execute = nil
os.exit = nil
os.remove = nil
os.rename = nil
os.getenv = nil
package = nil
require = function() return {{}} end

local _real_pcall = pcall
local ok, err = _real_pcall(function()
    {source}
end)

if not ok and _captured_payload == "" then
    local f = io.open("{output_path.replace('\\\\', '/')}", "w")
    if f then
        f:write("-- [HARNESS ERROR] " .. tostring(err))
        f:close()
    end
end
'''

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
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass

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
