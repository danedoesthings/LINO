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
        output_path_fixed = output_path.replace('\\', '/')

        harness_code = (
            "local _real_loadstring = loadstring or load\n"
            "local _real_load = load or loadstring\n"
            'local _captured_payload = ""\n'
            "\n"
            "local function hook_load(chunk, chunkname)\n"
            '    if type(chunk) == "string" and #chunk > 0 then\n'
            "        _captured_payload = chunk\n"
            '        local f = io.open("' + output_path_fixed + '", "w")\n'
            "        if f then\n"
            "            f:write(chunk)\n"
            "            f:close()\n"
            "        end\n"
            "    end\n"
            "    return _real_loadstring(chunk, chunkname)\n"
            "end\n"
            "\n"
            "_G.loadstring = hook_load\n"
            "_G.load = hook_load\n"
            "if getfenv then\n"
            "    local env = getfenv()\n"
            "    env.loadstring = hook_load\n"
            "    env.load = hook_load\n"
            "end\n"
            "\n"
            "os.execute = nil\n"
            "os.exit = nil\n"
            "os.remove = nil\n"
            "os.rename = nil\n"
            "os.getenv = nil\n"
            "package = nil\n"
            "require = function() return {{}} end\n"
            "\n"
            "local _real_pcall = pcall\n"
            "local ok, err = _real_pcall(function()\n"
            + source +
            "\nend)\n"
            "\n"
            'if not ok and _captured_payload == "" then\n'
            '    local f = io.open("' + output_path_fixed + '", "w")\n'
            "    if f then\n"
            '        f:write("-- [HARNESS ERROR] " .. tostring(err))\n'
            "        f:close()\n"
            "    end\n"
            "end\n"
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
