import os
import shutil
import tempfile
from typing import Optional, Dict


class LuaHarness:
    def __init__(self, unluac_path: str = None) -> None:
        self.unluac_path = unluac_path
        self.available = self._check_lupa()

    @staticmethod
    def _check_lupa() -> bool:
        try:
            import lupa
            return True
        except ImportError:
            return False

    def run(self, source: str, timeout: int = 30) -> Optional[str]:
        if not self.available:
            return self._run_subprocess_fallback(source, timeout)
        return self._run_lupa(source, timeout)

    def _run_lupa(self, source: str, timeout: int = 30) -> Optional[str]:
        import lupa
        from lupa import LuaRuntime
        
        lua = LuaRuntime(unpack_returned_tuples=True)
        
        captured = []
        def _25ms(var):
            if lua.type(var) == 'string':
                s = str(var)
                if len(s) > 3:
                    captured.append(s)
            return var
        
        lua.globals()._25ms = _25ms
        
        lua.execute('''
        local bit32 = {
            bxor = function(a,b) local r,m=0,1; while a>0 or b>0 do if (a%2)~=(b%2) then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end,
            band = function(a,b) local r,m=0,1; while a>0 and b>0 do if (a%2)+(b%2)==2 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end,
            bor = function(a,b) local r,m=0,1; while a>0 or b>0 do if (a%2)+(b%2)>0 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end,
            lshift = function(v,n) return math.floor(v*(2^n))%4294967296 end,
            rshift = function(v,n) return math.floor(v/(2^n)) end,
            arshift = function(v,n) return math.floor(v/(2^n)) end,
        }
        _G.bit32 = bit32
        _G.bit = bit32
        
        local _spy_mt = {
            __index = function(t, k)
                local new_t = {}
                setmetatable(new_t, _spy_mt)
                return new_t
            end,
            __newindex = function(t, k, v)
                py._25ms(v)
            end,
            __call = function(t, ...)
                local new_t = {}
                setmetatable(new_t, _spy_mt)
                return new_t
            end,
            __tostring = function() return "proxy" end,
            __len = function() return 2853638 end,
        }
        
        function _spy(name)
            local t = {}
            setmetatable(t, _spy_mt)
            return t
        end
        
        local orig_concat = table.concat
        table.concat = function(t, sep, i, j)
            local r = orig_concat(t, sep, i, j)
            if type(r) == "string" and #r > 3 then
                py._25ms(r)
            end
            return r
        end
        
        local orig_char = string.char
        string.char = function(...)
            local r = orig_char(...)
            if select("#", ...) >= 3 then
                py._25ms(r)
            end
            return r
        end
        
        local orig_loadstring = loadstring or load
        loadstring = function(src, name)
            if type(src) == "string" and #src > 0 then
                py._25ms(src)
            end
            return orig_loadstring(src, name)
        end
        load = loadstring
        
        game = _spy("game")
        workspace = _spy("workspace")
        script = _spy("script")
        shared = {}
        task = { wait = function() return 1 end, spawn = function(f) pcall(f) end }
        wait = function() return 1 end
        spawn = function(f) pcall(f) end
        delay = function(t,f) pcall(f) end
        os = { time = function() return 0 end, clock = function() return 0 end, date = function() return "" end }
        CFrame = _spy("CFrame")
        Vector3 = _spy("Vector3")
        Vector2 = _spy("Vector2")
        Color3 = _spy("Color3")
        UDim2 = _spy("UDim2")
        Instance = _spy("Instance")
        Enum = _spy("Enum")
        getgenv = function() return _G end
        getrenv = function() return _G end
        checkcaller = function() return true end
        identifyexecutor = function() return "Synapse X", "2.0.0" end
        getrawmetatable = function(t) return getmetatable(t) end
        hookfunction = function(f,h) return f end
        newcclosure = function(f) return f end
        islclosure = function() return true end
        request = function(o) return { StatusCode = 200, Body = "--PAYLOAD", Headers = {} } end
        http_request = request
        readfile = function() return "" end
        writefile = function() end
        isfile = function() return false end
        crypt = { encrypt = function(d) return d end, decrypt = function(d) return d end, base64encode = function(d) return d end, base64decode = function(d) return d end }
        syn = { request = request, crypt = crypt, queue_on_teleport = function() end }
        debug = {
            getinfo = function() return {source="mock", short_src="mock", func=function() end} end,
            getconstants = function() return {} end,
            getupvalues = function() return {} end,
            getprotos = function() return {} end,
            getregistry = function() return {} end,
        }
        require = function() return _spy("module") end
        newproxy = function(addmeta)
            local t = {}
            if addmeta then setmetatable(t, {__index=function() return nil end, __newindex=function() end, __metatable="locked"}) end
            return t
        end
        setfenv = setfenv or function(f,e) return f end
        getfenv = getfenv or function() return _G end
        unpack = unpack or table.unpack
        ''')
        
        try:
            lua.execute(source)
        except Exception as e:
            if captured:
                return "\n".join(captured)
            return None
        
        if captured:
            return "\n".join(captured)
        return None

    def _run_subprocess_fallback(self, source: str, timeout: int = 30) -> Optional[str]:
        import subprocess
        import signal
        
        lua_bin = None
        for candidate in ('lua5.1', 'lua5.2', 'lua', 'lua5.4', 'lua5.3'):
            if shutil.which(candidate):
                lua_bin = candidate
                break
        
        if not lua_bin:
            return None
        
        tmpdir = tempfile.mkdtemp()
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
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
