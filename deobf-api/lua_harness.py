import os
import re
from typing import Optional


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
            return None
        return self._run_lupa(source, timeout)

    def _run_lupa(self, source: str, timeout: int = 30) -> Optional[str]:
        import lupa
        from lupa import LuaRuntime

        lua = LuaRuntime(unpack_returned_tuples=True)
        output = []

        def _capture_output(s):
            try:
                if isinstance(s, str) and len(s) > 0:
                    output.append(s)
            except:
                pass

        lua.globals()._py_output = _capture_output

        lua.execute(r'''
        local _orig_print = print
        print = function(...)
            local parts = {}
            for i = 1, select('#', ...) do
                parts[i] = tostring(select(i, ...))
            end
            local msg = table.concat(parts, "\t")
            _py_output(msg)
            _orig_print(msg)
        end

        local _orig_loadstring = loadstring or load
        local _orig_load = load or loadstring

        loadstring = function(src, name)
            if type(src) == "string" and #src > 10 then
                _py_output(src)
            end
            if _orig_loadstring then
                return _orig_loadstring(src, name)
            end
            return _orig_load(src, name)
        end

        load = function(src, name)
            if type(src) == "string" and #src > 10 then
                _py_output(src)
            end
            if _orig_load then
                return _orig_load(src, name)
            end
            if _orig_loadstring then
                return _orig_loadstring(src, name)
            end
        end

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

        function _spy_make(name)
            local t = {}
            local mt = {
                _is_proxy = true,
                __type = function() return "userdata" end,
                __tostring = function() return name end,
                __len = function() return 2853638 end,
                __index = function(self, k) return _spy_make(name .. "." .. tostring(k)) end,
                __newindex = function() end,
                __call = function(self, ...) return _spy_make(name .. "(...)") end,
                __add = function() return 0 end,
                __sub = function() return 0 end,
                __mul = function() return 0 end,
                __div = function() return 0 end,
                __mod = function() return 0 end,
                __unm = function() return 0 end,
                __concat = function(a, b) return tostring(a) .. tostring(b) end,
                __lt = function() return false end,
                __le = function() return false end,
                __eq = function() return false end,
                __metatable = "The metatable is locked",
            }
            setmetatable(t, mt)
            return t
        end

        game = _spy_make("game")
        workspace = _spy_make("workspace")
        script = _spy_make("script")
        shared = {}
        task = { wait = function() return 1 end, spawn = function(f) pcall(f) end }
        wait = function() return 1 end
        spawn = function(f) pcall(f) end
        os = { time = function() return 0 end }
        CFrame = _spy_make("CFrame")
        Vector3 = _spy_make("Vector3")
        Vector2 = _spy_make("Vector2")
        Color3 = _spy_make("Color3")
        UDim2 = _spy_make("UDim2")
        Instance = _spy_make("Instance")
        Enum = _spy_make("Enum")
        getgenv = function() return _G end
        getrenv = function() return _G end
        checkcaller = function() return true end
        identifyexecutor = function() return "Synapse X", "2.0.0" end
        getrawmetatable = function(t) return getmetatable(t) end
        hookfunction = function(f, h) return f end
        newcclosure = function(f) return f end
        islclosure = function() return true end
        request = function() return { StatusCode = 200, Body = "ok" } end
        http_request = request
        readfile = function() return "" end
        writefile = function() end
        crypt = { encrypt = function(d) return d end, decrypt = function(d) return d end }
        syn = { request = request, crypt = crypt }
        debug = { getinfo = function() return {source="mock"} end, getconstants = function() return {} end, getupvalues = function() return {} end, getprotos = function() return {} end, getregistry = function() return {} end }
        require = function() return _spy_make("module") end
        newproxy = function(addmeta) return _spy_make("newproxy") end
        setfenv = setfenv or function(f,e) return f end
        getfenv = getfenv or function() return _G end
        unpack = unpack or table.unpack
        ''')

        stripped = source.strip()
        stripped = re.sub(r'^return\s+', '', stripped, count=1)

        patched = stripped.replace('error("Tamper Detected!")', '-- tamper bypassed')
        patched = re.sub(r'\btype\(', 'type_raw(', patched)
        patched = 'type_raw = type\n' + patched

        try:
            lua.execute(patched)
        except Exception:
            pass

        if output:
            return "\n".join(output)
        return None

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
