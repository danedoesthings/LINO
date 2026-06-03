import os
import shutil
import tempfile
import subprocess
import signal
import re
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
            return None
        return self._run_lupa(source, timeout)

    def _run_lupa(self, source: str, timeout: int = 30) -> Optional[str]:
        import lupa
        from lupa import LuaRuntime

        lua = LuaRuntime(unpack_returned_tuples=True)
        seen = set()
        accumulated = []

        def _accumulate(s):
            try:
                if isinstance(s, str) and len(s) > 0:
                    if s not in seen:
                        seen.add(s)
                        accumulated.append(s)
            except:
                pass

        lua.globals()._py_accumulate = _accumulate

        lua.execute(r'''
        local _orig_type = type

        function _spy_make(name)
            local t = {}
            local mt = {
                _is_proxy = true,
                __type = function() return "userdata" end,
                __tostring = function() return name end,
                __len = function() return 2853638 end,
                __index = function(self, k)
                    return _spy_make(name .. "." .. tostring(k))
                end,
                __newindex = function(self, k, v)
                    if type(v) == "string" and #v > 0 then
                        _py_accumulate(v)
                    end
                end,
                __call = function(self, ...)
                    return _spy_make(name .. "(...)")
                end,
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

        type = function(obj)
            local mt = getmetatable(obj)
            if mt and mt._is_proxy then
                return "userdata"
            end
            return _orig_type(obj)
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

        game = _spy_make("game")
        workspace = _spy_make("workspace")
        script = _spy_make("script")
        shared = {}
        task = { wait = function() return 1 end, spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end }
        wait = function() return 1 end
        spawn = function(f) pcall(f) end
        delay = function(t, f) pcall(f) end
        tick = function() return 0 end
        time = function() return 0 end
        os = { time = function() return 0 end, clock = function() return 0 end, date = function() return "" end }
        CFrame = _spy_make("CFrame")
        Vector3 = _spy_make("Vector3")
        Vector2 = _spy_make("Vector2")
        Color3 = _spy_make("Color3")
        UDim2 = _spy_make("UDim2")
        UDim = _spy_make("UDim")
        Instance = _spy_make("Instance")
        Enum = _spy_make("Enum")
        Drawing = _spy_make("Drawing")
        Ray = _spy_make("Ray")
        BrickColor = _spy_make("BrickColor")
        Region3 = _spy_make("Region3")
        TweenInfo = _spy_make("TweenInfo")
        getgenv = function() return _G end
        getrenv = function() return _G end
        checkcaller = function() return true end
        identifyexecutor = function() return "Synapse X", "2.0.0" end
        getrawmetatable = function(t) return getmetatable(t) end
        gethui = function() return _spy_make("HUI") end
        getnilinstances = function() return {} end
        getinstances = function() return {} end
        getgc = function() return {} end
        getreg = function() return {} end
        getloadedmodules = function() return {} end
        getconnections = function() return {} end
        firesignal = function() end
        setreadonly = function() end
        isreadonly = function() return false end
        hookfunction = function(f, h) return f end
        hookmetamethod = function(o, m, f) return function() end end
        newcclosure = function(f) return f end
        islclosure = function() return true end
        iscclosure = function() return false end
        getsynasset = function() return "content" end
        request = function(o) return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} } end
        http_request = request
        readfile = function() return "" end
        writefile = function() end
        appendfile = function() end
        isfile = function() return false end
        isfolder = function() return false end
        makefolder = function() end
        delfolder = function() end
        delfile = function() end
        listfiles = function() return {} end
        rconsoleprint = function() end
        rconsoleinfo = function() end
        rconsolewarn = function() end
        rconsoleerr = function() end
        rconsoleclear = function() end
        rconsolename = function() end
        mouse1click = function() end
        mouse1press = function() end
        mouse1release = function() end
        keypress = function() end
        keyrelease = function() end
        mousemoveabs = function() end
        mousemoverel = function() end
        iswindowactive = function() return true end
        setclipboard = function() end
        toclipboard = function() end
        crypt = {
            encrypt = function(d) return d end,
            decrypt = function(d) return d end,
            hash = function(d) return "hash" end,
            generatekey = function() return "key" end,
            base64encode = function(d) return d end,
            base64decode = function(d) return d end,
            base64 = { encode = function(d) return d end, decode = function(d) return d end },
            custom = { encrypt = function(d) return d end, decrypt = function(d) return d end },
        }
        syn = {
            request = request,
            crypt = crypt,
            queue_on_teleport = function() end,
            protect_gui = function() end,
        }
        fluxus = syn
        debug = {
            getinfo = function() return { source = "mock", short_src = "mock", func = function() end } end,
            getconstants = function() return {} end,
            getconstant = function() return nil end,
            getupvalues = function() return {} end,
            getupvalue = function() return nil end,
            getprotos = function() return {} end,
            getproto = function() return nil end,
            getstack = function() return {} end,
            setstack = function() end,
            setconstant = function() end,
            setupvalue = function() end,
            getregistry = function() return {} end,
            getmetatable = function(t) return getmetatable(t) end,
            setmetatable = function(t, m) return setmetatable(t, m) end,
            profilebegin = function() end,
            profileend = function() end,
            traceback = function() return "mock traceback" end,
        }
        math.clamp = math.clamp or function(x, mn, mx) return math.max(mn, math.min(mx, x)) end
        require = function(id) return _spy_make("module") end
        newproxy = function(addmeta)
            return _spy_make("newproxy_result")
        end
        setfenv = setfenv or function(f, e) return f end
        getfenv = getfenv or function() return _G end
        unpack = unpack or table.unpack
        os.execute = nil
        os.exit = nil
        os.remove = nil
        os.rename = nil
        os.getenv = nil
        package = nil
        script_key = "c4ce76cd36f2afee4dcee7e87576e5fa"
        ''')

        stripped = source.strip()
        stripped = re.sub(r'^return\s+', '', stripped, count=1)

        try:
            lua.execute(stripped)
        except Exception:
            pass

        if accumulated:
            return "".join(accumulated)
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
