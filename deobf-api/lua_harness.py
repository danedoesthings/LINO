import os
import shutil
import tempfile
import subprocess
import signal
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
        errors = []

        def _capture_string(s):
            try:
                if isinstance(s, str) and len(s) > 2:
                    captured.append(s)
            except:
                pass

        lua.globals()._py_capture = _capture_string
        lua.globals()._py_error = lambda msg: errors.append(str(msg))

        lua.execute(r'''
        local _orig_type = type

        function _spy_make(name)
            local t = {}
            local mt = {
                _is_proxy = true,
                __type = function() return "userdata" end,
                __tostring = function() return name end,
                __len = function() return 2853638 end,
                __gc = function() end,
                __index = function(self, k)
                    return _spy_make(name .. "." .. tostring(k))
                end,
                __newindex = function(self, k, v)
                    if type(v) == "string" and #v > 2 then
                        _py_capture(v)
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

        local _orig_concat = table.concat
        table.concat = function(t, sep, i, j)
            local r = _orig_concat(t, sep, i, j)
            if type(r) == "string" and #r > 3 then _py_capture(r) end
            return r
        end

        local _orig_char = string.char
        string.char = function(...)
            local r = _orig_char(...)
            if select("#", ...) >= 3 then _py_capture(r) end
            return r
        end

        local _orig_gsub = string.gsub
        string.gsub = function(s, p, r, n)
            local res = _orig_gsub(s, p, r, n)
            if type(res) == "string" and #res > 10 then _py_capture(res) end
            return res
        end

        local _orig_loadstring = loadstring or load
        local _orig_load = load or loadstring

        loadstring = function(src, name)
            if type(src) == "string" and #src > 0 then
                _py_capture(src)
            end
            return _orig_loadstring(src, name)
        end

        load = function(src, name)
            if type(src) == "string" and #src > 0 then
                _py_capture(src)
            end
            return _orig_load(src, name)
        end

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

        try:
            result = lua.execute(source)
        except Exception as e:
            errors.append("Lua execution error: " + str(e))

        if captured:
            return "\n".join(captured)
        if errors:
            return "ERROR:\n" + "\n".join(errors)
        return None

    def _run_subprocess_fallback(self, source: str, timeout: int = 30) -> Optional[str]:
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
