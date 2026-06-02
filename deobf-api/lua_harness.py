import subprocess
import tempfile
import os
import shutil
import signal

ENV_BOOTSTRAP = r"""
local bit32 = rawget(_G, "bit32")
if not bit32 then
    local function bxor(a,b) local r,m=0,1; while a>0 or b>0 do local ab,bb=a%2,b%2; if ab~=bb then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    local function band(a,b) local r,m=0,1; while a>0 and b>0 do if a%2+b%2==2 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    local function bor(a,b) local r,m=0,1; while a>0 or b>0 do if a%2+b%2>0 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    bit32 = {
        bxor = bxor, band = band, bor = bor,
        lshift = function(v,n) return math.floor(v*(2^n))%4294967296 end,
        rshift = function(v,n) return math.floor(v/(2^n)) end,
        arshift = function(v,n) return math.floor(v/(2^n)) end
    }
end
_G.bit32 = bit32
_G.bit = bit32

if not getfenv then getfenv = function(f) return _G end end
if not setfenv then setfenv = function(f, t) return f end end
if not newproxy then newproxy = function(addmeta) local p = {}; if addmeta then setmetatable(p, {}) end; return p end end
if not unpack then unpack = table.unpack or function(t, i, j) j = j or #t; i = i or 1; if i > j then return end; return t[i], unpack(t, i+1, j) end end

local Roblox = {}

function Roblox.make_proxy(name)
    local proxy = newproxy(true)
    local mt = getmetatable(proxy)
    mt.__index = function(t, k)
        local newPath = name .. "." .. tostring(k)
        if name == "game" then
            if k == "PlaceId" then return 123456 end
            if k == "JobId" then return "deadbeef-1234-5678-9abc-def012345678" end
            if k == "Players" then return Roblox.make_proxy("Players") end
            if k == "Workspace" then return Roblox.make_proxy("Workspace") end
            if k == "ReplicatedStorage" then return Roblox.make_proxy("ReplicatedStorage") end
            if k == "ServerStorage" then return Roblox.make_proxy("ServerStorage") end
            if k == "ServerScriptService" then return Roblox.make_proxy("ServerScriptService") end
            if k == "Lighting" then return Roblox.make_proxy("Lighting") end
            if k == "StarterGui" then return Roblox.make_proxy("StarterGui") end
            if k == "CoreGui" then return Roblox.make_proxy("CoreGui") end
            if k == "GetService" then
                return function(self, sn)
                    if sn == "Players" then return Roblox.make_proxy("Players") end
                    if sn == "HttpService" then return Roblox.make_proxy("HttpService") end
                    return Roblox.make_proxy(sn)
                end
            end
            if k == "HttpGet" or k == "HttpGetAsync" then return function() return "" end end
            if k == "SetCore" then return function() end end
        end
        if k == "LocalPlayer" then
            local lp = Roblox.make_proxy("LocalPlayer")
            local lmt = getmetatable(lp)
            lmt.__index = function(_, pk)
                if pk == "Name" then return "LocalPlayer" end
                if pk == "UserId" then return 1 end
                if pk == "Character" then return Roblox.make_proxy("Character") end
                return Roblox.make_proxy(pk)
            end
            return lp
        end
        if k == "Character" then
            local char = Roblox.make_proxy("Character")
            local cmt = getmetatable(char)
            cmt.__index = function(_, pk)
                if pk == "Humanoid" then return Roblox.make_proxy("Humanoid") end
                return Roblox.make_proxy(pk)
            end
            return char
        end
        return Roblox.make_proxy(newPath)
    end
    mt.__newindex = function() end
    mt.__call = function(t, ...) return Roblox.make_proxy(name .. "()") end
    mt.__tostring = function() return name end
    mt.__len = function() return 2853638 end
    mt.__gc = function() end
    mt.__add = function() return 0 end
    mt.__sub = function() return 0 end
    mt.__mul = function() return 0 end
    mt.__div = function() return 0 end
    mt.__mod = function() return 0 end
    mt.__unm = function() return 0 end
    mt.__concat = function(a, b) return tostring(a) .. tostring(b) end
    mt.__lt = function() return false end
    mt.__le = function() return false end
    mt.__eq = function() return false end
    return proxy
end

local _game = Roblox.make_proxy("game")
rawset(_game, "GetService", function(self, sn)
    if sn == "Players" then return Roblox.make_proxy("Players") end
    if sn == "HttpService" then return Roblox.make_proxy("HttpService") end
    return Roblox.make_proxy(sn)
end)
rawset(_game, "Players", Roblox.make_proxy("Players"))
rawset(_game, "Workspace", Roblox.make_proxy("Workspace"))
rawset(_game, "PlaceId", 123456)
rawset(_game, "JobId", "deadbeef-1234-5678-9abc-def012345678")
game = _game
workspace = Roblox.make_proxy("workspace")
script = Roblox.make_proxy("script")
shared = {}
task = { wait = function() end, spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end }
wait = function() end
spawn = function(f) pcall(f) end
delay = function(t, f) pcall(f) end
tick = function() return 0 end
time = function() return 0 end
os = { time = function() return 0 end, clock = function() return 0 end, date = function() return "" end }

CFrame = {}
function CFrame.new(...) return Roblox.make_proxy("CFrame") end
Vector3 = {}
function Vector3.new(...) return Roblox.make_proxy("Vector3") end
Vector2 = {}
function Vector2.new(...) return Roblox.make_proxy("Vector2") end
Color3 = {}
function Color3.new(...) return Roblox.make_proxy("Color3") end
function Color3.fromRGB(...) return Color3.new(...) end
function Color3.fromHSV(...) return Color3.new(...) end
UDim2 = {}
function UDim2.new(...) return Roblox.make_proxy("UDim2") end
function UDim2.fromScale(...) return UDim2.new(...) end
function UDim2.fromOffset(...) return UDim2.new(...) end
UDim = {}
function UDim.new(...) return Roblox.make_proxy("UDim") end
Ray = {}
function Ray.new(...) return Roblox.make_proxy("Ray") end
BrickColor = {}
function BrickColor.new(...) return Roblox.make_proxy("BrickColor") end
function BrickColor.random() return Roblox.make_proxy("BrickColor") end
Region3 = {}
function Region3.new(...) return Roblox.make_proxy("Region3") end
TweenInfo = {}
function TweenInfo.new(...) return Roblox.make_proxy("TweenInfo") end
Drawing = {}
function Drawing.new(...) return Roblox.make_proxy("Drawing") end
Instance = {}
function Instance.new(className) return Roblox.make_proxy("Instance." .. className) end
Enum = Roblox.make_proxy("Enum")

local HttpService = Roblox.make_proxy("HttpService")
local hmt = getmetatable(HttpService)
hmt.__index = function(t, k)
    if k == "JSONDecode" then return function(s) return {} end end
    if k == "JSONEncode" then return function(o) return "{}" end end
    if k == "GenerateGUID" then return function() return "dead-beef-1234-5678" end end
    return Roblox.make_proxy("HttpService." .. k)
end

local function make_stub(name)
    local stub = Roblox.make_proxy(name)
    return stub
end

getgenv = function() return _G end
getrenv = function() return _G end
checkcaller = function() return true end
identifyexecutor = function() return "Synapse X", "2.0.0" end
getrawmetatable = function(t) return getmetatable(t) end
gethui = function() return Roblox.make_proxy("HUI") end
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
request = function(o) return { StatusCode = 200, Body = "", Headers = {} } end
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
crypt = {
    encrypt = function(d) return d end,
    decrypt = function(d) return d end,
    hash = function(d) return "hash" end,
    generatekey = function() return "key" end,
    base64encode = function(d) return d end,
    base64decode = function(d) return d end,
    base64 = { encode = function(d) return d end, decode = function(d) return d end },
    custom = { encrypt = function(d) return d end, decrypt = function(d) return d end }
}
syn = {
    request = request,
    crypt = crypt,
    queue_on_teleport = function() end,
    protect_gui = function() end
}
fluxus = syn

math.clamp = math.clamp or function(x, mn, mx) return math.max(mn, math.min(mx, x)) end
"""


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
            ' if type(chunk) == "string" and #chunk > 0 then\n'
            "  _captured_payload = chunk\n"
            '  local f = io.open("' + output_path_fixed + '", "w")\n'
            "  if f then\n"
            "   f:write(chunk)\n"
            "   f:close()\n"
            "  end\n"
            " end\n"
            " return _real_loadstring(chunk, chunkname)\n"
            "end\n"
            "\n"
            "_G.loadstring = hook_load\n"
            "_G.load = hook_load\n"
            "if getfenv then\n"
            " local env = getfenv()\n"
            " env.loadstring = hook_load\n"
            " env.load = hook_load\n"
            "end\n"
            "\n"
            "os.execute = nil\n"
            "os.exit = nil\n"
            "os.remove = nil\n"
            "os.rename = nil\n"
            "os.getenv = nil\n"
            "package = nil\n"
            "require = function() return {} end\n"
            "\n"
            + ENV_BOOTSTRAP +
            "\n"
            "local _real_pcall = pcall\n"
            "local ok, err = _real_pcall(function()\n"
            + source +
            "\nend)\n"
            "\n"
            'if not ok and _captured_payload == "" then\n'
            ' local f = io.open("' + output_path_fixed + '", "w")\n'
            " if f then\n"
            '  f:write("-- [HARNESS ERROR] " .. tostring(err))\n'
            "  f:close()\n"
            " end\n"
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
                    if hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
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
            'os.execute = nil\n'
            'os.exit = nil\n'
            'os.remove = nil\n'
            'os.rename = nil\n'
            'os.getenv = nil\n'
            'package = nil\n'
            'require = function() return {} end\n'
            '\n'
            + ENV_BOOTSTRAP +
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
