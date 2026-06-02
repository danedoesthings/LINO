import subprocess
import tempfile
import os
import shutil
import signal
import time
import re

LOG_LIMIT = 10000
VM_INSTRUCTION_LIMIT = 2000000

ENV_BOOTSTRAP = r"""
local ORIGINAL_LOADSTRING = rawget(_G, "loadstring")
local ORIGINAL_LOAD = rawget(_G, "load")
local ORIGINAL_PCALL = pcall
local ORIGINAL_CONCAT = table.concat
local ORIGINAL_CHAR = string.char
local ORIGINAL_UNPACK = unpack or table.unpack

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

if not newproxy then
    local _userdata_counter = 0
    newproxy = function(addmeta)
        _userdata_counter = _userdata_counter + 1
        local ud = {}
        local name = "userdata_" .. _userdata_counter
        setmetatable(ud, {
            __type = function() return "userdata" end,
            __tostring = function() return name end,
        })
        if addmeta then
            setmetatable(ud, {
                __index = function() return nil end,
                __newindex = function() end,
                __type = function() return "userdata" end,
                __tostring = function() return name end,
                __metatable = "The metatable is locked",
            })
        end
        return ud
    end
    type = function(obj)
        local mt = getmetatable(obj)
        if mt and mt.__type then return mt.__type() end
        return _G.type(obj)
    end
end
if not unpack then unpack = table.unpack or function(t, i, j) j = j or #t; i = i or 1; if i > j then return end; return t[i], unpack(t, i+1, j) end end

local _log_file = nil
local _log_count = 0
local _log_limit = """ + str(LOG_LIMIT) + r"""
local _captured_buffers = {}
local _buffer_count = 0
local _state_count = 0
local _state_limit = 3000

function _log(msg)
    if _log_file and _log_count < _log_limit then
        _log_file:write(msg .. "\n")
        _log_file:flush()
        _log_count = _log_count + 1
    end
end

function _save_buffer(data, tag)
    _buffer_count = _buffer_count + 1
    if _buffer_count == 1 then
        _log("[BUFFER][" .. tag .. "][" .. _buffer_count .. "] len=" .. #data .. " first=" .. data:sub(1, 200))
        local f = io.open(_outpath, "w")
        if f then f:write(data); f:close() end
    end
end

function _log_state(state)
    _state_count = _state_count + 1
    if _state_count <= _state_limit then
        if _state_count <= 10 or _state_count % 100 == 0 then
            _log("[STATE][" .. _state_count .. "] -> " .. state)
        end
    end
end

function _log_reg_write(tbl_name, key, value)
    if _state_count > _state_limit then return end
    local vtype = type(value)
    local vstr
    if vtype == "string" then
        vstr = value:sub(1, 120)
        if #value > 20 then _save_buffer(value, "reg_string") end
    elseif vtype == "number" then
        vstr = tostring(value)
    elseif vtype == "function" then
        vstr = "function"
    elseif vtype == "table" then
        vstr = "table"
    elseif vtype == "nil" then
        vstr = "nil"
    else
        vstr = vtype
    end
    _log("[REG][" .. tbl_name .. "][" .. tostring(key) .. "] = " .. vstr .. " (" .. vtype .. ")")
end

table.concat = function(t, sep, i, j)
    local r = ORIGINAL_CONCAT(t, sep, i, j)
    if type(r) == "string" and #r > 100 then
        _save_buffer(r, "concat")
    end
    return r
end

string.char = function(...)
    local r = ORIGINAL_CHAR(...)
    local argc = select("#", ...)
    if argc >= 4 and #r > 50 then _save_buffer(r, "char") end
    return r
end

function loadstring(chunk, chunkname)
    if type(chunk) == "string" and #chunk > 0 then
        _save_buffer(chunk, "loadstring")
    end
    if ORIGINAL_LOADSTRING then return ORIGINAL_LOADSTRING(chunk, chunkname) end
    return ORIGINAL_LOAD(chunk, chunkname)
end

function load(chunk, chunkname)
    if type(chunk) == "string" and #chunk > 0 then
        _save_buffer(chunk, "load")
    end
    if ORIGINAL_LOAD then return ORIGINAL_LOAD(chunk, chunkname) end
    if ORIGINAL_LOADSTRING then return ORIGINAL_LOADSTRING(chunk, chunkname) end
end

getfenv = getfenv or function() return _G end
setfenv = setfenv or function(f, e) return f end

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
            if k == "GetService" then return function(self, sn)
                if sn == "Players" then return Roblox.make_proxy("Players") end
                if sn == "HttpService" then return Roblox.make_proxy("HttpService") end
                return Roblox.make_proxy(sn)
            end end
            if k == "HttpGet" or k == "HttpGetAsync" then return function(self, url) return "--REMOTE_PAYLOAD" end end
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
        if k == "Connect" or k == "connect" then return function(self, cb)
            if string.find(newPath, "Button") or string.find(newPath, "Click") then pcall(cb) end
        end end
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

CFrame = {} function CFrame.new(...) return Roblox.make_proxy("CFrame") end
Vector3 = {} function Vector3.new(...) return Roblox.make_proxy("Vector3") end
Vector2 = {} function Vector2.new(...) return Roblox.make_proxy("Vector2") end
Color3 = {} function Color3.new(...) return Roblox.make_proxy("Color3") end
function Color3.fromRGB(...) return Color3.new(...) end
function Color3.fromHSV(...) return Color3.new(...) end
UDim2 = {} function UDim2.new(...) return Roblox.make_proxy("UDim2") end
function UDim2.fromScale(...) return UDim2.new(...) end
function UDim2.fromOffset(...) return UDim2.new(...) end
UDim = {} function UDim.new(...) return Roblox.make_proxy("UDim") end
Ray = {} function Ray.new(...) return Roblox.make_proxy("Ray") end
BrickColor = {} function BrickColor.new(...) return Roblox.make_proxy("BrickColor") end
function BrickColor.random() return Roblox.make_proxy("BrickColor") end
Region3 = {} function Region3.new(...) return Roblox.make_proxy("Region3") end
TweenInfo = {} function TweenInfo.new(...) return Roblox.make_proxy("TweenInfo") end
Drawing = {} function Drawing.new(...) return Roblox.make_proxy("Drawing") end
Instance = {} function Instance.new(className) return Roblox.make_proxy("Instance." .. className) end
Enum = Roblox.make_proxy("Enum")

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
request = function(o) return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} } end
http_request = request
readfile = function(f) return "" end
writefile = function(f, c) end
appendfile = function(f, c) end
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
syn = { request = request, crypt = crypt, queue_on_teleport = function() end, protect_gui = function() end }
fluxus = syn

if debug then
    debug.getinfo = debug.getinfo or function() return {source="mock", short_src="mock", func=function() end} end
    debug.getconstants = debug.getconstants or function() return {} end
    debug.getconstant = debug.getconstant or function() return nil end
    debug.getupvalues = debug.getupvalues or function() return {} end
    debug.getupvalue = debug.getupvalue or function() return nil end
    debug.getprotos = debug.getprotos or function() return {} end
    debug.getproto = debug.getproto or function() return nil end
    debug.getstack = debug.getstack or function() return {} end
    debug.setstack = debug.setstack or function() end
    debug.setconstant = debug.setconstant or function() end
    debug.setupvalue = debug.setupvalue or function() end
    debug.getregistry = debug.getregistry or function() return {} end
    debug.getmetatable = debug.getmetatable or function(t) return getmetatable(t) end
    debug.setmetatable = debug.setmetatable or function(t, m) return setmetatable(t, m) end
    debug.profilebegin = debug.profilebegin or function() end
    debug.profileend = debug.profileend or function() end
    debug.traceback = debug.traceback or function() return "mock traceback" end
else
    debug = {}
end

math.clamp = math.clamp or function(x, mn, mx) return math.max(mn, math.min(mx, x)) end

os.execute = nil
os.exit = nil
os.remove = nil
os.rename = nil
os.getenv = nil
package = nil
require = function(id) return setmetatable({}, { __index = function() return function() end end, __call = function() return nil end }) end

local _instruction_count = 0
local _vm_limit = """ + str(VM_INSTRUCTION_LIMIT) + r"""
local _hooked_sethook = rawget(debug, "sethook") or (rawget(_G, "debug") and rawget(_G, "debug").sethook)
if _hooked_sethook then
    _hooked_sethook(function(event)
        _instruction_count = _instruction_count + 1
        if _instruction_count > _vm_limit then
            _log("VM_LOOP_LIMIT: " .. _instruction_count .. " instructions, " .. _buffer_count .. " buffers")
            error("VM LOOP LIMIT REACHED", 0)
        end
    end, "", 1000)
end
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

    def _instrument_source(self, source: str) -> str:
        """Inject _log_reg_write and _log_state calls into the VM source."""
        # Hook instrTbl[key] = value  ->  instrTbl[key] = (_log_reg_write("instrTbl", key, value) or value)
        source = re.sub(
            r'\b(instrTbl)\s*\[\s*(.+?)\s*\]\s*=\s*(.+?)(?=\n|;|$)',
            r'\1[ \2 ] = (_log_reg_write("\1", \2, \3) or \3)',
            source
        )
        # Hook vmStack[key] = value
        source = re.sub(
            r'\b(vmStack)\s*\[\s*(.+?)\s*\]\s*=\s*(.+?)(?=\n|;|$)',
            r'\1[ \2 ] = (_log_reg_write("\1", \2, \3) or \3)',
            source
        )
        # Hook vmState = <number> but only as a standalone assignment
        source = re.sub(
            r'^(\s*)(vmState)\s*=\s*(-?\d+)(\s*)$',
            r'\1\2 = (_log_state(\3) or \3)\4',
            source,
            flags=re.MULTILINE
        )
        return source

    def run(self, source: str, timeout: int = 20) -> str | None:
        if not self.available:
            return None
        source = self._instrument_source(source)
        tmpdir = tempfile.mkdtemp()
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        log_path = os.path.join(tmpdir, "log.txt")
        output_path_fixed = output_path.replace('\\', '/')
        log_path_fixed = log_path.replace('\\', '/')

        harness_code = (
            'local _outpath = "' + output_path_fixed + '"\n'
            + 'local _log_file = io.open("' + log_path_fixed + '", "w")\n'
            + ENV_BOOTSTRAP
            + "\n"
            "local ok, err = ORIGINAL_PCALL(function()\n"
            + source +
            "\nend)\n"
            "\n"
            "_log(\"EXECUTION_FINISHED ok=\" .. tostring(ok))\n"
            "if not ok then\n"
            ' _log("RUNTIME_ERROR: " .. tostring(err))\n'
            "end\n"
            "_log(\"State transitions: \" .. _state_count)\n"
            "_log(\"Buffers captured: \" .. _buffer_count)\n"
            "if _log_file then\n"
            " _log_file:close()\n"
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
        source = self._instrument_source(source)
        tmpdir = tempfile.mkdtemp()
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        log_path = os.path.join(tmpdir, "log.txt")
        output_path_fixed = output_path.replace('\\', '/')
        log_path_fixed = log_path.replace('\\', '/')

        harness_code = (
            'local _outpath = "' + output_path_fixed + '"\n'
            + 'local _log_file = io.open("' + log_path_fixed + '", "w")\n'
            + ENV_BOOTSTRAP
            + "\n"
            "local ok, err = ORIGINAL_PCALL(function()\n"
            + source +
            "\nend)\n"
            "\n"
            "_log(\"EXECUTION_FINISHED ok=\" .. tostring(ok))\n"
            "if not ok then\n"
            ' _log("RUNTIME_ERROR: " .. tostring(err))\n'
            "end\n"
            "_log(\"State transitions: \" .. _state_count)\n"
            "_log(\"Buffers captured: \" .. _buffer_count)\n"
            "if _log_file then\n"
            " _log_file:close()\n"
            "end\n"
        )

        result = {
            'captured': None,
            'trace': '',
            'error': None,
            'stdout': '',
            'stderr': '',
            'timed_out': False,
        }

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

            if os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8") as tf:
                    result['trace'] = tf.read()[:10000]

            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    captured = f.read().strip()
                if captured and not captured.startswith("-- [HARNESS ERROR]"):
                    result['captured'] = captured
                else:
                    result['error'] = captured

        except Exception as e:
            result['error'] = str(e)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return result
