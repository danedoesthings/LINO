import subprocess
import tempfile
import os
import shutil
import signal
import time

LOG_LIMIT = 3000
CAPTURE_LIMIT = 20
VM_INSTRUCTION_LIMIT = 500000

ENV_BOOTSTRAP = r"""
local ORIGINAL_LOADSTRING = rawget(_G, "loadstring")
local ORIGINAL_LOAD = rawget(_G, "load")
local ORIGINAL_CONCAT = table.concat
local ORIGINAL_CHAR = string.char
local ORIGINAL_PCALL = pcall
local ORIGINAL_XPCALL = xpcall or nil
local ORIGINAL_SETFENV = setfenv or (getfenv and function(f, e) end)
local ORIGINAL_GETFENV = getfenv or function() return _G end
local ORIGINAL_SETMETATABLE = setmetatable
local ORIGINAL_GETMETATABLE = getmetatable
local ORIGINAL_COROUTINE_CREATE = coroutine.create or nil
local ORIGINAL_COROUTINE_WRAP = coroutine.wrap or nil
local ORIGINAL_COROUTINE_RESUME = coroutine.resume or nil
local ORIGINAL_LOADFILE = loadfile or nil
local ORIGINAL_DOFILE = dofile or nil
local ORIGINAL_GSUB = string.gsub
local ORIGINAL_SUB = string.sub
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
        if mt and mt.__type then
            return mt.__type()
        end
        return _G.type(obj)
    end
end
if not unpack then unpack = table.unpack or function(t, i, j) j = j or #t; i = i or 1; if i > j then return end; return t[i], unpack(t, i+1, j) end end

local _inside_hook = false

local function safe_hook(fn)
    if _inside_hook then return end
    _inside_hook = true
    local ok = pcall(fn)
    _inside_hook = false
end

local _log_file = nil
local _log_count = 0
local _log_limit = """ + str(LOG_LIMIT) + r"""
local _captures = {}
local _capture_count = 0
local _capture_limit = """ + str(CAPTURE_LIMIT) + r"""
local _best_payload = ""
local _best_score = 0
local _bytecode_index = 0

local function _log(msg)
    if _log_file and _log_count < _log_limit then
        _log_file:write(msg .. "\n")
        _log_file:flush()
        _log_count = _log_count + 1
    end
end

local function dump(tag, data)
    safe_hook(function()
        local s = tostring(data)
        if #s > 400 then s = s:sub(1, 400) .. "... (len=" .. #s .. ")" end
        _log("[HOOK][" .. tag .. "] " .. s)
    end)
end

local function score_source(src)
    if type(src) ~= "string" then return 0 end
    if src:sub(1, 4) == "\27Lua" then
        _bytecode_index = _bytecode_index + 1
        local fn = _outpath_bytecode:gsub("%.luac$", "_" .. _bytecode_index .. ".luac")
        local f = io.open(fn, "wb")
        if f then f:write(src); f:close() end
        _log("BYTECODE saved to " .. fn)
        return -1000
    end
    local s = 0
    if src:find("^[%w_]+$") then s = s - 100 end
    local unique = {}
    for i = 1, #src do unique[src:sub(i,i)] = true end
    local ratio = 0
    for _ in pairs(unique) do ratio = ratio + 1 end
    ratio = ratio / math.max(#src, 1)
    if ratio > 0.8 then s = s - 50 end
    if src:find("function") then s = s + 10 end
    if src:find("local ") then s = s + 5 end
    if src:find("return") then s = s + 8 end
    if src:find("for ") then s = s + 8 end
    if src:find("while ") then s = s + 8 end
    if src:find("repeat") then s = s + 8 end
    if src:find("if ") then s = s + 8 end
    if src:find("\nthen") or src:find(" then") then s = s + 5 end
    if src:find("\nend") or src:find(" end") then s = s + 5 end
    if src:find("game[%.:]") or src:find("game:") then s = s + 10 end
    if src:find("print") then s = s + 1 end
    if src:find("loadstring") then s = s + 2 end
    if src:find("pcall") then s = s + 2 end
    if #src > 1000 then s = s + 20 end
    if #src > 5000 then s = s + 30 end
    if #src > 10000 then s = s + 40 end
    return s
end

local function store_capture(chunk, tag)
    safe_hook(function()
        tag = tag or "source"
        _capture_count = _capture_count + 1
        if _capture_count > _capture_limit then return end
        local sc = score_source(chunk)
        _captures[_capture_count] = {chunk = chunk, score = sc, tag = tag}
        _log("CAPTURE #" .. _capture_count .. " [" .. tag .. "] len=" .. #chunk .. " score=" .. sc .. " preview=" .. chunk:sub(1, 150))
        if sc > _best_score then
            _best_score = sc
            _best_payload = chunk
            _log("NEW BEST PAYLOAD score=" .. sc)
            local f = io.open(_outpath, "w")
            if f then f:write(chunk); f:close() end
        end
    end)
end

function loadstring(chunk, chunkname)
    if type(chunk) == "string" and #chunk > 0 then
        safe_hook(function() dump("loadstring", "len=" .. #chunk) end)
        store_capture(chunk, "loadstring")
    end
    if ORIGINAL_LOADSTRING then return ORIGINAL_LOADSTRING(chunk, chunkname) end
    return ORIGINAL_LOAD(chunk, chunkname)
end

function load(chunk, chunkname)
    if type(chunk) == "string" and #chunk > 0 then
        safe_hook(function() dump("load", "len=" .. #chunk) end)
        store_capture(chunk, "load")
    elseif type(chunk) == "function" then
        local reader = chunk
        local fragments = {}
        chunk = function()
            local data = reader()
            if data then
                table.insert(fragments, data)
            end
            return data
        end
        local fn = ORIGINAL_LOAD(chunk, chunkname)
        local assembled = table.concat(fragments)
        if #assembled > 0 then
            safe_hook(function() dump("load-reader", "len=" .. #assembled) end)
            store_capture(assembled, "load-reader")
        end
        return fn
    end
    if ORIGINAL_LOAD then return ORIGINAL_LOAD(chunk, chunkname) end
    if ORIGINAL_LOADSTRING then return ORIGINAL_LOADSTRING(chunk, chunkname) end
end

if ORIGINAL_LOADFILE then
    loadfile = function(filename, ...)
        safe_hook(function() dump("loadfile", filename) end)
        return ORIGINAL_LOADFILE(filename, ...)
    end
end

if ORIGINAL_DOFILE then
    dofile = function(filename, ...)
        safe_hook(function() dump("dofile", filename) end)
        return ORIGINAL_DOFILE(filename, ...)
    end
end

table.concat = function(t, sep, i, j)
    local r = ORIGINAL_CONCAT(t, sep, i, j)
    if type(r) == "string" and #r > 0 then
        safe_hook(function() dump("table.concat", "len=" .. #r .. " first=" .. r:sub(1, 100)) end)
        if #r > 20 then store_capture(r, "table.concat") end
    end
    return r
end

string.char = function(...)
    local r = ORIGINAL_CHAR(...)
    local argc = select("#", ...)
    if argc >= 4 and #r > 0 then
        safe_hook(function() dump("string.char", "args=" .. argc .. " len=" .. #r .. " first=" .. r:sub(1, 80)) end)
        if #r > 3 then store_capture(r, "string.char") end
    end
    return r
end

string.gsub = function(s, p, r, n)
    local res = ORIGINAL_GSUB(s, p, r, n)
    if type(res) == "string" and #res > 50 then
        safe_hook(function() dump("string.gsub", "len=" .. #res .. " first=" .. res:sub(1, 100)) end)
        store_capture(res, "string.gsub")
    end
    return res
end

string.sub = function(s, i, j)
    local res = ORIGINAL_SUB(s, i, j)
    if type(res) == "string" and #res > 50 then
        safe_hook(function() dump("string.sub", "len=" .. #res .. " first=" .. res:sub(1, 100)) end)
        store_capture(res, "string.sub")
    end
    return res
end

table.unpack = function(t, i, j)
    local parts = {}
    local count = 0
    local function collector(...)
        count = select("#", ...)
        for idx = 1, count do parts[idx] = tostring(select(idx, ...)) end
    end
    if ORIGINAL_UNPACK then collector(ORIGINAL_UNPACK(t, i, j)) end
    if count > 10 then
        local assembled = table.concat(parts, " ")
        safe_hook(function() dump("unpack", "count=" .. count .. " len=" .. #assembled .. " first=" .. assembled:sub(1, 100)) end)
        store_capture(assembled, "unpack")
    end
    return ORIGINAL_UNPACK(t, i, j)
end

pcall = function(fn, ...)
    safe_hook(function() dump("pcall", tostring(fn):sub(1, 80)) end)
    return ORIGINAL_PCALL(fn, ...)
end

if ORIGINAL_XPCALL then
    xpcall = function(fn, errh, ...)
        safe_hook(function() dump("xpcall", tostring(fn):sub(1, 80)) end)
        return ORIGINAL_XPCALL(fn, errh, ...)
    end
end

setfenv = function(fn, env)
    safe_hook(function() dump("setfenv", tostring(fn):sub(1, 80)) end)
    return ORIGINAL_SETFENV(fn, env)
end

getfenv = function(fn)
    local r = ORIGINAL_GETFENV(fn)
    safe_hook(function() dump("getfenv", tostring(fn):sub(1, 80)) end)
    return r
end

setmetatable = function(t, mt)
    safe_hook(function() dump("setmetatable", tostring(mt):sub(1, 80)) end)
    return ORIGINAL_SETMETATABLE(t, mt)
end

getmetatable = function(t)
    local r = ORIGINAL_GETMETATABLE(t)
    if r then safe_hook(function() dump("getmetatable", tostring(t):sub(1, 80)) end) end
    return r
end

if ORIGINAL_COROUTINE_CREATE then
    coroutine.create = function(fn)
        safe_hook(function() dump("coroutine.create", tostring(fn):sub(1, 80)) end)
        return ORIGINAL_COROUTINE_CREATE(fn)
    end
end

if ORIGINAL_COROUTINE_WRAP then
    coroutine.wrap = function(fn)
        safe_hook(function() dump("coroutine.wrap", tostring(fn):sub(1, 80)) end)
        return ORIGINAL_COROUTINE_WRAP(fn)
    end
end

if ORIGINAL_COROUTINE_RESUME then
    coroutine.resume = function(co, ...)
        safe_hook(function() dump("coroutine.resume", tostring(co):sub(1, 80)) end)
        return ORIGINAL_COROUTINE_RESUME(co, ...)
    end
end

local _real_print = print
print = function(...)
    local parts = {}
    for i = 1, select('#', ...) do
        parts[i] = tostring(select(i, ...))
    end
    local msg = table.concat(parts, "\t")
    safe_hook(function() dump("print", msg) end)
    if #msg > 20 then store_capture(msg, "print") end
    _real_print(msg)
end

local _real_warn = warn or print
warn = function(...)
    local parts = {}
    for i = 1, select('#', ...) do
        parts[i] = tostring(select(i, ...))
    end
    local msg = table.concat(parts, "\t")
    safe_hook(function() dump("warn", msg) end)
    _real_warn(msg)
end

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
                    safe_hook(function() dump("GetService", sn) end)
                    if sn == "Players" then return Roblox.make_proxy("Players") end
                    if sn == "HttpService" then return Roblox.make_proxy("HttpService") end
                    return Roblox.make_proxy(sn)
                end
            end
            if k == "HttpGet" or k == "HttpGetAsync" then
                return function(self, url)
                    safe_hook(function() dump("HttpGet", url) end)
                    return "--REMOTE_PAYLOAD"
                end
            end
            if k == "SetCore" then
                return function(self, method, args)
                    safe_hook(function() dump("SetCore", method .. " args=" .. tostring(args)) end)
                end
            end
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
        if k == "Connect" or k == "connect" then
            return function(self, cb)
                safe_hook(function() dump("Connect", newPath) end)
                if string.find(newPath, "Button") or string.find(newPath, "Click") or string.find(newPath, "Submit") then
                    _log("Auto-triggering callback for " .. newPath)
                    pcall(cb)
                end
            end
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
    safe_hook(function() dump("GetService", sn) end)
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
request = function(o)
    safe_hook(function() dump("request", o.Url or "?") end)
    return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} }
end
http_request = request
readfile = function(f) safe_hook(function() dump("readfile", f) end); return "" end
writefile = function(f, c) safe_hook(function() dump("writefile", f) end) end
appendfile = function(f, c) safe_hook(function() dump("appendfile", f) end) end
isfile = function() return false end
isfolder = function() return false end
makefolder = function() end
delfolder = function() end
delfile = function() end
listfiles = function() return {} end
rconsoleprint = function(...) safe_hook(function() dump("rconsole", table.concat({...}, "\t")) end) end
rconsoleinfo = function(...) safe_hook(function() dump("rconsole", table.concat({...}, "\t")) end) end
rconsolewarn = function(...) safe_hook(function() dump("rconsole", table.concat({...}, "\t")) end) end
rconsoleerr = function(...) safe_hook(function() dump("rconsole", table.concat({...}, "\t")) end) end
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

debug = {
    getinfo = function() return {source="mock", short_src="mock", func=function() end} end,
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
    traceback = function() return "mock traceback" end
}

math.clamp = math.clamp or function(x, mn, mx) return math.max(mn, math.min(mx, x)) end

local _instruction_count = 0
local _vm_limit = """ + str(VM_INSTRUCTION_LIMIT) + r"""
debug.sethook(function(event)
    _instruction_count = _instruction_count + 1
    if _instruction_count > _vm_limit then
        _log("VM_LOOP_LIMIT reached: " .. _instruction_count .. " instructions")
        error("VM LOOP LIMIT REACHED", 0)
    end
end, "", 1000)

setclipboard = function(s) safe_hook(function() dump("setclipboard", s:sub(1, 100)) end) end
toclipboard = function(s) safe_hook(function() dump("toclipboard", s:sub(1, 100)) end) end
os.execute = nil
os.exit = nil
os.remove = nil
os.rename = nil
os.getenv = nil
package = nil
require = function(id)
    safe_hook(function() dump("require", id) end)
    return setmetatable({}, {
        __index = function(t, k) return function() return nil end end,
        __call = function(t, ...) return nil end,
        __tostring = function() return "module:" .. id end
    })
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

    def run(self, source: str, timeout: int = 20) -> str | None:
        if not self.available:
            return None
        tmpdir = tempfile.mkdtemp()
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        bytecode_path = os.path.join(tmpdir, "captured.luac")
        log_path = os.path.join(tmpdir, "log.txt")
        output_path_fixed = output_path.replace('\\', '/')
        bytecode_path_fixed = bytecode_path.replace('\\', '/')
        log_path_fixed = log_path.replace('\\', '/')

        harness_code = (
            'local _outpath = "' + output_path_fixed + '"\n'
            + 'local _outpath_bytecode = "' + bytecode_path_fixed + '"\n'
            + 'local _captured_payload = ""\n'
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
            "if _best_payload ~= \"\" then\n"
            ' _captured_payload = _best_payload\n'
            "end\n"
            'if _captured_payload == "" then\n'
            " local f = io.open(_outpath, \"w\")\n"
            " if f then\n"
            '  f:write("-- [HARNESS ERROR] " .. tostring(err or "no payload captured"))\n'
            "  f:close()\n"
            " end\n"
            "end\n"
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
        tmpdir = tempfile.mkdtemp()
        harness_path = os.path.join(tmpdir, "harness.lua")
        output_path = os.path.join(tmpdir, "captured.lua")
        bytecode_path = os.path.join(tmpdir, "captured.luac")
        log_path = os.path.join(tmpdir, "log.txt")
        output_path_fixed = output_path.replace('\\', '/')
        bytecode_path_fixed = bytecode_path.replace('\\', '/')
        log_path_fixed = log_path.replace('\\', '/')

        harness_code = (
            'local _outpath = "' + output_path_fixed + '"\n'
            + 'local _outpath_bytecode = "' + bytecode_path_fixed + '"\n'
            + 'local _captured_payload = ""\n'
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
            "if _best_payload ~= \"\" then\n"
            ' _captured_payload = _best_payload\n'
            "end\n"
            'if _captured_payload == "" then\n'
            " local f = io.open(_outpath, \"w\")\n"
            " if f then\n"
            '  f:write("-- [HARNESS ERROR] " .. tostring(err or "no payload captured"))\n'
            "  f:close()\n"
            " end\n"
            "end\n"
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
                    result['trace'] = tf.read()[:4000]

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
