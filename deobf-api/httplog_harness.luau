local fs = require("@lune/fs")
local process = require("@lune/process")
local luau = require("@lune/luau")

local targetFile = process.args[1]
local outFile = process.args[2] or "captured.lua"

if not fs.isFile(targetFile) then
    error("Target file not found: " .. targetFile)
end

local input = fs.readFile(targetFile)

local r = {}
local c = 0

local function _25ms(var)
    if type(var) == "string" then
        c = c + 1
        r[c] = var
    end
    return var
end

local function _spy_make(name)
    local t = {}
    local mt = {
        __type = function() return "userdata" end,
        __tostring = function() return name end,
        __len = function() return 2853638 end,
        __metatable = "The metatable is locked",
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
        __gc = function() end,
    }
    mt.__index = function(self, k)
        return _spy_make(name .. "." .. tostring(k))
    end
    mt.__newindex = function(self, k, v)
        if type(v) == "string" then
            _25ms(v)
        end
    end
    mt.__call = function(self, ...)
        return _spy_make(name .. "(...)")
    end
    setmetatable(t, mt)
    return t
end

local _cenv = {}
setmetatable(_cenv, { __index = _G })

_cenv.pcall = function(fn, ...)
    local results = {pcall(fn, ...)}
    if not results[1] then
        local err = results[2]
        local trace = debug.traceback("", 2)
        _25ms("[Error] " .. tostring(err))
        _25ms("[Trace] " .. trace)
    end
    return unpack(results)
end

_cenv.getfenv = function(lvl)
    if lvl then
        local res = getfenv(lvl)
        return res
    end
    return _cenv
end

_cenv.setfenv = function(f, e)
    if type(f) == "function" and type(e) == "table" then
        setfenv(f, e)
    end
    return f
end

_cenv.loadstring = function(src, b)
    if type(src) == "string" then
        _25ms(src)
        local fn = luau.load(src, b)
        setfenv(fn, _cenv)
        return fn
    end
end

_cenv.load = function(src, b)
    if type(src) == "string" then
        _25ms(src)
        local fn = luau.load(src, b)
        setfenv(fn, _cenv)
        return fn
    end
end

_cenv.game = _spy_make("game")
_cenv.workspace = _spy_make("workspace")
_cenv.script = _spy_make("script")
_cenv.shared = {}
_cenv.task = { wait = function() return 1 end, spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end }
_cenv.wait = function() return 1 end
_cenv.spawn = function(f) pcall(f) end
_cenv.delay = function(t, f) pcall(f) end
_cenv.tick = function() return 0 end
_cenv.time = function() return 0 end
_cenv.os = { time = function() return 0 end, clock = function() return 0 end, date = function() return "" end }
_cenv.CFrame = _spy_make("CFrame")
_cenv.Vector3 = _spy_make("Vector3")
_cenv.Vector2 = _spy_make("Vector2")
_cenv.Color3 = _spy_make("Color3")
_cenv.UDim2 = _spy_make("UDim2")
_cenv.UDim = _spy_make("UDim")
_cenv.Instance = _spy_make("Instance")
_cenv.Enum = _spy_make("Enum")
_cenv.Drawing = _spy_make("Drawing")
_cenv.Ray = _spy_make("Ray")
_cenv.BrickColor = _spy_make("BrickColor")
_cenv.Region3 = _spy_make("Region3")
_cenv.TweenInfo = _spy_make("TweenInfo")
_cenv.getgenv = function() return _cenv end
_cenv.getrenv = function() return _G end
_cenv.checkcaller = function() return true end
_cenv.identifyexecutor = function() return "Synapse X", "2.0.0" end
_cenv.getrawmetatable = function(t) return getmetatable(t) end
_cenv.gethui = function() return _spy_make("HUI") end
_cenv.getnilinstances = function() return {} end
_cenv.getinstances = function() return {} end
_cenv.getgc = function() return {} end
_cenv.getreg = function() return {} end
_cenv.getloadedmodules = function() return {} end
_cenv.getconnections = function() return {} end
_cenv.firesignal = function() end
_cenv.setreadonly = function() end
_cenv.isreadonly = function() return false end
_cenv.hookfunction = function(f, h) return f end
_cenv.hookmetamethod = function(o, m, f) return function() end end
_cenv.newcclosure = function(f) return f end
_cenv.islclosure = function() return true end
_cenv.iscclosure = function() return false end
_cenv.getsynasset = function() return "content" end
_cenv.request = function(o) return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} } end
_cenv.http_request = _cenv.request
_cenv.readfile = function(f) return "" end
_cenv.writefile = function(f, c) end
_cenv.appendfile = function(f, c) end
_cenv.isfile = function() return false end
_cenv.isfolder = function() return false end
_cenv.makefolder = function() end
_cenv.delfolder = function() end
_cenv.delfile = function() end
_cenv.listfiles = function() return {} end
_cenv.rconsoleprint = function() end
_cenv.rconsoleinfo = function() end
_cenv.rconsolewarn = function() end
_cenv.rconsoleerr = function() end
_cenv.rconsoleclear = function() end
_cenv.rconsolename = function() end
_cenv.mouse1click = function() end
_cenv.mouse1press = function() end
_cenv.mouse1release = function() end
_cenv.keypress = function() end
_cenv.keyrelease = function() end
_cenv.mousemoveabs = function() end
_cenv.mousemoverel = function() end
_cenv.iswindowactive = function() return true end
_cenv.setclipboard = function(s) end
_cenv.toclipboard = function(s) end
_cenv.crypt = {
    encrypt = function(d) return d end, decrypt = function(d) return d end,
    hash = function(d) return "hash" end, generatekey = function() return "key" end,
    base64encode = function(d) return d end, base64decode = function(d) return d end,
    base64 = { encode = function(d) return d end, decode = function(d) return d end },
    custom = { encrypt = function(d) return d end, decrypt = function(d) return d end },
}
_cenv.syn = {
    request = _cenv.request,
    crypt = _cenv.crypt,
    queue_on_teleport = function() end,
    protect_gui = function() end,
}
_cenv.fluxus = _cenv.syn
_cenv.debug = {
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
_cenv.typeof = function(obj)
    local mt = getmetatable(obj)
    if mt and mt.__type and mt.__type() == "userdata" then
        return "userdata"
    end
    return type(obj)
end
_cenv.math = math
_cenv.string = string
_cenv.table = table
_cenv.bit32 = rawget(_G, "bit32") or {
    bxor = function(a, b) local r, m = 0, 1; while a > 0 or b > 0 do if (a % 2) ~= (b % 2) then r = r + m end; a = math.floor(a / 2); b = math.floor(b / 2); m = m * 2 end; return r end,
    band = function(a, b) local r, m = 0, 1; while a > 0 and b > 0 do if (a % 2) + (b % 2) == 2 then r = r + m end; a = math.floor(a / 2); b = math.floor(b / 2); m = m * 2 end; return r end,
    bor = function(a, b) local r, m = 0, 1; while a > 0 or b > 0 do if (a % 2) + (b % 2) > 0 then r = r + m end; a = math.floor(a / 2); b = math.floor(b / 2); m = m * 2 end; return r end,
    lshift = function(v, n) return math.floor(v * (2 ^ n)) % 4294967296 end,
    rshift = function(v, n) return math.floor(v / (2 ^ n)) end,
    arshift = function(v, n) return math.floor(v / (2 ^ n)) end,
}
_cenv.bit = _cenv.bit32
_cenv.newproxy = function(addmeta) local p = {}; if addmeta then setmetatable(p, {}) end; return p end
_cenv.unpack = unpack or table.unpack
_cenv.require = function(id)
    if id == "@lune/fs" then return fs end
    if id == "@lune/process" then return process end
    if id == "@lune/luau" then return luau end
    return _spy_make("require." .. tostring(id))
end
_cenv.script_key = "c4ce76cd36f2afee4dcee7e87576e5fa"

local _orig_table_concat = table.concat
table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    if type(r) == "string" and #r > 5 then _25ms(r) end
    return r
end

local _orig_string_char = string.char
string.char = function(...)
    local r = _orig_string_char(...)
    if select("#", ...) >= 3 then _25ms(r) end
    return r
end

local chunk, err = luau.load(input)
if err then
    fs.writeFile(outFile, "-- [ERROR] Compile: " .. err)
    return
end

setfenv(chunk, _cenv)

local success, result = pcall(chunk)
if not success then
    c = c + 1
    local trace = debug.traceback("", 2)
    r[c] = "[Error] " .. tostring(result) .. "\n[Trace] " .. trace
end

local output = _orig_table_concat(r, "\n")
fs.writeFile(outFile, output)
