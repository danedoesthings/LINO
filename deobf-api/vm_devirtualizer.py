local fs = require("@lune/fs")
local process = require("@lune/process")
local luau = require("@lune/luau")

local targetFile = process.args[1]
local outFile = process.args[2] or "deobfuscated.lua"

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
    local mt = {}
    mt.__type = function() return "userdata" end
    mt.__tostring = function() return name end
    mt.__len = function() return 2853638 end
    mt.__metatable = "The metatable is locked"
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
    mt.__gc = function() end
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

local _bit32 = rawget(_G, "bit32")
if not _bit32 then
    _bit32 = {
        bxor = function(a, b)
            local r, m = 0, 1
            while a > 0 or b > 0 do
                if (a % 2) ~= (b % 2) then r = r + m end
                a = math.floor(a / 2)
                b = math.floor(b / 2)
                m = m * 2
            end
            return r
        end,
        band = function(a, b)
            local r, m = 0, 1
            while a > 0 and b > 0 do
                if (a % 2) + (b % 2) == 2 then r = r + m end
                a = math.floor(a / 2)
                b = math.floor(b / 2)
                m = m * 2
            end
            return r
        end,
        bor = function(a, b)
            local r, m = 0, 1
            while a > 0 or b > 0 do
                if (a % 2) + (b % 2) > 0 then r = r + m end
                a = math.floor(a / 2)
                b = math.floor(b / 2)
                m = m * 2
            end
            return r
        end,
        lshift = function(v, n) return math.floor(v * (2 ^ n)) % 4294967296 end,
        rshift = function(v, n) return math.floor(v / (2 ^ n)) end,
        arshift = function(v, n) return math.floor(v / (2 ^ n)) end,
    }
end

local _unpack = table.unpack or unpack

local _cenv = _spy_make("env")

_cenv._25ms = _25ms
_cenv.math = math
_cenv.string = string
_cenv.table = table
_cenv.bit32 = _bit32
_cenv.bit = _bit32
_cenv.unpack = _unpack
_cenv.select = select or function(n, ...)
    if n == "#" then return select("#", ...) end
    local args = {...}
    local result = {}
    for i = n, #args do
        result[#result + 1] = args[i]
    end
    return _unpack(result)
end
_cenv.pcall = function(fn, ...)
    local results = {pcall(fn, ...)}
    if not results[1] then
        _25ms("[Error] " .. tostring(results[2]))
    end
    return _unpack(results)
end
_cenv.xpcall = xpcall or function(f, errh, ...) return pcall(f, ...) end
_cenv.getfenv = function() return _cenv end
_cenv.setfenv = function() end
_cenv.loadstring = function(src, b)
    if type(src) == "string" then
        _25ms(src)
        local fn = luau.load(src, b)
        return fn
    end
end
_cenv.load = _cenv.loadstring
_cenv.error = error
_cenv.assert = assert
_cenv.next = next
_cenv.ipairs = ipairs
_cenv.pairs = pairs
_cenv.rawequal = rawequal or function(a, b) return a == b end
_cenv.rawget = rawget or function(t, k) return t[k] end
_cenv.rawset = rawset or function(t, k, v) t[k] = v; return t end
_cenv.collectgarbage = collectgarbage or function() return 0 end
_cenv.typeof = function(obj)
    local mt = getmetatable(obj)
    if mt and mt.__type and mt.__type() == "userdata" then
        return "userdata"
    end
    return type(obj)
end
_cenv.script_key = "c4ce76cd36f2afee4dcee7e87576e5fa"
_cenv.coroutine = coroutine or {
    create = function(f) return { __func = f } end,
    resume = function(co, ...)
        if type(co) == "table" and co.__func then
            return pcall(co.__func, ...)
        end
        return pcall(co, ...)
    end,
    wrap = function(f)
        return function(...)
            return pcall(f, ...)
        end
    end,
    yield = function() end,
}
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
_cenv.require = function(id)
    if id == "@lune/fs" then return fs end
    if id == "@lune/process" then return process end
    if id == "@lune/luau" then return luau end
    return _spy_make("require." .. tostring(id))
end

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
    r[c] = "[Error] " .. tostring(result)
end

local output = _orig_table_concat(r, "\n")
fs.writeFile(outFile, output)
