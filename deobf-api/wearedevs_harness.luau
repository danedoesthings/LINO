local fs = require("@lune/fs")
local process = require("@lune/process")
local luau = require("@lune/luau")

local targetFile = process.args[1]
local outFile = process.args[2] or "captured.lua"
local stringsFile = process.args[3]

if not fs.isFile(targetFile) then
    error("Target file not found: " .. targetFile)
end

local input = fs.readFile(targetFile)

if not bit32 then
    bit32 = {
        bxor = function(a,b) local r=0; for i=0,31 do local aa=math.floor(a/2^i)%2; local bb=math.floor(b/2^i)%2; if aa~=bb then r=r+2^i end end; return r end,
        band = function(a,b) local r=0; for i=0,31 do if math.floor(a/2^i)%2+math.floor(b/2^i)%2==2 then r=r+2^i end end; return r end,
        bor = function(a,b) local r=0; for i=0,31 do if math.floor(a/2^i)%2+math.floor(b/2^i)%2>0 then r=r+2^i end end; return r end,
        lshift = function(v,n) return math.floor(v * 2^n) % 4294967296 end,
        rshift = function(v,n) return math.floor(v / 2^n) end,
        arshift = function(v,n) return math.floor(v / 2^n) end,
    }
end
bit = bit32

local captured_lines = {}
local function log_line(msg)
    captured_lines[#captured_lines + 1] = msg
end

local function _25ms(var)
    if type(var) == "string" and #var > 0 then
        log_line(var)
    end
    return var
end

local function _hook_and(a, b)
    local expr = tostring(a) .. " and " .. tostring(b)
    _25ms(expr)
    return a and b
end

local function _hook_or(a, b)
    local expr = tostring(a) .. " or " .. tostring(b)
    _25ms(expr)
    return a or b
end

local function _hook_lt(a, b)
    local expr = tostring(a) .. " < " .. tostring(b)
    _25ms(expr)
    return a < b
end

local function _hook_le(a, b)
    local expr = tostring(a) .. " <= " .. tostring(b)
    _25ms(expr)
    return a <= b
end

local function _hook_gt(a, b)
    local expr = tostring(a) .. " > " .. tostring(b)
    _25ms(expr)
    return a > b
end

local function _hook_ge(a, b)
    local expr = tostring(a) .. " >= " .. tostring(b)
    _25ms(expr)
    return a >= b
end

local function _hook_eq(a, b)
    local expr = tostring(a) .. " == " .. tostring(b)
    _25ms(expr)
    return a == b
end

local function _hook_neq(a, b)
    local expr = tostring(a) .. " ~= " .. tostring(b)
    _25ms(expr)
    return a ~= b
end

local function _hook_not(a)
    local expr = "not " .. tostring(a)
    _25ms(expr)
    return not a
end

local function _hook_len(a)
    local expr = "#" .. tostring(a)
    _25ms(expr)
    return #a
end

local function _hook_add(a, b)
    local expr = tostring(a) .. " + " .. tostring(b)
    _25ms(expr)
    return a + b
end

local function _hook_sub(a, b)
    local expr = tostring(a) .. " - " .. tostring(b)
    _25ms(expr)
    return a - b
end

local function _hook_mul(a, b)
    local expr = tostring(a) .. " * " .. tostring(b)
    _25ms(expr)
    return a * b
end

local function _hook_div(a, b)
    local expr = tostring(a) .. " / " .. tostring(b)
    _25ms(expr)
    return a / b
end

local function _hook_concat(a, b)
    local expr = tostring(a) .. " .. " .. tostring(b)
    _25ms(expr)
    return tostring(a) .. tostring(b)
end

local function make_proxy(name)
    local proxy = newproxy(true)
    local mt = getmetatable(proxy)
    mt.__index = function(t, k)
        return make_proxy(name .. "." .. tostring(k))
    end
    mt.__newindex = function(t, k, v)
        if type(v) == "string" and #v > 0 then
            _25ms(v)
        end
    end
    mt.__call = function(t, ...)
        return make_proxy(name .. "(...)")
    end
    mt.__tostring = function() return name end
    mt.__len = function() return 0 end
    mt.__add = function() return 0 end
    mt.__sub = function() return 0 end
    mt.__mul = function() return 0 end
    mt.__div = function() return 0 end
    mt.__concat = function(a, b) return tostring(a) .. tostring(b) end
    mt.__lt = function() return false end
    mt.__le = function() return false end
    mt.__eq = function() return false end
    return proxy
end

local env = {}
local function build_env()
    local services = {
        Players = function()
            local p = make_proxy("Players")
            p.LocalPlayer = make_proxy("LocalPlayer")
            p.LocalPlayer.UserId = 1
            p.LocalPlayer.Name = "Player"
            p.LocalPlayer.Character = make_proxy("Character")
            p.GetPlayers = function() return {p.LocalPlayer} end
            return p
        end,
        Workspace = function()
            local w = make_proxy("Workspace")
            w.CurrentCamera = make_proxy("Camera")
            return w
        end,
        RunService = function() return make_proxy("RunService") end,
        HttpService = function() return make_proxy("HttpService") end,
        ReplicatedStorage = function() return make_proxy("ReplicatedStorage") end,
        Lighting = function() return make_proxy("Lighting") end,
        StarterGui = function() return make_proxy("StarterGui") end,
        TweenService = function() return make_proxy("TweenService") end,
        UserInputService = function() return make_proxy("UserInputService") end,
    }
    local game_obj = make_proxy("game")
    game_obj.GetService = function(self, name)
        local svc = services[name]
        if svc then return svc() end
        return make_proxy(name)
    end
    game_obj.PlaceId = 1
    game_obj.JobId = "deadbeef-1234-5678-9abc-def012345678"
    env.game = game_obj
    env.workspace = services.Workspace()
    env.script = make_proxy("script")
    env.shared = {}
    env._G = env
    env.getfenv = function() return env end
    env.setfenv = function(f, t) return f end
    env.getgenv = function() return env end
    env.getrenv = function() return _G end
    env.print = function(...) local args={...}; for i=1,#args do _25ms(tostring(args[i])) end end
    env.warn = env.print
    env.error = function(msg) _25ms("error: " .. tostring(msg)) end
    env.pcall = function(f, ...) return pcall(f, ...) end
    env.xpcall = function(f, e, ...) return xpcall(f, e, ...) end
    env.loadstring = function(s, n) _25ms(s); return loadstring(s, n) end
    env.load = env.loadstring
    env.require = function(m) return make_proxy("module:" .. tostring(m)) end
    env.identifyexecutor = function() return "LINO", "1.0" end
    env.getexecutorname = function() return "LINO" end
    env.checkcaller = function() return true end
    env.iscclosure = function() return false end
    env.islclosure = function() return true end
    env.newcclosure = function(f) return f end
    env.hookfunction = function(f, h) return f end
    env.hookmetamethod = function(o, m, h) return function() end end
    env.getrawmetatable = function(t) return getmetatable(t) end
    env.setreadonly = function() end
    env.isreadonly = function() return false end
    env.gethui = function() return make_proxy("HUI") end
    env.getgc = function() return {} end
    env.getinstances = function() return {} end
    env.getnilinstances = function() return {} end
    env.getconnections = function() return {} end
    env.firesignal = function() end
    env.readfile = function() return "" end
    env.writefile = function() end
    env.isfile = function() return false end
    env.makefolder = function() end
    env.listfiles = function() return {} end
    env.request = function() return {StatusCode=200, Body=""} end
    env.http_request = env.request
    env.crypt = {encrypt=function(d) return d end, decrypt=function(d) return d end, hash=function() return "hash" end}
    env.syn = {request=env.request, crypt=env.crypt}
    env.task = {wait=function() return 0 end, spawn=function(f) pcall(f) end, defer=function(f) pcall(f) end}
    env.wait = function() return 0 end
    env.spawn = function(f) pcall(f) end
    env.delay = function(t, f) pcall(f) end
    env.tick = function() return 0 end
    env.time = function() return 0 end
    env.os = {time=function() return 0 end, clock=function() return 0 end, date=function() return "" end}
    env.table = table
    env.string = string
    env.math = math
    env.coroutine = coroutine
    env.debug = {getinfo=function() return {source="", short_src="", func=function() end} end}
    env.CFrame = make_proxy("CFrame")
    env.Vector3 = make_proxy("Vector3")
    env.Vector2 = make_proxy("Vector2")
    env.Color3 = make_proxy("Color3")
    env.UDim2 = make_proxy("UDim2")
    env.Instance = make_proxy("Instance")
    env.Enum = make_proxy("Enum")
    env.unpack = table.unpack or unpack
    env.select = select
    env.type = type
    env.tonumber = tonumber
    env.tostring = tostring
    env.rawequal = rawequal
    env.rawget = rawget
    env.rawset = rawset
    env.next = next
    env.pairs = pairs
    env.ipairs = ipairs
    env.setmetatable = setmetatable
    env.getmetatable = getmetatable
    env.newproxy = newproxy
    env._VERSION = "Lua 5.1"
    env._HOOK_AND = _hook_and
    env._HOOK_OR = _hook_or
    env._HOOK_LT = _hook_lt
    env._HOOK_LE = _hook_le
    env._HOOK_GT = _hook_gt
    env._HOOK_GE = _hook_ge
    env._HOOK_EQ = _hook_eq
    env._HOOK_NEQ = _hook_neq
    env._HOOK_NOT = _hook_not
    env._HOOK_LEN = _hook_len
    env._HOOK_ADD = _hook_add
    env._HOOK_SUB = _hook_sub
    env._HOOK_MUL = _hook_mul
    env._HOOK_DIV = _hook_div
    env._HOOK_CONCAT = _hook_concat
end

build_env()

local function patch_source(src)
    src = src:gsub("([%w_]+)%s+and%s+([%w_]+)", "_HOOK_AND(%1, %2)")
    src = src:gsub("([%w_]+)%s+or%s+([%w_]+)", "_HOOK_OR(%1, %2)")
    src = src:gsub("([%w_]+)%s+<%s+([%w_]+)", "_HOOK_LT(%1, %2)")
    src = src:gsub("([%w_]+)%s+<=%s+([%w_]+)", "_HOOK_LE(%1, %2)")
    src = src:gsub("([%w_]+)%s+>%s+([%w_]+)", "_HOOK_GT(%1, %2)")
    src = src:gsub("([%w_]+)%s+>=%s+([%w_]+)", "_HOOK_GE(%1, %2)")
    src = src:gsub("([%w_]+)%s+==%s+([%w_]+)", "_HOOK_EQ(%1, %2)")
    src = src:gsub("([%w_]+)%s+~=%s+([%w_]+)", "_HOOK_NEQ(%1, %2)")
    src = src:gsub("not%s+([%w_]+)", "_HOOK_NOT(%1)")
    src = src:gsub("#([%w_]+)", "_HOOK_LEN(%1)")
    src = src:gsub("([%w_]+)%s+%+%s+([%w_]+)", "_HOOK_ADD(%1, %2)")
    src = src:gsub("([%w_]+)%s+-%s+([%w_]+)", "_HOOK_SUB(%1, %2)")
    src = src:gsub("([%w_]+)%s+%*%s+([%w_]+)", "_HOOK_MUL(%1, %2)")
    src = src:gsub("([%w_]+)%s+/%s+([%w_]+)", "_HOOK_DIV(%1, %2)")
    src = src:gsub("([%w_]+)%s+%.%.,%s+([%w_]+)", "_HOOK_CONCAT(%1, %2)")
    return src
end

local strings_table = {}
if stringsFile and #stringsFile > 0 and fs.isFile(stringsFile) then
    local chunk, err = luau.load(fs.readFile(stringsFile))
    if chunk then
        local ok, result = pcall(chunk)
        if ok and type(result) == "table" then
            for i, s in ipairs(result) do
                strings_table[tostring(i)] = s
                strings_table["R[" .. i .. "]"] = s
            end
        end
    end
end

local resolved = input
for k, v in pairs(strings_table) do
    if type(v) == "string" then
        local escaped = v:gsub('\\', '\\\\'):gsub('"', '\\"')
        resolved = resolved:gsub(k, '"' .. escaped .. '"')
    end
end

local patched = patch_source(resolved)

local chunk, err = luau.load(patched)
if not chunk then
    fs.writeFile(outFile, "-- ERROR: " .. tostring(err))
    return
end

setfenv(chunk, env)
local ok, result = pcall(chunk)
if not ok then
    captured_lines[#captured_lines + 1] = "-- RUNTIME ERROR: " .. tostring(result)
end

if type(result) == "function" then
    local ok2, res2 = pcall(result)
    if not ok2 then
        captured_lines[#captured_lines + 1] = "-- FUNCTION ERROR: " .. tostring(res2)
    end
end

local output = table.concat(captured_lines, "\n")
if output == "" then
    output = "-- No output captured"
end
fs.writeFile(outFile, output)
