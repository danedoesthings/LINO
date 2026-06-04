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

local captured = {}

local function log(s)
    if type(s) == "string" and #s > 0 then
        captured[#captured + 1] = s
    end
    return s
end

local function _25ms(var)
    if type(var) == "string" and #var > 0 then
        captured[#captured + 1] = var
    end
    return var
end

local strings = {}
if stringsFile and #stringsFile > 0 and fs.isFile(stringsFile) then
    local chunk, err = luau.load(fs.readFile(stringsFile))
    if chunk then
        local ok, result = pcall(chunk)
        if ok and type(result) == "table" then
            strings = result
        end
    end
end

local env = getfenv()
local function make_proxy(name)
    local proxy = newproxy(true)
    local mt = getmetatable(proxy)
    mt.__index = function(t, k)
        return make_proxy(name .. "." .. tostring(k))
    end
    mt.__newindex = function(t, k, v)
        if type(v) == "string" and #v > 0 then
            log(v)
        end
    end
    mt.__call = function(t, ...)
        return make_proxy(name .. "(...)")
    end
    mt.__tostring = function() return name end
    mt.__len = function() return 0 end
    return proxy
end

local game_obj = make_proxy("game")
game_obj.GetService = function(self, name)
    return make_proxy("service:" .. name)
end
game_obj.PlaceId = 1
game_obj.JobId = "deadbeef-1234-5678-9abc-def012345678"

env.game = game_obj
env.workspace = make_proxy("workspace")
env.script = make_proxy("script")
env.shared = {}
env._G = env

env.getfenv = function() return env end
env.setfenv = function(f, t) return f end
env.getgenv = function() return env end
env.getrenv = function() return _G end

env.print = function(...) 
    local args = {...}
    for i = 1, #args do
        log(tostring(args[i]))
    end
end
env.warn = env.print

env.pcall = pcall
env.xpcall = xpcall

local orig_loadstring = loadstring
env.loadstring = function(s, n)
    log(s)
    return orig_loadstring(s, n)
end
env.load = env.loadstring

env.require = function(m) return make_proxy("module") end
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
env.getconnections = function() return {} end
env.readfile = function() return "" end
env.writefile = function() end
env.isfile = function() return false end
env.makefolder = function() end
env.listfiles = function() return {} end
env.request = function() return {StatusCode=200, Body=""} end
env.http_request = env.request
env.crypt = {encrypt=function(d) return d end, decrypt=function(d) return d end}
env.syn = {request=env.request, crypt=env.crypt}

env.task = {wait=function() return 0 end, spawn=function(f) pcall(f) end}
env.wait = function() return 0 end
env.spawn = function(f) pcall(f) end
env.delay = function(t, f) pcall(f) end
env.tick = function() return 0 end
env.time = function() return 0 end
env.os = {time=function() return 0 end, clock=function() return 0 end}

env.table = table
env.string = string
env.math = math
env.coroutine = coroutine
env.debug = {getinfo=function() return {source="", func=function() end} end}
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

env.CFrame = make_proxy("CFrame")
env.Vector3 = make_proxy("Vector3")
env.Vector2 = make_proxy("Vector2")
env.Color3 = make_proxy("Color3")
env.UDim2 = make_proxy("UDim2")
env.Instance = make_proxy("Instance")
env.Enum = make_proxy("Enum")
env.Drawing = make_proxy("Drawing")

if not bit32 then
    bit32 = {
        bxor = function(a,b) local r=0; for i=0,31 do local aa=math.floor(a/2^i)%2; local bb=math.floor(b/2^i)%2; if aa~=bb then r=r+2^i end end; return r end,
        band = function(a,b) local r=0; for i=0,31 do if math.floor(a/2^i)%2+math.floor(b/2^i)%2==2 then r=r+2^i end end; return r end,
        bor = function(a,b) local r=0; for i=0,31 do if math.floor(a/2^i)%2+math.floor(b/2^i)%2>0 then r=r+2^i end end; return r end,
        lshift = function(v,n) return math.floor(v * 2^n) % 4294967296 end,
        rshift = function(v,n) return math.floor(v / 2^n) end,
    }
end
env.bit32 = bit32
env.bit = bit32

local function patch_strings(src)
    for i, s in ipairs(strings) do
        if s and type(s) == "string" then
            local escaped = s:gsub('\\', '\\\\'):gsub('"', '\\"')
            src = src:gsub('R%[' .. i .. '%]', '"' .. escaped .. '"')
            src = src:gsub('R%[%s*' .. i .. '%s*%]', '"' .. escaped .. '"')
            src = src:gsub('EncStr%[%s*' .. i .. '%s*%]', '"' .. escaped .. '"')
        end
    end
    
    local getter_name, offset = src:match('local%s+function%s+(%w+)%s*%((%w+)%)%s*return%s+R%[%2%s*%+%s*([%d]+)%]')
    if getter_name and offset then
        local off = tonumber(offset)
        src = src:gsub(getter_name .. '%s*%(%s*(%d+)%s*%)', function(n)
            local idx = tonumber(n) + off
            if strings[idx] then
                return '"' .. strings[idx]:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"'
            end
            return getter_name .. '(' .. n .. ')'
        end)
    end
    
    return src
end

local patched = patch_strings(input)

local chunk, err = luau.load(patched)
if not chunk then
    fs.writeFile(outFile, "-- ERROR: " .. tostring(err))
    return
end

setfenv(chunk, env)

local ok, result = pcall(chunk)
if not ok and result then
    captured[#captured + 1] = "-- RUNTIME ERROR: " .. tostring(result)
end

if type(result) == "function" then
    local ok2, res2 = pcall(result)
    if not ok2 and res2 then
        captured[#captured + 1] = "-- FUNCTION ERROR: " .. tostring(res2)
    end
end

local output = table.concat(captured, "\n")
if output == "" then
    output = "-- No output captured.\n-- The script may have failed before reaching the payload."
end

fs.writeFile(outFile, output)
