local targetFile = arg[1]
local outFile = arg[2] or "captured.lua"
local stringsFile = arg[3]

local decoded_strings = {}
if stringsFile and #stringsFile > 0 then
    local f = io.open(stringsFile, "r")
    if f then
        local chunk = f:read("*a")
        f:close()
        local fn, err = loadstring(chunk)
        if fn then
            local ok, data = pcall(fn)
            if ok and type(data) == "table" then
                decoded_strings = data
            end
        end
    end
end

local f = io.open(targetFile, "r")
local input = f:read("*a")
f:close()

local r = {}
local c = 0

local function _25ms(var)
    if type(var) == "string" then
        c = c + 1
        r[c] = var
        local f = io.open(outFile, "a")
        if f then
            f:write(var .. "\n")
            f:close()
        end
    end
    return var
end

local function _spy_make(name)
    local t = {}
    local mt = {
        __type = function() return "userdata" end,
        __tostring = function() return name end,
        __len = function() return 0 end,
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
    }
    mt.__index = function(self, k)
        if k == "Parent" then return nil end
        return _spy_make(name .. "." .. tostring(k))
    end
    mt.__newindex = function(self, k, v)
        if type(v) == "string" then _25ms(v) end
    end
    mt.__call = function(self, ...)
        return _spy_make(name .. "(...)")
    end
    setmetatable(t, mt)
    return t
end

local bit32 = {
    bxor = function(a,b) local r,m=0,1; while a>0 or b>0 do if (a%2)~=(b%2) then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end,
    band = function(a,b) local r,m=0,1; while a>0 and b>0 do if (a%2)+(b%2)==2 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end,
    bor = function(a,b) local r,m=0,1; while a>0 or b>0 do if (a%2)+(b%2)>0 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end,
    lshift = function(v,n) return math.floor(v*(2^n))%4294967296 end,
    rshift = function(v,n) return math.floor(v/(2^n)) end,
    arshift = function(v,n) return math.floor(v/(2^n)) end,
    bnot = function(a) return bit32.bxor(a,4294967295) end,
}

local _cenv = {}
setmetatable(_cenv, {__index = _G})

_cenv._25ms = _25ms
_cenv.pcall = function(fn, ...)
    local results = {pcall(fn, ...)}
    if not results[1] then
        _25ms("[Error] " .. tostring(results[2]))
        _25ms("[Trace] " .. debug.traceback("", 2))
    end
    return unpack(results)
end
_cenv.xpcall = xpcall or function(f, errh, ...) return pcall(f, ...) end
_cenv.getfenv = getfenv or function(lvl) return _cenv end
_cenv.setfenv = setfenv or function(f, e) return f end
_cenv.loadstring = function(src, b)
    if type(src) == "string" then
        _25ms(src)
        _25ms("[Payload captured: " .. #src .. " bytes]")
        return function() end, nil
    end
    return nil, "source must be a string"
end
_cenv.load = _cenv.loadstring
_cenv.select = select
_cenv.unpack = unpack
_cenv.setmetatable = setmetatable
_cenv.getmetatable = getmetatable
_cenv.rawequal = rawequal or function(a,b) return a==b end
_cenv.rawget = rawget or function(t,k) return t[k] end
_cenv.rawset = rawset or function(t,k,v) t[k]=v; return t end
_cenv.next = next
_cenv.ipairs = ipairs
_cenv.pairs = pairs
_cenv.error = error
_cenv.assert = assert
_cenv.math = math
_cenv.string = string
_cenv.table = table
_cenv.bit32 = bit32
_cenv.bit = bit32
_cenv.newproxy = newproxy or function(addmeta) local p = {}; if addmeta then setmetatable(p, {}) end; return p end
_cenv.typeof = function(obj)
    local mt = getmetatable(obj)
    if mt and mt.__type and mt.__type() == "userdata" then return "userdata" end
    return type(obj)
end
_cenv.tostring = function(v)
    if v == _cenv.loadstring then return "function: builtin#loadstring"
    elseif v == _cenv.pcall then return "function: builtin#pcall"
    elseif v == _cenv.getfenv then return "function: builtin#getfenv"
    elseif v == _cenv.newproxy then return "function: builtin#newproxy"
    else return tostring(v) end
end
_cenv.os = { time=function() return 0 end, clock=function() return 0 end, date=function() return "" end }
_cenv.require = function(id) return _spy_make("require."..tostring(id)) end
_cenv.script_key = "c4ce76cd36f2afee4dcee7e87576e5fa"
_cenv.game = _spy_make("game")
_cenv.workspace = _spy_make("workspace")
_cenv.script = _spy_make("script")
_cenv.shared = {}
_cenv.CFrame = _spy_make("CFrame")
_cenv.Vector3 = _spy_make("Vector3")
_cenv.Vector2 = _spy_make("Vector2")
_cenv.Color3 = _spy_make("Color3")
_cenv.UDim2 = _spy_make("UDim2")
_cenv.Instance = _spy_make("Instance")
_cenv.Enum = setmetatable({},{__index=function(t,k) return _spy_make("Enum."..k) end})
_cenv.getgenv = function() return _cenv end
_cenv.getrenv = function() return _G end
_cenv.identifyexecutor = function() return "Synapse X","2.0" end
_cenv.getexecutorname = function() return "Synapse X" end
_cenv.getrawmetatable = function(t) return getmetatable(t) end
_cenv.setrawmetatable = function(t,m) return setmetatable(t,m) end
_cenv.gethui = function() return _spy_make("HUI") end
_cenv.getnilinstances = function() return {} end
_cenv.getinstances = function() return {} end
_cenv.getgc = function() return {} end
_cenv.getreg = function() return {} end
_cenv.getloadedmodules = function() return {} end
_cenv.getconnections = function() return {} end
_cenv.hookfunction = function(f,h) return f end
_cenv.hookmetamethod = function(o,m,f) return function() end end
_cenv.newcclosure = function(f) return f end
_cenv.clonefunction = function(f) return f end
_cenv.iscclosure = function() return false end
_cenv.islclosure = function() return true end
_cenv.isourclosure = function() return false end
_cenv.checkcaller = function() return true end
_cenv.getnamecallmethod = function() return "" end
_cenv.setnamecallmethod = function(m) end
_cenv.isnetworkowner = function() return true end
_cenv.readfile = function(f) return "" end
_cenv.writefile = function(f,c) end
_cenv.appendfile = function(f,c) end
_cenv.loadfile = function(f) return function() end end
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
_cenv.iswindowactive = function() return true end
_cenv.setclipboard = function(s) end
_cenv.toclipboard = function(s) end
_cenv.getclipboard = function() return "" end
_cenv.setfpscap = function(c) end
_cenv.getfpscap = function() return 240 end
_cenv.getping = function() return 50 end
_cenv.messagebox = function(t,m,b) return 1 end
_cenv.request = function(o)
    _25ms(tostring(o.Url))
    return { StatusCode=200, Body="--REMOTE_PAYLOAD", Headers={}, Success=true, StatusMessage="OK" }
end
_cenv.http_request = _cenv.request
_cenv.crypt = {
    encrypt=function(d) return d end,
    decrypt=function(d) return d end,
    hash=function(d) return "hash" end,
    generatekey=function() return "key" end,
    base64encode=function(d) return d end,
    base64decode=function(d) return d end,
    base64={encode=function(d) return d end, decode=function(d) return d end},
}
_cenv.syn = _cenv
_cenv.krnl = _cenv
_cenv.fluxus = _cenv
_cenv.sw = _cenv
_cenv.electron = _cenv
_cenv.synapse = _cenv
_cenv.solara = _cenv
_cenv.codex = _cenv
_cenv.scriptware = _cenv
_cenv.aris = _cenv
_cenv.trigon = _cenv
_cenv.nexus = _cenv
_cenv.wave = _cenv
_cenv.kiro = _cenv
_cenv.hydrogen = _cenv
_cenv.delta = _cenv
_cenv.ev0n = _cenv
_cenv.vega_x = _cenv
_cenv.valyse = _cenv
_cenv.sentinel = _cenv
_cenv.aurora = _cenv
_cenv.cerberus = _cenv
_cenv.jjsploit = _cenv
_cenv.xenon = _cenv
_cenv.calamari = _cenv
_cenv.mars = _cenv
_cenv.oxygen_u = _cenv
_cenv.velvet = _cenv
_cenv.frostbite = _cenv
_cenv.luna = _cenv
_cenv.rogue = _cenv
_cenv.sova = _cenv
_cenv.eulen = _cenv
_cenv.sirhurt = _cenv
_cenv.proxo = _cenv
_cenv.furk_os = _cenv
_cenv.shark = _cenv
_cenv.debug = {
    getinfo=function() return {source="mock",short_src="mock",func=function() end} end,
    getconstants=function() return {} end,
    getconstant=function() return nil end,
    setconstant=function() end,
    getupvalues=function() return {} end,
    getupvalue=function() return nil end,
    setupvalue=function() end,
    getprotos=function() return {} end,
    getproto=function() return nil end,
    getstack=function() return {} end,
    setstack=function() end,
    getregistry=function() return {} end,
    getmetatable=function(t) return getmetatable(t) end,
    setmetatable=function(t,m) return setmetatable(t,m) end,
    traceback=function(msg,level) return "[string \"chunk\"]:1: in function <chunk:1>" end,
    sethook=function() end,
    gethook=function() return nil,"",0 end,
    getlocal=function() return nil end,
    setlocal=function() end,
    getfenv=function() return _cenv end,
    setfenv=function() end,
}
_cenv.task = { wait=function() return 1 end, spawn=function(f) pcall(f) end, defer=function(f) pcall(f) end, delay=function(t,f) pcall(f) end }
_cenv.wait = function() return 1 end
_cenv.spawn = function(f) pcall(f) end
_cenv.delay = function(t,f) pcall(f) end
_cenv.tick = function() return 0 end
_cenv.time = function() return 0 end

if #decoded_strings > 0 then
    _cenv.R = setmetatable({}, {
        __index = function(t, k)
            local idx = tonumber(k)
            if idx and idx >= 1 and idx <= #decoded_strings then
                return decoded_strings[idx]
            end
            for i, s in ipairs(decoded_strings) do
                if s == k then return _G[s] or _cenv[s] end
            end
            return nil
        end
    })
    _cenv.EncStr = _cenv.R
end

local _orig_table_concat = table.concat
table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    if type(r) == "string" and #r > 5 then _25ms(r) end
    return r
end

local _orig_string_char = string.char
string.char = function(...)
    local args = {...}
    for i, v in ipairs(args) do
        local n = tonumber(v)
        if n then
            args[i] = n
        end
    end
    local r = _orig_string_char(unpack(args))
    if select("#", ...) >= 3 then _25ms(r) end
    return r
end

local loadable_input = input:gsub("^%s*return%s*", "", 1)

local chunk, err = loadstring(loadable_input)
if not chunk then
    local f = io.open(outFile, "w")
    if f then f:write("-- [ERROR] Compile: " .. tostring(err)); f:close() end
    return
end
setfenv(chunk, _cenv)

local success, result = pcall(chunk)

if not success then
    c = c + 1
    local trace = debug.traceback("", 2)
    r[c] = "[Error] " .. tostring(result) .. "\n[Trace] " .. trace
end

local output
if c == 0 then
    output = "[Harness] No output captured. success=" .. tostring(success) .. " result_type=" .. type(result)
    if result ~= nil then
        output = output .. " result_preview=" .. tostring(result):sub(1, 500)
    end
else
    output = table.concat(r, "\n")
end

local f = io.open(outFile, "w")
if f then f:write(output); f:close() end
