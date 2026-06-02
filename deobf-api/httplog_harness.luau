local fs = require("@lune/fs")
local process = require("@lune/process")
local luau = require("@lune/luau")

local targetfilename = process.args[1]
local outpath = process.args[2] or "captured.lua"

if not fs.isFile(targetfilename) then
    error("Target file not found: " .. targetfilename)
end

local input = fs.readFile(targetfilename)

local r = {}
local c = 0

local function _25ms(var)
    local vartype = type(var)
    if vartype == "string" then
        c = c + 1
        r[c] = "[" .. vartype .. "]" .. var
    end
    return var
end

local function spy_tbl(pre, parent)
    return setmetatable({}, {
        __index = function(_, key)
            return spy_tbl(pre .. "." .. tostring(key), _)
        end,
        __newindex = function(_, key, value)
            _25ms(value)
        end,
        __call = function(_, ...)
            return spy_tbl(pre .. "(...)")
        end,
        __tostring = function() return pre end,
        __type = "userdata",
        __len = function() return 2853638 end,
    })
end

local cenv = {
    _25ms = _25ms,
    pcall = function(fn, ...)
        local results = {pcall(fn, ...)}
        if not results[1] then
            _25ms("[Error] " .. tostring(results[2]))
        end
        return unpack(results)
    end,
    getfenv = function(lvl)
        if lvl then
            local res = getfenv(lvl)
            if res.require ~= cenv.require then return cenv end
            return res
        end
        return cenv
    end,
    setfenv = function(f, e) return f end,
    loadstring = function(src, b)
        if type(src) == "string" then
            _25ms(src)
            local fn = luau.load(src, b)
            setfenv(fn, cenv)
            return fn
        elseif type(src) == "userdata" then
            return function(...)
                return spy_tbl("loadstring_result")
            end
        end
    end,
    load = function(src, b)
        if type(src) == "string" then
            _25ms(src)
            local fn = luau.load(src, b)
            setfenv(fn, cenv)
            return fn
        end
        return function() end
    end,
    game = spy_tbl("game"),
    workspace = spy_tbl("workspace"),
    script = spy_tbl("script"),
    shared = {},
    task = { wait = function() return 1 end, spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end },
    wait = function() return 1 end,
    spawn = function(f) pcall(f) end,
    delay = function(t, f) pcall(f) end,
    tick = function() return 0 end,
    time = function() return 0 end,
    os = { time = function() return 0 end, clock = function() return 0 end, date = function() return "" end },
    CFrame = spy_tbl("CFrame"),
    Vector3 = spy_tbl("Vector3"),
    Vector2 = spy_tbl("Vector2"),
    Color3 = spy_tbl("Color3"),
    UDim2 = spy_tbl("UDim2"),
    UDim = spy_tbl("UDim"),
    Instance = spy_tbl("Instance"),
    Enum = spy_tbl("Enum"),
    Drawing = spy_tbl("Drawing"),
    Ray = spy_tbl("Ray"),
    BrickColor = spy_tbl("BrickColor"),
    Region3 = spy_tbl("Region3"),
    TweenInfo = spy_tbl("TweenInfo"),
    getgenv = function() return cenv end,
    getrenv = function() return _G end,
    checkcaller = function() return true end,
    identifyexecutor = function() return "Synapse X", "2.0.0" end,
    getrawmetatable = function(t) return getmetatable(t) end,
    gethui = function() return spy_tbl("HUI") end,
    getnilinstances = function() return {} end,
    getinstances = function() return {} end,
    getgc = function() return {} end,
    getreg = function() return {} end,
    getloadedmodules = function() return {} end,
    getconnections = function() return {} end,
    firesignal = function() end,
    setreadonly = function() end,
    isreadonly = function() return false end,
    hookfunction = function(f, h) return f end,
    hookmetamethod = function(o, m, f) return function() end end,
    newcclosure = function(f) return f end,
    islclosure = function() return true end,
    iscclosure = function() return false end,
    getsynasset = function() return "content" end,
    request = function(o) return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} } end,
    http_request = function(o) return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} } end,
    readfile = function(f) return "" end,
    writefile = function(f, c) end,
    appendfile = function(f, c) end,
    isfile = function() return false end,
    isfolder = function() return false end,
    makefolder = function() end,
    delfolder = function() end,
    delfile = function() end,
    listfiles = function() return {} end,
    rconsoleprint = function() end,
    rconsoleinfo = function() end,
    rconsolewarn = function() end,
    rconsoleerr = function() end,
    rconsoleclear = function() end,
    rconsolename = function() end,
    mouse1click = function() end,
    mouse1press = function() end,
    mouse1release = function() end,
    keypress = function() end,
    keyrelease = function() end,
    mousemoveabs = function() end,
    mousemoverel = function() end,
    iswindowactive = function() return true end,
    setclipboard = function(s) end,
    toclipboard = function(s) end,
    crypt = {
        encrypt = function(d) return d end, decrypt = function(d) return d end,
        hash = function(d) return "hash" end, generatekey = function() return "key" end,
        base64encode = function(d) return d end, base64decode = function(d) return d end,
        base64 = { encode = function(d) return d end, decode = function(d) return d end },
        custom = { encrypt = function(d) return d end, decrypt = function(d) return d end },
    },
    syn = {
        request = function(o) return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} } end,
        crypt = {
            encrypt = function(d) return d end, decrypt = function(d) return d end,
            hash = function(d) return "hash" end, generatekey = function() return "key" end,
            base64encode = function(d) return d end, base64decode = function(d) return d end,
        },
        queue_on_teleport = function() end, protect_gui = function() end,
    },
    fluxus = {},
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
    },
    math = math,
    string = string,
    table = table,
    bit32 = rawget(_G, "bit32") or {
        bxor = function(a, b) local r, m = 0, 1; while a > 0 or b > 0 do if (a % 2) ~= (b % 2) then r = r + m end; a = math.floor(a / 2); b = math.floor(b / 2); m = m * 2 end; return r end,
        band = function(a, b) local r, m = 0, 1; while a > 0 and b > 0 do if (a % 2) + (b % 2) == 2 then r = r + m end; a = math.floor(a / 2); b = math.floor(b / 2); m = m * 2 end; return r end,
        bor = function(a, b) local r, m = 0, 1; while a > 0 or b > 0 do if (a % 2) + (b % 2) > 0 then r = r + m end; a = math.floor(a / 2); b = math.floor(b / 2); m = m * 2 end; return r end,
        lshift = function(v, n) return math.floor(v * (2 ^ n)) % 4294967296 end,
        rshift = function(v, n) return math.floor(v / (2 ^ n)) end,
        arshift = function(v, n) return math.floor(v / (2 ^ n)) end,
    },
    bit = rawget(_G, "bit") or rawget(_G, "bit32"),
    newproxy = newproxy or function(addmeta) local p = {}; if addmeta then setmetatable(p, {}) end; return p end,
    unpack = unpack or table.unpack,
    require = function(id)
        if id == "@lune/fs" then return fs end
        if id == "@lune/process" then return process end
        if id == "@lune/luau" then return luau end
        return spy_tbl("require." .. tostring(id))
    end,
}

cenv.script_key = "c4ce76cd36f2afee4dcee7e87576e5fa"

table.concat = function(t, sep, i, j)
    local r = table.concat(t, sep, i, j)
    if type(r) == "string" and #r > 5 then _25ms(r) end
    return r
end

string.char = function(...)
    local r = string.char(...)
    if select("#", ...) >= 3 then _25ms(r) end
    return r
end

local chunk, err = luau.load(input)
if err then
    fs.writeFile(outpath, "-- [ERROR] Compile: " .. err)
    return
end

setfenv(chunk, cenv)

local success, result = pcall(chunk)
if not success then
    c = c + 1
    r[c] = "[Error] " .. tostring(result)
end

local output = table.concat(r, "\n")
fs.writeFile(outpath, output)
