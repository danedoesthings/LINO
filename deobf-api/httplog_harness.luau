local fs = require("@lune/fs")
local process = require("@lune/process")
local luau = require("@lune/luau")
local net = require("@lune/net")

local targetFile = process.args[1]
local outFile = process.args[2] or "captured.lua"
local logFile = process.args[3] or "harness_log.txt"

if not fs.isFile(targetFile) then
    error("Target file not found: " .. targetFile)
end

local input = fs.readFile(targetFile)

local _log = {}
local function log(msg)
    table.insert(_log, msg)
end

local r = {}
local c = 0

local function _25ms(var)
    local vartype = type(var)
    if vartype == "string" then
        c = c + 1
        r[c] = "[" .. vartype .. "]" .. var
        log("[25ms][" .. c .. "] " .. var:sub(1, 150))
    end
    return var
end

local function spy_tbl(pre, parent)
    return setmetatable({
        __25mslocation = pre,
    }, {
        __index = function(_, key)
            return spy_tbl(pre .. "." .. tostring(key), _)
        end,
        __newindex = function(_, key, value)
            log("[SPY][" .. pre .. "." .. tostring(key) .. "] = " .. tostring(value):sub(1, 200))
            _25ms(value)
        end,
        __call = function(_, ...)
            local args = {...}
            local arg_strs = {}
            for i, v in ipairs(args) do
                arg_strs[i] = tostring(v):sub(1, 100)
                _25ms(v)
            end
            log("[CALL][" .. pre .. "](" .. table.concat(arg_strs, ", ") .. ")")
            return spy_tbl(pre .. "(...)")
        end,
        __tostring = function() return pre end,
        __type = "userdata",
        __len = function() return 2853638 end,
    })
end

local env = {
    game = spy_tbl("game"),
    workspace = spy_tbl("workspace"),
    script = spy_tbl("script"),
    shared = {},
    task = {
        wait = function() return 1 end,
        spawn = function(f) pcall(f) end,
        defer = function(f) pcall(f) end,
    },
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
    getgenv = function() return env end,
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
    request = function(o)
        log("[REQUEST] " .. (o.Url or "?"))
        return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} }
    end,
    http_request = function(o)
        log("[HTTP_REQUEST] " .. (o.Url or "?"))
        return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} }
    end,
    readfile = function(f) log("[READFILE] " .. f); return "" end,
    writefile = function(f, c) log("[WRITEFILE] " .. f) end,
    appendfile = function(f, c) log("[APPENDFILE] " .. f) end,
    isfile = function() return false end,
    isfolder = function() return false end,
    makefolder = function() end,
    delfolder = function() end,
    delfile = function() end,
    listfiles = function() return {} end,
    rconsoleprint = function(...) log("[RCONSOLE] " .. table.concat({...}, "\t")) end,
    rconsoleinfo = function(...) log("[RCONSOLE] " .. table.concat({...}, "\t")) end,
    rconsolewarn = function(...) log("[RCONSOLE] " .. table.concat({...}, "\t")) end,
    rconsoleerr = function(...) log("[RCONSOLE] " .. table.concat({...}, "\t")) end,
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
    setclipboard = function(s) log("[SETCLIPBOARD] " .. s:sub(1, 100)) end,
    toclipboard = function(s) log("[TOCLIPBOARD] " .. s:sub(1, 100)) end,
    crypt = {
        encrypt = function(d) return d end,
        decrypt = function(d) return d end,
        hash = function(d) return "hash" end,
        generatekey = function() return "key" end,
        base64encode = function(d) return d end,
        base64decode = function(d) return d end,
        base64 = { encode = function(d) return d end, decode = function(d) return d end },
        custom = { encrypt = function(d) return d end, decrypt = function(d) return d end },
    },
    syn = {
        request = function(o)
            log("[SYN.REQUEST] " .. (o.Url or "?"))
            return { StatusCode = 200, Body = "--REMOTE_PAYLOAD", Headers = {} }
        end,
        crypt = {
            encrypt = function(d) return d end,
            decrypt = function(d) return d end,
            hash = function(d) return "hash" end,
            generatekey = function() return "key" end,
            base64encode = function(d) return d end,
            base64decode = function(d) return d end,
            base64 = { encode = function(d) return d end, decode = function(d) return d end },
            custom = { encrypt = function(d) return d end, decrypt = function(d) return d end },
        },
        queue_on_teleport = function() end,
        protect_gui = function() end,
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
        bxor = function(a, b) return a ~ b end,
        band = function(a, b) return a & b end,
        bor = function(a, b) return a | b end,
        lshift = function(v, n) return (v << n) & 0xFFFFFFFF end,
        rshift = function(v, n) return v >> n end,
        arshift = function(v, n) return v >> n end,
    },
    bit = rawget(_G, "bit") or rawget(_G, "bit32"),
    newproxy = newproxy or function(addmeta)
        local p = {}
        if addmeta then setmetatable(p, {}) end
        return p
    end,
    unpack = unpack or table.unpack,
    getfenv = getfenv or function() return env end,
    setfenv = setfenv or function(f, e) return f end,
    require = function(id)
        log("[REQUIRE] " .. tostring(id))
        if id == "@lune/fs" then return fs end
        if id == "@lune/process" then return process end
        if id == "@lune/luau" then return luau end
        return setmetatable({}, {
            __index = function() return function() end end,
            __call = function() return nil end
        })
    end,
}

env.script_key = "c4ce76cd36f2afee4dcee7e87576e5fa"

local wrapped_loadstring = function(src, b)
    if type(src) == "string" then
        log("[LOADSTRING] len=" .. #src)
        log("[LOADSTRING] " .. src:sub(1, 500))
        table.insert(r, "[loadstring]" .. src)
    end
    return luau.load(src, b)
end
env.loadstring = wrapped_loadstring
env.load = wrapped_loadstring

env.pcall = function(fn, ...)
    log("[PCALL]")
    local results = { pcall(fn, ...) }
    if not results[1] then
        log("[PCALL_ERROR] " .. tostring(results[2]))
    end
    return unpack(results)
end

env._25ms = _25ms

env.type = function(obj)
    local mt = getmetatable(obj)
    if mt and mt.__type then return mt.__type() end
    return type(obj)
end

_G.print = function(...)
    local args = {...}
    local parts = {}
    for i = 1, select("#", ...) do
        parts[i] = tostring(select(i, ...))
    end
    log("[PRINT] " .. table.concat(parts, "\t"))
end

_G.warn = function(...)
    local args = {...}
    local parts = {}
    for i = 1, select("#", ...) do
        parts[i] = tostring(select(i, ...))
    end
    log("[WARN] " .. table.concat(parts, "\t"))
end

local function _real_concat(t, sep, i, j)
    local r = table.concat(t, sep, i, j)
    if type(r) == "string" and #r > 10 then
        log("[TABLE.CONCAT] len=" .. #r .. " first=" .. r:sub(1, 150))
        _25ms(r)
    end
    return r
end

local function _real_char(...)
    local r = string.char(...)
    if select("#", ...) >= 3 and #r > 0 then
        log("[STRING.CHAR] args=" .. select("#", ...) .. " result=" .. r:sub(1, 100))
        _25ms(r)
    end
    return r
end

local _real_gsub = string.gsub
string.gsub = function(s, p, r, n)
    local res = _real_gsub(s, p, r, n)
    if type(res) == "string" and #res > 50 then
        log("[STRING.GSUB] len=" .. #res .. " first=" .. res:sub(1, 100))
        _25ms(res)
    end
    return res
end

local _real_sub = string.sub
string.sub = function(s, i, j)
    local res = _real_sub(s, i, j)
    if type(res) == "string" and #res > 50 then
        log("[STRING.SUB] len=" .. #res .. " first=" .. res:sub(1, 100))
        _25ms(res)
    end
    return res
end

string.char = _real_char
table.concat = _real_concat

log("Starting execution of " .. targetFile)

local chunk, err = luau.load(input)
if err then
    log("[COMPILE_ERROR] " .. err)
    error("Compile error: " .. err)
end

setfenv(chunk, env)

local success, result = pcall(chunk)
if not success then
    log("[RUNTIME_ERROR] " .. tostring(result))
end

log("Execution finished, success=" .. tostring(success))
log("Strings captured: " .. c)

local output = table.concat(r, "\n")
fs.writeFile(outFile, output)
fs.writeFile(logFile, table.concat(_log, "\n"))

print("Done. " .. c .. " strings captured.")
