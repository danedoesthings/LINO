local outdir = "OUTDIR_PLACEHOLDER"
local inpath = "INPATH_PLACEHOLDER"
local varargs_embedded = VARARGS_PLACEHOLDER

local _real_io_open = io.open
local _real_tostring = tostring
local _real_debug_traceback = debug.traceback
local _real_xpcall = xpcall
local _real_setfenv = setfenv
local _real_getfenv = getfenv
local _real_loadfile = loadfile
local _real_pairs = pairs
local _real_ipairs = ipairs
local _real_type = type
local _real_select = select
local _real_unpack = unpack
local _real_rawget = rawget
local _real_rawset = rawset
local _real_setmetatable = setmetatable
local _real_getmetatable = getmetatable
local _real_next = next
local _real_table_concat = table.concat
local _real_string_byte = string.byte
local _real_math_floor = math.floor
local _real_math_random = math.random
local _real_math_randomseed = math.randomseed

local _real_G = _real_getfenv(0) or _G
_real_rawset(_real_G, "ipairs", _real_ipairs)
_real_rawset(_real_G, "pairs", _real_pairs)
_real_rawset(_real_G, "next", _real_next)
_real_rawset(_real_G, "tostring", _real_tostring)
_real_rawset(_real_G, "type", _real_type)
_real_rawset(_real_G, "unpack", _real_unpack)
_real_rawset(_real_G, "select", _real_select)
_real_rawset(_real_G, "setmetatable", _real_setmetatable)
_real_rawset(_real_G, "getmetatable", _real_getmetatable)
_real_rawset(_real_G, "rawget", _real_rawget)
_real_rawset(_real_G, "rawset", _real_rawset)
_real_rawset(_real_G, "pcall", pcall)
_real_rawset(_real_G, "xpcall", _real_xpcall)
_real_rawset(_real_G, "error", error)
_real_rawset(_real_G, "assert", assert)

local function _pure_bit32()
    local bit = {}
    function bit.bxor(a, b)
        local r, p = 0, 1
        while a > 0 or b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit ~= bbit then r = r + p end
            a, b, p = _real_math_floor(a/2), _real_math_floor(b/2), p * 2
        end
        return r
    end
    function bit.band(a, b)
        local r, p = 0, 1
        while a > 0 and b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit == 1 and bbit == 1 then r = r + p end
            a, b, p = _real_math_floor(a/2), _real_math_floor(b/2), p * 2
        end
        return r
    end
    function bit.bor(a, b)
        local r, p = 0, 1
        while a > 0 or b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit == 1 or bbit == 1 then r = r + p end
            a, b, p = _real_math_floor(a/2), _real_math_floor(b/2), p * 2
        end
        return r
    end
    function bit.bnot(a, bits)
        bits = bits or 32
        local r = 0
        for i = 0, bits-1 do
            if a % 2 == 0 then r = r + 2^i end
            a = _real_math_floor(a/2)
        end
        return r
    end
    function bit.lshift(a, n)
        return a * 2^n
    end
    function bit.rshift(a, n)
        return _real_math_floor(a / 2^n)
    end
    function bit.arshift(a, n)
        if a >= 0 then return _real_math_floor(a / 2^n)
        else return bit.bor(_real_math_floor(a / 2^n), bit.bnot(2^(32-n)-1)) end
    end
    function bit.rol(a, n)
        local bits = 32
        n = n % bits
        local left = bit.band(bit.lshift(a, n), 2^bits-1)
        local right = bit.rshift(a, bits-n)
        return bit.bor(left, right)
    end
    function bit.ror(a, n)
        local bits = 32
        n = n % bits
        local left = bit.lshift(bit.band(a, 2^n-1), bits-n)
        local right = bit.rshift(a, n)
        return bit.bor(left, right)
    end
    return bit
end

local bit32_real = _pure_bit32()
local bit_real   = bit32_real

local _proxy_mt = {
    __index = function(t, k)
        if _real_type(k) == "number" then return 0 end
        local child = {}
        _real_setmetatable(child, _proxy_mt)
        _real_rawset(t, k, child)
        return child
    end,
    __newindex = function(t, k, v) _real_rawset(t, k, v) end,
    __call = function(t, ...)
        local result = {}
        _real_setmetatable(result, _proxy_mt)
        return result
    end,
    __add = function() return 0 end,
    __sub = function() return 0 end,
    __mul = function() return 0 end,
    __div = function() return 1 end,
    __mod = function() return 0 end,
    __pow = function() return 0 end,
    __unm = function() return 0 end,
    __concat = function(a, b) return _real_tostring(a) .. _real_tostring(b) end,
    __eq = function() return false end,
    __lt = function() return false end,
    __le = function() return false end,
    __tostring = function(t) return _real_tostring(_real_rawget(t, "_name") or "proxy") end,
    __len = function() return 0 end,
}

local function _new_proxy(name)
    local p = { _name = name or "proxy" }
    _real_setmetatable(p, _proxy_mt)
    return p
end

local function newproxy(addmetatable)
    return _new_proxy("newproxy")
end

local _players_service = _new_proxy("Players")
local _local_player = {
    UserId = 1,
    Name = "Player",
    DisplayName = "Player",
    Character = _new_proxy("Character"),
    Backpack = _new_proxy("Backpack"),
    PlayerGui = _new_proxy("PlayerGui"),
    PlayerScripts = _new_proxy("PlayerScripts"),
    Team = nil,
    AccountAge = 365,
    MembershipType = _new_proxy("MembershipType"),
}
_players_service.LocalPlayer = _local_player
_players_service.GetPlayers = function() return { _local_player } end
_players_service.GetPlayerByUserId = function() return _local_player end

local _game = _new_proxy("game")
_real_rawset(_game, "GetService", function(self, name)
    local svc = _new_proxy("Service:" .. _real_tostring(name))
    if name == "Players" then return _players_service end
    if name == "ReplicatedStorage" then return _new_proxy("ReplicatedStorage") end
    if name == "ServerStorage" then return _new_proxy("ServerStorage") end
    if name == "ServerScriptService" then return _new_proxy("ServerScriptService") end
    if name == "Workspace" then return _new_proxy("Workspace") end
    if name == "Lighting" then return _new_proxy("Lighting") end
    if name == "StarterGui" then return _new_proxy("StarterGui") end
    if name == "StarterPack" then return _new_proxy("StarterPack") end
    if name == "StarterPlayer" then return _new_proxy("StarterPlayer") end
    return svc
end)
_real_rawset(_game, "Players", _players_service)
_real_rawset(_game, "Workspace", _new_proxy("Workspace"))
_real_rawset(_game, "ReplicatedStorage", _new_proxy("ReplicatedStorage"))
_real_rawset(_game, "ServerStorage", _new_proxy("ServerStorage"))
_real_rawset(_game, "ServerScriptService", _new_proxy("ServerScriptService"))
_real_rawset(_game, "Lighting", _new_proxy("Lighting"))
_real_rawset(_game, "StarterGui", _new_proxy("StarterGui"))
_real_rawset(_game, "StarterPack", _new_proxy("StarterPack"))
_real_rawset(_game, "StarterPlayer", _new_proxy("StarterPlayer"))
_real_rawset(_game, "PlaceId", 1)
_real_rawset(_game, "JobId", "00000000-0000-0000-0000-000000000000")
_real_rawset(_game, "CreatorId", 0)
_real_rawset(_game, "CreatorType", _new_proxy("CreatorType"))
_real_rawset(_game, "IsLoaded", function() return true end)

game = _game
workspace = _new_proxy("Workspace")
script = _new_proxy("script")
_G = {}

local _safe_globals = {
    game = _game,
    workspace = _new_proxy("Workspace"),
    script = _new_proxy("script"),
    shared = {},
    _G = {},
    _VERSION = "Lua 5.1",
    print = function(...)
        local args = {...}
        local parts = {}
        for i = 1, _real_select("#", ...) do
            parts[i] = _real_tostring(args[i])
        end
        local capfile = _real_io_open(outdir .. "/cap.txt", "a")
        if capfile then
            capfile:write(_real_table_concat(parts, "\t") .. "---SEP---")
            capfile:close()
        end
    end,
    warn = function(...)
        local capfile = _real_io_open(outdir .. "/cap.txt", "a")
        if capfile then
            capfile:write(_real_tostring(_real_select(1, ...)) .. "---SEP---")
            capfile:close()
        end
    end,
    error = function(msg, level)
        local errfile = _real_io_open(outdir .. "/error.txt", "w")
        if errfile then
            errfile:write(_real_tostring(msg))
            errfile:close()
        end
        error(msg, level or 0)
    end,
    assert = function(v, msg)
        if not v then
            local errfile = _real_io_open(outdir .. "/error.txt", "w")
            if errfile then
                errfile:write(_real_tostring(msg or "assertion failed"))
                errfile:close()
            end
        end
        return v, msg
    end,
    pcall = function(f, ...)
        local args = {...}
        local results = { pcall(f, _real_unpack(args)) }
        return _real_unpack(results)
    end,
    xpcall = function(f, errhandler, ...)
        local args = {...}
        return _real_xpcall(function() return f(_real_unpack(args)) end, errhandler)
    end,
    type = _real_type,
    tostring = _real_tostring,
    tonumber = tonumber,
    pairs = _real_pairs,
    ipairs = _real_ipairs,
    next = _real_next,
    rawget = _real_rawget,
    rawset = _real_rawset,
    setmetatable = _real_setmetatable,
    getmetatable = _real_getmetatable,
    select = _real_select,
    unpack = _real_unpack,
    string = string,
    table = table,
    math = math,
    io = { open = _real_io_open },
    os = { time = function() return 0 end, clock = function() return 0 end, date = function() return "01/01/2000" end, difftime = function() return 0 end },
    coroutine = coroutine,
    bit32 = bit32_real,
    bit = bit_real,
    tick = function() return 0 end,
    time = function() return 0 end,
    wait = function() end,
    spawn = function(f) pcall(f) end,
    delay = function(t, f) pcall(f) end,
    task = { wait = function() end, spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end },
    newproxy = newproxy,
    Instance = _new_proxy("Instance"),
    Vector3 = _new_proxy("Vector3"),
    Vector2 = _new_proxy("Vector2"),
    CFrame = _new_proxy("CFrame"),
    Color3 = _new_proxy("Color3"),
    BrickColor = _new_proxy("BrickColor"),
    UDim2 = _new_proxy("UDim2"),
    UDim = _new_proxy("UDim"),
    Ray = _new_proxy("Ray"),
    Region3 = _new_proxy("Region3"),
    TweenInfo = _new_proxy("TweenInfo"),
    NumberRange = _new_proxy("NumberRange"),
    NumberSequence = _new_proxy("NumberSequence"),
    NumberSequenceKeypoint = _new_proxy("NumberSequenceKeypoint"),
    ColorSequence = _new_proxy("ColorSequence"),
    ColorSequenceKeypoint = _new_proxy("ColorSequenceKeypoint"),
    Enum = _new_proxy("Enum"),
    Axes = _new_proxy("Axes"),
    Faces = _new_proxy("Faces"),
    Rect = _new_proxy("Rect"),
    PathWaypoint = _new_proxy("PathWaypoint"),
    PhysicalProperties = _new_proxy("PhysicalProperties"),
    Random = _new_proxy("Random"),
    RaycastParams = _new_proxy("RaycastParams"),
    CatalogSearchParams = _new_proxy("CatalogSearchParams"),
    DateTime = _new_proxy("DateTime"),
    DebuggerManager = _new_proxy("DebuggerManager"),
    DockWidgetPluginGuiInfo = _new_proxy("DockWidgetPluginGuiInfo"),
    OverlapParams = _new_proxy("OverlapParams"),
    plugin = _new_proxy("plugin"),
    stats = _new_proxy("stats"),
    settings = _new_proxy("settings"),
    UserSettings = _new_proxy("UserSettings"),
    require = function(id)
        return _new_proxy("require:" .. _real_tostring(id))
    end,
}

local _env_mt = {
    __index = function(t, k)
        local v = _safe_globals[k]
        if v ~= nil then return v end
        if _real_type(k) == "string" then
            return _new_proxy(k)
        end
        return nil
    end,
    __newindex = function(t, k, v)
        _real_rawset(t, k, v)
    end,
}

_real_setmetatable(_G, _env_mt)
_real_rawset(_G, "ipairs", _real_ipairs)
_real_rawset(_G, "pairs", _real_pairs)
_real_rawset(_G, "next", _real_next)
_real_rawset(_G, "tostring", _real_tostring)
_real_rawset(_G, "type", _real_type)
_real_rawset(_G, "unpack", _real_unpack)
_real_rawset(_G, "select", _real_select)
_real_rawset(_G, "setmetatable", _real_setmetatable)
_real_rawset(_G, "getmetatable", _real_getmetatable)
_real_rawset(_G, "rawget", _real_rawget)
_real_rawset(_G, "rawset", _real_rawset)
_real_rawset(_G, "pcall", pcall)
_real_rawset(_G, "xpcall", _real_xpcall)
_real_rawset(_G, "error", error)
_real_rawset(_G, "assert", assert)
_real_rawset(_G, "_G", _G)
_safe_globals._G = _G

local _capture_count = 0
local _orig_loadstring = loadstring

loadstring = function(chunk, chunkname)
    if chunk and _real_type(chunk) == "string" and #chunk > 0 then
        _capture_count = _capture_count + 1
        local layer_path = outdir .. "/layer_" .. _real_tostring(_capture_count) .. ".lua"
        local f = _real_io_open(layer_path, "w")
        if f then
            f:write(chunk)
            f:close()
        end
        local dump_path = outdir .. "/dump.bin"
        local dumpf = _real_io_open(dump_path, "wb")
        if dumpf then
            dumpf:write(chunk)
            dumpf:close()
        end
        local fn, compile_err = _orig_loadstring(chunk, chunkname)
        if fn then
            _real_setfenv(fn, _G)
            return fn, nil
        end
        return function() end, compile_err
    end
    return function() end, nil
end

load = loadstring
_real_rawset(_G, "loadstring", loadstring)
_real_rawset(_G, "load", load)

local _orig_string_dump = string.dump
string.dump = function(func, strip)
    local bc = _orig_string_dump(func, strip)
    local dump_path = outdir .. "/dump.bin"
    local f = _real_io_open(dump_path, "wb")
    if f then
        f:write(bc)
        f:close()
    end
    return bc
end

local diagfile = _real_io_open(outdir .. "/diag.txt", "w")
if diagfile then
    diagfile:write("Sandbox starting...\n")
    diagfile:close()
end

_real_setfenv(1, _G)

local function _error_handler(err)
    local msg = _real_tostring(err)
    local traceback_str = _real_debug_traceback(msg, 2)
    local errfile = _real_io_open(outdir .. "/error.txt", "w")
    if errfile then
        errfile:write(traceback_str)
        errfile:close()
    end
    return traceback_str
end

local function _run_input()
    local f, err = _real_loadfile(inpath)
    if not f then
        local errfile = _real_io_open(outdir .. "/error.txt", "w")
        if errfile then
            errfile:write("LOADFILE_ERROR: " .. _real_tostring(err))
            errfile:close()
        end
        return
    end
    _real_setfenv(f, _G)
    
    local args_table = nil
    if varargs_embedded ~= nil and _real_type(varargs_embedded) == "table" then
        args_table = varargs_embedded
    end
    
    local ok, result
    if args_table then
        local diagf = _real_io_open(outdir .. "/diag.txt", "a")
        if diagf then
            diagf:write("Args loaded: " .. _real_tostring(#args_table) .. " strings\n")
            diagf:write("Arg[1] preview: " .. _real_tostring(args_table[1] or "nil"):sub(1,40) .. "\n")
            diagf:close()
        end
        ok, result = _real_xpcall(function()
            local run_ok, run_result = pcall(f, _real_unpack(args_table))
            if not run_ok then
                local errfile = _real_io_open(outdir .. "/error.txt", "a")
                if errfile then
                    errfile:write("\nVM_CRASH: " .. _real_tostring(run_result))
                    errfile:close()
                end
            end
            return run_result
        end, _error_handler)
    else
        local diagf = _real_io_open(outdir .. "/diag.txt", "a")
        if diagf then
            diagf:write("Args not loaded, using proxy\n")
            diagf:close()
        end
        local proxy_arg = _real_setmetatable({}, { __index = function(t,k) if _real_type(k) == "number" then return "" else return _real_rawget(t,k) or "" end end })
        ok, result = _real_xpcall(function() return f(proxy_arg) end, _error_handler)
    end
    
    if not ok then
        local errfile = _real_io_open(outdir .. "/error.txt", "a")
        if errfile then
            errfile:write("\nEXECUTION_ERROR: " .. _real_tostring(result))
            errfile:close()
        end
    end
    local diagf = _real_io_open(outdir .. "/diag.txt", "a")
    if diagf then
        diagf:write("Sandbox complete. Captures: " .. _real_tostring(_capture_count) .. "\n")
        diagf:close()
    end
end

_run_input()
