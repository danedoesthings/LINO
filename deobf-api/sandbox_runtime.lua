local outdir = "OUTDIR_PLACEHOLDER"
local inpath = "INPATH_PLACEHOLDER"

local _proxy_mt = {
    __index = function(t, k)
        if type(k) == "number" then return 0 end
        local child = {}
        setmetatable(child, _proxy_mt)
        rawset(t, k, child)
        return child
    end,
    __newindex = function(t, k, v) rawset(t, k, v) end,
    __call = function(t, ...)
        local result = {}
        setmetatable(result, _proxy_mt)
        return result
    end,
    __add = function() return 0 end,
    __sub = function() return 0 end,
    __mul = function() return 0 end,
    __div = function() return 1 end,
    __mod = function() return 0 end,
    __pow = function() return 0 end,
    __unm = function() return 0 end,
    __concat = function(a, b) return tostring(a) .. tostring(b) end,
    __eq = function() return false end,
    __lt = function() return false end,
    __le = function() return false end,
    __tostring = function(t) return tostring(rawget(t, "_name") or "proxy") end,
    __len = function() return 0 end,
}

local function _new_proxy(name)
    local p = { _name = name or "proxy" }
    setmetatable(p, _proxy_mt)
    return p
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
rawset(_game, "GetService", function(self, name)
    local svc = _new_proxy("Service:" .. tostring(name))
    if name == "Players" then return _players_service end
    if name == "ReplicatedStorage" then return _new_proxy("ReplicatedStorage") end
    if name == "ServerStorage" then return _new_proxy("ServerStorage") end
    if name == "ServerScriptService" then return _new_proxy("ServerScriptService") end
    if name == "Workspace" then return _new_proxy("Workspace") end
    if name == "Lighting" then return _new_proxy("Lighting") end
    if name == "StarterGui" then return _new_proxy("StarterGui") end
    if name == "StarterPack" then return _new_proxy("StarterPack") end
    if name == "StarterPlayer" then return _new_proxy("StarterPlayer") end
    if name == "SoundService" then return _new_proxy("SoundService") end
    if name == "Chat" then return _new_proxy("Chat") end
    if name == "TeleportService" then return _new_proxy("TeleportService") end
    if name == "MarketplaceService" then return _new_proxy("MarketplaceService") end
    if name == "InsertService" then return _new_proxy("InsertService") end
    if name == "HttpService" then return _new_proxy("HttpService") end
    if name == "RunService" then return _new_proxy("RunService") end
    if name == "UserInputService" then return _new_proxy("UserInputService") end
    if name == "ContextActionService" then return _new_proxy("ContextActionService") end
    if name == "TweenService" then return _new_proxy("TweenService") end
    if name == "CollectionService" then return _new_proxy("CollectionService") end
    if name == "Debris" then return _new_proxy("Debris") end
    if name == "PhysicsService" then return _new_proxy("PhysicsService") end
    return svc
end)
rawset(_game, "Players", _players_service)
rawset(_game, "Workspace", _new_proxy("Workspace"))
rawset(_game, "ReplicatedStorage", _new_proxy("ReplicatedStorage"))
rawset(_game, "ServerStorage", _new_proxy("ServerStorage"))
rawset(_game, "ServerScriptService", _new_proxy("ServerScriptService"))
rawset(_game, "Lighting", _new_proxy("Lighting"))
rawset(_game, "StarterGui", _new_proxy("StarterGui"))
rawset(_game, "StarterPack", _new_proxy("StarterPack"))
rawset(_game, "StarterPlayer", _new_proxy("StarterPlayer"))
rawset(_game, "PlaceId", 1)
rawset(_game, "JobId", "00000000-0000-0000-0000-000000000000")
rawset(_game, "CreatorId", 0)
rawset(_game, "CreatorType", _new_proxy("CreatorType"))
rawset(_game, "IsLoaded", function() return true end)

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
        for i = 1, select("#", ...) do
            parts[i] = tostring(args[i])
        end
        local capfile = io.open(outdir .. "/cap.txt", "a")
        if capfile then
            capfile:write(table.concat(parts, "\t") .. "---SEP---")
            capfile:close()
        end
    end,
    warn = function(...)
        local capfile = io.open(outdir .. "/cap.txt", "a")
        if capfile then
            capfile:write(tostring(select(1, ...)) .. "---SEP---")
            capfile:close()
        end
    end,
    error = function(msg, level)
        local errfile = io.open(outdir .. "/error.txt", "w")
        if errfile then
            errfile:write(tostring(msg))
            errfile:close()
        end
        error(msg, level or 0)
    end,
    assert = function(v, msg)
        if not v then
            local errfile = io.open(outdir .. "/error.txt", "w")
            if errfile then
                errfile:write(tostring(msg or "assertion failed"))
                errfile:close()
            end
        end
        return v, msg
    end,
    pcall = function(f, ...)
        local results = { pcall(f, ...) }
        return unpack(results)
    end,
    xpcall = function(f, errhandler)
        return xpcall(f, errhandler)
    end,
    type = type,
    tostring = tostring,
    tonumber = tonumber,
    pairs = pairs,
    ipairs = ipairs,
    next = next,
    rawget = rawget,
    rawset = rawset,
    setmetatable = setmetatable,
    getmetatable = getmetatable,
    select = select,
    unpack = unpack,
    string = string,
    table = table,
    math = math,
    os = { time = function() return 0 end, clock = function() return 0 end, date = function() return "01/01/2000" end, difftime = function() return 0 end },
    coroutine = coroutine,
    bit32 = _new_proxy("bit32"),
    bit = _new_proxy("bit"),
    tick = function() return 0 end,
    time = function() return 0 end,
    wait = function() end,
    spawn = function(f) pcall(f) end,
    delay = function(t, f) pcall(f) end,
    task = { wait = function() end, spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end },
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
        return _new_proxy("require:" .. tostring(id))
    end,
}

local _env_mt = {
    __index = function(t, k)
        local v = _safe_globals[k]
        if v ~= nil then return v end
        if type(k) == "string" then
            return _new_proxy(k)
        end
        return nil
    end,
    __newindex = function(t, k, v)
        rawset(t, k, v)
    end,
}

setmetatable(_G, _env_mt)
local _capture_count = 0
local _orig_loadstring = loadstring

loadstring = function(chunk, chunkname)
    if chunk and type(chunk) == "string" and #chunk > 0 then
        _capture_count = _capture_count + 1
        local layer_path = outdir .. "/layer_" .. tostring(_capture_count) .. ".lua"
        local f = io.open(layer_path, "w")
        if f then
            f:write(chunk)
            f:close()
        end
        local dump_path = outdir .. "/dump.bin"
        local dumpf = io.open(dump_path, "wb")
        if dumpf then
            dumpf:write(chunk)
            dumpf:close()
        end
    end
    return function() end, nil
end

load = loadstring

-- Hook string.dump to capture bytecode produced by the script
local _orig_string_dump = string.dump
string.dump = function(func, strip)
    local bc = _orig_string_dump(func, strip)
    local dump_path = outdir .. "/dump.bin"
    local f = io.open(dump_path, "wb")
    if f then
        f:write(bc)
        f:close()
    end
    return bc
end

local function _scan_table(t, name, depth, visited)
    if depth > 10 then return end
    if visited[t] then return end
    visited[t] = true
    local memfile = io.open(outdir .. "/memory.txt", "a")
    if memfile then
        memfile:write(tostring(name) .. " = " .. tostring(t) .. "---MEMSEP---")
        memfile:close()
    end
    if type(t) == "table" then
        for k, v in pairs(t) do
            if type(v) == "string" and #v >= 12 then
                local bytes = {}
                for i = 1, #v do
                    bytes[i] = string.byte(v, i)
                end
                if bytes[1] == 27 and bytes[2] == 76 and bytes[3] == 117 and bytes[4] == 97 then
                    local sofile = io.open(outdir .. "/sandbox_output.lua", "w")
                    if sofile then
                        sofile:write("SANDBOX_OUTPUT_START")
                        for i = 1, #bytes do
                            sofile:write("\\" .. tostring(bytes[i]))
                        end
                        sofile:write("SANDBOX_OUTPUT_END")
                        sofile:close()
                    end
                end
            end
            if type(v) == "table" or type(v) == "function" then
                _scan_table(v, name .. "." .. tostring(k), depth + 1, visited)
            end
        end
    end
end

local diagfile = io.open(outdir .. "/diag.txt", "w")
if diagfile then
    diagfile:write("Sandbox starting...\n")
    diagfile:close()
end

setfenv(0, _G)

local function _run_input()
    local f, err = loadfile(inpath)
    if not f then
        local errfile = io.open(outdir .. "/error.txt", "w")
        if errfile then
            errfile:write("LOADFILE_ERROR: " .. tostring(err))
            errfile:close()
        end
        return
    end
    setfenv(f, _G)
    local ok, result = pcall(f)
    if not ok then
        local errfile = io.open(outdir .. "/error.txt", "w")
        if errfile then
            errfile:write("EXECUTION_ERROR: " .. tostring(result))
            errfile:close()
        end
    end
    local visited = {}
    _scan_table(_G, "_G", 0, visited)
    for k, v in pairs(_safe_globals) do
        if type(v) == "table" then
            _scan_table(v, k, 0, visited)
        end
    end
    local diagfile2 = io.open(outdir .. "/diag.txt", "a")
    if diagfile2 then
        diagfile2:write("Sandbox complete. Captures: " .. tostring(_capture_count) .. "\n")
        diagfile2:close()
    end
end

_run_input()
