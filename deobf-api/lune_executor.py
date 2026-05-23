import asyncio, os, tempfile, hashlib

EXECUTION_TIMEOUT = 15
LUNE_BIN = os.environ.get("LUNE_BIN", "lune")

_BIT32_FALLBACK = """
local function _pure_bit32()
    local bit = {}
    function bit.bxor(a, b)
        local r, p = 0, 1
        while a > 0 or b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit ~= bbit then r = r + p end
            a, b, p = math.floor(a/2), math.floor(b/2), p * 2
        end
        return r
    end
    function bit.band(a, b)
        local r, p = 0, 1
        while a > 0 and b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit == 1 and bbit == 1 then r = r + p end
            a, b, p = math.floor(a/2), math.floor(b/2), p * 2
        end
        return r
    end
    function bit.bor(a, b)
        local r, p = 0, 1
        while a > 0 or b > 0 do
            local abit, bbit = a % 2, b % 2
            if abit == 1 or bbit == 1 then r = r + p end
            a, b, p = math.floor(a/2), math.floor(b/2), p * 2
        end
        return r
    end
    function bit.bnot(a, bits)
        bits = bits or 32
        local r = 0
        for i = 0, bits-1 do
            if a % 2 == 0 then r = r + 2^i end
            a = math.floor(a/2)
        end
        return r
    end
    function bit.lshift(a, n)
        return a * 2^n
    end
    function bit.rshift(a, n)
        return math.floor(a / 2^n)
    end
    function bit.arshift(a, n)
        if a >= 0 then return math.floor(a / 2^n)
        else return bit.bor(math.floor(a / 2^n), bit.bnot(2^(32-n)-1)) end
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
if not bit32 then bit32 = _pure_bit32() end
if not bit then bit = _pure_bit32() end
"""

_SHIM_PART1 = r"""
local function make_proxy(name)
    local proxy = setmetatable({}, {
        __index    = function(t, k)
            if type(k) == "number" then return 0 end
            return make_proxy(tostring(name) .. "." .. tostring(k))
        end,
        __newindex = function() end,
        __call     = function(t, ...) return make_proxy(tostring(name) .. "()") end,
        __tostring = function() return tostring(name) end,
        __len      = function() return 0 end,
        __add      = function() return 0 end,
        __sub      = function() return 0 end,
        __mul      = function() return 0 end,
        __div      = function() return 0 end,
        __mod      = function() return 0 end,
        __unm      = function() return 0 end,
        __concat   = function(a, b) return tostring(a) .. tostring(b) end,
        __lt       = function() return false end,
        __le       = function() return false end,
        __eq       = function() return false end,
    })
    return proxy
end

""" + _BIT32_FALLBACK + r"""

local _player = {
    UserId = 1, Name = "Player", DisplayName = "Player",
    AccountAge = 100,
    MembershipType = make_proxy("MembershipType"),
    Character = make_proxy("Character"),
    Backpack = make_proxy("Backpack"),
    PlayerGui = make_proxy("PlayerGui"),
    PlayerScripts = make_proxy("PlayerScripts"),
}
local _game = make_proxy("game")
rawset(_game, "GetService",   function(self, svc) return make_proxy("game:" .. svc) end)
rawset(_game, "Players",      { LocalPlayer = _player, GetPlayers = function() return {_player} end })
rawset(_game, "HttpGet",      function() return "" end)
rawset(_game, "HttpGetAsync", function() return "" end)
rawset(_game, "PlaceId",      1)
rawset(_game, "JobId",        "00000000-0000-0000-0000-000000000000")
rawset(_game, "Workspace",    make_proxy("Workspace"))
rawset(_game, "ReplicatedStorage", make_proxy("ReplicatedStorage"))
rawset(_game, "ServerStorage", make_proxy("ServerStorage"))
rawset(_game, "ServerScriptService", make_proxy("ServerScriptService"))
rawset(_game, "Lighting", make_proxy("Lighting"))
rawset(_game, "StarterGui", make_proxy("StarterGui"))
rawset(_game, "StarterPack", make_proxy("StarterPack"))
rawset(_game, "StarterPlayer", make_proxy("StarterPlayer"))

game      = _game
workspace = make_proxy("workspace")
script    = make_proxy("script")
shared    = {}
_G        = {}

setmetatable(_G, {
    __index    = function(t, k)
        io.write("STUB_GLOBAL: " .. tostring(k) .. "\n")
        return make_proxy(k)
    end,
    __newindex = function() end,
})

local _services = {
    "Players", "ReplicatedStorage", "ServerStorage", "ServerScriptService",
    "Workspace", "Lighting", "StarterGui", "StarterPack", "StarterPlayer",
    "SoundService", "Chat", "TeleportService", "MarketplaceService",
    "InsertService", "HttpService", "RunService", "UserInputService",
    "ContextActionService", "TweenService", "CollectionService", "Debris",
    "PhysicsService", "SocialService", "BadgeService", "GroupService",
    "PolicyService", "AnalyticsService", "AvatarEditorService",
    "DataStoreService", "MessagingService", "PathfindingService",
    "PointsService", "ScriptContext", "TextService", "TouchInputService",
    "VRService", "GamepadService", "GuiService", "HapticService",
    "LocalizationService", "LogService", "MemoryStoreService",
}
for _, svc_name in ipairs(_services) do
    _G[svc_name] = make_proxy(svc_name)
end

task   = { wait = function() end, spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end }
wait   = function() end
spawn  = function(f) pcall(f) end
delay  = function(t, f) pcall(f) end
tick   = function() return 0 end
time   = function() return 0 end
os     = { time = function() return 0 end, clock = function() return 0 end, date = function() return "" end }

local _captured = false
local _outpath  = """

_SHIM_PART2 = r"""

local _orig_loadstring = loadstring
loadstring = function(chunk, chunkname)
    if not _captured and chunk and #chunk > 0 then
        _captured = true
        io.write("CAPTURE_SUCCESS: " .. #chunk .. " bytes\n")
        local f = io.open(_outpath, "wb")
        if f then f:write(chunk); f:close() end
    end
    return function() end, nil
end
load = loadstring

local ok, err = pcall(function()
"""

_SHIM_PART3 = r"""
end)

if not ok then
    io.write("RUNTIME_ERROR: " .. tostring(err) .. "\n")
end
if not _captured then
    io.write("CAPTURE_FAILED: loadstring was never called\n")
end
"""

async def execute_and_capture(lua_source):
    info = {"stub_globals": [], "runtime_error": None, "capture_success": False}
    with tempfile.TemporaryDirectory() as tmpdir:
        tag = hashlib.md5(lua_source.encode(errors="replace")).hexdigest()[:8]
        script_path = os.path.join(tmpdir, f"input_{tag}.luau")
        output_path = os.path.join(tmpdir, f"captured_{tag}.luac")
        indented = "\n".join("    " + line for line in lua_source.splitlines())
        shim = _SHIM_PART1 + repr(output_path) + _SHIM_PART2 + indented + _SHIM_PART3
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(shim)
        try:
            proc = await asyncio.create_subprocess_exec(
                LUNE_BIN, "run", script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=EXECUTION_TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return None, {"error": "timeout"}
        except FileNotFoundError:
            return None, {"error": "lune_not_found"}
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith("STUB_GLOBAL: "):
                info["stub_globals"].append(line[len("STUB_GLOBAL: "):])
            elif line.startswith("RUNTIME_ERROR: "):
                info["runtime_error"] = line[len("RUNTIME_ERROR: "):]
            elif line.startswith("CAPTURE_SUCCESS: "):
                info["capture_success"] = True
        if os.path.isfile(output_path):
            with open(output_path, "rb") as f:
                data = f.read()
            return data, info
        return None, info
