import os, sys, re, subprocess, tempfile, shutil, traceback

LUA_BIN = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
APP_DIR = os.path.dirname(os.path.abspath(__file__))

def _lua_escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\0', '\\0')

RUNTIME = r'''local outdir = "{outdir}"
local inpath = "{inpath}"
local varargs_embedded = {varargs_table}

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
local _real_newproxy = newproxy

math.randomseed(0)

local function _pure_bit32()
    local bit = {{}}
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

local _proxy_mt = {{
    __index = function(t, k)
        if _real_type(k) == "number" then return 0 end
        local child = _new_userdata(k)
        _real_rawset(t, k, child)
        return child
    end,
    __newindex = function(t, k, v) _real_rawset(t, k, v) end,
    __call = function(t, ...)
        local result = _new_userdata("call_result")
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
}}

function _new_userdata(name)
    local ud = _real_newproxy(true)
    _real_rawset(ud, "_name", name or "ud")
    _real_setmetatable(ud, _proxy_mt)
    return ud
end

local _players_service = _new_userdata("Players")
local _local_player = {{
    UserId = 1,
    Name = "Player",
    DisplayName = "Player",
    Character = _new_userdata("Character"),
    Backpack = _new_userdata("Backpack"),
    PlayerGui = _new_userdata("PlayerGui"),
    PlayerScripts = _new_userdata("PlayerScripts"),
    Team = nil,
    AccountAge = 365,
    MembershipType = _new_userdata("MembershipType"),
}}
_players_service.LocalPlayer = _local_player
_players_service.GetPlayers = function() return {{ _local_player }} end
_players_service.GetPlayerByUserId = function() return _local_player end

local _game = _new_userdata("game")
_real_rawset(_game, "GetService", function(self, name)
    local svc = _new_userdata("Service:" .. _real_tostring(name))
    if name == "Players" then return _players_service end
    return svc
end)
_real_rawset(_game, "Players", _players_service)
_real_rawset(_game, "Workspace", _new_userdata("Workspace"))
_real_rawset(_game, "ReplicatedStorage", _new_userdata("ReplicatedStorage"))
_real_rawset(_game, "ServerStorage", _new_userdata("ServerStorage"))
_real_rawset(_game, "ServerScriptService", _new_userdata("ServerScriptService"))
_real_rawset(_game, "Lighting", _new_userdata("Lighting"))
_real_rawset(_game, "StarterGui", _new_userdata("StarterGui"))
_real_rawset(_game, "StarterPack", _new_userdata("StarterPack"))
_real_rawset(_game, "StarterPlayer", _new_userdata("StarterPlayer"))
_real_rawset(_game, "PlaceId", 1)
_real_rawset(_game, "JobId", "00000000-0000-0000-0000-000000000000")
_real_rawset(_game, "CreatorId", 0)
_real_rawset(_game, "CreatorType", _new_userdata("CreatorType"))
_real_rawset(_game, "IsLoaded", function() return true end)

game = _game
workspace = _new_userdata("Workspace")
script = _new_userdata("script")

local sandbox_env = {{
    game = _game,
    workspace = workspace,
    script = script,
    shared = {{}},
    _G = nil,
    _VERSION = "Lua 5.1",
    print = function(...)
        local args = {{...}}
        local parts = {{}}
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
    error = error,
    assert = assert,
    pcall = pcall,
    xpcall = _real_xpcall,
    type = _real_type,
    tostring = _real_tostring,
    tonumber = tonumber,
    pairs = _real_pairs,
    ipairs = _real_ipairs,
    next = _real_next,
    rawget = _real_rawget,
    rawset = _real_rawset,
    setmetatable = _real_setmetatable,
    getmetatable = function(t)
        if t == sandbox_env or t == _G then return nil end
        return _real_getmetatable(t)
    end,
    select = _real_select,
    unpack = _real_unpack,
    string = string,
    table = table,
    math = math,
    io = {{ open = _real_io_open }},
    os = {{ time = function() return 0 end, clock = function() return 0 end, date = function() return "01/01/2000" end, difftime = function() return 0 end }},
    coroutine = coroutine,
    bit32 = bit32_real,
    bit = bit_real,
    tick = function() return 0 end,
    time = function() return 0 end,
    wait = function() end,
    spawn = function(f) pcall(f) end,
    delay = function(t, f) pcall(f) end,
    task = {{ wait = function() end, spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end }},
    newproxy = _real_newproxy,
    getfenv = function()
        return sandbox_env
    end,
    setfenv = function(fn, env)
        return fn
    end,
    Instance = _new_userdata("Instance"),
    Vector3 = _new_userdata("Vector3"),
    Vector2 = _new_userdata("Vector2"),
    CFrame = _new_userdata("CFrame"),
    Color3 = _new_userdata("Color3"),
    BrickColor = _new_userdata("BrickColor"),
    UDim2 = _new_userdata("UDim2"),
    UDim = _new_userdata("UDim"),
    Ray = _new_userdata("Ray"),
    Region3 = _new_userdata("Region3"),
    TweenInfo = _new_userdata("TweenInfo"),
    NumberRange = _new_userdata("NumberRange"),
    NumberSequence = _new_userdata("NumberSequence"),
    NumberSequenceKeypoint = _new_userdata("NumberSequenceKeypoint"),
    ColorSequence = _new_userdata("ColorSequence"),
    ColorSequenceKeypoint = _new_userdata("ColorSequenceKeypoint"),
    Enum = _new_userdata("Enum"),
    Axes = _new_userdata("Axes"),
    Faces = _new_userdata("Faces"),
    Rect = _new_userdata("Rect"),
    PathWaypoint = _new_userdata("PathWaypoint"),
    PhysicalProperties = _new_userdata("PhysicalProperties"),
    Random = _new_userdata("Random"),
    RaycastParams = _new_userdata("RaycastParams"),
    CatalogSearchParams = _new_userdata("CatalogSearchParams"),
    DateTime = _new_userdata("DateTime"),
    DebuggerManager = _new_userdata("DebuggerManager"),
    DockWidgetPluginGuiInfo = _new_userdata("DockWidgetPluginGuiInfo"),
    OverlapParams = _new_userdata("OverlapParams"),
    plugin = _new_userdata("plugin"),
    stats = _new_userdata("stats"),
    settings = _new_userdata("settings"),
    UserSettings = _new_userdata("UserSettings"),
    require = function(id)
        return _new_userdata("require:" .. _real_tostring(id))
    end,
}}

sandbox_env._G = sandbox_env

debug = nil

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
            _real_setfenv(fn, sandbox_env)
            return fn, nil
        end
        return function() end, compile_err
    end
    return function() end, nil
end

load = loadstring
sandbox_env.loadstring = loadstring
sandbox_env.load = load

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

_real_setfenv(1, sandbox_env)

local function _error_handler(err)
    local msg = _real_tostring(err)
    local traceback_str = _real_debug_traceback(msg, 2)
    local errfile = _real_io_open(outdir .. "/error.txt", "a")
    if errfile then
        errfile:write("FULL_TRACEBACK:\n" .. traceback_str .. "\n")
        errfile:close()
    end
    return traceback_str
end

local function _run_input()
    local f, err = _real_loadfile(inpath)
    if not f then
        local errfile = _real_io_open(outdir .. "/error.txt", "a")
        if errfile then errfile:write("LOADFILE_ERROR: " .. _real_tostring(err) .. "\n"); errfile:close() end
        return
    end
    _real_setfenv(f, sandbox_env)

    if varargs_embedded == nil or _real_type(varargs_embedded) ~= "table" then
        varargs_embedded = {{}}
    end

    local diagf = _real_io_open(outdir .. "/diag.txt", "a")
    if diagf then diagf:write("Varargs: " .. _real_tostring(#varargs_embedded) .. " strings\n"); diagf:close() end

    local chunk_ok, vmFunc = pcall(f, varargs_embedded)
    if not chunk_ok then
        local errfile = _real_io_open(outdir .. "/error.txt", "a")
        if errfile then errfile:write("CHUNK_CRASH: " .. _real_tostring(vmFunc) .. "\n"); errfile:close() end
        return
    end

    if _real_type(vmFunc) ~= "function" then
        local rvf = _real_io_open(outdir .. "/diag.txt", "a")
        if rvf then rvf:write("Chunk returned non-function (type=" .. _real_type(vmFunc) .. ")\n"); rvf:close() end
        return
    end

    local diagf2 = _real_io_open(outdir .. "/diag.txt", "a")
    if diagf2 then diagf2:write("Calling VM with args...\n"); diagf2:close() end

    local ok, result = _real_xpcall(function()
        local run_ok, run_result = pcall(vmFunc,
            sandbox_env,
            _real_unpack,
            _real_newproxy,
            _real_setmetatable,
            _real_getmetatable,
            _real_select,
            varargs_embedded
        )
        if not run_ok then
            local errfile = _real_io_open(outdir .. "/error.txt", "a")
            if errfile then errfile:write("VM_CRASH: " .. _real_tostring(run_result) .. "\n"); errfile:close() end
        end
        return run_result
    end, _error_handler)

    if not ok then
        local errfile = _real_io_open(outdir .. "/error.txt", "a")
        if errfile then errfile:write("EXECUTION_ERROR: " .. _real_tostring(result) .. "\n"); errfile:close() end
    end
    local diagf3 = _real_io_open(outdir .. "/diag.txt", "a")
    if diagf3 then diagf3:write("Sandbox complete. Captures: " .. _real_tostring(_capture_count) .. "\n"); diagf3:close() end
end

_run_input()
'''

def execute_sandbox(source, timeout=120, varargs=None):
    error_log, layers, caps, diag = [], [], [], ''
    try:
        temp_dir = tempfile.mkdtemp()
    except Exception as e:
        return [], [], f'TEMP_DIR_ERROR: {e}'
    try:
        inp = os.path.join(temp_dir, 'input.lua')
        drv = os.path.join(temp_dir, 'driver.lua')
        out_dir = temp_dir.replace('\\', '/')
        inp_path = inp.replace('\\', '/')

        with open(inp, 'wb') as f:
            f.write(source.encode('utf-8', errors='replace'))

        if varargs and isinstance(varargs, list) and len(varargs) > 0:
            parts = ['"' + _lua_escape(s) + '"' for s in varargs]
            table_literal = '{' + ','.join(parts) + '}'
        else:
            table_literal = '{}'

        driver = RUNTIME.replace('{outdir}', out_dir).replace('{inpath}', inp_path).replace('{varargs_table}', table_literal)

        with open(drv, 'w', encoding='utf-8') as f:
            f.write(driver)

        env = os.environ.copy()
        env['LUA_PATH'] = os.path.join(APP_DIR, '?.lua') + ';' + env.get('LUA_PATH', '')
        env['LUA_CPATH'] = os.path.join(APP_DIR, '?.so') + ';' + env.get('LUA_CPATH', '')

        proc_error = ''
        stdout_output = ''
        stderr_output = ''
        try:
            result = subprocess.run(
                [LUA_BIN, drv],
                capture_output=True, text=True, timeout=timeout, cwd=temp_dir, env=env
            )
            stdout_output = result.stdout
            stderr_output = result.stderr
            if result.returncode != 0:
                proc_error = f'LUA_EXIT_{result.returncode}: {stderr_output[:400]}'
        except subprocess.TimeoutExpired:
            proc_error = f'TIMEOUT_EXPIRED ({timeout}s)'
        except FileNotFoundError:
            proc_error = f'LUA_NOT_FOUND: {LUA_BIN}'
        except Exception as e:
            proc_error = f'SUBPROCESS_ERROR: {e}'
        if proc_error:
            error_log.append(proc_error)
        if stdout_output.strip():
            error_log.append(f'STDOUT: {stdout_output.strip()[:500]}')
        if stderr_output.strip():
            error_log.append(f'STDERR: {stderr_output.strip()[:500]}')

        i = 1
        while True:
            p = os.path.join(temp_dir, f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            try:
                with open(p, encoding='utf-8', errors='replace') as f:
                    data = f.read()
                if data:
                    layers.append(data)
            except Exception as e:
                error_log.append(f'READ_LAYER_{i}_ERROR: {e}')
            i += 1

        for extra in ('dump.bin', 'return_value.lua'):
            extra_path = os.path.join(temp_dir, extra)
            if os.path.exists(extra_path):
                try:
                    with open(extra_path, 'rb') as f:
                        data = f.read()
                    if data and len(data) >= 12:
                        layers.append(data)
                except Exception as e:
                    error_log.append(f'READ_{extra}_ERROR: {e}')

        for fname in ('cap.txt', 'memory.txt'):
            fp = os.path.join(temp_dir, fname)
            if os.path.exists(fp):
                try:
                    with open(fp, encoding='utf-8', errors='replace') as f:
                        data = f.read()
                    if data:
                        parts = data.split('---SEP---') if fname == 'cap.txt' else data.split('---MEMSEP---')
                        caps.extend([p.strip() for p in parts if len(p.strip()) > 5])
                except Exception as e:
                    error_log.append(f'READ_{fname}_ERROR: {e}')

        diag_parts = []
        for fname in ('diag.txt', 'error.txt'):
            fp = os.path.join(temp_dir, fname)
            if os.path.exists(fp):
                try:
                    with open(fp, encoding='utf-8', errors='replace') as f:
                        txt = f.read()
                    if txt:
                        diag_parts.append(f"[{fname}]\n{txt.strip()}")
                except Exception:
                    pass
        if diag_parts:
            diag = '\n'.join(diag_parts)
        if error_log:
            prefix = '\n'.join(error_log)
            diag = prefix + ('\n---\n' + diag if diag else '')
        if not layers and not caps and not diag:
            diag = 'NO_OUTPUT'
        if not proc_error and not layers:
            diag = (diag or '') + '\nNo layers captured'
    except Exception as e:
        diag = f'SANDBOX_FATAL: {e}\n{traceback.format_exc()}'
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    return layers, caps, diag
