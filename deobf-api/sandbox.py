import os, sys, re, subprocess, tempfile, shutil, traceback

LUA_BIN = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
APP_DIR = os.path.dirname(os.path.abspath(__file__))

RUNTIME_TEMPLATE = r"""local outdir = "{outdir}"
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
        local child = {{}}
        _real_setmetatable(child, _proxy_mt)
        _real_rawset(t, k, child)
        return child
    end,
    __newindex = function(t, k, v) _real_rawset(t, k, v) end,
    __call = function(t, ...)
        local result = {{}}
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
}}

local function _new_proxy(name)
    local p = {{ _name = name or "proxy" }}
    _real_setmetatable(p, _proxy_mt)
    return p
end

local function newproxy(addmetatable)
    return _new_proxy("newproxy")
end

-- Rest of the mock environment (Players, game, etc.) omitted for brevity – use the same as before.

local function _run_input()
    local f, err = _real_loadfile(inpath)
    if not f then
        local errfile = _real_io_open(outdir .. "/error.txt", "a")
        if errfile then errfile:write("LOADFILE_ERROR: " .. _real_tostring(err) .. "\n"); errfile:close() end
        return
    end
    _real_setfenv(f, _G)

    if varargs_embedded == nil or _real_type(varargs_embedded) ~= "table" then
        varargs_embedded = {{}}
    end

    local diagf = _real_io_open(outdir .. "/diag.txt", "a")
    if diagf then diagf:write("Calling chunk with 7 args...\n"); diagf:close() end

    local chunk_ok, vmFunc = pcall(f,
        _real_getfenv(0) or _G,
        _real_unpack,
        newproxy,
        _real_setmetatable,
        _real_getmetatable,
        _real_select,
        varargs_embedded
    )
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
            _real_getfenv(0) or _G,
            _real_unpack,
            newproxy,
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
"""

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

        # Build varargs table literal with proper escaping
        if varargs and isinstance(varargs, list) and len(varargs) > 0:
            parts = ['"' + s + '"' for s in varargs]
            table_literal = '{' + ','.join(parts) + '}'
        else:
            table_literal = '{}'
        # Escape braces for Python format
        table_literal_escaped = table_literal.replace('{', '{{').replace('}', '}}')

        driver = RUNTIME_TEMPLATE.format(outdir=out_dir, inpath=inp_path, varargs_table=table_literal_escaped)

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

        # Collect layers (loadstring captures)
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

        # Collect dump.bin and return_value.lua
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

        # Caps from cap.txt and memory.txt
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

        # Combine diag.txt and error.txt
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
