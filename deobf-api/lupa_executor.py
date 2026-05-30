import base64, re, os, subprocess, tempfile, signal, traceback
from typing import Optional, List, Tuple

try:
    import lupa
    HAS_LUPA = True
except ImportError:
    HAS_LUPA = False


PRINT_CAPTURE_LUA = r"""
local captured = {}
local real_print = print

local bit32 = rawget(_G, "bit32")
if not bit32 then
    local function bxor(a,b) local r,m=0,1; while a>0 or b>0 do local ab,bb=a%2,b%2; if ab~=bb then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    local function band(a,b) local r,m=0,1; while a>0 and b>0 do if a%2+b%2==2 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    local function bor(a,b) local r,m=0,1; while a>0 or b>0 do if a%2+b%2>0 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    bit32 = {
        bxor = bxor,
        band = band,
        bor  = bor,
        lshift = function(v,n) return math.floor(v*(2^n))%4294967296 end,
        rshift = function(v,n) return math.floor(v/(2^n)) end,
        arshift = function(v,n) return math.floor(v/(2^n)) end
    }
end
_G.bit32 = bit32
_G.bit   = bit32

if not getfenv then
    getfenv = function(f) return _G end
end
if not setfenv then
    setfenv = function(f, t) return f end
end

os.execute = function() error("os.execute blocked") end
io.popen   = function() error("io.popen blocked") end

_G.print = function(...)
    local parts = {}
    for i = 1, select('#', ...) do
        parts[i] = tostring(select(i, ...))
    end
    table.insert(captured, table.concat(parts, "\t"))
end

if warn then
    _G.warn = function(...)
        local parts = {}
        for i = 1, select('#', ...) do
            parts[i] = tostring(select(i, ...))
        end
        table.insert(captured, "WARN: " .. table.concat(parts, "\t"))
    end
end

local f, err = loadfile("_SRCFILE_")
if not f then
    table.insert(captured, "ERR:COMPILE:" .. tostring(err))
else
    local ok, result = pcall(f)
    if not ok then
        table.insert(captured, "ERR:RUNTIME:" .. tostring(result))
    end
end

real_print("___CAPTURED_PRINT_START___")
for _, line in ipairs(captured) do
    real_print(line)
end
real_print("___CAPTURED_PRINT_END___")
"""


def _capture_via_subprocess(source, timeout=45):
    src_path = None
    harness_path = None
    try:
        src_fd, src_path = tempfile.mkstemp(suffix='.lua', text=True)
        harness_fd, harness_path = tempfile.mkstemp(suffix='.lua', text=True)

        with open(src_path, 'w', encoding='utf-8') as f:
            f.write(source)
        os.close(src_fd)

        harness_code = PRINT_CAPTURE_LUA.replace('_SRCFILE_', src_path)
        with open(harness_path, 'w', encoding='utf-8') as f:
            f.write(harness_code)
        os.close(harness_fd)

        for lua_bin in ['lua5.1', 'lua']:
            try:
                proc = subprocess.Popen(
                    [lua_bin, harness_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True
                )
                try:
                    stdout_b, stderr_b = proc.communicate(timeout=timeout)
                    stdout = stdout_b.decode('latin-1', errors='replace')
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except:
                        pass
                    proc.wait()
                    return "TIMEOUT", "timeout"

                in_block = False
                lines = []
                for line in stdout.splitlines():
                    if line == "___CAPTURED_PRINT_START___":
                        in_block = True
                        continue
                    if line == "___CAPTURED_PRINT_END___":
                        break
                    if in_block:
                        lines.append(line)

                if lines:
                    return "\n".join(lines), "subprocess success"
                else:
                    if stdout.strip():
                        return f"[no capture]\nRaw stdout:\n{stdout}", "subprocess no capture"
                    return None, "subprocess empty stdout"
            except FileNotFoundError:
                continue
        return None, "no lua binary found"
    finally:
        for p in (src_path, harness_path):
            if p:
                try:
                    os.unlink(p)
                except:
                    pass


def _capture_via_lupa(source):
    if not HAS_LUPA:
        return None, "lupa not installed"
    captured = []
    try:
        lua = lupa.LuaRuntime(unpack_returned_tuples=True)
    except Exception as e:
        return None, f"lupa init: {e}"

    lua.globals().print = lambda *a: captured.append("\t".join(str(x) for x in a))
    lua.globals().warn  = lambda *a: captured.append("WARN: " + "\t".join(str(x) for x in a))

    try:
        lua.execute("os.execute = function() error('blocked') end")
        lua.execute("io = nil")
    except:
        pass

    try:
        lua.execute(source)
        if captured:
            return "\n".join(captured), "lupa success"
    except Exception as e:
        return f"LUA_ERROR: {e}", "lupa error"
    return None, "no output"


def _lupa_decode_wearedevs(source):
    trace = []
    out, msg = _capture_via_subprocess(source)
    trace.append(f"subprocess: {msg}")
    if out and out.strip():
        return out.strip(), trace

    out, msg = _capture_via_lupa(source)
    trace.append(f"lupa: {msg}")
    if out and out.strip():
        return out.strip(), trace

    return None, trace
