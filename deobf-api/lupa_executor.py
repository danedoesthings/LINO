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
    real_print("ERR:COMPILE:" .. tostring(err))
else
    local ok, result = pcall(f)
    if not ok then
        real_print("ERR:RUNTIME:" .. tostring(result))
    end
end
if #captured > 0 then
    real_print("___CAPTURED_PRINT_START___")
    for _, line in ipairs(captured) do
        real_print(line)
    end
    real_print("___CAPTURED_PRINT_END___")
end
"""


def _capture_via_subprocess(source: str, timeout: int = 45) -> Tuple[Optional[str], str]:
    src_fd, src_path = tempfile.mkstemp(suffix='.lua', text=True)
    harness_fd, harness_path = tempfile.mkstemp(suffix='.lua', text=True)
    try:
        with os.fdopen(src_fd, 'w', encoding='utf-8') as f:
            f.write(source)
        with os.fdopen(harness_fd, 'w', encoding='utf-8') as f:
            f.write(PRINT_CAPTURE_LUA.replace('_SRCFILE_', src_path))
        
        for lua_bin in ['lua5.1', 'lua']:
            try:
                proc = subprocess.Popen(
                    [lua_bin, harness_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    preexec_fn=lambda: None, start_new_session=True
                )
                try:
                    stdout_b, _ = proc.communicate(timeout=timeout)
                    stdout = stdout_b.decode('latin-1', errors='replace')
                except subprocess.TimeoutExpired:
                    try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except: pass
                    proc.wait()
                    return None, "timeout"
                
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
            except FileNotFoundError:
                continue
        return None, "no lua binary found"
    finally:
        for p in (src_path, harness_path):
            try: os.unlink(p)
            except: pass


def _capture_via_lupa(source: str) -> Tuple[Optional[str], str]:
    if not HAS_LUPA:
        return None, "lupa not installed"
    captured = []
    try:
        lua = lupa.LuaRuntime(unpack_returned_tuples=True)
    except Exception as e:
        return None, f"lupa init: {e}"
    
    lua.globals().print = lambda *a: captured.append("\t".join(str(x) for x in a))
    lua.globals().warn = lambda *a: captured.append("WARN: " + "\t".join(str(x) for x in a))
    
    try:
        lua.execute("os.execute = function() error('blocked') end")
        lua.execute("io = nil")
    except Exception:
        pass
    
    try:
        lua.execute(source)
        if captured:
            return "\n".join(captured), "lupa success"
    except Exception as e:
        return None, f"lupa error: {e}"
    return None, "no output"


def _lupa_decode_wearedevs(source: str) -> Tuple[Optional[str], List[str]]:
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
