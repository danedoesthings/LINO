"""
lupa_executor.py — in-process Lua execution via lupa (LuaJIT/Lua 5.x)
Used as a fast, reliable fallback when no system Lua binary is available,
or as the primary executor for scripts that output via print/warn rather
than loadstring/load hooks.
"""

import base64, re, math, sys
from typing import Optional, List, Tuple

try:
    import lupa
    HAS_LUPA = True
except ImportError:
    HAS_LUPA = False


def _lupa_run(source: str, timeout_seconds: int = 30) -> Tuple[Optional[str], List[str]]:
    """
    Execute Lua source in-process via lupa.
    Returns (captured_output: str | None, trace: list[str])
    captured_output is a joined string of all print/warn calls.
    """
    if not HAS_LUPA:
        return None, ["lupa not installed"]

    trace = []
    captured_lines = []

    try:
        lua = lupa.LuaRuntime(unpack_returned_tuples=True)
    except Exception as e:
        return None, [f"lupa init failed: {e}"]

    def py_print(*args):
        line = "\t".join("nil" if a is None else str(a) for a in args)
        captured_lines.append(line)

    def py_warn(*args):
        line = "\t".join("nil" if a is None else str(a) for a in args)
        captured_lines.append(line)  # capture warn() output too

    lua.globals().print = py_print
    lua.globals().warn = py_warn

    # Block dangerous globals
    try:
        lua.execute("os.execute = function() error('blocked') end")
        lua.execute("io = nil")
    except Exception:
        pass

    # Instruction limit via debug hook (Lua 5.x only)
    try:
        lua.execute("""
            if debug and debug.sethook then
                local _count = 0
                debug.sethook(function()
                    _count = _count + 1
                    if _count > 2000000 then error("instruction limit exceeded") end
                end, "", 1000)
            end
        """)
    except Exception:
        pass

    try:
        lua.execute(source)
        trace.append("lupa_exec: success")
    except lupa.LuaError as e:
        trace.append(f"lupa_exec: lua error: {e}")
    except Exception as e:
        trace.append(f"lupa_exec: python error: {e}")

    if captured_lines:
        return "\n".join(captured_lines), trace
    return None, trace


def _lupa_decode_wearedevs(source: str) -> Tuple[Optional[str], List[str]]:
    """
    Run the script and capture all print/warn output.
    For Lua Land Hub / wearedevs VM scripts that produce output
    via print() rather than loadstring(), this is the correct
    capture method.
    """
    output, trace = _lupa_run(source)
    if output and len(output.strip()) > 0:
        return output.strip(), trace
    return None, trace
