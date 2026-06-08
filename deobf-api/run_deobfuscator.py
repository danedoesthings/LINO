"""
Subprocess runners for external Lua deobfuscators.
Handles vm_deobfuscator.lua, deobfuscator.lua, and unveilr.
"""

import subprocess
import tempfile
import os
import shutil
import logging

log = logging.getLogger('deobf-api')


def run_vm_deobfuscator(source_code: str, timeout: int = 60) -> str:
    """Run the VM deobfuscator Lua script."""
    lua_path = shutil.which('lua5.1') or shutil.which('lua')
    if not lua_path:
        log.warning("No Lua interpreter found for VM deobfuscator")
        return ""

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.lua', delete=False) as inf:
        inf.write(source_code.encode('latin-1', errors='replace'))
        input_path = inf.name

    output_path = tempfile.NamedTemporaryFile(suffix='.lua', delete=False).name
    deobf_path = os.path.join(os.path.dirname(__file__), 'vm_deobfuscator.lua')

    if not os.path.exists(deobf_path):
        log.error(f"VM deobfuscator not found at {deobf_path}")
        return ""

    cmd = [lua_path, deobf_path, input_path, '-o', output_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout)
        if proc.returncode == 0 and os.path.exists(output_path):
            with open(output_path, 'rb') as f:
                result_bytes = f.read()
            try:
                return result_bytes.decode('utf-8', errors='replace')
            except Exception:
                return result_bytes.decode('latin-1', errors='replace')
        else:
            stderr = proc.stderr.decode('utf-8', errors='replace') if proc.stderr else ""
            if stderr:
                log.debug(f"VM deobfuscator stderr: {stderr[:200]}")
    except subprocess.TimeoutExpired:
        log.warning(f"VM deobfuscator timed out after {timeout}s")
    except Exception as e:
        log.error(f"VM deobfuscator error: {e}")
    finally:
        try:
            os.unlink(input_path)
        except Exception:
            pass
        try:
            if os.path.exists(output_path):
                os.unlink(output_path)
        except Exception:
            pass

    return ""


def run_prometheus_deobfuscator(source_code: str, timeout: int = 120) -> str:
    """Run the Prometheus deobfuscator Lua script."""
    lua_path = shutil.which('lua5.1') or shutil.which('lua')
    if not lua_path:
        log.warning("No Lua interpreter found for Prometheus deobfuscator")
        return ""

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.lua', delete=False) as inf:
        inf.write(source_code.encode('latin-1', errors='replace'))
        input_path = inf.name

    output_path = tempfile.NamedTemporaryFile(suffix='.lua', delete=False).name
    deobf_path = os.path.join(os.path.dirname(__file__), 'deobfuscator.lua')

    if not os.path.exists(deobf_path):
        log.error(f"Prometheus deobfuscator not found at {deobf_path}")
        return ""

    cmd = [lua_path, deobf_path, input_path, '-o', output_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout)
        if proc.returncode == 0 and os.path.exists(output_path):
            with open(output_path, 'rb') as f:
                result_bytes = f.read()
            try:
                return result_bytes.decode('utf-8', errors='replace')
            except Exception:
                return result_bytes.decode('latin-1', errors='replace')
        else:
            stderr = proc.stderr.decode('utf-8', errors='replace') if proc.stderr else ""
            if stderr:
                log.debug(f"Prometheus deobfuscator stderr: {stderr[:200]}")
    except subprocess.TimeoutExpired:
        log.warning(f"Prometheus deobfuscator timed out after {timeout}s")
    except Exception as e:
        log.error(f"Prometheus deobfuscator error: {e}")
    finally:
        try:
            os.unlink(input_path)
        except Exception:
            pass
        try:
            if os.path.exists(output_path):
                os.unlink(output_path)
        except Exception:
            pass

    return ""


def run_unveilr(source_code: str, timeout: int = 120) -> str:
    """Run the Unveilr Luau deobfuscator."""
    lune_path = shutil.which("lune")
    if not lune_path:
        lune_path = shutil.which("luau")
    if not lune_path:
        log.warning("Neither lune nor luau found for Unveilr")
        return ""

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.lua', delete=False) as inf:
        inf.write(source_code.encode('latin-1', errors='replace'))
        input_path = inf.name

    output_path = tempfile.NamedTemporaryFile(suffix='.lua', delete=False).name
    unveilr_main = os.path.join(os.path.dirname(__file__), 'unveilr', 'main.lua')

    if not os.path.exists(unveilr_main):
        log.error(f"Unveilr main.lua not found at {unveilr_main}")
        return ""

    cmd = [lune_path, 'run', unveilr_main, input_path, output_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout)
        if proc.returncode == 0 and os.path.exists(output_path):
            with open(output_path, 'rb') as f:
                result_bytes = f.read()
            try:
                return result_bytes.decode('utf-8', errors='replace')
            except Exception:
                return result_bytes.decode('latin-1', errors='replace')
        else:
            stderr = proc.stderr.decode('utf-8', errors='replace') if proc.stderr else ""
            if stderr:
                log.debug(f"Unveilr stderr: {stderr[:200]}")
    except subprocess.TimeoutExpired:
        log.warning(f"Unveilr timed out after {timeout}s")
    except Exception as e:
        log.error(f"Unveilr error: {e}")
    finally:
        try:
            os.unlink(input_path)
        except Exception:
            pass
        try:
            if os.path.exists(output_path):
                os.unlink(output_path)
        except Exception:
            pass

    return ""
