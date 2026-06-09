import subprocess
import tempfile
import os
import shutil
import logging

log = logging.getLogger(__name__)


def run_unveilr(source_code: str, timeout: int = 60) -> str:
    """Run the Unveilr Luau deobfuscator."""
    lune_path = shutil.which("lune")
    if not lune_path:
        lune_path = shutil.which("luau")
    if not lune_path:
        log.warning("Neither lune nor luau found for Unveilr")
        return ""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as inf:
        inf.write(source_code)
        input_path = inf.name

    output_path = tempfile.NamedTemporaryFile(suffix='.lua', delete=False).name

    unveilr_main = os.path.join(os.path.dirname(__file__), 'unveilr', 'main.lua')

    if not os.path.exists(unveilr_main):
        log.error(f"Unveilr main.lua not found at {unveilr_main}")
        _cleanup(input_path, output_path)
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
        _cleanup(input_path, output_path)

    return ""


def _cleanup(*paths):
    """Helper to clean up temp files."""
    for path in paths:
        try:
            if path and os.path.exists(path):
                os.unlink(path)
        except Exception:
            pass
