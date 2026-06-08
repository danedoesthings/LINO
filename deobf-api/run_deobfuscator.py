def run_unveilr(source_code: str, timeout: int = 120) -> str:
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
    # CRITICAL FIX: cmd was missing
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
        for p in (input_path, output_path):
            try:
                if os.path.exists(p):
                    os.unlink(p)
            except Exception:
                pass
    return ""
