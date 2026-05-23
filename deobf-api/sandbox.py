import os, sys, re, subprocess, tempfile, shutil, traceback

LUA_BIN = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
RUNTIME_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox_runtime.lua')
APP_DIR = os.path.dirname(os.path.abspath(__file__))

def _lua_str(path):
    return '"' + path.replace('\\', '\\\\').replace('"', '\\"') + '"'

def _lua_table_literal(strings):
    """Build a Lua table literal from a list of already‑escaped Lua strings."""
    parts = []
    for s in strings:
        parts.append('"' + s + '"')
    return '{' + ','.join(parts) + '}'

def execute_sandbox(source, use_emulator=False, timeout=120, varargs=None):
    if not os.path.isfile(RUNTIME_PATH):
        return [], [], f'MISSING_RUNTIME: {RUNTIME_PATH}'
    error_log, layers, caps, diag = [], [], [], ''
    try:
        temp_dir = tempfile.mkdtemp()
    except Exception as e:
        return [], [], f'TEMP_DIR_ERROR: {e}'
    try:
        inp = os.path.join(temp_dir, 'input.lua')
        drv = os.path.join(temp_dir, 'driver.lua')
        try:
            raw = source.encode('utf-8', errors='replace') if isinstance(source, str) else source
            with open(inp, 'wb') as f:
                f.write(raw)
        except Exception as e:
            return [], [], f'WRITE_INPUT_ERROR: {e}'
        try:
            with open(RUNTIME_PATH, 'r', encoding='utf-8') as f:
                runtime = f.read()
        except Exception as e:
            return [], [], f'READ_RUNTIME_ERROR: {e}'
        out_dir = temp_dir.replace('\\', '/')
        inp_path = inp.replace('\\', '/')
        driver = runtime.replace('"OUTDIR_PLACEHOLDER"', _lua_str(out_dir)).replace('"INPATH_PLACEHOLDER"', _lua_str(inp_path))

        # Embed varargs directly by replacing the bare placeholder with a Lua table literal
        if varargs and isinstance(varargs, list):
            table_literal = _lua_table_literal(varargs)
            driver = driver.replace('VARARGS_PLACEHOLDER', table_literal)
            print(f"[sandbox] embedded {len(varargs)} varargs into driver", file=sys.stderr)
        else:
            driver = driver.replace('VARARGS_PLACEHOLDER', 'nil')
            print(f"[sandbox] no varargs, set to nil", file=sys.stderr)

        try:
            with open(drv, 'w', encoding='utf-8') as f:
                f.write(driver)
        except Exception as e:
            return [], [], f'WRITE_DRIVER_ERROR: {e}'

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
        dump = os.path.join(temp_dir, 'dump.bin')
        if os.path.exists(dump):
            try:
                with open(dump, 'rb') as f:
                    bc = f.read()
                if bc and len(bc) >= 12:
                    layers.append(bc)
            except Exception as e:
                error_log.append(f'READ_DUMP_ERROR: {e}')
        capf = os.path.join(temp_dir, 'cap.txt')
        if os.path.exists(capf):
            try:
                with open(capf, encoding='utf-8', errors='replace') as f:
                    data = f.read()
                if data:
                    for part in data.split('---SEP---'):
                        s = part.strip()
                        if len(s) > 5:
                            caps.append(s)
            except Exception as e:
                error_log.append(f'READ_CAP_ERROR: {e}')
        memf = os.path.join(temp_dir, 'memory.txt')
        if os.path.exists(memf):
            try:
                with open(memf, encoding='utf-8', errors='replace') as f:
                    data = f.read()
                if data:
                    for part in data.split('---MEMSEP---'):
                        s = part.strip()
                        if len(s) > 10:
                            caps.append(s)
            except Exception as e:
                error_log.append(f'READ_MEM_ERROR: {e}')
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
