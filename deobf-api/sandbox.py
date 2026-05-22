import os, re, subprocess, tempfile, shutil, traceback, hashlib

LUA_BIN = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
RUNTIME_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox_runtime.lua')
APP_DIR = os.path.dirname(os.path.abspath(__file__))

def _lua_str(path):
    return '"' + path.replace('\\', '\\\\').replace('"', '\\"') + '"'

def execute_sandbox(source, use_emulator=False, timeout=120):
    if not os.path.isfile(RUNTIME_PATH):
        return [], [], f'sandbox_runtime.lua not found at {RUNTIME_PATH!r}'
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
        try:
            with open(drv, 'w', encoding='utf-8') as f:
                f.write(driver)
        except Exception as e:
            return [], [], f'WRITE_DRIVER_ERROR: {e}'
        env = os.environ.copy()
        env['LUA_PATH'] = os.path.join(APP_DIR, '?.lua') + ';' + env.get('LUA_PATH', '')
        env['LUA_CPATH'] = os.path.join(APP_DIR, '?.so') + ';' + env.get('LUA_CPATH', '')
        proc_error = ''
        try:
            result = subprocess.run(
                [LUA_BIN, drv],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=temp_dir,
                env=env
            )
            if result.returncode != 0:
                proc_error = f'LUA_EXIT_{result.returncode}: {result.stderr[:400]}'
        except subprocess.TimeoutExpired:
            proc_error = 'TIMEOUT_EXPIRED'
        except FileNotFoundError:
            proc_error = f'LUA_NOT_FOUND: {LUA_BIN}'
        except Exception as e:
            proc_error = f'SUBPROCESS_ERROR: {e}'
        if proc_error:
            error_log.append(proc_error)
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
        so_path = os.path.join(temp_dir, 'sandbox_output.lua')
        if os.path.exists(so_path):
            try:
                with open(so_path, encoding='utf-8', errors='replace') as f:
                    so_data = f.read()
                if so_data.strip():
                    layers.append(so_data)
            except Exception as e:
                error_log.append(f'READ_SANDBOX_OUTPUT_ERROR: {e}')
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
        for fname in ('diag.txt', 'error.txt'):
            fp = os.path.join(temp_dir, fname)
            if os.path.exists(fp):
                try:
                    with open(fp, encoding='utf-8', errors='replace') as f:
                        txt = f.read()
                    if txt:
                        diag = (txt + '\n---\n' + diag) if diag else txt
                except Exception:
                    pass
        if error_log:
            prefix = '\n'.join(error_log)
            diag = prefix + ('\n---\n' + diag if diag else '')
        if not layers and not caps and not diag:
            diag = 'NO_OUTPUT: sandbox produced no output files'
    except Exception as e:
        diag = f'SANDBOX_FATAL: {e}\n{traceback.format_exc()}'
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    return layers, caps, diag
