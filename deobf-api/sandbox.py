import os, subprocess, tempfile, shutil, traceback

LUNE_BIN = shutil.which('lune')
RENBEX_VM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'renbex_vm.luau')

def execute_sandbox(source, timeout=120, varargs=None):
    if not LUNE_BIN:
        return [], [], "Lune not installed"
    if not os.path.isfile(RENBEX_VM_PATH):
        return [], [], "Renbex0 VM not found"

    error_log, layers, caps, diag = [], [], [], ''
    try:
        temp_dir = tempfile.mkdtemp()
    except Exception as e:
        return [], [], f'TEMP_DIR_ERROR: {e}'
    try:
        input_script = os.path.join(temp_dir, 'input.luau')
        driver_script = os.path.join(temp_dir, 'driver.luau')
        output_dir   = temp_dir.replace('\\', '/')

        with open(input_script, 'wb') as f:
            f.write(source.encode('utf-8', errors='replace'))

        driver_code = f'''
local renbex = loadfile("{RENBEX_VM_PATH}")
if renbex then
    local ok, err = pcall(renbex)
    if not ok then
        io.stderr:write("RENBEX_LOAD_ERROR: " .. tostring(err) .. "\\n")
    end
end

local cap_dir = "{output_dir}"
local cap_count = 0

local orig_load = loadstring or load
loadstring = function(chunk, name)
    cap_count = cap_count + 1
    local f = io.open(cap_dir .. "/layer_" .. cap_count .. ".luau", "w")
    if f then
        f:write(chunk)
        f:close()
    end
    if orig_load then
        return orig_load(chunk, name)
    end
    return function() end
end
load = loadstring

local target = loadfile("{input_script}")
if target then
    local ok, err = pcall(target)
    if not ok then
        io.stderr:write("EXECUTION_ERROR: " .. tostring(err) .. "\\n")
    end
else
    io.stderr:write("COULD_NOT_LOAD_INPUT\\n")
end

local diag = io.open(cap_dir .. "/diag.txt", "w")
if diag then
    diag:write("Captures: " .. cap_count .. "\\n")
    diag:close()
end
'''

        with open(driver_script, 'w', encoding='utf-8') as f:
            f.write(driver_code)

        env = os.environ.copy()
        proc_error = ''
        stderr_output = ''
        try:
            result = subprocess.run(
                [LUNE_BIN, 'run', driver_script],
                capture_output=True, text=True, timeout=timeout, cwd=temp_dir, env=env
            )
            stderr_output = result.stderr
            if result.returncode != 0:
                proc_error = f'LUNE_EXIT_{result.returncode}: {stderr_output[:400]}'
        except subprocess.TimeoutExpired:
            proc_error = f'TIMEOUT_EXPIRED ({timeout}s)'
        except Exception as e:
            proc_error = f'SUBPROCESS_ERROR: {e}'

        if proc_error:
            error_log.append(proc_error)
        if stderr_output.strip():
            error_log.append(f'STDERR: {stderr_output.strip()[:500]}')

        i = 1
        while True:
            p = os.path.join(temp_dir, f'layer_{i}.luau')
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

        diag_parts = []
        for fname in ('diag.txt', 'error.txt'):
            fp = os.path.join(temp_dir, fname)
            if os.path.exists(fp):
                try:
                    with open(fp, encoding='utf-8', errors='replace') as f:
                        txt = f.read()
                    if txt:
                        diag_parts.append(f"[{fname}]\n{txt.strip()}")
                except:
                    pass
        if diag_parts:
            diag = '\n'.join(diag_parts)
        if error_log:
            prefix = '\n'.join(error_log)
            diag = prefix + ('\n---\n' + diag if diag else '')
        if not layers and not diag:
            diag = 'NO_OUTPUT'
    except Exception as e:
        diag = f'SANDBOX_FATAL: {e}\n{traceback.format_exc()}'
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    return layers, caps, diag
