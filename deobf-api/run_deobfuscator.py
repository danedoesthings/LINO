import subprocess
import tempfile
import os
import shutil

def run_vm_deobfuscator(source_code: str, timeout: int = 60) -> str:
    lua_path = shutil.which('lua5.1') or shutil.which('lua')
    if not lua_path:
        return ""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.lua', delete=False) as inf:
        inf.write(source_code.encode('latin-1'))
        input_path = inf.name
    output_path = tempfile.NamedTemporaryFile(suffix='.lua', delete=False).name
    deobf_path = os.path.join(os.path.dirname(__file__), 'vm_deobfuscator.lua')
    cmd = [lua_path, deobf_path, input_path, '-o', output_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout)
        if os.path.exists(output_path):
            with open(output_path, 'rb') as f:
                result_bytes = f.read()
                try:
                    return result_bytes.decode('utf-8', errors='replace')
                except:
                    return result_bytes.decode('latin-1', errors='replace')
        return ""
    except Exception:
        return ""
    finally:
        try:
            os.unlink(input_path)
        except:
            pass
        try:
            if os.path.exists(output_path):
                os.unlink(output_path)
        except:
            pass

def run_prometheus_deobfuscator(source_code: str, timeout: int = 120) -> str:
    lua_path = shutil.which('lua5.1') or shutil.which('lua')
    if not lua_path:
        return ""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.lua', delete=False) as inf:
        inf.write(source_code.encode('latin-1'))
        input_path = inf.name
    output_path = tempfile.NamedTemporaryFile(suffix='.lua', delete=False).name
    deobf_path = os.path.join(os.path.dirname(__file__), 'deobfuscator.lua')
    cmd = [lua_path, deobf_path, input_path, '-o', output_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout)
        if os.path.exists(output_path):
            with open(output_path, 'rb') as f:
                result_bytes = f.read()
                try:
                    return result_bytes.decode('utf-8', errors='replace')
                except:
                    return result_bytes.decode('latin-1', errors='replace')
        return ""
    except Exception:
        return ""
    finally:
        try:
            os.unlink(input_path)
        except:
            pass
        try:
            if os.path.exists(output_path):
                os.unlink(output_path)
        except:
            pass

def run_unveilr(source_code: str, timeout: int = 60) -> str:
    lune_path = shutil.which("lune")
    if not lune_path:
        lune_path = shutil.which("luau")
        if not lune_path:
            return ""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.lua', delete=False) as inf:
        inf.write(source_code.encode('latin-1'))
        input_path = inf.name
    output_path = tempfile.NamedTemporaryFile(suffix='.lua', delete=False).name
    unveilr_main = os.path.join(os.path.dirname(__file__), 'unveilr', 'main.lua')
    cmd = [lune_path, 'run', unveilr_main, input_path, output_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=False, timeout=timeout)
        if os.path.exists(output_path):
            with open(output_path, 'rb') as f:
                result_bytes = f.read()
                try:
                    return result_bytes.decode('utf-8', errors='replace')
                except:
                    return result_bytes.decode('latin-1', errors='replace')
        return ""
    except Exception:
        return ""
    finally:
        try:
            os.unlink(input_path)
        except:
            pass
        try:
            if os.path.exists(output_path):
                os.unlink(output_path)
        except:
            pass
