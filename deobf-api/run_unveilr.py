import subprocess
import tempfile
import os
import sys
import shutil

def run_unveilr(source_code: str, timeout: int = 60) -> str:
    """
    Run Unveilr on the given Lua source code and return the deobfuscated output.
    """
    # Find lune executable (assumes it's installed)
    lune_path = shutil.which("lune")
    if not lune_path:
        # Fallback to luau if lune not available
        lune_path = shutil.which("luau")
        if not lune_path:
            raise RuntimeError("Neither lune nor luau found. Please install lune (https://lune-org.github.io/)")
    
    # Create temporary input file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as inf:
        inf.write(source_code)
        input_path = inf.name
    
    output_path = tempfile.NamedTemporaryFile(suffix='.lua', delete=False).name
    
    # Path to unveilr main.lua
    unveilr_main = os.path.join(os.path.dirname(__file__), 'unveilr', 'main.lua')
    
    # Build command: lune run unveilr/main.lua input.lua output.lua
    cmd = [lune_path, 'run', unveilr_main, input_path, output_path]
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise RuntimeError(f"Unveilr failed: {proc.stderr}")
        
        if not os.path.exists(output_path):
            raise RuntimeError("Unveilr did not produce output file")
        
        with open(output_path, 'r', encoding='utf-8') as f:
            result = f.read()
        
        return result
    finally:
        # Clean up temp files
        os.unlink(input_path)
        if os.path.exists(output_path):
            os.unlink(output_path)
