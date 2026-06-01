import os, json, subprocess, tempfile, shutil, re

def run_lune_darklua_pipeline(source: str) -> str:
    tmpdir = tempfile.mkdtemp()
    input_path = os.path.join(tmpdir, "input.lua")
    cache_path = os.path.join(tmpdir, "string_cache.json")
    stage2_path = os.path.join(tmpdir, "stage2.lua")
    output_path = os.path.join(tmpdir, "output.lua")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    extractor_path = os.path.join(base_dir, "extractor.luau")
    darklua_config_path = os.path.join(base_dir, "darklua.json")

    try:
        with open(input_path, "w", encoding="utf-8") as f:
            f.write(source)

        subprocess.run(
            ["lune", "run", extractor_path, input_path],
            capture_output=True, text=True, timeout=45, cwd=tmpdir
        )

        if not os.path.exists(cache_path):
            return ""

        with open(cache_path, "r", encoding="utf-8") as f:
            string_lookup = json.load(f)

        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            source_code = f.read()

        for index, raw_string in string_lookup.items():
            safe_string = raw_string.replace('\\', '\\\\').replace('"', '\\"')
            source_code = source_code.replace(f"R[{index}]", f'"{safe_string}"')
            source_code = source_code.replace(f'R["{index}"]', f'"{safe_string}"')

        getter_match = re.search(
            r'function\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*return\s+[a-zA-Z0-9_]+\s*\[[^\]]+\+\s*\(?(\d+)\)?\s*\]\s*end',
            source_code
        )
        if getter_match:
            getter_name = getter_match.group(1)
            offset_const = int(getter_match.group(2))

            def repl(m):
                idx = int(m.group(1)) + offset_const
                str_idx = str(idx)
                if str_idx in string_lookup:
                    safe_str = string_lookup[str_idx].replace('\\', '\\\\').replace('"', '\\"')
                    return f'"{safe_str}"'
                return m.group(0)

            source_code = re.sub(rf'{getter_name}\s*\(\s*(-?\d+)\s*\)', repl, source_code)

        with open(stage2_path, "w", encoding="utf-8") as f:
            f.write(source_code)

        subprocess.run(
            ["darklua", "process", "--config", darklua_config_path, stage2_path, output_path],
            capture_output=True, text=True, timeout=45, cwd=tmpdir
        )

        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8") as f:
                return f.read()
        return ""

    except Exception:
        return ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
