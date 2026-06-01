import os
import json
import subprocess

def run_deobfuscation_pipeline(input_filename, output_filename):
    print(f"[*] Commencing pipeline execution on: {input_filename}")

    subprocess.run(["lune", "run", "extractor.luau", input_filename], check=True)

    with open("string_cache.json", "r") as f:
        string_lookup = json.load(f)

    with open(input_filename, "r", encoding="utf-8", errors="replace") as f:
        source_code = f.read()

    print("[*] Stage 2: Substituting string lookups across script body...")
    for index, raw_string in string_lookup.items():
        source_code = source_code.replace(f"R[{index}]", f'"{raw_string}"')
        source_code = source_code.replace(f'R["{index}"]', f'"{raw_string}"')

    intermediate_file = "stage2_substituted.lua"
    with open(intermediate_file, "w", encoding="utf-8") as f:
        f.write(source_code)

    print("[*] Stage 3: Deploying AST Optimization Engines via Darklua...")
    darklua_config = {
        "generator": {
            "name": "readable",
            "column_span": 120
        },
        "rules": [
            "compute_expression",
            "remove_unused_if_branch",
            "remove_unused_while",
            "convert_index_to_field",
            "remove_nil_declaration"
        ]
    }

    with open("darklua.json", "w") as f:
        json.dump(darklua_config, f, indent=4)

    try:
        subprocess.run(["darklua", "process", intermediate_file, output_filename], check=True)
        print(f"[+] Complete Success! Fully linearized code compiled inside: {output_filename}")
    except FileNotFoundError:
        print("[-] Critical: Darklua binary must be installed and globally appended to your system PATH variables.")
    finally:
        if os.path.exists(intermediate_file): os.remove(intermediate_file)
        if os.path.exists("string_cache.json"): os.remove("string_cache.json")
        if os.path.exists("darklua.json"): os.remove("darklua.json")

if __name__ == "__main__":
    run_deobfuscation_pipeline("Test deobf.txt", "deobfuscated_clean.lua")
